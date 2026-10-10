#!/usr/bin/env node

import https from 'node:https';
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import child_process from 'node:child_process';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import {
  decideInstallMode,
  findRemovalTargets,
  getNcRootForMode,
  installerEnvForMode,
  modeWarningFor,
  runUninstallerScript,
  uninstallFailureSuggestion,
  uninstallerForRoot
} from '../lib/setup.mjs';

const baseUrl = process.env.NC_BASE_URL || 'https://auth.nodecommand.app';
/**
 * Agent API origin for device-channel endpoints (`/api/clients/*`), package
 * downloads, and `/releases/*`. The auth host (`baseUrl` above) serves only
 * browser-facing OAuth/device flow and enrollment (`/oauth/*`, `/api/enroll*`);
 * Caddy routes `/api/clients*` solely on the agent (and dash) edge, so
 * verification against the auth host answers 404. `NC_SERVER_URL` is NOT
 * this value: it is the agent WS/server address written to the client env.
 */
export const apiBase = process.env.NC_API_URL || 'https://agent.nodecommand.app';
const clientId = 'nc-cli';

export const DEFAULT_CLI_REQUEST_TIMEOUT_MS = 30_000;
export const DEFAULT_CLI_MAX_RESPONSE_BYTES = 8 * 1024 * 1024; // 8 MiB

export function getCliRequestTimeoutMs() {
  const envVal = Number(process.env.NC_CLI_TIMEOUT_MS || process.env.NC_TIMEOUT_MS);
  return Number.isFinite(envVal) && envVal > 0 ? envVal : DEFAULT_CLI_REQUEST_TIMEOUT_MS;
}

export function getCliMaxResponseBytes() {
  const envVal = Number(process.env.NC_CLI_MAX_RESPONSE_BYTES);
  return Number.isFinite(envVal) && envVal > 0 ? envVal : DEFAULT_CLI_MAX_RESPONSE_BYTES;
}

/**
 * Sends a JSON HTTP request using node:https or node:http with timeout and response cap guards (NC-AUD-010).
 * @param {string} method
 * @param {string} targetUrl
 * @param {Record<string, unknown>|null} body
 * @param {Record<string, string>} [extraHeaders]
 * @param {{ timeoutMs?: number, maxResponseBytes?: number, signal?: AbortSignal }} [options]
 * @returns {Promise<{ status: number, headers: import('node:http').IncomingHttpHeaders, data: any }>}
 */
export function requestJson(method, targetUrl, body, extraHeaders = {}, options = {}) {
  const timeoutMs = options.timeoutMs ?? getCliRequestTimeoutMs();
  const maxBytes = options.maxResponseBytes ?? getCliMaxResponseBytes();

  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const client = u.protocol === 'http:' ? http : https;
    const payload = body === null || body === undefined ? null : JSON.stringify(body);
    const signal = options.signal ?? (timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined);

    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };

    const req = client.request(
      u,
      {
        method,
        signal,
        headers: {
          ...(payload !== null
            ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
            : {}),
          Accept: 'application/json',
          'User-Agent': 'nc-cli/0.1.0',
          ...extraHeaders
        }
      },
      (res) => {
        let totalBytes = 0;
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          if (settled) return;
          totalBytes += Buffer.byteLength(chunk, 'utf8');
          if (totalBytes > maxBytes) {
            const err = new Error(`Response exceeded maximum allowed size of ${maxBytes} bytes`);
            res.destroy(err);
            req.destroy(err);
            fail(err);
            return;
          }
          raw += chunk;
        });
        res.on('end', () => {
          if (settled) return;
          settled = true;
          let data;
          try {
            data = JSON.parse(raw);
          } catch {
            data = { raw };
          }
          resolve({
            status: res.statusCode || 0,
            headers: res.headers,
            data
          });
        });
        res.on('error', fail);
      }
    );

    req.on('error', fail);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

/**
 * Sends a JSON POST request using node:https or node:http.
 * @param {string} targetUrl
 * @param {Record<string, unknown>} body
 * @param {Record<string, string>} [extraHeaders]
 * @param {{ timeoutMs?: number, maxResponseBytes?: number, signal?: AbortSignal }} [options]
 * @returns {Promise<{ status: number, headers: import('node:http').IncomingHttpHeaders, data: any }>}
 */
function postJson(targetUrl, body, extraHeaders = {}, options = {}) {
  return requestJson('POST', targetUrl, body, extraHeaders, options);
}

/**
 * Sends a JSON GET request using node:https or node:http.
 * @param {string} targetUrl
 * @param {Record<string, string>} [extraHeaders]
 * @param {{ timeoutMs?: number, maxResponseBytes?: number, signal?: AbortSignal }} [options]
 * @returns {Promise<{ status: number, headers: import('node:http').IncomingHttpHeaders, data: any }>}
 */
function getJson(targetUrl, extraHeaders = {}, options = {}) {
  return requestJson('GET', targetUrl, null, extraHeaders, options);
}

/**
 * True when two absolute URLs share scheme + host + port (redirect guard).
 * Device credentials are only forwarded on same-origin redirects so a token
 * issued for the agent edge never leaks to a third-party host.
 * @param {string} a
 * @param {string} b
 */
function isSameOrigin(a, b) {
  try {
    const ua = new URL(String(a));
    const ub = new URL(String(b));
    return ua.protocol === ub.protocol && ua.host === ub.host;
  } catch {
    return false;
  }
}

/**
 * True for per-client device-authenticated package URLs
 * (`/api/clients/<id>/update/...`: bootstrap, package, windows-exe). These
 * endpoints run the control-plane clientAuth path (NC-Device bearer +
 * Device Proof v1, see apps/agent/core/enroll-bootstrap.mjs and
 * apps/control-plane/server.mjs clientAuth) and answer 401 without them.
 * The public fallback (`/releases/client/<version>/bootstrap.tar.gz`) is
 * anonymous and must NEVER receive device headers.
 * @param {string} targetUrl
 */
export function isDeviceAuthenticatedPackageUrl(targetUrl) {
  try {
    const u = new URL(String(targetUrl), 'http://nc.invalid');
    return (u.pathname || '').startsWith('/api/clients/');
  } catch {
    return false;
  }
}

/**
 * Builds the device-identity headers for one package download. Parameters
 * mirror redeemEnrollment exactly: the same createDeviceProofCli with
 * method GET, the full request URL, and the redemption-issued client token
 * as credential (same canonical string the agent updater uses via
 * authenticatedHeaders/deviceAuthHeaders).
 * @param {{ hostId: string, hostToken: string, privateKey: import('node:crypto').KeyObject }} device
 * @param {string} absoluteUrl Full request URL the proof is bound to
 */
export function buildDeviceDownloadHeaders({ hostId, hostToken, privateKey }, absoluteUrl) {
  const proof = createDeviceProofCli({
    privateKey,
    hostId,
    method: 'GET',
    url: String(absoluteUrl),
    credential: String(hostToken)
  });
  return {
    Authorization: `NC-Device ${String(hostToken)}`,
    'NC-Device-Proof': proof
  };
}

/**
 * Performs an HTTP GET request, following redirects up to maxRedirects.
 * Device headers (when supplied) are forwarded only on same-origin
 * redirects; cross-origin redirects drop them so credentials stay scoped
 * to the original edge host.
 * @param {string} targetUrl
 * @param {number} [maxRedirects=5]
 * @param {Record<string, string>} [extraHeaders]
 * @returns {Promise<import('node:http').IncomingMessage>}
 */
function httpGet(targetUrl, maxRedirects = 5, extraHeaders = {}) {
  if (typeof maxRedirects === 'object' && maxRedirects !== null) {
    extraHeaders = /** @type {Record<string, string>} */ (maxRedirects);
    maxRedirects = 5;
  }
  return new Promise((resolve, reject) => {
    if (maxRedirects < 0) {
      return reject(new Error(`Too many redirects while requesting ${targetUrl}`));
    }
    const u = new URL(targetUrl);
    const client = u.protocol === 'http:' ? http : https;

    const req = client.get(
      u,
      {
        headers: {
          'User-Agent': 'nc-cli/0.1.0',
          Accept: '*/*',
          ...extraHeaders
        }
      },
      (res) => {
        if (
          res.statusCode &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          const redirectUrl = new URL(res.headers.location, targetUrl).toString();
          res.resume();
          const forwarded = isSameOrigin(targetUrl, redirectUrl) ? extraHeaders : {};
          return resolve(httpGet(redirectUrl, maxRedirects - 1, forwarded));
        }

        if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
          res.resume();
          return reject(new Error(`Request to ${targetUrl} failed with status ${res.statusCode}`));
        }

        resolve(res);
      }
    );

    req.on('error', reject);
  });
}

/**
 * Fetches and parses a JSON endpoint. The update manifest (`/api/updates`)
 * is admin-only and never takes device headers, so this stays anonymous;
 * device identity is only attached to per-client package downloads.
 * @param {string} targetUrl
 * @param {Record<string, string>} [extraHeaders]
 * @returns {Promise<any>}
 */
async function fetchJson(targetUrl, extraHeaders = {}) {
  const res = await httpGet(targetUrl, 5, extraHeaders);
  return new Promise((resolve, reject) => {
    let raw = '';
    res.setEncoding('utf8');
    res.on('data', (chunk) => {
      raw += chunk;
    });
    res.on('end', () => {
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(new Error(`Failed to parse JSON from ${targetUrl}: ${err.message}`));
      }
    });
    res.on('error', reject);
  });
}

/**
 * Downloads a remote file stream directly to disk.
 * @param {string} targetUrl
 * @param {string} destinationPath
 * @param {Record<string, string>} [extraHeaders] Device headers for `/api/clients/...` package URLs; empty for public `/releases/...` URLs.
 * @returns {Promise<string>}
 */
async function downloadToFile(targetUrl, destinationPath, extraHeaders = {}) {
  const res = await httpGet(targetUrl, 5, extraHeaders);
  return new Promise((resolve, reject) => {
    const fileStream = fs.createWriteStream(destinationPath);
    let resolved = false;

    const onError = (err) => {
      if (resolved) return;
      resolved = true;
      fileStream.destroy();
      try {
        fs.unlinkSync(destinationPath);
      } catch {}
      reject(err);
    };

    res.on('error', onError);
    fileStream.on('error', onError);

    fileStream.on('finish', () => {
      if (resolved) return;
      resolved = true;
      fileStream.close(() => resolve(destinationPath));
    });

    res.pipe(fileStream);
  });
}

/**
 * Determines the installation root (NC_ROOT) dynamically based on OS:
 * - Windows: %LOCALAPPDATA%\nc
 * - macOS: ~/Library/Application Support/nc
 * - Linux (root): /opt/nc
 * - Linux (non-root): ~/.local/share/nc
 * @returns {string}
 */
export function getNcRoot() {
  if (process.env.NC_ROOT) {
    return process.env.NC_ROOT;
  }
  const platform = os.platform();
  if (platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
    return path.join(localAppData, 'nc');
  }
  if (platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support', 'nc');
  }
  // Linux and other POSIX: root vs non-root
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  if (isRoot) {
    return '/opt/nc';
  }
  return path.join(os.homedir(), '.local', 'share', 'nc');
}

/**
 * Resolves the tar executable command name or path.
 * @returns {string}
 */
function getTarCommand() {
  if (os.platform() === 'win32') {
    const sysTar = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe');
    if (fs.existsSync(sysTar)) {
      return sysTar;
    }
    return 'tar.exe';
  }
  return 'tar';
}

/**
 * Extracts a tarball archive to target directory using system tar.
 * @param {string} archivePath
 * @param {string} targetDir
 */
function extractTarball(archivePath, targetDir) {
  const tarCmd = getTarCommand();
  try {
    child_process.execFileSync(tarCmd, ['-xzf', archivePath, '-C', targetDir], {
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (err) {
    const details = err.stderr ? err.stderr.toString().trim() : err.message;
    throw new Error(`Failed to extract tarball (${tarCmd}): ${details}`, { cause: err });
  }
}

/**
 * Locates the platform installation script inside the extracted tarball.
 * @param {string} tempDir
 * @returns {string}
 */
export function findInstallerScript(tempDir) {
  const platform = os.platform();
  if (platform === 'win32') {
    const defaultWin = path.join(tempDir, 'install', 'install-windows.ps1');
    if (fs.existsSync(defaultWin)) return defaultWin;
    const fallbackWin = path.join(tempDir, 'install-windows.ps1');
    if (fs.existsSync(fallbackWin)) return fallbackWin;
    return defaultWin;
  }
  if (platform === 'darwin') {
    const darwinScript = path.join(tempDir, 'install', 'install-darwin.sh');
    if (fs.existsSync(darwinScript)) return darwinScript;
    const macosScript = path.join(tempDir, 'install', 'install-macos.sh');
    if (fs.existsSync(macosScript)) return macosScript;
    const fallbackDarwin = path.join(tempDir, 'install-darwin.sh');
    if (fs.existsSync(fallbackDarwin)) return fallbackDarwin;
    const fallbackMacos = path.join(tempDir, 'install-macos.sh');
    if (fs.existsSync(fallbackMacos)) return fallbackMacos;
    return darwinScript;
  }
  // Linux and other POSIX
  const defaultLinux = path.join(tempDir, 'install', 'install-linux.sh');
  if (fs.existsSync(defaultLinux)) return defaultLinux;
  const fallbackLinux = path.join(tempDir, 'install-linux.sh');
  if (fs.existsSync(fallbackLinux)) return fallbackLinux;
  return defaultLinux;
}

/**
 * Executes the OS-specific installer script with NC_ROOT passed in environment.
 * Extra env (e.g. NC_MODE from installerEnvForMode) is merged on top so the
 * installer layout matches the CLI mode decision.
 * @param {string} scriptPath
 * @param {string} ncRoot
 * @param {Record<string, string>} [extraEnv]
 */
export function runInstallerScript(scriptPath, ncRoot, extraEnv = {}) {
  const platform = os.platform();
  const installEnv = {
    ...process.env,
    NC_ROOT: ncRoot,
    ...extraEnv
  };

  if (platform === 'win32') {
    child_process.execFileSync(
      'powershell.exe',
      ['-ExecutionPolicy', 'Bypass', '-File', scriptPath],
      {
        env: installEnv,
        stdio: 'inherit'
      }
    );
  } else if (platform === 'darwin') {
    child_process.execFileSync('bash', [scriptPath], {
      env: installEnv,
      stdio: 'inherit'
    });
  } else {
    // Linux and other POSIX
    child_process.execFileSync('bash', [scriptPath], {
      env: installEnv,
      stdio: 'inherit'
    });
  }
}

/**
 * Zero-touch device pairing library.
 *
 * The OAuth device-code flow yields a USER access token. That token
 * authenticates the user for exactly one privileged call (POST /api/enroll)
 * and must NEVER become agent credentials: it is kept in memory, never
 * written to disk, and never placed in nc-client.env. Enrollment mints a
 * canonical host identity (nc_<64hex>); redemption binds a locally generated
 * Ed25519 device key to it via Device Proof v1 and returns the host token
 * (nc_tok_<64hex>). Only those host credentials are persisted.
 *
 * The Ed25519 / Device Proof v1 construction below mirrors
 * apps/agent/core/device-proof.mjs and apps/control-plane/lib/device-proof.mjs
 * exactly (same canonical string, same header names). It is duplicated rather
 * than imported because this CLI ships as a dependency-free binary; the CLI
 * pairing test verifies every proof it mints against the control-plane
 * verifier so the copies cannot drift silently.
 */

/**
 * Pairing failure with a stable machine-readable code. Messages never contain
 * secrets (no OAuth token, host token, enrollment token, or private key).
 */
export class PairingError extends Error {
  /** @param {string} code @param {string} message */
  constructor(code, message) {
    super(message);
    this.name = 'PairingError';
    this.code = code;
  }
}

export const HOST_ID_RE = /^nc_[0-9a-f]{64}$/;
export const HOST_TOKEN_RE = /^nc_tok_[0-9a-f]{64}$/;
export const ENROLL_TOKEN_RE = /^nc_enr_[0-9a-f]{64}$/;
const DEVICE_PUBKEY_RE = /^[A-Za-z0-9_-]{43}$/;
const DEVICE_NONCE_RE = /^[0-9a-f]{32}$/;

/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Maps node platform names to the enrollment API platform contract.
 * @param {string} [platform]
 */
export function mapEnrollPlatform(platform = os.platform()) {
  if (platform === 'win32') return 'windows';
  if (platform === 'darwin') return 'macos';
  return 'linux';
}

/** @param {string} [ncRoot] */
export function getEnvFilePath(ncRoot = getNcRoot()) {
  return path.join(ncRoot, 'config', 'nc-client.env');
}

/** @param {string} [ncRoot] */
export function getDeviceKeyPath(ncRoot = getNcRoot()) {
  return path.join(ncRoot, 'config', 'nc-device-key.pem');
}

/** @param {string} [ncRoot] */
export function getEnrollStatePath(ncRoot = getNcRoot()) {
  return path.join(ncRoot, 'config', 'nc-enroll-state.json');
}

/**
 * Builds the canonical agent env file content from HOST credentials only.
 * There is deliberately no parameter for the OAuth token: by construction it
 * cannot end up in the file. Host id/token shapes are enforced so a caller
 * mistake (e.g. passing an enrollment token as the client token) fails here
 * instead of producing a broken agent that crash-loops on 401.
 * @param {{ serverUrl: string, hostId: string, hostToken: string, clientName?: string }} options
 */
export function buildHostEnvContent({ serverUrl, hostId, hostToken, clientName = os.hostname() }) {
  if (typeof serverUrl !== 'string' || !serverUrl) {
    throw new PairingError('INVALID_SERVER_URL', 'Refusing to write agent config without a server URL.');
  }
  if (!HOST_ID_RE.test(String(hostId || ''))) {
    throw new PairingError(
      'INVALID_HOST_ID',
      'Refusing to write agent config: host identity is not a canonical nc_<64hex> id. The OAuth access token must never be used as NC_CLIENT_ID.'
    );
  }
  if (!HOST_TOKEN_RE.test(String(hostToken || ''))) {
    throw new PairingError(
      'INVALID_HOST_TOKEN',
      'Refusing to write agent config: host token is not a canonical nc_tok_<64hex> token. The OAuth access token must never be used as NC_CLIENT_TOKEN.'
    );
  }
  return [
    `NC_SERVER_URL=${serverUrl}`,
    `NC_CLIENT_ID=${hostId}`,
    `NC_CLIENT_NAME=${clientName}`,
    `NC_CLIENT_TOKEN=${hostToken}`,
    'NC_REMOTE_EXEC_ENABLED=true',
    'NC_SESSION_ENABLED=true'
  ].join('\n') + '\n';
}

/**
 * Writes the env file with owner-only permissions.
 * @param {string} envPath
 * @param {string} content
 */
export function writeHostEnvFile(envPath, content) {
  fs.mkdirSync(path.dirname(envPath), { recursive: true, mode: 0o750 });
  fs.writeFileSync(envPath, content, { mode: 0o600 });
  if (os.platform() !== 'win32') {
    try {
      fs.chmodSync(envPath, 0o600);
    } catch {}
  }
}

/**
 * Parses a KEY=VALUE env file into a record (no interpolation, no execution).
 * @param {string} text
 */
export function parseEnvFile(text) {
  const out = {};
  for (const line of String(text || '').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return out;
}

/**
 * Reads and validates locally persisted host credentials. Returns null when
 * there is nothing usable (missing file, unparsable, or wrong shapes) so the
 * caller can fall through to a fresh enrollment.
 * @param {string} [envPath]
 */
export function loadValidHostEnv(envPath = getEnvFilePath()) {
  let text;
  try {
    text = fs.readFileSync(envPath, 'utf8');
  } catch {
    return null;
  }
  const env = parseEnvFile(text);
  if (!HOST_ID_RE.test(String(env.NC_CLIENT_ID || ''))) return null;
  if (!HOST_TOKEN_RE.test(String(env.NC_CLIENT_TOKEN || ''))) return null;
  if (typeof env.NC_SERVER_URL !== 'string' || !env.NC_SERVER_URL) return null;
  return env;
}

/**
 * Resume marker for idempotent re-runs. Holds the host id and lifecycle
 * phase only — never any token or key material (those live in nc-client.env
 * and nc-device-key.pem with 0600).
 *
 * Security tradeoff (documented choice): a re-run after a post-redemption
 * failure resumes from locally persisted, already-issued credentials instead
 * of minting a fresh enrollment. This keeps single-use redemption strict
 * (no re-redemption grace window, no 410 special-casing server-side) and
 * avoids orphaning a quota-counted host on every retry. The cost is that a
 * cloned NC_ROOT directory carries resumable pairing state — acceptable
 * because the same directory already holds the private device key.
 * @param {string} statePath
 * @param {{ host_id: string, phase: string }} state
 */
export function writePairState(statePath, state) {
  fs.mkdirSync(path.dirname(statePath), { recursive: true, mode: 0o750 });
  const body = JSON.stringify(
    { version: 1, host_id: state.host_id, phase: state.phase, updated_at: new Date().toISOString() },
    null,
    2
  ) + '\n';
  fs.writeFileSync(statePath, body, { mode: 0o600 });
  if (os.platform() !== 'win32') {
    try {
      fs.chmodSync(statePath, 0o600);
    } catch {}
  }
}

/**
 * @param {string} [statePath]
 * @returns {{ host_id?: string, phase?: string }|null}
 */
export function readPairState(statePath = getEnrollStatePath()) {
  try {
    const parsed = JSON.parse(fs.readFileSync(statePath, 'utf8'));
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * @param {import('node:crypto').KeyObject} privateKey
 */
function publicRawFromPrivateCli(privateKey) {
  const jwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
  const x = String(jwk?.x || '');
  if (jwk?.kty !== 'OKP' || jwk?.crv !== 'Ed25519' || !DEVICE_PUBKEY_RE.test(x)) {
    throw new PairingError('KEY_INVALID', 'Device key is not a valid Ed25519 key.');
  }
  if (Buffer.from(x, 'base64url').length !== 32) {
    throw new PairingError('KEY_INVALID', 'Device key is not a valid Ed25519 key.');
  }
  return x;
}

/** @param {unknown} publicKey */
export function deviceKeyThumbprintCli(publicKey) {
  if (!DEVICE_PUBKEY_RE.test(String(publicKey || ''))) {
    throw new PairingError('KEY_INVALID', 'Device public key has an unexpected shape.');
  }
  return crypto
    .createHash('sha256')
    .update(Buffer.from(String(publicKey), 'base64url'))
    .digest('base64url');
}

/**
 * Loads an existing Ed25519 device key. Throws KEY_NOT_FOUND when absent
 * (caller generates) and KEY_INVALID when present but unusable — never
 * silently overwrites, so a damaged key is reported, not hidden.
 * @param {string} keyFile
 */
export function loadDeviceKeyPair(keyFile) {
  let pem;
  try {
    pem = fs.readFileSync(keyFile, 'utf8');
  } catch (err) {
    throw new PairingError(
      'KEY_NOT_FOUND',
      `Device key not found at ${keyFile}. It will be generated during enrollment.`
    );
  }
  let key;
  try {
    key = crypto.createPrivateKey(pem);
  } catch {
    throw new PairingError(
      'KEY_INVALID',
      `Device key at ${keyFile} is unreadable. Remove the file to re-enroll, or restore it from backup.`
    );
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new PairingError(
      'KEY_INVALID',
      `Device key at ${keyFile} is not an Ed25519 key. Remove the file to re-enroll, or restore it from backup.`
    );
  }
  const publicKey = publicRawFromPrivateCli(key);
  return { privateKey: key, publicKey, thumbprint: deviceKeyThumbprintCli(publicKey) };
}

/**
 * Loads the device key, generating and persisting a fresh Ed25519 key when
 * none exists (atomic tmp-write + rename, 0600). Mirrors
 * apps/agent/core/device-proof.mjs ensureDeviceKey.
 * @param {string} keyFile
 */
export function ensureDeviceKeyPair(keyFile) {
  try {
    return loadDeviceKeyPair(keyFile);
  } catch (err) {
    if (err instanceof PairingError && err.code === 'KEY_NOT_FOUND') {
      try {
        fs.mkdirSync(path.dirname(keyFile), { recursive: true, mode: 0o750 });
        const { privateKey } = crypto.generateKeyPairSync('ed25519');
        const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
        const tmp = `${keyFile}.tmp-${process.pid}-${crypto.randomBytes(6).toString('hex')}`;
        fs.writeFileSync(tmp, pem, { mode: 0o600, flag: 'wx' });
        try {
          fs.chmodSync(tmp, 0o600);
        } catch {}
        try {
          fs.renameSync(tmp, keyFile);
        } catch (renameErr) {
          try {
            fs.unlinkSync(tmp);
          } catch {}
          throw renameErr;
        }
        return loadDeviceKeyPair(keyFile);
      } catch (genErr) {
        if (genErr instanceof PairingError) throw genErr;
        throw new PairingError(
          'KEY_GENERATION_FAILED',
          `Could not generate the device key at ${keyFile}: ${genErr.message}`
        );
      }
    }
    throw err;
  }
}

/**
 * Builds a Device Proof v1 header value binding the given credential to this
 * request. Canonical string is identical to the agent implementation:
 * NC-DEVICE-PROOF-V1 + client_id/method/target/credential_sha256/iat/nonce.
 * @param {{ privateKey: import('node:crypto').KeyObject, hostId: string, method: string, url: string, credential: string }} options
 */
export function createDeviceProofCli({ privateKey, hostId, method, url, credential }) {
  const id = String(hostId || '');
  const m = String(method || '').toUpperCase();
  if (!HOST_ID_RE.test(id)) throw new PairingError('INVALID_HOST_ID', 'Cannot prove identity for a non-canonical host id.');
  if (!/^[A-Z]+$/.test(m)) throw new PairingError('DEVICE_PROOF_FAILED', `Cannot sign device proof for method "${m}".`);
  let target;
  try {
    const u = /^https?:\/\//i.test(String(url)) ? new URL(String(url)) : new URL(String(url), 'http://nc.invalid');
    if (u.hash) throw new Error('hash');
    target = (u.pathname || '/') + (u.search || '');
  } catch {
    throw new PairingError('DEVICE_PROOF_FAILED', 'Cannot sign device proof for an invalid request target.');
  }
  if (typeof credential !== 'string' || !credential) {
    throw new PairingError('DEVICE_PROOF_FAILED', 'Cannot sign device proof without a credential.');
  }
  const iat = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomBytes(16).toString('hex');
  if (!DEVICE_NONCE_RE.test(nonce)) throw new PairingError('DEVICE_PROOF_FAILED', 'Could not mint device-proof nonce.');
  const credHash = crypto.createHash('sha256').update(credential, 'utf8').digest('hex');
  const canonical = [
    'NC-DEVICE-PROOF-V1',
    `client_id:${id}`,
    `method:${m}`,
    `target:${target}`,
    `credential_sha256:${credHash}`,
    `iat:${String(iat)}`,
    `nonce:${nonce}`,
    ''
  ].join('\n');
  let signature;
  try {
    signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKey).toString('base64url');
  } catch (err) {
    throw new PairingError('DEVICE_PROOF_FAILED', `Could not sign device proof: ${err.message}`);
  }
  return `v1.${iat}.${nonce}.${signature}`;
}

/**
 * Requests a single-use enrollment with the OAuth USER token as bearer
 * authorization. The token authenticates the user; the response carries a
 * fresh host identity plus a one-time enrollment token.
 * @param {{ baseUrl: string, oauthToken: string, platform?: string, name?: string, tenantId?: string|null }} options
 */
export async function requestEnrollment({ baseUrl, oauthToken, platform = 'linux', name = undefined, tenantId = null }) {
  if (!oauthToken || typeof oauthToken !== 'string') {
    throw new PairingError('ENROLL_NO_OAUTH_TOKEN', 'Cannot request enrollment without a sign-in token. Re-run the device flow.');
  }
  const origin = String(baseUrl || '').replace(/\/$/, '');
  const body = { platform, ...(name ? { name } : {}), ...(tenantId ? { tenant_id: tenantId } : {}) };
  let res;
  try {
    res = await postJson(`${origin}/api/enroll`, body, { Authorization: `Bearer ${oauthToken}` });
  } catch (err) {
    throw new PairingError('ENROLL_NETWORK_ERROR', `Could not reach the enrollment endpoint: ${err.message}`);
  }
  if (res.status === 201 && res.data?.host_id && res.data?.enrollment_token) {
    if (!HOST_ID_RE.test(String(res.data.host_id)) || !ENROLL_TOKEN_RE.test(String(res.data.enrollment_token))) {
      throw new PairingError('ENROLL_BAD_RESPONSE', 'Enrollment endpoint returned a malformed identity. Aborting.');
    }
    return res.data;
  }
  const serverError = res.data?.error;
  const serverMessage = typeof res.data?.message === 'string' ? `: ${res.data.message}` : '';
  if (res.status === 401) {
    throw new PairingError('ENROLL_UNAUTHORIZED', 'Sign-in expired or was revoked. Re-run the device flow to sign in again.');
  }
  if (res.status === 403 && serverError === 'TWO_FACTOR_REQUIRED') {
    throw new PairingError('ENROLL_TWO_FACTOR_REQUIRED', 'This account requires a two-factor code to enroll a machine. Approve pairing from the dashboard instead.');
  }
  if (res.status === 403) {
    throw new PairingError('ENROLL_FORBIDDEN', `Enrollment was refused (${serverError || 'forbidden'})${serverMessage}.`);
  }
  if (res.status === 409 && serverError === 'PLAN_HOST_LIMIT_EXCEEDED') {
    throw new PairingError('ENROLL_QUOTA_EXCEEDED', `Plan host quota reached${serverMessage}. Upgrade the workspace plan or remove an old host, then re-run.`);
  }
  if (res.status === 409) {
    throw new PairingError('ENROLL_CONFLICT', `Enrollment was refused (${serverError || 'conflict'})${serverMessage}.`);
  }
  if (res.status === 429) {
    throw new PairingError('ENROLL_RATE_LIMITED', 'Enrollment is rate limited. Wait a minute and re-run.');
  }
  throw new PairingError('ENROLL_REJECTED', `Enrollment was rejected (${serverError || `HTTP ${res.status}`})${serverMessage}.`);
}

/**
 * Redeems a one-time enrollment token with Device Proof v1, binding the
 * local Ed25519 key to the host identity. Returns the redemption payload
 * (client_id, client_token, release). A 410 ENROLLMENT_ALREADY_USED means a
 * previous run already consumed this token — the caller resumes from local
 * credentials instead of retrying redemption.
 * @param {{ baseUrl: string, hostId: string, enrollmentToken: string, keyPair: { privateKey: import('node:crypto').KeyObject, publicKey: string, thumbprint: string } }} options
 */
export async function redeemEnrollment({ baseUrl, hostId, enrollmentToken, keyPair }) {
  const origin = String(baseUrl || '').replace(/\/$/, '');
  const redeemPath = '/api/enroll/redeem';
  const proof = createDeviceProofCli({
    privateKey: keyPair.privateKey,
    hostId,
    method: 'POST',
    url: origin + redeemPath,
    credential: enrollmentToken
  });
  let res;
  try {
    res = await postJson(
      origin + redeemPath,
      { host_id: hostId, token: enrollmentToken, device_public_key: keyPair.publicKey },
      { 'NC-Device-Proof': proof }
    );
  } catch (err) {
    throw new PairingError('REDEEM_NETWORK_ERROR', `Could not reach the redemption endpoint: ${err.message}`);
  }
  if (res.status === 200 && res.data) {
    const r = res.data;
    if (r.client_id !== hostId || r.token_type !== 'NC-Device' || r.device_key_thumbprint !== keyPair.thumbprint) {
      throw new PairingError('REDEEM_BINDING_MISMATCH', 'Redemption response is not bound to this device key. Aborting.');
    }
    if (!HOST_TOKEN_RE.test(String(r.client_token || ''))) {
      throw new PairingError('REDEEM_BAD_TOKEN', 'Redemption returned a malformed host token. Aborting.');
    }
    return r;
  }
  const serverError = res.data?.error;
  if (res.status === 410 && serverError === 'ENROLLMENT_ALREADY_USED') {
    throw new PairingError(
      'ENROLLMENT_ALREADY_USED',
      'This enrollment was already redeemed (a previous run consumed it). Re-running resumes from the locally stored host credentials.'
    );
  }
  if (res.status === 410) {
    throw new PairingError(
      'ENROLLMENT_EXPIRED',
      `This enrollment is no longer valid (${serverError || 'expired'}). Re-run to request a fresh one.`
    );
  }
  if (res.status === 401) {
    throw new PairingError('REDEEM_UNAUTHORIZED', `Redemption was refused (${serverError || 'unauthorized'}). Re-run to request a fresh enrollment.`);
  }
  throw new PairingError('REDEEM_REJECTED', `Redemption failed (${serverError || `HTTP ${res.status}`}). Re-run to request a fresh enrollment.`);
}

/**
 * Verifies the redeemed host identity against the server using the device
 * channel (the same authenticateClient + Device Proof path the agent itself
 * uses). Polls until the identity is accepted or the timeout expires.
 * Success here proves the env credentials actually authenticate; only then
 * may the CLI print a success message.
 * Device-channel endpoints live on the agent edge (`apiBase`/`NC_API_URL`),
 * never on the auth host. `baseUrl` stays accepted for backward
 * compatibility but an explicit `apiBase` (or `NC_API_URL`/default agent
 * origin when neither is given) wins.
 * @param {{ baseUrl?: string, apiBase?: string, hostId: string, hostToken: string, privateKey: import('node:crypto').KeyObject, timeoutMs?: number, intervalMs?: number }} options
  */
export async function verifyHostRegistration({ baseUrl: baseUrlOpt = undefined, apiBase: apiBaseOpt = undefined, hostId, hostToken, privateKey, timeoutMs = 45000, intervalMs = 2000 }) {
  const origin = String(apiBaseOpt ?? baseUrlOpt ?? process.env.NC_API_URL ?? apiBase).replace(/\/$/, '');
  const target = `/api/clients/${encodeURIComponent(hostId)}/policy`;
  const deadline = Date.now() + Math.max(1000, Number(timeoutMs) || 45000);
  const step = Math.max(250, Math.min(Number(intervalMs) || 2000, deadline - Date.now()));
  let lastError = 'no attempt yet';
  for (;;) {
    const proof = createDeviceProofCli({ privateKey, hostId, method: 'GET', url: origin + target, credential: hostToken });
    try {
      const res = await getJson(origin + target, {
        Authorization: `NC-Device ${hostToken}`,
        'NC-Device-Proof': proof
      });
      if (res.status === 200 && res.data?.policy) return { ok: true, hostId };
      lastError = res.data?.error || `HTTP ${res.status}`;
      // A missing client row will never appear by waiting: fail fast so the
      // user gets the real cause instead of a timeout.
      if (res.status === 404) {
        throw new PairingError('VERIFY_FAILED', `Host ${hostId} is not registered on the server (${lastError}). Re-run to enroll again.`);
      }
    } catch (err) {
      if (err instanceof PairingError) throw err;
      lastError = err.message;
    }
    if (Date.now() >= deadline) {
      throw new PairingError(
        'VERIFY_TIMEOUT',
        `Could not confirm host ${hostId} on the server in time (last: ${lastError}). The credentials are stored; check connectivity and re-run to verify.`
      );
    }
    await sleep(Math.min(step, Math.max(250, deadline - Date.now())));
  }
}

/**
 * Downloads, verifies, extracts, and installs the agent package. Writes NO
 * credentials — the env file must already exist before this runs.
 *
 * When `release` (the redemption `release` payload) is supplied, the
 * admin-only GET /api/updates manifest is NEVER fetched: the release already
 * carries concrete per-client bootstrap/package URLs plus integrity pins,
 * and the CLI is not an admin so the manifest would answer 401 anyway.
 * Relative URLs resolve against `serverUrl`/`NC_SERVER_URL`. Without a
 * release the legacy manifest fetch is attempted, and an admin-auth refusal
 * surfaces an explanatory error pointing at enrollment-based setup.
 * The /api/updates endpoint stays admin-only (Caddy and control-plane are
 * intentionally untouched): opening it on the agent edge would only trade a
 * 404 for a 401 while widening the security surface.
 * Device identity (`hostId`/`hostToken`/`privateKey`) is attached ONLY to
 * per-client package URLs (`/api/clients/<id>/update/...`, same
 * Authorization + Device Proof the agent updater sends). The public fallback
 * (`/releases/client/<version>/bootstrap.tar.gz`) stays anonymous. The
 * proof binds method GET + the full request URL + the redemption-issued
 * client token, exactly like redeemEnrollment.
 * @param {{ ncRoot?: string, updatesUrl?: string, serverUrl?: string, release?: Record<string, unknown>|null, installMode?: 'system'|'user', runInstaller?: (scriptPath: string, ncRoot: string) => void, hostId?: string, hostToken?: string, privateKey?: import('node:crypto').KeyObject }} options
 */
export async function downloadAndInstallAgent({ ncRoot = getNcRoot(), updatesUrl = undefined, serverUrl = undefined, release = undefined, installMode = undefined, runInstaller = undefined, hostId = undefined, hostToken = undefined, privateKey = undefined } = {}) {
  const modeEnv = installMode ? installerEnvForMode(installMode) : {};
  const invokeInstaller =
    runInstaller || ((scriptPath, root) => runInstallerScript(scriptPath, root, modeEnv));
  const root = ncRoot || getNcRoot();
  console.log(`📍 Installation root: ${root}`);

  // Package/release resolution stays on the agent edge: an explicit
  // serverUrl (usually the enrollment server_url) wins, then NC_SERVER_URL,
  // then the agent API origin (NC_API_URL/apiBase). The auth host is never
  // used here. NC_SERVER_URL remains the agent server address and is read
  // before the API origin so existing installs keep resolving as before.
  const defaultBaseUrl = serverUrl || process.env.NC_SERVER_URL || process.env.NC_API_URL || apiBase;
  /** @type {Record<string, any>} */
  let activeRelease;
  if (release && typeof release === 'object') {
    // Redemption release wins: skip the admin-only manifest entirely, so its
    // URL is never logged as a misleading signal.
    activeRelease = /** @type {Record<string, any>} */ (release);
    const releaseVersion = activeRelease.version ? ` ${activeRelease.version}` : '';
    console.log(`📦 Using release${releaseVersion} from enrollment redemption; skipping update manifest.`);
  } else {
    const manifestOrigin = String(process.env.NC_API_URL || apiBase).replace(/\/$/, '');
    const manifestUrl = updatesUrl || process.env.NC_UPDATES_URL || `${manifestOrigin}/api/updates`;
    console.log(`📡 Fetching update manifest from ${manifestUrl}...`);
    let manifestData;
    try {
      manifestData = await fetchJson(manifestUrl);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      if (/status 401\b/i.test(detail)) {
        throw new PairingError(
          'INSTALL_MANIFEST_ERROR',
          `Update manifest refused with ADMIN_AUTH_REQUIRED (${detail}). The manifest endpoint is admin-only; run with an enrollment (setup <host_id> <token>) so the release ships with the redemption, then re-run.`
        );
      }
      throw new PairingError('INSTALL_MANIFEST_ERROR', `Could not fetch the agent release manifest: ${detail}`);
    }
    if (manifestData && typeof manifestData === 'object' && manifestData.error === 'ADMIN_AUTH_REQUIRED') {
      throw new PairingError(
        'INSTALL_MANIFEST_ERROR',
        'Update manifest refused with ADMIN_AUTH_REQUIRED. The manifest endpoint is admin-only; run with an enrollment (setup <host_id> <token>) so the release ships with the redemption, then re-run.'
      );
    }
    activeRelease = manifestData?.release || manifestData || {};
  }
  const version = activeRelease.version;

  const usableUrl = (value) =>
    typeof value === 'string' && value && !value.includes('{client_id}') ? value : null;
  let tarballUrl =
    usableUrl(activeRelease.bootstrap_tar_gz_url) ||
    usableUrl(activeRelease.bootstrap_url) ||
    usableUrl(activeRelease.download_url) ||
    usableUrl(activeRelease.url) ||
    usableUrl(activeRelease.package_url);

  if (tarballUrl) {
    if (!tarballUrl.startsWith('http://') && !tarballUrl.startsWith('https://')) {
      tarballUrl = new URL(tarballUrl, defaultBaseUrl).toString();
    }
  } else {
    if (!version) {
      throw new PairingError('INSTALL_MANIFEST_ERROR', 'Unable to determine agent version from update manifest.');
    }
    tarballUrl = `${defaultBaseUrl}/releases/client/${encodeURIComponent(version)}/bootstrap.tar.gz`;
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nc-install-'));
  const archivePath = path.join(tempDir, 'bootstrap.tar.gz');

  const cleanup = () => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  };

  // Identity decision per endpoint: device headers only for the
  // device-authenticated per-client URLs; public release URLs stay bare so
  // no credential is ever sent where it is not required (or valid).
  let downloadHeaders = {};
  if (isDeviceAuthenticatedPackageUrl(tarballUrl)) {
    if (typeof hostId === 'string' && typeof hostToken === 'string' && hostId && hostToken && privateKey) {
      downloadHeaders = buildDeviceDownloadHeaders({ hostId, hostToken, privateKey }, tarballUrl);
    }
  }

  try {
    console.log(`⬇️ Downloading agent package from ${tarballUrl}...`);
    try {
      await downloadToFile(tarballUrl, archivePath, downloadHeaders);
    } catch (err) {
      throw new PairingError('INSTALL_DOWNLOAD_ERROR', `Could not download the agent package: ${err.message}`);
    }

    const expectedHash = activeRelease.bootstrap_sha256 || activeRelease.sha256;
    const expectedSizeRaw = activeRelease.bootstrap_size_bytes ?? activeRelease.size_bytes;
    const expectedSize =
      expectedSizeRaw === undefined || expectedSizeRaw === null ? null : Number(expectedSizeRaw);
    const archiveBytes = fs.readFileSync(archivePath);
    if (expectedSize !== null && Number.isFinite(expectedSize)) {
      if (archiveBytes.length !== expectedSize) {
        try {
          fs.unlinkSync(archivePath);
        } catch {}
        throw new PairingError(
          'INSTALL_MANIFEST_ERROR',
          `Agent package integrity check failed: size mismatch for ${tarballUrl} (expected ${expectedSize} bytes, got ${archiveBytes.length}). The download was discarded; nothing was installed.`
        );
      }
    }
    if (expectedHash && /^[a-f0-9]{64}$/i.test(String(expectedHash))) {
      const actualHash = crypto.createHash('sha256').update(archiveBytes).digest('hex');
      if (actualHash.toLowerCase() !== String(expectedHash).toLowerCase()) {
        try {
          fs.unlinkSync(archivePath);
        } catch {}
        throw new PairingError(
          'INSTALL_MANIFEST_ERROR',
          `Agent package integrity check failed: sha256 mismatch for ${tarballUrl}. The download was discarded; nothing was installed.`
        );
      }
    } else {
      console.warn('⚠️ Release manifest lacks a valid sha256; skipping archive integrity check.');
    }

    console.log('📂 Extracting agent archive...');
    try {
      extractTarball(archivePath, tempDir);
    } catch (err) {
      throw new PairingError('INSTALL_EXTRACT_ERROR', `Could not extract the agent package: ${err.message}`);
    }

    console.log('🚀 Running installation script...');
    const scriptPath = findInstallerScript(tempDir);
    if (!fs.existsSync(scriptPath)) {
      throw new PairingError('INSTALL_SCRIPT_MISSING', `Installation script not found: ${scriptPath}.`);
    }

    try {
      invokeInstaller(scriptPath, root);
    } catch (err) {
      if (err instanceof PairingError) throw err;
      throw new PairingError('INSTALL_FAILED', `Agent installer failed: ${err.message}. Re-running resumes from the stored host credentials.`);
    }
  } finally {
    console.log('🧹 Cleaning up temporary directory...');
    cleanup();
  }
}

/**
 * Full zero-touch pairing chain: enroll (OAuth user auth) -> device key ->
 * redeem (Device Proof) -> host env -> install -> device-auth verification.
 * Prints success ONLY after verification. Re-runs resume from locally stored
 * host credentials instead of minting a fresh enrollment. When `enrollment`
 * (host_id + enrollment_token, e.g. from `setup <host_id> <token>`) is given,
 * the OAuth enrollment step is skipped and the supplied token is redeemed
 * directly. `installMode` is forwarded to the installer via NC_MODE.
 * Host split: enrollment (OAuth/redeem) uses the auth origin (`baseUrl` /
 * `NC_BASE_URL`); device-channel verification (`/api/clients/*`) uses the
 * agent origin (`apiBase` / `NC_API_URL`). `NC_SERVER_URL` stays the agent
 * server address and never selects the verify host.
 * @param {{ baseUrl?: string, apiBase?: string, oauthToken?: string|null, enrollment?: { host_id: string, enrollment_token: string, server_url?: string }|null, ncRoot?: string, serverUrl?: string, deviceName?: string, platform?: string, installMode?: 'system'|'user', verifyTimeoutMs?: number, verifyIntervalMs?: number, hooks?: { installAgent?: (options: { ncRoot: string, serverUrl: string, release?: Record<string, unknown>|null, hostId?: string, hostToken?: string, privateKey?: import('node:crypto').KeyObject }) => Promise<void> } }} options
  */
export async function pairDeviceAndInstall({
  baseUrl: baseUrlParam = undefined,
  apiBase: apiBaseParam = undefined,
  oauthToken = null,
  enrollment = null,
  ncRoot = getNcRoot(),
  serverUrl = undefined,
  deviceName = os.hostname(),
  platform = mapEnrollPlatform(),
  installMode = undefined,
  verifyTimeoutMs = 45000,
  verifyIntervalMs = 2000,
  hooks = {}
} = {}) {
  if (!enrollment && (!oauthToken || typeof oauthToken !== 'string')) {
    throw new PairingError('ENROLL_NO_OAUTH_TOKEN', 'Cannot pair without a sign-in token. Re-run the device flow.');
  }
  if (enrollment) {
    if (!HOST_ID_RE.test(String(enrollment.host_id || ''))) {
      throw new PairingError('INVALID_HOST_ID', 'The supplied host id is not a canonical nc_<64hex> id. Re-run setup without arguments for a fresh enrollment.');
    }
    if (!ENROLL_TOKEN_RE.test(String(enrollment.enrollment_token || ''))) {
      throw new PairingError('INVALID_ENROLL_TOKEN', 'The supplied enrollment token is not a canonical nc_enr_<64hex> token. Re-run setup without arguments for a fresh enrollment.');
    }
  }
  const root = ncRoot || getNcRoot();
  const origin = String(baseUrlParam ?? process.env.NC_BASE_URL ?? baseUrl).replace(/\/$/, '');
  const apiOrigin = String(apiBaseParam ?? process.env.NC_API_URL ?? apiBase).replace(/\/$/, '');
  const defaultServerUrl = serverUrl || process.env.NC_SERVER_URL || 'https://agent.nodecommand.app';
  const envPath = getEnvFilePath(root);
  const keyPath = getDeviceKeyPath(root);
  const statePath = getEnrollStatePath(root);

  const installAgent =
    hooks.installAgent ||
    (async ({ ncRoot: installRoot, serverUrl: installServerUrl, release: installRelease = undefined, hostId: installHostId = undefined, hostToken: installHostToken = undefined, privateKey: installPrivateKey = undefined }) => {
      await downloadAndInstallAgent({ ncRoot: installRoot, serverUrl: installServerUrl, installMode, release: installRelease, hostId: installHostId, hostToken: installHostToken, privateKey: installPrivateKey });
    });

  // Fast path — idempotent resume: usable host credentials already on disk
  // are verified over the device channel and the installer is resumed. No
  // new enrollment is minted, so a re-run can never orphan a host or hit
  // ENROLLMENT_ALREADY_USED for a token it no longer holds.
  const localEnv = loadValidHostEnv(envPath);
  if (localEnv) {
    let localKey = null;
    try {
      localKey = loadDeviceKeyPair(keyPath);
    } catch (err) {
      if (!(err instanceof PairingError) || err.code !== 'KEY_NOT_FOUND') throw err;
    }
    if (localKey) {
      const prior = readPairState(statePath);
      try {
        await verifyHostRegistration({
          apiBase: apiOrigin,
          hostId: localEnv.NC_CLIENT_ID,
          hostToken: localEnv.NC_CLIENT_TOKEN,
          privateKey: localKey.privateKey,
          timeoutMs: Math.min(10000, verifyTimeoutMs),
          intervalMs: verifyIntervalMs
        });
        const phase = prior?.phase;
        if (phase === 'installed' || phase === 'verified') {
          writePairState(statePath, { host_id: localEnv.NC_CLIENT_ID, phase: 'verified' });
          return { hostId: localEnv.NC_CLIENT_ID, serverUrl: localEnv.NC_SERVER_URL, resumed: true };
        }
        console.log(`🔁 Resuming installation for host ${localEnv.NC_CLIENT_ID} (stored credentials verified)...`);
        await installAgent({ ncRoot: root, serverUrl: localEnv.NC_SERVER_URL, hostId: localEnv.NC_CLIENT_ID, hostToken: localEnv.NC_CLIENT_TOKEN, privateKey: localKey.privateKey });
        writePairState(statePath, { host_id: localEnv.NC_CLIENT_ID, phase: 'installed' });
        await verifyHostRegistration({
          apiBase: apiOrigin,
          hostId: localEnv.NC_CLIENT_ID,
          hostToken: localEnv.NC_CLIENT_TOKEN,
          privateKey: localKey.privateKey,
          timeoutMs: verifyTimeoutMs,
          intervalMs: verifyIntervalMs
        });
        writePairState(statePath, { host_id: localEnv.NC_CLIENT_ID, phase: 'verified' });
        return { hostId: localEnv.NC_CLIENT_ID, serverUrl: localEnv.NC_SERVER_URL, resumed: true };
      } catch (err) {
        if (err instanceof PairingError && (err.code === 'VERIFY_TIMEOUT' || err.code === 'VERIFY_FAILED')) {
          // Stored credentials no longer authenticate (rotated, revoked, or
          // server reset): fall through to a fresh enrollment, which
          // overwrites the stale files below.
          console.warn(`⚠️ Stored host credentials no longer verify (${err.code}); requesting a fresh enrollment...`);
        } else {
          throw err;
        }
      }
    }
  }

  // Fresh enrollment with the OAuth USER token (user authorization only),
  // or the caller-supplied enrollment from `setup <host_id> <token>`.
  let activeEnrollment = enrollment;
  if (!activeEnrollment) {
    console.log('🔐 Requesting enrollment for this machine...');
    activeEnrollment = await requestEnrollment({ baseUrl: origin, oauthToken, platform, name: deviceName });
  } else {
    console.log(`🔐 Using supplied enrollment for host ${activeEnrollment.host_id}...`);
  }
  const hostId = activeEnrollment.host_id;
  const enrollServerUrl = typeof activeEnrollment.server_url === 'string' && activeEnrollment.server_url ? activeEnrollment.server_url : defaultServerUrl;
  writePairState(statePath, { host_id: hostId, phase: 'enrolled' });
  console.log(`🆔 Enrollment created for host ${hostId}; generating device key...`);

  const keyPair = ensureDeviceKeyPair(keyPath);

  console.log('🤝 Redeeming enrollment and binding device key...');
  let hostToken;
  let agentVersion = null;
  /** @type {Record<string, unknown>|null} */
  let redemptionRelease = null;
  try {
    const redemption = await redeemEnrollment({
      baseUrl: origin,
      hostId,
      enrollmentToken: activeEnrollment.enrollment_token,
      keyPair
    });
    hostToken = redemption.client_token;
    if (redemption.release && typeof redemption.release === 'object') {
      redemptionRelease = /** @type {Record<string, unknown>} */ (redemption.release);
    }
    if (redemption.release?.version) {
      agentVersion = redemption.release.version;
      console.log(`📦 Release: ${agentVersion}`);
    }
  } catch (err) {
    if (err instanceof PairingError && err.code === 'ENROLLMENT_ALREADY_USED') {
      // A previous run consumed this token and stored the credentials:
      // resume from them instead of failing on the single-use rule.
      const again = loadValidHostEnv(envPath);
      if (again && again.NC_CLIENT_ID === hostId) {
        console.log('🔁 Enrollment was already redeemed by an earlier run — resuming from stored credentials...');
        hostToken = again.NC_CLIENT_TOKEN;
      } else {
        throw err;
      }
    } else {
      throw err;
    }
  }

  // Host credentials ONLY — the OAuth token is never written here.
  console.log('📝 Creating configuration file...');
  writeHostEnvFile(envPath, buildHostEnvContent({ serverUrl: enrollServerUrl, hostId, hostToken, clientName: deviceName }));
  console.log(`📝 Configuration saved to ${envPath}`);
  writePairState(statePath, { host_id: hostId, phase: 'redeemed' });

  console.log('🚀 Installing agent...');
  await installAgent({ ncRoot: root, serverUrl: enrollServerUrl, release: redemptionRelease, hostId, hostToken, privateKey: keyPair.privateKey });
  writePairState(statePath, { host_id: hostId, phase: 'installed' });

  console.log('🔍 Verifying host registration...');
  await verifyHostRegistration({
    apiBase: apiOrigin,
    hostId,
    hostToken,
    privateKey: keyPair.privateKey,
    timeoutMs: verifyTimeoutMs,
    intervalMs: verifyIntervalMs
  });
  writePairState(statePath, { host_id: hostId, phase: 'verified' });
  return { hostId, serverUrl: enrollServerUrl, resumed: false, version: agentVersion };
}

/**
 * Prints a styled ASCII box in the terminal.
 * @param {Array<{ text: string, rawLength?: number }>} lines
 */
function printBox(lines) {
  const bold = '\x1b[1m';
  const cyan = '\x1b[36m';
  const reset = '\x1b[0m';

  const maxLen = lines.reduce((max, line) => {
    const len = line.rawLength !== undefined ? line.rawLength : line.text.length;
    return Math.max(max, len);
  }, 0);

  const innerWidth = Math.max(maxLen + 4, 52);
  const horizontal = '─'.repeat(innerWidth);

  console.log(`\n${cyan}┌${horizontal}┐${reset}`);
  for (const line of lines) {
    const len = line.rawLength !== undefined ? line.rawLength : line.text.length;
    const padRight = ' '.repeat(Math.max(0, innerWidth - len - 2));
    console.log(`${cyan}│${reset}  ${line.text}${padRight}${cyan}│${reset}`);
  }
  console.log(`${cyan}└${horizontal}┘${reset}\n`);
}

function printCliHelp() {
  console.log(
    [
      'nodecommand (nc) — Node Command device pairing and diagnostics',
      '',
      'Usage:',
      '  nodecommand                          pair this machine via the browser device flow',
      '  nodecommand setup [host_id token]    install the agent (auto system/user mode; no args = browser device flow)',
      '  nodecommand remove [--yes]           uninstall the agent (asks for confirmation unless --yes)',
      '  nodecommand --diagnostics            preview a redacted diagnostics bundle (dry-run, writes nothing)',
      '  nodecommand --diagnostics --apply    write the diagnostics bundle (.tar.gz) for a support ticket',
      '  nodecommand --diagnostics --apply --output <path>   write the bundle to a chosen path',
      '  nodecommand --help                   show this help',
      '',
      'Environment:',
      '  NC_BASE_URL   auth host for the browser OAuth/device flow and enrollment',
      '                (/oauth/*, /api/enroll*) (default https://auth.nodecommand.app)',
      '  NC_API_URL    agent API host for device-channel endpoints (/api/clients/*),',
      '                package downloads and /releases/* (default https://agent.nodecommand.app)',
      '  NC_SERVER_URL agent server address written to the client env (distinct from NC_API_URL)',
      '',
      'Diagnostics redaction: tokens (nc_tok_*/nc_enr_*/nc_pat_*/nc_rfk_*), HMAC keys,',
      'client secrets, cookies and private keys are replaced with [REDACTED]; the',
      'device private key is never opened. Attach the bundle to a support ticket',
      'alongside an nc_feedback report (include_diagnostics: true adds the',
      'server-side event window).'
    ].join('\n')
  );
}

async function main() {
  const cliArgs = process.argv.slice(2);
  // Subcommands route FIRST: otherwise `setup --diagnostics` or a stray flag
  // would be swallowed by the global flag handlers instead of the command.
  const [subcommand, ...subArgs] = cliArgs;
  if (subcommand === 'setup') {
    await runSetup(subArgs);
    return;
  }
  if (subcommand === 'remove') {
    await runRemove(subArgs);
    return;
  }
  if (cliArgs.includes('--help') || cliArgs.includes('-h')) {
    printCliHelp();
    return;
  }
  if (cliArgs.includes('--diagnostics') || cliArgs.some((a) => a.startsWith('--diagnostics='))) {
    // Redacted support bundle. Preview by default; only --apply writes.
    // Failures stay user-facing (no stack traces): the runner resolves
    // { ok: false } with a suggested_action-style next step.
    let result;
    try {
      const { runCliDiagnostics } = await import('../lib/diagnostics-bundle.mjs');
      result = runCliDiagnostics(cliArgs, { baseUrl });
    } catch (err) {
      console.error(`\n❌ Diagnostics failed to start: ${err.message}. Suggested action: verify the CLI install is intact and re-run.`);
      process.exit(1);
    }
    console.log(result.summary);
    if (!result.ok) process.exit(1);
    return;
  }
  await runDeviceFlow();
}

/**
 * Maps a pairing failure code to the next step shown as `suggested_action`.
 * Every setup/remove failure prints both `error:` and `suggested_action:`
 * lines so the CLI never exits silently.
 * @param {string} code
 */
export function suggestedActionFor(code) {
  switch (code) {
    case 'ENROLL_NO_OAUTH_TOKEN':
      return 'Re-run `nodecommand setup` without arguments and approve the browser device flow.';
    case 'ENROLL_UNAUTHORIZED':
      return 'Re-run `nodecommand setup` for a fresh sign-in; the previous grant expired or was revoked.';
    case 'ENROLL_TWO_FACTOR_REQUIRED':
      return 'Approve pairing from the dashboard, or re-run with a two-factor code.';
    case 'ENROLL_QUOTA_EXCEEDED':
    case 'PLAN_HOST_LIMIT_EXCEEDED':
      return 'Upgrade the workspace plan or remove an old host, then re-run.';
    case 'ENROLLMENT_ALREADY_USED':
      return 'Re-run `nodecommand setup` without arguments; it resumes from the stored host credentials.';
    case 'ENROLLMENT_EXPIRED':
    case 'INVALID_ENROLL_TOKEN':
    case 'INVALID_HOST_ID':
      return 'Re-run `nodecommand setup` without arguments for a fresh enrollment.';
    case 'INSTALL_MANIFEST_ERROR':
      return 'The update manifest is admin-only; run with an enrollment (setup <host_id> <token>) so the release ships with the redemption, or check network connectivity to the agent release host and re-run; stored credentials are reused.';
    case 'INSTALL_DOWNLOAD_ERROR':
      return 'The agent package endpoint requires the device credential issued at redemption; re-run `nodecommand setup <host_id> <token>` to redeem a fresh enrollment, then re-run; stored credentials are reused.';
    case 'INSTALL_FAILED':
    case 'INSTALL_EXTRACT_ERROR':
    case 'INSTALL_INTEGRITY_ERROR':
      return 'The agent install did not complete; check network connectivity to the agent release host and re-run; stored credentials are reused.';
    case 'VERIFY_TIMEOUT':
      return 'Check connectivity to the server and re-run to verify; credentials are already stored.';
    default:
      return 'Re-run the command; use `nodecommand --help` for usage.';
  }
}

/**
 * Rejects unknown flags before any work happens: a typo like `--ys` must
 * never be silently treated as "no flags". Always exits with both an
 * `error:` line and a `suggested_action:` line.
 * @param {string[]} args
 * @param {string[]} allowed
 * @param {string} command
 */
function assertKnownFlags(args, allowed, command) {
  const unknown = args.filter((a) => a.startsWith('-') && !allowed.includes(a));
  if (unknown.length === 0) return;
  console.error(`error: [UNKNOWN_FLAG] \`${command}\` does not recognize ${unknown.join(', ')}.`);
  console.error(`suggested_action: Allowed flags: ${allowed.join(', ')}. Run \`nodecommand ${command} --help\`.`);
  process.exit(1);
}

/**
 * Prints a setup/remove failure with a machine-readable code and a next step.
 * @param {unknown} err
 */
function reportSetupError(err) {
  const code = err instanceof PairingError ? err.code : 'UNEXPECTED_ERROR';
  const message = err instanceof Error ? err.message : String(err);
  console.error(`error: [${code}] ${message}`);
  console.error(`suggested_action: ${suggestedActionFor(code)}`);
}

/**
 * Resolves the CLI version from the sibling package.json (falls back to the
 * release the User-Agent header already advertises).
 */
function getCliVersion() {
  try {
    const pkgPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
    const parsed = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    if (typeof parsed.version === 'string' && parsed.version) return parsed.version;
  } catch {}
  return '0.1.0';
}

/**
 * Prints the one-line install summary required after a successful setup:
 * host id, install mode, CLI version, and verification status.
 * @param {{ hostId: string, serverUrl: string, installMode?: 'system'|'user', resumed?: boolean, version?: string|null }} options
 */
function printSetupSuccess({ hostId, serverUrl, installMode = undefined, resumed = false, version = null }) {
  console.log(`\n✅ Setup complete for host ${hostId}${resumed ? ' (resumed)' : ''}.`);
  if (installMode) console.log(`installed as ${installMode}`);
  if (version) console.log(`agent version: ${version}`);
  console.log(`cli version: ${getCliVersion()}`);
  console.log(`server: ${serverUrl}`);
  console.log('status: agent credentials verified online');
}

/**
 * `nodecommand setup [host_id enrollment_token]`.
 *
 * Mode is automatic (never prompted): elevated processes install system-wide,
 * everything else installs per-user with a single-line capability notice.
 * Without arguments a fresh enrollment is requested via the browser device
 * flow; with `host_id` + `token` (dashboard flow) the supplied enrollment is
 * redeemed directly. Enrollment always goes through POST /api/enroll with the
 * OAuth user grant — the same tested chain as the default pairing flow — not
 * through the dashboard shell snippets, because this CLI already embeds
 * download, install, and device-auth verification.
 * @param {string[]} args
 */
export async function runSetup(args = []) {
  const positionals = args.filter((a) => !a.startsWith('-'));
  if (positionals.includes('help') || args.includes('--help') || args.includes('-h')) {
    console.log(
      [
        'Usage:',
        '  nodecommand setup                  install via the browser device flow (auto system/user mode)',
        '  nodecommand setup <host_id> <token>  install with a dashboard enrollment token',
        '',
        'The install mode is chosen automatically: administrator/root installs',
        'machine-wide (system), anything else installs per-user (user).'
      ].join('\n')
    );
    return;
  }
  assertKnownFlags(args, ['--help', '-h'], 'setup');
  // Arity is validated BEFORE any mode/root output: an invalid invocation
  // must fail without printing an installation plan it will not execute.
  if (positionals.length !== 0 && positionals.length !== 2) {
    console.error('error: [INVALID_SETUP_ARGS] setup takes either no arguments or `<host_id> <token>`.');
    console.error('suggested_action: Re-run as `nodecommand setup` or `nodecommand setup <host_id> <token>`.');
    process.exit(1);
  }
  const installMode = decideInstallMode();
  // Mode-aware root: on win32 a system install lives in %ProgramData%\NC,
  // not the %LOCALAPPDATA% tree getNcRoot() returns, so credentials must be
  // written where the system installer will actually read them.
  const ncRoot = getNcRootForMode(installMode);
  console.log(installMode === 'system' ? `Installing as system (machine-wide), root: ${ncRoot}.` : `Installing as user (per-user), root: ${ncRoot}.`);
  const warning = modeWarningFor(installMode);
  if (warning) console.warn(warning);

  if (positionals.length === 2) {
    const [hostId, enrollmentToken] = positionals;
    try {
      const result = await pairDeviceAndInstall({
        baseUrl,
        apiBase,
        enrollment: { host_id: hostId, enrollment_token: enrollmentToken },
        installMode,
        ncRoot
      });
      printSetupSuccess({ hostId: result.hostId, serverUrl: result.serverUrl, installMode, resumed: result.resumed, version: result.version });
    } catch (err) {
      reportSetupError(err);
      process.exit(1);
    }
    return;
  }
  await runDeviceFlow({ installMode, ncRoot });
}

/**
 * Asks a yes/no question on the terminal. Resolves false on EOF/empty. The
 * first resolution wins: readline emits 'close' synchronously inside
 * rl.close(), so a naive close-handler would overwrite a real answer.
 * @param {string} question
 * @param {() => import('node:readline').Interface} [openInterface]
 */
export function confirmPrompt(question, openInterface = null) {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const open =
      openInterface || (() => readline.createInterface({ input: process.stdin, output: process.stdout }));
    const rl = open();
    rl.on('close', () => settle(false));
    rl.question(question, (answer) => {
      const yes = /^y(es)?$/i.test(String(answer || '').trim());
      // Settle BEFORE close(): readline emits 'close' synchronously from
      // rl.close(), and the first resolution must be the real answer.
      settle(yes);
      try {
        rl.close();
      } catch {}
    });
  });
}

/**
 * `nodecommand remove [--yes]`. Idempotent: no install found means success
 * (exit 0). Otherwise the uninstaller living inside each installed tree is
 * executed (never a downloaded copy) and its exit status is reported.
 * @param {string[]} args
 */
export async function runRemove(args = []) {
  if (args.includes('--help') || args.includes('-h') || args.includes('help')) {
    printCliHelp();
    return;
  }
  assertKnownFlags(args, ['--yes', '-y', '--help', '-h'], 'remove');
  const stray = args.filter((a) => !a.startsWith('-') && a !== 'help');
  if (stray.length > 0) {
    console.error(`error: [UNKNOWN_ARGUMENT] \`remove\` takes no positional arguments (got: ${stray.join(', ')}).`);
    console.error('suggested_action: Run `nodecommand remove --yes` (or plain `nodecommand remove` to be asked).');
    process.exit(1);
  }
  const yes = args.includes('--yes') || args.includes('-y');
  const { install, unreadable } = findRemovalTargets();
  const targets = [...install, ...unreadable];
  if (targets.length === 0) {
    console.log('No Node Command installation found (nothing to remove).');
    return;
  }
  console.log(`Found Node Command installation(s): ${targets.join(', ')}`);
  if (unreadable.length > 0) {
    console.log(
      `Elevated removal needed for system install(s): ${unreadable.join(', ')} (not readable as the current user).`
    );
  }
  if (!yes) {
    if (!process.stdin.isTTY) {
      console.error('error: [CONFIRMATION_REQUIRED] remove needs confirmation in non-interactive shells.');
      console.error('suggested_action: Re-run as `nodecommand remove --yes`.');
      process.exit(1);
    }
    const confirmed = await confirmPrompt(`Remove ${targets.length === 1 ? 'this installation' : 'these installations'}? [y/N] `);
    if (!confirmed) {
      console.log('Aborted (nothing removed).');
      return;
    }
  }
  let failed = 0;
  for (const root of install) {
    const script = uninstallerForRoot(root);
    if (!fs.existsSync(script)) {
      console.error(`error: [UNINSTALLER_MISSING] uninstaller not found at ${script}; skipping ${root}.`);
      console.error('suggested_action: Remove the directory manually after stopping the agent service.');
      failed += 1;
      continue;
    }
    try {
      runUninstallerScript(script);
      console.log(`Removed ${root} (exit 0).`);
    } catch (err) {
      const rc = typeof err?.status === 'number' ? err.status : 1;
      console.error(`error: [UNINSTALL_FAILED] uninstaller for ${root} exited with status ${rc}: ${err.message}`);
      console.error(uninstallFailureSuggestion());
      failed += 1;
    }
  }
  // Unreadable (system) roots: the local tree cannot be stat'ed, so the
  // uninstaller's presence is validated by the elevated run itself — the
  // in-tree script refuses non-NC directories before deleting anything.
  for (const root of unreadable) {
    const script = uninstallerForRoot(root);
    try {
      runUninstallerScript(script);
      console.log(`Removed ${root} (elevated, exit 0).`);
    } catch (err) {
      const rc = typeof err?.status === 'number' ? err.status : 1;
      console.error(`error: [UNINSTALL_FAILED] elevated uninstaller for ${root} exited with status ${rc}: ${err.message}`);
      console.error(uninstallFailureSuggestion());
      failed += 1;
    }
  }
  if (failed > 0) process.exit(1);
  console.log('Remove complete.');
}

/**
 * Browser device flow + enroll/redeem/install/verify. Extracted verbatim from
 * the historical bare-invocation path; `setup` reuses it with an explicit
 * install mode while bare `nodecommand` keeps the previous behavior.
 * @param {{ installMode?: 'system'|'user' }} [options]
 */
async function runDeviceFlow({ installMode = undefined, ncRoot = undefined } = {}) {
  const deviceEndpoint = `${baseUrl}/oauth/device/code`;
  let initRes;

  // RFC 7636 S256 PKCE for the RFC 8628 device flow: the verifier never
  // leaves this machine except as a code_verifier at token time, so an
  // eavesdropped device_code alone cannot be exchanged by another party.
  // 32 random bytes -> 43 base64url chars (RFC 7636 §4.1: 43-128).
  const deviceCodeVerifier = crypto.randomBytes(32).toString('base64url');
  const deviceCodeChallenge = crypto
    .createHash('sha256')
    .update(deviceCodeVerifier)
    .digest('base64url');

  try {
    initRes = await postJson(deviceEndpoint, {
      client_id: clientId,
      code_challenge: deviceCodeChallenge,
      code_challenge_method: 'S256'
    });
  } catch (err) {
    console.error(`error: [DEVICE_FLOW_CONNECT] Could not connect to ${deviceEndpoint}: ${err.message}`);
    console.error('suggested_action: Check network access to the control plane (or NC_BASE_URL), then re-run.');
    process.exit(1);
  }

  if (initRes.status !== 200 || !initRes.data || !initRes.data.device_code) {
    const err = initRes.data?.error_description || initRes.data?.error || `HTTP ${initRes.status}`;
    console.error(`error: [DEVICE_FLOW_START] Failed to start device flow: ${err}`);
    console.error('suggested_action: Re-run the command; if it persists, verify the control plane is reachable and NC_BASE_URL is correct.');
    process.exit(1);
  }

  const {
    device_code,
    user_code,
    verification_uri_complete,
    verification_uri,
    interval = 3
  } = initRes.data;

  const bold = '\x1b[1m';
  const green = '\x1b[32m';
  const yellow = '\x1b[33m';
  const cyan = '\x1b[36m';
  const dim = '\x1b[2m';
  const reset = '\x1b[0m';

  // Print the CLEAN verification_uri (no ?user_code= query). The /device page
  // has a manual 8-character code input; the deep-link form is useless here
  // because the login redirect strips the query (return_to=/device only), so
  // the code would never auto-fill after sign-in anyway.
  const verifyUrl = verification_uri || `${baseUrl}/device`;

  printBox([
    { text: `${bold}Node Command — Device Authorization${reset}`, rawLength: 'Node Command — Device Authorization'.length },
    { text: '', rawLength: 0 },
    { text: 'To complete pairing, open this URL in your browser:', rawLength: 'To complete pairing, open this URL in your browser:'.length },
    { text: `${cyan}${bold}${verifyUrl}${reset}`, rawLength: verifyUrl.length },
    { text: '', rawLength: 0 },
    { text: `Then enter this code on the page: ${yellow}${bold}${user_code}${reset}`, rawLength: `Then enter this code on the page: ${user_code}`.length },
    { text: '', rawLength: 0 },
    { text: `${dim}Waiting for approval in browser...${reset}`, rawLength: 'Waiting for approval in browser...'.length }
  ]);

  const pollIntervalSeconds = Number(interval) > 0 ? Number(interval) : 3;
  const pollIntervalMs = pollIntervalSeconds * 1000;
  const tokenEndpoint = `${baseUrl}/oauth/token`;

  let isPolling = false;
  let currentIntervalMs = pollIntervalMs;

  const poll = async () => {
    if (isPolling) return;
    isPolling = true;

    try {
      const tokenRes = await postJson(tokenEndpoint, {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code,
        client_id: clientId,
        code_verifier: deviceCodeVerifier
      });

      if (tokenRes.status === 200 && tokenRes.data?.access_token) {
        // The OAuth token authorizes enrollment ONLY. It stays in memory:
        // never persisted, never written to the agent env file. Success is
        // printed only after the host identity verifies over the device
        // channel inside pairDeviceAndInstall.
        const oauthToken = tokenRes.data.access_token;
        console.log('\n🔓 Browser approval received. Enrolling this machine...');
        try {
          const result = await pairDeviceAndInstall({ baseUrl, apiBase, oauthToken, installMode, ncRoot });
          if (installMode) {
            // `setup` reports the structured success block (host, mode,
            // versions, online status); bare `nodecommand` keeps the legacy
            // pairing messages below.
            printSetupSuccess({
              hostId: result.hostId,
              serverUrl: result.serverUrl,
              installMode,
              resumed: result.resumed,
              version: result.version
            });
          } else if (result.resumed) {
            console.log(`\n✅ Device pairing resumed and verified for host ${result.hostId}.`);
          } else {
            console.log(`\n✅ Device paired and verified successfully! Host: ${result.hostId}`);
          }
          if (!installMode) console.log('\n🎉 Node Command agent installed and configured successfully!');
          process.exit(0);
        } catch (pairErr) {
          const code = pairErr instanceof PairingError ? pairErr.code : 'PAIRING_FAILED';
          console.error(`\nerror: [${code}] Device pairing failed: ${pairErr.message}`);
          console.error(`suggested_action: ${suggestedActionFor(code)}`);
          process.exit(1);
        }
      }

      if (tokenRes.status === 400 && tokenRes.data?.error === 'authorization_pending') {
        // Do nothing while pending
      } else if (tokenRes.status === 400 && tokenRes.data?.error === 'slow_down') {
        // Slow down request per RFC 8628
        currentIntervalMs += 5000;
      } else {
        // Any fatal error (expired_token, access_denied, invalid_grant, etc.)
        const errMsg = tokenRes.data?.error_description || tokenRes.data?.error || `HTTP ${tokenRes.status}`;
        console.error(`\nerror: [DEVICE_FLOW_AUTH_DENIED] Authorization failed: ${errMsg}`);
        console.error('suggested_action: Re-run the command and approve the prompt in the browser.');
        process.exit(1);
      }
    } catch (pollErr) {
      // Ephemeral network glitch during poll, continue polling
    } finally {
      isPolling = false;
      setTimeout(poll, currentIntervalMs);
    }
  };

  setTimeout(poll, currentIntervalMs);
}

const isMainModule = () => {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
  }
};

if (isMainModule()) {
  main();
}
