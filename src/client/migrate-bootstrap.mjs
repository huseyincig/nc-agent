import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { deviceAuthHeaders, loadDeviceKey } from './device-proof.mjs';
import { readCappedResponseBody } from '../updater/updater.mjs';

/**
 * @param {unknown} text
 */
function parseEnv(text) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i < 1) throw new Error('MIGRATION_ENV_INVALID');
    out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

/**
 * @param {unknown} value
 */
function normalizedServer(value) {
  const server = String(value || '').replace(/\/$/, '');
  if (!/^https:\/\//i.test(server) && !/^http:\/\/127\.0\.0\.1(?::\d+)?$/i.test(server))
    throw new Error('MIGRATION_HTTPS_REQUIRED');
  return server;
}

/**
 * @param {object} [options]
 * @param {string} [options.serverUrl]
 * @param {string} [options.root]
 * @param {string} [options.expectedVersion]
 * @param {string} [options.archiveFile]
 * @param {string | null} [options.configFile]
 * @param {string | null} [options.keyFile]
 */
export async function migrateBootstrap({
  serverUrl,
  root,
  expectedVersion,
  archiveFile,
  configFile = null,
  keyFile = null
} = {}) {
  const server = normalizedServer(serverUrl);
  const canonicalRoot = String(root || '');
  // Machine roots plus per-user roots (any absolute path whose final segment
  // is the NC stem). The real authentication is the device key + token
  // below; this only rejects typos.
  const posixRoot = canonicalRoot.startsWith('/') && /(^|\/)nc$/.test(canonicalRoot);
  const winRoot =
    /^[A-Za-z]:\\/i.test(canonicalRoot) && /\\NC$/i.test(canonicalRoot) && canonicalRoot.length > 7;
  const machineRoot =
    canonicalRoot === '/opt/nc' ||
    /^[A-Za-z]:\\(?:ProgramData\\)?NC$/i.test(canonicalRoot);
  if (!posixRoot && !winRoot && !machineRoot) throw new Error('MIGRATION_ROOT_INVALID');
  if (!/^\d+\.\d+\.\d+$/.test(String(expectedVersion || '')))
    throw new Error('MIGRATION_VERSION_INVALID');
  if (typeof archiveFile !== 'string' || !archiveFile)
    throw new Error('MIGRATION_ARCHIVE_PATH_REQUIRED');

  const configDir = path.join(canonicalRoot, 'config');
  const envFile = configFile || path.join(configDir, 'nc-client.env');
  const deviceKeyFile = keyFile || path.join(configDir, 'nc-device-key.pem');
  const env = parseEnv(await fs.readFile(envFile, 'utf8'));
  const configuredServer = normalizedServer(env.NC_SERVER_URL);
  if (configuredServer !== server) throw new Error('MIGRATION_SERVER_MISMATCH');
  const clientId = String(env.NC_CLIENT_ID || '');
  const token = String(env.NC_CLIENT_TOKEN || '');
  if (!/^nc_[0-9a-f]{64}$/.test(clientId)) throw new Error('INVALID_CLIENT_ID');
  if (!/^nc_tok_[0-9a-f]{64}$/.test(token)) throw new Error('INVALID_CLIENT_TOKEN');

  const privateKey = await loadDeviceKey(deviceKeyFile);
  const manifestUrl = server + '/api/clients/' + encodeURIComponent(clientId) + '/update/manifest';
  const manifestHeaders = deviceAuthHeaders({
    privateKey,
    clientId,
    method: 'GET',
    url: manifestUrl,
    token
  });
  const manifestResponse = await fetch(manifestUrl, {
    headers: manifestHeaders,
    signal: AbortSignal.timeout(15000)
  });
  const manifestText = await manifestResponse.text();
  /** @type {any} */
  let manifestBody = {};
  try {
    manifestBody = manifestText ? JSON.parse(manifestText) : {};
  } catch {}
  if (!manifestResponse.ok)
    throw new Error(
      String(manifestBody.error || 'MIGRATION_MANIFEST_HTTP_' + manifestResponse.status)
    );
  const release = manifestBody.release;
  if (
    !release ||
    release.version !== expectedVersion ||
    !/^[0-9a-f]{64}$/.test(String(release.bootstrap_sha256 || ''))
  )
    throw new Error('MIGRATION_RELEASE_MISMATCH');
  if (typeof release.bootstrap_url !== 'string' || !release.bootstrap_url.startsWith('/'))
    throw new Error('MIGRATION_BOOTSTRAP_URL_INVALID');

  const bootstrapUrl = server + release.bootstrap_url;
  const bootstrapHeaders = deviceAuthHeaders({
    privateKey,
    clientId,
    method: 'GET',
    url: bootstrapUrl,
    token
  });
  const bootstrapResponse = await fetch(bootstrapUrl, {
    headers: bootstrapHeaders,
    signal: AbortSignal.timeout(300000)
  });
  if (!bootstrapResponse.ok)
    throw new Error('MIGRATION_BOOTSTRAP_HTTP_' + bootstrapResponse.status);
  const body = await readCappedResponseBody(bootstrapResponse);
  const actual = crypto.createHash('sha256').update(body).digest('hex');
  if (actual !== release.bootstrap_sha256) throw new Error('MIGRATION_BOOTSTRAP_SHA256_MISMATCH');
  if (
    Number(release.bootstrap_size_bytes || 0) > 0 &&
    body.length !== Number(release.bootstrap_size_bytes)
  )
    throw new Error('MIGRATION_BOOTSTRAP_SIZE_MISMATCH');
  await fs.writeFile(archiveFile, body, { mode: 0o600 });
  return {
    client_id: clientId,
    release_version: release.version,
    bootstrap_sha256: actual,
    bootstrap_size_bytes: body.length
  };
}

if (process.argv[1] && process.argv[1].endsWith('migrate-bootstrap.mjs')) {
  const [serverUrl, root, expectedVersion, archiveFile] = process.argv.slice(2);
  try {
    const out = await migrateBootstrap({ serverUrl, root, expectedVersion, archiveFile });
    process.stdout.write(JSON.stringify(out));
  } catch (error) {
    const message =
      error && typeof error === 'object' && 'message' in error && error.message
        ? error.message
        : error;
    process.stderr.write(String(message) + '\n');
    process.exitCode = 1;
  }
}
