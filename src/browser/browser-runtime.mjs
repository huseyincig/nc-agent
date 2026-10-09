import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { spawn, execFile } from 'node:child_process';
import { ncLayout } from '../client/nc-paths.mjs';
import { extractReleaseArchive } from '../updater/tar-extract.mjs';

// Pinned browser runtime. playwright-core is platform-independent JS; the
// Chromium binary revision is coupled to it via the payload's browsers.json.
// Bump BOTH together; the installer/OTA refuses to activate a new runtime
// whose browser revision is not installed AND launch-validated.
export const BROWSER_RUNTIME_PIN = Object.freeze({
  playwright: '1.63.0',
  chromiumRevision: '1243'
});

// Central browser policy defaults. No magic numbers in the manager: every
// tunable below is overridden by (in order) explicit tool args, the projected
// host-policy capabilities, then these defaults.
export const BROWSER_DEFAULTS = Object.freeze({
  mode: 'managed',
  headless: true,
  viewport: { width: 1280, height: 800 },
  actionTimeoutMs: 5000,
  navigationTimeoutMs: 60000,
  settleMs: 500,
  maxTimeoutMs: 120000,
  idleTimeoutMs: 15 * 60 * 1000,
  maxLifetimeMs: 2 * 60 * 60 * 1000,
  maxSessionsPerClient: 5,
  maxConsoleEntries: 500,
  maxNetworkEntries: 500,
  maxSnapshotChars: 20000,
  maxScreenshotBytes: 131072,
  maxDownloadBytes: 50 * 1024 * 1024,
  sweepIntervalMs: 60 * 1000
});

/**
 * @param {string} dir
 * @param {string} name
 */
function readJsonFile(dir, name) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Deterministic Chromium executable resolution (SYN-BRW-002). Playwright
 * resolves the binary through process-global registry state (memoized at
 * first import/launch), which makes launches hostage to import order and
 * early env values. NC resolves the exact file itself with plain fs checks
 * and passes executablePath explicitly, so a launch can never consult stale
 * registry state. Returns the first hit plus the full tried list for
 * diagnostics (surfaced on launch failure).
 * Layout mirrors Playwright 1.63 EXECUTABLE_PATHS (linux/mac/win, x64/arm64,
 * headless-shell vs full, with legacy chrome-linux fallback).
 * @param {{browsersDir?: string|null, revision?: string|null, headless?: boolean, platform?: string, arch?: string}} [options]
 */
export function resolveChromiumExecutable({
  browsersDir = null,
  revision = null,
  headless = true,
  platform = process.platform,
  arch = process.arch
} = {}) {
  const tried = [];
  const rev = String(revision || BROWSER_RUNTIME_PIN.chromiumRevision || '');
  const root = String(browsersDir || '');
  const isMac = platform === 'darwin';
  const isWin = platform === 'win32';
  const arm = arch === 'arm64';
  /** @type {Array<Array<string>>} */
  let candidates = [];
  if (headless) {
    if (isWin)
      candidates = [
        [
          `chromium_headless_shell-${rev}`,
          'chrome-headless-shell-win64',
          'chrome-headless-shell.exe'
        ]
      ];
    else if (isMac)
      candidates = [
        [
          `chromium_headless_shell-${rev}`,
          arm ? 'chrome-headless-shell-mac-arm64' : 'chrome-headless-shell-mac-x64',
          'chrome-headless-shell'
        ]
      ];
    else
      candidates = [
        [
          `chromium_headless_shell-${rev}`,
          arm ? 'chrome-headless-shell-linux-arm64' : 'chrome-headless-shell-linux64',
          'chrome-headless-shell'
        ]
      ];
  } else if (isWin) candidates = [[`chromium-${rev}`, 'chrome-win64', 'chrome.exe']];
  else if (isMac)
    candidates = [
      [
        `chromium-${rev}`,
        arm ? 'chrome-mac-arm64' : 'chrome-mac-x64',
        'Google Chrome for Testing.app',
        'Contents',
        'MacOS',
        'Google Chrome for Testing'
      ]
    ];
  else if (arm) candidates = [[`chromium-${rev}`, 'chrome-linux-arm64', 'chrome']];
  else
    candidates = [
      [`chromium-${rev}`, 'chrome-linux64', 'chrome'],
      [`chromium-${rev}`, 'chrome-linux', 'chrome']
    ];
  if (root) {
    for (const parts of candidates) {
      const full = path.join(root, ...parts);
      tried.push(full);
      try {
        const st = fs.statSync(full);
        if (!st.isFile()) continue;
        if (!isWin) {
          try {
            fs.accessSync(full, fs.constants.X_OK);
          } catch {
            continue;
          }
        }
        return { ok: true, executablePath: full, tried };
      } catch {}
    }
  }
  return { ok: false, executablePath: null, tried };
}

/**
 * @param {{root?: string|null, dataDir?: string|null, env?: NodeJS.ProcessEnv}} [options]
 */
export function resolveBrowserRuntime(options = {}) {
  const env = options.env || process.env;
  let data = options.dataDir || env.NC_BROWSER_DATA_DIR || null;
  if (!data) {
    try {
      data = ncLayout(options.root || undefined).data;
    } catch {
      data = null;
    }
  }
  if (!data) data = env.NC_BROWSER_DATA_DIR || path.join(os.tmpdir(), 'nc-browser');
  const base = path.join(path.resolve(data), 'browser');
  const runtime = path.join(base, 'browser-runtime');
  return Object.freeze({
    base,
    runtime,
    coreDir: env.NC_PLAYWRIGHT_CORE_PATH || path.join(runtime, 'playwright-core'),
    browsersDir: env.PLAYWRIGHT_BROWSERS_PATH || path.join(base, 'playwright-browsers'),
    stagingDir: path.join(base, 'playwright-browsers.staging'),
    profilesDir: path.join(base, 'profiles'),
    downloadsDir: path.join(base, 'downloads'),
    pin: BROWSER_RUNTIME_PIN
  });
}

/** @type {Record<string, any>|null} */
let cachedCore = null;
/** @type {string|null} */
let cachedCoreKey = null;

/**
 * Loads the vendored playwright-core from an explicit path only. Never a
 * bare specifier: production hosts must not resolve an ambient copy.
 * @param {string} coreDir
 */
export async function loadPlaywrightCore(coreDir) {
  if (cachedCore && cachedCoreKey === coreDir) return cachedCore;
  let mod = null;
  for (const entry of ['index.mjs', 'index.js']) {
    try {
      const full = path.join(coreDir, entry);
      if (!fs.existsSync(full)) continue;
      mod = await import(pathToFileURL(full).href);
      break;
    } catch {
      mod = null;
    }
  }
  if (!mod || !mod.chromium) throw new Error('BROWSER_RUNTIME_MISSING');
  const pkg = readJsonFile(coreDir, 'package.json');
  const version = String(pkg?.version || '');
  if (version !== BROWSER_RUNTIME_PIN.playwright) throw new Error('BROWSER_VERSION_MISMATCH');
  cachedCore = { ...mod, __version: version, __coreDir: coreDir };
  cachedCoreKey = coreDir;
  return cachedCore;
}

/** @param {string} coreDir */
export function expectedChromiumRevision(coreDir) {
  try {
    const browsers = JSON.parse(fs.readFileSync(path.join(coreDir, 'browsers.json'), 'utf8'));
    const entry = (browsers?.browsers || []).find(
      (/** @type {Record<string, any>} */ b) => b?.name === 'chromium'
    );
    if (entry?.revision) return String(entry.revision);
  } catch {}
  return BROWSER_RUNTIME_PIN.chromiumRevision;
}

/** @param {string} browsersDir */
export function installedChromiumRevisions(browsersDir) {
  try {
    return fs
      .readdirSync(browsersDir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && /^chromium-/.test(e.name))
      .map((e) => e.name.replace(/^chromium-/, ''));
  } catch {
    return [];
  }
}

/**
 * Fetches playwright-core from the npm registry (never from our hub) and
 * installs it as the live runtime. Hub rule: our server carries agent
 * trees only; runtimes and binaries come from upstream.
 * Integrity rests on TLS + the exact version pin (verified after extract),
 * the same trust already placed in the Chromium CDN and Node sources.
 * No npm scripts ever run: the tarball is extracted with the safe
 * in-house extractor, never installed.
 * @param {string} base browser base dir (holds browser-runtime/)
 * @param {{pin?: string, pack?: ((dir: string, spec: string, timeoutMs?: number) => Promise<{ok: boolean, file?: string, error?: string}>), timeoutMs?: number}} [options]
 */
export async function ensurePlaywrightCore(base, options = {}) {
  const pin = String(options.pin || BROWSER_RUNTIME_PIN.playwright || '');
  if (!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(pin))
    return { ok: false, error: 'INVALID_BROWSER_RUNTIME_VERSION' };
  const coreDir = path.join(base, 'browser-runtime', 'playwright-core');
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(coreDir, 'package.json'), 'utf8'));
    if (
      String(pkg?.name || '') === 'playwright-core' &&
      String(pkg?.version || '') === pin &&
      fs.existsSync(path.join(coreDir, 'cli.js'))
    )
      return { ok: true, current: true, version: pin };
  } catch {}
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'nc-pwcore-'));
  let phase = 'pack';
  try {
    const pack = options.pack || defaultNpmPack;
    const packed = await pack(tmp, `playwright-core@${pin}`, options.timeoutMs);
    if (!packed || !packed.ok || !packed.file)
      throw new Error((packed && packed.error) || 'BROWSER_CORE_PACK_FAILED');
    phase = 'extract';
    const tgz = path.resolve(tmp, String(packed.file));
    if (!tgz.startsWith(path.resolve(tmp) + path.sep))
      throw new Error('BROWSER_CORE_PATH_ESCAPE');
    let stat = null;
    try {
      stat = fs.statSync(tgz);
    } catch {}
    if (!stat || !stat.isFile() || stat.size <= 0 || stat.size > 64 * 1024 * 1024)
      throw new Error('BROWSER_CORE_BAD_ARCHIVE');
    const extractDir = path.join(tmp, 'extract');
    fs.mkdirSync(extractDir, { recursive: true });
    await extractReleaseArchive(fs.readFileSync(tgz), extractDir);
    phase = 'verify';
    const extracted = path.join(extractDir, 'package');
    const pkg = JSON.parse(fs.readFileSync(path.join(extracted, 'package.json'), 'utf8'));
    if (String(pkg?.name || '') !== 'playwright-core' || String(pkg?.version || '') !== pin)
      throw new Error('BROWSER_VERSION_MISMATCH');
    if (!fs.existsSync(path.join(extracted, 'cli.js')))
      throw new Error('BROWSER_RUNTIME_MISSING');
    phase = 'promote';
    rmrf(path.join(base, 'browser-runtime'));
    fs.mkdirSync(path.join(base, 'browser-runtime'), { recursive: true });
    fs.renameSync(extracted, coreDir);
    // Drop the loader cache so the fresh copy is picked up in-process.
    cachedCore = null;
    cachedCoreKey = null;
    return { ok: true, version: pin };
  } catch (error) {
    const rec = error && typeof error === 'object' ? error : null;
    const code =
      rec && 'code' in rec && (typeof rec.code === 'string' || typeof rec.code === 'number')
        ? String(rec.code)
        : null;
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      // Both code and message: code-only reports (e.g. bare EINVAL) are
      // undiagnosable across platforms.
      error: code && code !== message ? `${code}:${message}`.slice(0, 300) : message.slice(0, 300),
      stage: phase
    };
  } finally {
    rmrf(tmp);
  }
}

/**
 * Resolves npm's CLI next to the running node binary (standard layouts:
 * nodejs.org, winget, portable zip). Running npm-cli.js with node directly
 * avoids every Windows batch quirk (PATH search, %~dp0, cmd quoting).
 * @returns {string|null}
 */
export function npmCliPath() {
  try {
    const cli = path.join(
      path.dirname(process.execPath),
      'node_modules',
      'npm',
      'bin',
      'npm-cli.js'
    );
    if (fs.existsSync(cli)) return cli;
  } catch {}
  return null;
}

/**
 * Builds the npm-pack invocation for a platform. Prefers node+npm-cli.js;
 * falls back to COMSPEC + single quoted command on Windows when npm-cli.js
 * is absent. Pure (exported for tests).
 * @param {string} [platform]
 * @param {string} [spec]
 */
export function npmPackArgv(platform = process.platform, spec = 'playwright-core') {
  const parts = ['pack', spec, '--silent', '--no-audit', '--no-fund', '--no-progress'];
  if (platform === 'win32') {
    const comspec =
      (typeof process === 'object' && process.env && process.env.ComSpec) ||
      (typeof process === 'object' && process.env && process.env.COMSPEC) ||
      'C:\\Windows\\System32\\cmd.exe';
    const q = (s) => `"${String(s).replace(/"/g, '')}"`;
    const inner = [q('npm.cmd'), ...parts.map(q)].join(' ');
    return { file: comspec, args: ['/d', '/s', '/c', inner] };
  }
  return { file: 'npm', args: parts };
}

/**
 * Default npm-pack runner: `npm pack` the exact pinned spec into dir.
 * argv-exec only (no shell); pin format is validated by the caller.
 * @param {string} dir
 * @param {string} spec
 * @param {number} [timeoutMs]
 */
function defaultNpmPack(dir, spec, timeoutMs) {
  return new Promise((resolve) => {
    if (!/^playwright-core@\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(String(spec || ''))) {
      resolve({ ok: false, error: 'BROWSER_CORE_PACK_FAILED' });
      return;
    }
    const cli = npmCliPath();
    const invoked = cli
      ? { file: process.execPath, args: [cli, 'pack', spec, '--silent', '--no-audit', '--no-fund', '--no-progress'] }
      : npmPackArgv(process.platform, spec);
    execFile(
      invoked.file,
      invoked.args,
      { cwd: dir, timeout: Math.max(10000, Number(timeoutMs) || 300000), windowsHide: true },
      (error, stdout) => {
        if (error) {
          resolve({ ok: false, error: String((error && error.message) || error).slice(0, 200) });
          return;
        }
        const found = String(stdout || '')
          .split('\n')
          .map((x) => x.trim())
          .filter(Boolean)
          .pop();
        if (!found) {
          resolve({ ok: false, error: 'BROWSER_CORE_PACK_FAILED' });
          return;
        }
        resolve({ ok: true, file: found });
      }
    );
  });
}

/** @param {string} p */
function rmrf(p) {
  try {
    fs.rmSync(p, { recursive: true, force: true });
  } catch {}
  return null;
}

/**
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {Record<string, string>} [env]
 * @param {number} [timeoutMs]
 */
function runCmd(cmd, args, env, timeoutMs = 600000) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      env: { ...process.env, ...(env || {}) },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {}
      resolve({ ok: false, out, err: (err + '\nINSTALL_TIMEOUT').slice(-2000) });
    }, timeoutMs);
    if (timer.unref) timer.unref();
    child.stdout.on('data', (d) => {
      out += String(d);
    });
    child.stderr.on('data', (d) => {
      err += String(d);
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ ok: false, out, err: String((e && e.message) || e).slice(-2000) });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, out: out.slice(-2000), err: err.slice(-2000) });
    });
  });
}

/**
 * Moves staged browser revision dirs into the live browsers dir (.prev kept
 * for one generation). Shared by the installer path and boot promotion.
 * @param {string} browsersDir
 * @param {string} stagingDir
 */
export function promoteStagedBrowserDirs(browsersDir, stagingDir) {
  try {
    fs.mkdirSync(browsersDir, { recursive: true });
    const staged = fs.readdirSync(stagingDir);
    let moved = 0;
    for (const name of staged) {
      if (!/^(chromium-|chromium_headless_shell-|ffmpeg-)/.test(name)) continue;
      const target = path.join(browsersDir, name);
      if (/^chromium-/.test(name)) {
        rmrf(path.join(browsersDir, `${name}.prev`));
        if (fs.existsSync(target)) fs.renameSync(target, path.join(browsersDir, `${name}.prev`));
      } else {
        rmrf(target);
      }
      try {
        fs.renameSync(path.join(stagingDir, name), target);
        moved++;
      } catch {}
    }
    return { ok: moved > 0, moved };
  } catch {
    return { ok: false, moved: 0 };
  }
}

/**
 * Staged browser install: downloads into a staging directory, validates by
 * launching a blank page, and only then promotes the revision directory into
 * the live browsers dir. The previous revision is kept as .prev for rollback.
 * Never breaks the running revision on validation failure.
 * @param {{coreDir: string, browsersDir: string, stagingDir: string, withDeps?: boolean, timeoutMs?: number, promote?: boolean}} options
 */
export async function stageBrowserInstall(options) {
  const { coreDir, browsersDir, stagingDir } = options;
  const promote = options.promote !== false;
  const cli = path.join(coreDir, 'cli.js');
  if (!fs.existsSync(cli)) return { ok: false, error: 'BROWSER_RUNTIME_MISSING' };
  const revision = expectedChromiumRevision(coreDir);
  rmrf(stagingDir);
  try {
    fs.mkdirSync(stagingDir, { recursive: true });
  } catch {
    return { ok: false, error: 'BROWSER_INSTALLATION_MISSING' };
  }
  const args = ['install'];
  // OS dependencies only on Linux and only when running privileged; never
  // implied on Windows/macOS, and never during OTA (installer-only).
  if (options.withDeps === true && process.platform === 'linux') args.push('--with-deps');
  args.push('chromium');
  const installed = await runCmd(
    process.execPath,
    [cli, ...args],
    { PLAYWRIGHT_BROWSERS_PATH: stagingDir },
    options.timeoutMs || 600000
  );
  if (!installed.ok) {
    rmrf(stagingDir);
    return { ok: false, error: 'BROWSER_INSTALLATION_MISSING', detail: installed.err };
  }
  const staged = installedChromiumRevisions(stagingDir);
  if (!staged.includes(revision)) {
    rmrf(stagingDir);
    return { ok: false, error: 'BROWSER_VERSION_MISMATCH', detail: staged.join(',') };
  }
  // Validate BEFORE promoting: launch a blank page from the staged revision.
  const probe = await validateBrowserLaunch({
    coreDir,
    browsersDir: stagingDir,
    headless: true,
    timeoutMs: 60000
  });
  if (!probe.ok) {
    rmrf(stagingDir);
    return {
      ok: false,
      error: 'BROWSER_LAUNCH_FAILED',
      detail:
        typeof probe.detail === 'string'
          ? probe.detail.slice(0, 300)
          : typeof probe.detail === 'object' && probe.detail !== null
            ? JSON.stringify(probe.detail).slice(0, 300)
            : probe.error
    };
  }
  if (!promote)
    return { ok: true, revision, playwright: BROWSER_RUNTIME_PIN.playwright, staged: true };
  const promoted = promoteStagedBrowserDirs(browsersDir, stagingDir);
  rmrf(stagingDir);
  if (!promoted.ok) return { ok: false, error: 'BROWSER_INTERNAL_ERROR' };
  return { ok: true, revision, playwright: BROWSER_RUNTIME_PIN.playwright };
}

/**
 * Playwright resolves browsers via PLAYWRIGHT_BROWSERS_PATH at launch time.
 * The manager calls this once with the NC-managed dir; an operator-set
 * value is never overridden.
 * @param {string} browsersDir
 */
export function applyBrowsersPathEnv(browsersDir) {
  if (!process.env.PLAYWRIGHT_BROWSERS_PATH) {
    process.env.PLAYWRIGHT_BROWSERS_PATH = browsersDir;
  }
  return process.env.PLAYWRIGHT_BROWSERS_PATH;
}

/**
 * Boot-time activation of the app-bundled browser runtime (OTA vehicle for
 * pin changes: client.tar.gz carries browser-runtime/). When the bundled
 * payload version equals the running code pin and the live data runtime
 * differs, the bundle is copied to staging and promoted through the same
 * validated path as OTA staging. A bundle that disagrees with the pin is
 * ignored (fail-closed; the health gate reports the mismatch).
 * @param {{appDir: string, base: string}} options
 */
export async function activateBundledBrowserRuntime({ appDir, base }) {
  try {
    const bundledPkg = readJsonFile(
      path.join(appDir, 'browser-runtime', 'playwright-core'),
      'package.json'
    );
    if (!bundledPkg || String(bundledPkg.version || '') !== BROWSER_RUNTIME_PIN.playwright)
      return { promoted: false, reason: 'pin-mismatch' };
    const livePkg = readJsonFile(
      path.join(base, 'browser-runtime', 'playwright-core'),
      'package.json'
    );
    if (livePkg && String(livePkg.version || '') === BROWSER_RUNTIME_PIN.playwright)
      return { promoted: false, reason: 'current' };
    const staged = path.join(base, 'browser-runtime.staging');
    rmrf(staged);
    fs.mkdirSync(staged, { recursive: true });
    const bundled = path.join(appDir, 'browser-runtime');
    for (const entry of fs.readdirSync(bundled)) {
      fs.cpSync(path.join(bundled, entry), path.join(staged, entry), { recursive: true });
    }
    return activateStagedBrowserRuntime(base);
  } catch {
    return { promoted: false, reason: 'BROWSER_INTERNAL_ERROR' };
  }
}

/**
 * Background convergence for the managed Chromium binary (OTA vehicle is
 * the bundled/standalone runtime JS; the ~150 MB binary follows on first
 * boot when missing). Never blocks boot or hello: browser tools stay hidden
 * behind the health gate until the binary validates. No OS dependencies are
 * ever installed here (installer-only); failures carry stage/detail so the
 * cause is diagnosable, and scheduleConvergenceRetry re-attempts in-process
 * instead of waiting for the next restart.
 * @param {string} base
 * @returns {Promise<{installed: boolean, revision?: string, error?: string, stage?: string, detail?: string}>}
 */
export async function ensureManagedBrowsers(base) {
  try {
    const browsersDir = path.join(base, 'playwright-browsers');
    const revision = expectedChromiumRevision(
      path.join(base, 'browser-runtime', 'playwright-core')
    );
    if (installedChromiumRevisions(browsersDir).includes(revision))
      return { installed: true, revision };
    const coreDir = path.join(base, 'browser-runtime', 'playwright-core');
    if (!fs.existsSync(path.join(coreDir, 'cli.js')))
      return { installed: false, error: 'BROWSER_RUNTIME_MISSING', stage: 'preflight' };
    const staged = await stageBrowserInstall({
      coreDir,
      browsersDir,
      stagingDir: path.join(base, 'playwright-browsers.staging'),
      withDeps: false,
      promote: true
    });
    if (!staged.ok)
      return {
        installed: false,
        error: staged.error || 'BROWSER_INSTALLATION_MISSING',
        stage: staged.error === 'BROWSER_LAUNCH_FAILED' ? 'validate' : 'download',
        detail:
          typeof staged.detail === 'string'
            ? staged.detail.slice(0, 300)
            : staged.detail && typeof staged.detail === 'object'
              ? JSON.stringify(staged.detail).slice(0, 300)
              : undefined
      };
    return { installed: true, revision: staged.revision || revision };
  } catch {
    return { installed: false, error: 'BROWSER_INTERNAL_ERROR', stage: 'unknown' };
  }
}

export const CONVERGENCE_RETRY_BASE_MS = 5 * 60 * 1000;
export const CONVERGENCE_RETRY_MAX_MS = 60 * 60 * 1000;

/**
 * @param {number} attempt 1-based
 * @param {() => number} [rand]
 */
export function convergenceRetryDelay(attempt = 1, rand = Math.random) {
  return Math.min(
    CONVERGENCE_RETRY_MAX_MS,
    CONVERGENCE_RETRY_BASE_MS * 2 ** Math.min(Math.max(1, attempt) - 1, 4) +
      Math.floor((typeof rand === 'function' ? rand() : Math.random()) * 60 * 1000)
  );
}

/**
 * Pure validate-retry decision for convergence (SYN-BRW-003).
 * @param {{stage?: unknown, validateFails?: number}} [options]
 */
export function convergenceValidateOutcome({ stage = null, validateFails = 0 } = {}) {
  const fails = stage === 'validate' ? validateFails + 1 : validateFails;
  if (stage === 'validate' && fails > 3) {
    return { fails, terminal: true, note: 'PLATFORM_BROWSER_FIX_NEEDED' };
  }
  return { fails, terminal: false, note: null };
}

/**
 * Fire-and-forget background retry for failed convergence (SYN-BRW-003).
 * A single download/validation failure (transient CDN, slow disk) must not
 * defer browsers to the next process restart. Retries back off exponentially
 * with jitter, never run concurrently, and stop permanently on success.
 * Staging-dir collisions with OTA are avoided by skipping while staging
 * exists. Timer is unref'd (never holds the process open).
 * Validate-stage failures are NOT retried forever: three consecutive
 * validate failures mean a deterministic platform problem (missing OS
 * deps, sandbox, quarantine) that re-downloading will never fix — stop
 * after 3 and report PLATFORM_BROWSER_FIX_NEEDED instead of burning
 * bandwidth in a download→validate→wipe loop. Download-stage failures
 * keep retrying (transient) without touching the validate counter.
 * @param {{base?: string|null, attempt?: number, validateFails?: number, onResult?: ((r: unknown) => unknown)|null}} [options]
 */
export function scheduleConvergenceRetry({
  base = null,
  attempt = 1,
  validateFails = 0,
  onResult = null
} = {}) {
  if (!base) return null;
  const delay = convergenceRetryDelay(attempt);
  const timer = setTimeout(() => {
    (async () => {
      try {
        if (fs.existsSync(path.join(base, 'playwright-browsers.staging'))) return;
        try {
          await ensurePlaywrightCore(base);
        } catch {}
        const r = /** @type {{installed?: unknown, error?: unknown, stage?: unknown}} */ (
          await ensureManagedBrowsers(base)
        );
        if (onResult) {
          try {
            await onResult(r);
          } catch {}
        }
        if (!r || r.installed === true) return;
        const outcome = convergenceValidateOutcome({ stage: r.stage, validateFails });
        if (outcome.terminal) {
          if (onResult) {
            try {
              await onResult({
                ...r,
                terminal: true,
                note: outcome.note
              });
            } catch {}
          }
          return;
        }
        scheduleConvergenceRetry({
          base,
          attempt: attempt + 1,
          validateFails: outcome.fails,
          onResult
        });
      } catch {}
    })();
  }, delay);
  if (timer.unref) timer.unref();
  return timer;
}

/**
 * Boot-time promotion of a staged browser runtime (OTA path). The staged
 * payload activates only when its Playwright version equals the running
 * code pin: old code ignores newer staging, new code ignores stale staging.
 *
 * The runtime JS and the browser binaries promote INDEPENDENTLY: a pin
 * match always promotes the JS (validating the binary would deadlock fresh
 * hosts, where the binary can only arrive after the JS is live). Missing
 * binaries are reported, stay hidden behind the health gate, and converge
 * via ensureManagedBrowsers on this and every later boot. The previous
 * runtime is kept as .prev for one generation.
 * @param {string} base
 */
export async function activateStagedBrowserRuntime(base) {
  const live = path.join(base, 'browser-runtime');
  const staged = path.join(base, 'browser-runtime.staging');
  const prev = path.join(base, 'browser-runtime.prev');
  const stagedCore = path.join(staged, 'playwright-core');
  const pkg = readJsonFile(stagedCore, 'package.json');
  if (!pkg || String(pkg.version || '') !== BROWSER_RUNTIME_PIN.playwright) {
    if (fs.existsSync(staged)) rmrf(staged);
    return { promoted: false, reason: 'pin-mismatch' };
  }
  const browsersDir = path.join(base, 'playwright-browsers');
  const stagingDir = path.join(base, 'playwright-browsers.staging');
  const revision = expectedChromiumRevision(stagedCore);
  // Promote the JS first: it is what the health gate and all later steps
  // execute. Binaries follow opportunistically below.
  try {
    rmrf(prev);
    if (fs.existsSync(live)) fs.renameSync(live, prev);
    fs.renameSync(staged, live);
  } catch {
    return { promoted: false, reason: 'BROWSER_INTERNAL_ERROR' };
  }
  // Binaries: live already has them, or staging validated them, or they
  // converge later via ensureManagedBrowsers (never a promotion blocker).
  let browsers = 'absent';
  try {
    if (installedChromiumRevisions(browsersDir).includes(revision)) {
      browsers = 'live';
    } else if (installedChromiumRevisions(stagingDir).includes(revision)) {
      const probe = await validateBrowserLaunch({
        coreDir: path.join(live, 'playwright-core'),
        browsersDir: stagingDir,
        headless: true,
        timeoutMs: 60000
      });
      if (probe.ok) {
        const promoted = promoteStagedBrowserDirs(browsersDir, stagingDir);
        browsers = promoted.ok ? 'promoted' : 'validation-failed';
      } else {
        browsers = probe.error || 'BROWSER_LAUNCH_FAILED';
      }
      rmrf(stagingDir);
    }
  } catch {
    browsers = 'BROWSER_INTERNAL_ERROR';
  }
  return { promoted: true, playwright: BROWSER_RUNTIME_PIN.playwright, revision, browsers };
}

/**
 * Service-user browser HOME (SYN-BRW-004). Chromium CHECK-traps (SIGILL,
 * empty stderr, "browser has been closed") when the daemon user's HOME is
 * missing or unwritable — e.g. macOS `_nc` whose NFSHomeDirectory is
 * /var/empty. Healthy hosts keep their ambient HOME untouched; only an
 * unwritable HOME falls back to a managed 0700 dir under the data tree.
 * @param {{browsersDir?: string|null, home?: string}} [options]
 */
export function resolveBrowserServiceHome({ browsersDir = null, home = undefined } = {}) {
  const ambient = home === undefined ? process.env.HOME : home;
  if (typeof ambient === 'string' && ambient) {
    try {
      fs.accessSync(ambient, fs.constants.W_OK);
      return { home: ambient, managed: false };
    } catch {}
  }
  const managed = path.join(
    browsersDir ? path.dirname(String(browsersDir)) : os.tmpdir(),
    'browser-service-home'
  );
  fs.mkdirSync(managed, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(managed, 0o700);
  } catch {}
  return { home: managed, managed: true };
}

/**
 * Environment for browser child processes (SYN-BRW-004): process env with
 * a guaranteed-writable HOME. Playwright's `env` defaults to process.env,
 * so this is a no-op override on healthy hosts.
 * @param {{browsersDir?: string|null}} [options]
 */
export function browserLaunchEnv({ browsersDir = null } = {}) {
  const { home } = resolveBrowserServiceHome({ browsersDir });
  return { ...process.env, HOME: home };
}

/**
 * Launch validation: blank page open + title read + clean close.
 * Uses explicit executable resolution (same determinism rationale as the
 * manager: never trust registry memoization for validation verdicts).
 * @param {{coreDir: string, browsersDir: string, headless?: boolean, timeoutMs?: number}} options
 */
export async function validateBrowserLaunch(options) {
  const started = Date.now();
  applyBrowsersPathEnv(options.browsersDir);
  const timeoutMs = options.timeoutMs || 60000;
  const headless = options.headless !== false;
  const resolved = resolveChromiumExecutable({
    browsersDir: options.browsersDir,
    headless
  });
  if (!resolved.ok || !resolved.executablePath) {
    return {
      ok: false,
      error: 'BROWSER_INSTALLATION_MISSING',
      detail: { tried: resolved.tried, browsersDir: options.browsersDir }
    };
  }
  let core = null;
  try {
    core = await loadPlaywrightCore(options.coreDir);
  } catch (e) {
    return {
      ok: false,
      error:
        e && typeof e === 'object' && 'message' in e ? String(e.message) : 'BROWSER_RUNTIME_MISSING'
    };
  }
  if (!core) return { ok: false, error: 'BROWSER_RUNTIME_MISSING' };
  let browser = null;
  try {
    browser = await core.chromium.launch({
      headless,
      executablePath: resolved.executablePath,
      timeout: Math.min(timeoutMs, 60000),
      env: browserLaunchEnv({ browsersDir: options.browsersDir }),
      args: ['--no-first-run', '--no-default-browser-check', '--disable-dev-shm-usage']
    });
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto('about:blank', { timeout: Math.min(timeoutMs, 30000) });
    await page.title();
    await ctx.close();
    await browser.close();
    browser = null;
    return {
      ok: true,
      duration_ms: Date.now() - started,
      playwright: BROWSER_RUNTIME_PIN.playwright,
      revision: expectedChromiumRevision(options.coreDir)
    };
  } catch (e) {
    try {
      if (browser) await browser.close();
    } catch {}
    const msg = e && typeof e === 'object' && 'message' in e ? String(e.message) : '';
    if (/executable doesn't exist|Executable doesn't exist/i.test(msg))
      return { ok: false, error: 'BROWSER_INSTALLATION_MISSING' };
    return { ok: false, error: 'BROWSER_LAUNCH_FAILED', detail: msg.slice(0, 300) || undefined };
  }
}

/**
 * Lightweight startup health: import + pin + executable presence. No launch
 * (launch validation runs on first browser_create and is cached).
 * @param {{coreDir?: string, browsersDir?: string}} [options]
 */
export async function browserHealth(options = {}) {
  const rt = resolveBrowserRuntime();
  const coreDir = options.coreDir || rt.coreDir;
  const browsersDir = options.browsersDir || rt.browsersDir;
  let version = null;
  try {
    // SYN-BRW-002: read the version from package.json — NEVER import the
    // core here. Importing memoizes Playwright's browsers-dir registry from
    // the ambient env (unset this early in boot), which would then poison
    // every later launch in the process even after the env is set correctly.
    const pkg = readJsonFile(coreDir, 'package.json');
    version = pkg && typeof pkg.version === 'string' ? pkg.version : null;
    if (!version) throw new Error('BROWSER_RUNTIME_MISSING');
  } catch (e) {
    return {
      available: false,
      error:
        e && typeof e === 'object' && 'message' in e ? String(e.message) : 'BROWSER_NOT_AVAILABLE',
      playwright: null,
      revision: null,
      installed: []
    };
  }
  const revision = expectedChromiumRevision(coreDir);
  const installed = installedChromiumRevisions(browsersDir);
  if (!installed.includes(revision))
    return {
      available: false,
      error: 'BROWSER_INSTALLATION_MISSING',
      playwright: version,
      revision,
      installed
    };
  return { available: true, error: null, playwright: version, revision, installed };
}

/**
 * @param {string} p
 */
export function ensureDir(p) {
  try {
    fs.mkdirSync(p, { recursive: true, mode: 0o700 });
  } catch {}
  return p;
}
