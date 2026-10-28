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
  // L01a-5: bound on in-flight request-timing entries per context.
  maxPendingEntries: 500,
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
 * Required managed-Chromium artifacts, verified as files (never directory
 * names): the headless-shell executable that headless launches resolve and
 * the full-chromium executable headed launches resolve. `playwright install
 * chromium` downloads both sets as one unit, so a complete install satisfies
 * both and a partial set is never mistaken for an installed one (HHC-PC
 * 2026-10-17: a chromium-<rev> directory satisfied convergence while the
 * headless-shell artifact browser_* tools need was missing).
 * @param {{browsersDir?: string|null, revision?: string|null, platform?: string, arch?: string}} [options]
 */
export function managedBrowserArtifactStatus({
  browsersDir = null,
  revision = null,
  platform = process.platform,
  arch = process.arch
} = {}) {
  const headless = resolveChromiumExecutable({ browsersDir, revision, headless: true, platform, arch });
  const headed = resolveChromiumExecutable({ browsersDir, revision, headless: false, platform, arch });
  return {
    ok: headless.ok && headed.ok,
    headless: { ok: headless.ok, executablePath: headless.executablePath },
    headed: { ok: headed.ok, executablePath: headed.executablePath },
    tried: [...headless.tried, ...headed.tried]
  };
}

/**
 * @param {{base?: string|null, root?: string|null, dataDir?: string|null, env?: NodeJS.ProcessEnv}} [options]
 */
export function resolveBrowserRuntime(options = {}) {
  const env = options.env || process.env;
  // Callers that already hold the browser base dir (boot convergence, core
  // ensure) must resolve the SAME env-aware dirs as health/launch, or a
  // download lands where no launch ever reads it (HHC-PC 2026-10-17:
  // ensure reported installed:true while health reported
  // BROWSER_INSTALLATION_MISSING on an operator-set browsers dir).
  let base = options.base ? path.resolve(String(options.base)) : null;
  if (!base) {
    let data = options.dataDir || env.NC_BROWSER_DATA_DIR || null;
    if (!data) {
      try {
        data = ncLayout(options.root || undefined).data;
      } catch {
        data = null;
      }
    }
    if (!data) data = env.NC_BROWSER_DATA_DIR || path.join(os.tmpdir(), 'nc-browser');
    base = path.join(path.resolve(data), 'browser');
  }
  const runtime = path.join(base, 'browser-runtime');
  return Object.freeze({
    base,
    runtime,
    coreDir: env.NC_PLAYWRIGHT_CORE_PATH || path.join(runtime, 'playwright-core'),
    get browsersDir() { return env.PLAYWRIGHT_BROWSERS_PATH || path.join(base, 'playwright-browsers'); },
    stagingDir: path.join(base, 'playwright-browsers.staging'),
    profilesDir: path.join(base, 'profiles'),
    downloadsDir: path.join(base, 'downloads'),
    pin: BROWSER_RUNTIME_PIN
  });
}

const failedInstalledBrowsers = new Set();
const browserPreparation = new Map();
const convergenceRetries = new Map();

/** One preflight choice for launch, health and convergence; never a login probe.
 * @param {{coreDir?: string, browsersDir?: string, headless?: boolean, platform?: string, env?: NodeJS.ProcessEnv}} [options]
 */
export async function resolveBrowserProvider({ coreDir, browsersDir, headless = true, platform = process.platform, env = process.env } = {}) {
  const rt = resolveBrowserRuntime({ env });
  coreDir ||= rt.coreDir;
  browsersDir ||= rt.browsersDir;
  const operatorPath = Boolean(env.NC_PLAYWRIGHT_CORE_PATH) ||
    Boolean(env.PLAYWRIGHT_BROWSERS_PATH && !(env === process.env && env.PLAYWRIGHT_BROWSERS_PATH === managedBrowsersPath));
  if (!operatorPath && (platform === 'win32' || platform === 'darwin')) {
    const brand = platform === 'darwin' ? 'chrome' : env.NC_BROWSER_DEFAULT_BRAND;
    if (brand === 'chrome' || brand === 'edge') {
      // Lazy import avoids eager cycles through the existing adapter facade.
      const { findSystemBrowser } = await import('./browser-adapter.mjs');
      const installed = findSystemBrowser(brand, { platform, env });
      if (installed && !failedInstalledBrowsers.has(installed.path))
        return { ok: true, provider: installed.type, installed: true, executablePath: installed.path, tried: [installed.path] };
    }
  }
  return { ...resolveChromiumExecutable({ browsersDir, revision: expectedChromiumRevision(coreDir), headless }), provider: 'managed', installed: false };
}

/** Do not endlessly retry the same failed installed executable this process. */
export function rejectInstalledBrowser(executablePath) {
  failedInstalledBrowsers.add(executablePath);
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
  // Pin coupling (single source): the live core's declared chromium revision
  // must be the revision the runtime pin (and therefore every launch's
  // default executable resolution) expects. Otherwise health/gates check one
  // revision while launches resolve another.
  if (expectedChromiumRevision(coreDir) !== BROWSER_RUNTIME_PIN.chromiumRevision)
    throw new Error('BROWSER_REVISION_MISMATCH');
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
      // L01a-14: gate on the revision of the executable headless launches
      // actually resolve (chromium_headless_shell-<rev>), not just the
      // full-chromium dir — the old filter never matched headless-shell
      // dirs (`chromium_` does not match /^chromium-/).
      .filter((e) => e.isDirectory() && /^(chromium-|chromium_headless_shell-)/.test(e.name))
      .map((e) => e.name.replace(/^(chromium-|chromium_headless_shell-)/, ''));
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
 * @param {{pin?: string, pack?: ((dir: string, spec: string, timeoutMs?: number, env?: NodeJS.ProcessEnv) => Promise<{ok: boolean, file?: string, error?: string}>), timeoutMs?: number}} [options]
 */
export async function ensurePlaywrightCore(base, options = {}) {
  const pin = String(options.pin || BROWSER_RUNTIME_PIN.playwright || '');
  if (!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(pin))
    return { ok: false, error: 'INVALID_BROWSER_RUNTIME_VERSION' };
  // Same env-aware resolution as health/launch (see resolveBrowserRuntime).
  const coreDir = resolveBrowserRuntime({ base }).coreDir;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(coreDir, 'package.json'), 'utf8'));
    if (
      String(pkg?.name || '') === 'playwright-core' &&
      String(pkg?.version || '') === pin &&
      fs.existsSync(path.join(coreDir, 'cli.js')) &&
      (pin !== BROWSER_RUNTIME_PIN.playwright ||
        expectedChromiumRevision(coreDir) === BROWSER_RUNTIME_PIN.chromiumRevision)
    )
      return { ok: true, current: true, version: pin };
  } catch {}
  let tmp = null;
  let phase = 'prepare';
  try {
    const env = browserBootstrapEnv({ browsersDir: resolveBrowserRuntime({ base }).browsersDir });
    tmp = fs.mkdtempSync(path.join(env.TMPDIR, 'nc-pwcore-'));
    phase = 'pack';
    const pack = options.pack || defaultNpmPack;
    const packed = await pack(tmp, `playwright-core@${pin}`, options.timeoutMs, env);
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
    // The JS version and the chromium revision are ONE pin: a tarball whose
    // browsers.json revises away from the pin would strand every later
    // health/gate check on a revision no launch resolves. Custom pins
    // (explicit playwright version) cannot know a revision; only the
    // canonical pin is revision-coupled.
    if (
      pin === BROWSER_RUNTIME_PIN.playwright &&
      expectedChromiumRevision(extracted) !== BROWSER_RUNTIME_PIN.chromiumRevision
    )
      throw new Error('BROWSER_REVISION_MISMATCH');
    phase = 'promote';
    // L01a-11: rename live -> .prev before extracted -> live (mirror
    // activateStagedBrowserRuntime): the old rmrf-then-rename left no
    // rollback copy when the rename failed midway.
    const liveDir = path.join(base, 'browser-runtime');
    const prevDir = path.join(base, 'browser-runtime.prev');
    const managed = path.resolve(coreDir).startsWith(path.resolve(liveDir) + path.sep);
    const previous = managed ? prevDir : coreDir + '.prev';
    const active = managed ? liveDir : coreDir;
    let savedPrevious = false;
    try {
      // Recover an old interrupted placement before recycling its only copy.
      if (!fs.existsSync(active) && fs.existsSync(previous)) fs.renameSync(previous, active);
      rmrf(previous);
      if (managed) {
        if (fs.existsSync(liveDir)) { fs.renameSync(liveDir, prevDir); savedPrevious = true; }
        fs.mkdirSync(liveDir, { recursive: true });
      } else {
        // Operator-set core path: retain one rollback generation beside it.
        fs.mkdirSync(path.dirname(coreDir), { recursive: true });
        if (fs.existsSync(coreDir)) { fs.renameSync(coreDir, previous); savedPrevious = true; }
      }
      promoteDirectory(extracted, coreDir);
    } catch (error) {
      if (savedPrevious) {
        rmrf(active);
        try { fs.renameSync(previous, active); } catch {}
      }
      throw error;
    }
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
    if (tmp) rmrf(tmp);
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
 * @param {NodeJS.ProcessEnv} [env]
 */
function defaultNpmPack(dir, spec, timeoutMs, env) {
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
      { cwd: dir, env, timeout: Math.max(10000, Number(timeoutMs) || 300000), windowsHide: true },
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
 * Moves a directory into place across filesystem boundaries. rename(2) is
 * atomic but cannot cross devices: on Linux os.tmpdir() is commonly tmpfs
 * while the data tree is not, so the rename fails with EXDEV and every
 * runtime install died at promote (ubuntu live 2026-10-17). Fallback: copy
 * into a sibling temp dir on the DESTINATION filesystem and rename that
 * into place, so the visible promote stays atomic and a failed copy cleans
 * up after itself instead of exposing a half-populated directory.
 * @param {string} src
 * @param {string} dest
 */
function promoteDirectory(src, dest) {
  try {
    fs.renameSync(src, dest);
    return;
  } catch {
    const staging = `${dest}.incoming-${process.pid}`;
    rmrf(staging);
    try {
      fs.cpSync(src, staging, { recursive: true, force: true });
      fs.renameSync(staging, dest);
    } catch (error) {
      rmrf(staging);
      throw error;
    }
    rmrf(src);
  }
}

/**
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {Record<string, string>} [env]
 * @param {number} [timeoutMs]
 */
/**
 * L01a-12: exported for tests (buffer-cap regression pin).
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {Record<string, string|undefined>|undefined} env
 * @param {number} [timeoutMs]
 */
export function runCmd(cmd, args, env, timeoutMs = 600000) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      env: env || browserBootstrapEnv(),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true
    });
    let out = '';
    let err = '';
    // L01a-12: cap the running buffers per chunk (a chatty installer
    // previously grew these strings without bound until the close slice).
    const MAX_RUNCMD_BUF = 1024 * 1024;
    const push = (d, which) => {
      const text = String(d);
      if (!text) return;
      if (which === 0) {
        if (out.length < MAX_RUNCMD_BUF) out += text.slice(0, MAX_RUNCMD_BUF - out.length);
      } else if (err.length < MAX_RUNCMD_BUF) {
        err += text.slice(0, MAX_RUNCMD_BUF - err.length);
      }
    };
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {}
      resolve({ ok: false, out, err: (err + '\nINSTALL_TIMEOUT').slice(-2000) });
    }, timeoutMs);
    if (timer.unref) timer.unref();
    child.stdout.on('data', (d) => push(d, 0));
    child.stderr.on('data', (d) => push(d, 1));
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
  const prepared = [];
  const switched = [];
  try {
    fs.mkdirSync(browsersDir, { recursive: true });
    const staged = fs.readdirSync(stagingDir);
    for (const name of staged) {
      if (!/^(chromium|chromium_headless_shell|ffmpeg)-[0-9]+$/.test(name)) continue;
      const target = path.join(browsersDir, name);
      const incoming = `${target}.incoming-${process.pid}`;
      const entry = { target, incoming, prev: `${target}.prev`, hadPrevious: false };
      prepared.push(entry);
      rmrf(incoming);
      // Finish every copy on the destination filesystem before replacing
      // either half of the verified headed/headless artifact set.
      promoteDirectory(path.join(stagingDir, name), incoming);
    }
    for (const entry of prepared) {
      if (!fs.existsSync(entry.target) && fs.existsSync(entry.prev))
        fs.renameSync(entry.prev, entry.target);
      rmrf(entry.prev);
      entry.hadPrevious = fs.existsSync(entry.target);
      if (entry.hadPrevious) fs.renameSync(entry.target, entry.prev);
      switched.push(entry);
      fs.renameSync(entry.incoming, entry.target);
    }
    return { ok: prepared.length > 0, moved: prepared.length };
  } catch {
    for (const entry of switched.reverse()) {
      rmrf(entry.target);
      if (entry.hadPrevious) {
        try { fs.renameSync(entry.prev, entry.target); } catch {}
      }
    }
    return { ok: false, moved: 0 };
  } finally {
    for (const entry of prepared) {
      rmrf(entry.incoming);
      rmrf(`${entry.incoming}.incoming-${process.pid}`);
    }
  }
}

function browserPathsOverlap(a, b) {
  const windows = process.platform === 'win32';
  const api = windows ? path.win32 : path;
  const normalize = value => windows ? api.resolve(value).toLowerCase() : api.resolve(value);
  const left = normalize(a), right = normalize(b);
  const prefix = value => value.endsWith(api.sep) ? value : value + api.sep;
  return left === right || left.startsWith(prefix(right)) || right.startsWith(prefix(left));
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
  if (browserPathsOverlap(browsersDir, stagingDir))
    return { ok: false, error: 'BROWSER_INSTALLATION_MISSING', detail: 'active-staging-overlap' };
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
  let installed;
  try {
    installed = await runCmd(process.execPath, [cli, ...args],
      browserBootstrapEnv({ browsersDir: stagingDir }), options.timeoutMs || 600000);
  } catch (error) {
    rmrf(stagingDir);
    return { ok: false, error: 'BROWSER_INSTALLATION_MISSING', detail: String(error?.message || error) };
  }
  if (!installed.ok) {
    rmrf(stagingDir);
    return { ok: false, error: 'BROWSER_INSTALLATION_MISSING', detail: installed.err };
  }
  const staged = installedChromiumRevisions(stagingDir);
  if (!staged.includes(revision)) {
    rmrf(stagingDir);
    return { ok: false, error: 'BROWSER_VERSION_MISMATCH', detail: staged.join(',') };
  }
  // A revision directory name is not an artifact set: `install chromium`
  // downloads the headless shell and the full chromium together, and a
  // partial download must never pass as staged.
  if (!managedBrowserArtifactStatus({ browsersDir: stagingDir, revision }).ok) {
    rmrf(stagingDir);
    return { ok: false, error: 'BROWSER_INSTALLATION_MISSING', detail: 'staged-artifacts-incomplete' };
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
  applyBrowsersPathEnv(browsersDir);
  return { ok: true, revision, playwright: BROWSER_RUNTIME_PIN.playwright };
}

let managedBrowsersPath = null;

/**
 * Playwright resolves browsers via PLAYWRIGHT_BROWSERS_PATH at launch time.
 * The manager calls this once with the NC-managed dir; an operator-set
 * value is never overridden.
 * @param {string} browsersDir
 */
export function applyBrowsersPathEnv(browsersDir) {
  if (!process.env.PLAYWRIGHT_BROWSERS_PATH || process.env.PLAYWRIGHT_BROWSERS_PATH === managedBrowsersPath) {
    process.env.PLAYWRIGHT_BROWSERS_PATH = browsersDir;
    managedBrowsersPath = browsersDir;
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
    const bundledDir = path.join(appDir, 'browser-runtime');
    // No bundle in the payload is the normal shape today (runtimes come from
    // upstream npm): report it honestly instead of a fabricated pin-mismatch
    // (HHC-PC 2026-10-17 boot evidence).
    if (!fs.existsSync(bundledDir)) return { promoted: false, reason: 'absent' };
    const bundledCore = path.join(bundledDir, 'playwright-core');
    const bundledPkg = readJsonFile(bundledCore, 'package.json');
    // Pin acceptance covers BOTH halves of the coupled pin (JS version +
    // chromium revision), so a bundle built against a different browser
    // revision can never activate against this runtime pin.
    if (
      !bundledPkg ||
      String(bundledPkg.version || '') !== BROWSER_RUNTIME_PIN.playwright ||
      expectedChromiumRevision(bundledCore) !== BROWSER_RUNTIME_PIN.chromiumRevision
    )
      return { promoted: false, reason: 'pin-mismatch' };
    const liveCore = path.join(base, 'browser-runtime', 'playwright-core');
    const livePkg = readJsonFile(liveCore, 'package.json');
    if (
      livePkg &&
      String(livePkg.version || '') === BROWSER_RUNTIME_PIN.playwright &&
      expectedChromiumRevision(liveCore) === BROWSER_RUNTIME_PIN.chromiumRevision
    )
      return { promoted: false, reason: 'current' };
    const staged = path.join(base, 'browser-runtime.staging');
    rmrf(staged);
    fs.mkdirSync(staged, { recursive: true });
    for (const entry of fs.readdirSync(bundledDir)) {
      fs.cpSync(path.join(bundledDir, entry), path.join(staged, entry), { recursive: true });
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
export function ensureManagedBrowsers(base) {
  if (browserPreparation.has(base)) return browserPreparation.get(base);
  const pending = prepareManagedBrowsers(base).finally(() => browserPreparation.delete(base));
  browserPreparation.set(base, pending);
  return pending;
}

async function prepareManagedBrowsers(base) {
  try {
    // Env-aware resolution shared with health/launch (resolveBrowserRuntime):
    // an operator-set PLAYWRIGHT_BROWSERS_PATH or NC_PLAYWRIGHT_CORE_PATH
    // must steer convergence too, or the download lands where nothing reads
    // it (HHC-PC 2026-10-17: installed:true from ensure while health never
    // found the artifacts).
    const rt = resolveBrowserRuntime({ base });
    const browsersDir = rt.browsersDir;
    const coreDir = rt.coreDir;
    const revision = expectedChromiumRevision(coreDir);
    const provider = await resolveBrowserProvider({ coreDir, browsersDir });
    if (provider.installed) {
      if (!fs.existsSync(path.join(coreDir, 'cli.js')))
        return { installed: false, error: 'BROWSER_RUNTIME_MISSING', stage: 'preflight' };
      return { installed: true, revision, provider: provider.provider };
    }
    // Fast path only for a complete artifact set — the executable files
    // launches resolve, never just a revision directory name.
    if (managedBrowserArtifactStatus({ browsersDir, revision }).ok)
      return { installed: true, revision };
    if (!fs.existsSync(path.join(coreDir, 'cli.js')))
      return { installed: false, error: 'BROWSER_RUNTIME_MISSING', stage: 'preflight' };
    const staged = await stageBrowserInstall({
      coreDir,
      browsersDir,
      stagingDir: rt.stagingDir,
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
 * One structured JSON line for a runtime-install failure in the retry path.
 * console is the process log channel (client.mjs log() writes JSON lines and
 * mirrors them to the console), so the real cause stays findable — before
 * this, a swallowed EXDEV resurfaced only as the misleading preflight
 * BROWSER_RUNTIME_MISSING (ubuntu live 2026-10-17).
 * @param {{error: string, stage: string, detail?: string}} failure
 */
function logRuntimeInstallFailure(failure) {
  try {
    console.error(
      JSON.stringify({
        ts: new Date().toISOString(),
        level: 'error',
        message: 'browser_runtime_install_failed',
        error: failure.error,
        stage: failure.stage,
        detail: failure.detail
      })
    );
  } catch {}
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
 * The runtime install is never swallowed: a failure (returned or thrown)
 * is logged as browser_runtime_install_failed (error/stage/detail) and its
 * cause replaces the downstream preflight error on the reported result, so
 * the retry names the real cause (e.g. EXDEV) instead of a misleading
 * BROWSER_RUNTIME_MISSING.
 * @param {{base?: string|null, attempt?: number, validateFails?: number, onResult?: ((r: unknown) => unknown)|null, ensureCore?: ((base: string) => Promise<{ok?: unknown, error?: unknown, stage?: unknown, detail?: unknown}>), runAttempt?: ((work: () => Promise<void>) => unknown)}} [options]
 */
export function scheduleConvergenceRetry({
  base = null,
  attempt = 1,
  validateFails = 0,
  onResult = null,
  ensureCore = ensurePlaywrightCore,
  runAttempt = work => work()
} = {}) {
  if (!base) return null;
  if (convergenceRetries.has(base)) return convergenceRetries.get(base);
  const delay = convergenceRetryDelay(attempt);
  const timer = setTimeout(() => {
    const run = async () => {
      try {
        if (fs.existsSync(path.join(base, 'playwright-browsers.staging'))) {
          convergenceRetries.delete(base);
          return;
        }
        /** @type {{error: string, stage: string, detail?: string}|null} */
        let coreFailure = null;
        try {
          const core = await ensureCore(base);
          if (!core || core.ok !== true) {
            coreFailure = {
              error: String((core && core.error) || 'BROWSER_CORE_PACK_FAILED').slice(0, 300),
              stage: String((core && core.stage) || 'unknown'),
              detail: core && typeof core.detail === 'string' ? core.detail.slice(0, 300) : undefined
            };
          }
        } catch (error) {
          coreFailure = {
            error: (error instanceof Error ? error.message : String(error)).slice(0, 300),
            stage: 'unknown'
          };
        }
        if (coreFailure) logRuntimeInstallFailure(coreFailure);
        const managed = /** @type {{installed?: unknown, error?: unknown, stage?: unknown}} */ (
          await ensureManagedBrowsers(base)
        );
        // A missing runtime makes the downstream preflight report the
        // misleading BROWSER_RUNTIME_MISSING; the install failure is the
        // real cause, so it replaces error/stage on the reported result.
        const r =
          coreFailure && managed && managed.installed !== true
            ? {
                ...managed,
                error: coreFailure.error,
                stage: coreFailure.stage,
                runtime_install: coreFailure,
                note: 'BROWSER_RUNTIME_INSTALL_FAILED'
              }
            : managed;
        if (onResult) {
          try {
            await onResult(r);
          } catch {}
        }
        if (!r || r.installed === true) {
          convergenceRetries.delete(base);
          return;
        }
        const outcome = convergenceValidateOutcome({ stage: r.stage, validateFails });
        if (outcome.terminal) {
          convergenceRetries.set(base, null);
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
        convergenceRetries.delete(base);
        scheduleConvergenceRetry({
          base,
          attempt: attempt + 1,
          validateFails: outcome.fails,
          onResult,
          ensureCore,
          runAttempt
        });
      } catch { convergenceRetries.delete(base); }
    };
    // Agent-owned callers admit the entire attempt before either installer
    // starts, and keep it in the handoff drain until all shared-tree work ends.
    void (async () => runAttempt(run))().catch(() => {
      convergenceRetries.delete(base);
    }).finally(() => {
      if (convergenceRetries.get(base) === timer) convergenceRetries.delete(base);
    });
  }, delay);
  if (timer.unref) timer.unref();
  convergenceRetries.set(base, timer);
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
  // Nothing staged is a no-op, not a pin verdict: releases carry no
  // browser-runtime payload (npm convergence owns it), so every normal boot
  // lands here and must not log a fabricated pin-mismatch.
  if (!fs.existsSync(staged)) return { promoted: false, reason: 'absent' };
  const browsersDir = path.join(base, 'playwright-browsers');
  const stagingDir = path.join(base, 'playwright-browsers.staging');
  const selected = resolveBrowserRuntime({ base }).browsersDir;
  // A module-managed old staging selection can be repaired; an explicit
  // operator-selected active tree must never be consumed as disposable state.
  if (selected !== managedBrowsersPath &&
      (browserPathsOverlap(selected, stagingDir) || browserPathsOverlap(selected, staged)))
    return { promoted: false, reason: 'BROWSER_INSTALLATION_MISSING' };
  const stagedCore = path.join(staged, 'playwright-core');
  const pkg = readJsonFile(stagedCore, 'package.json');
  // Pin acceptance covers BOTH halves of the coupled pin: the Playwright JS
  // version and the chromium revision it resolves. A JS-only match could
  // otherwise activate a runtime whose browsers.json diverges from the pin.
  if (
    !pkg ||
    String(pkg.version || '') !== BROWSER_RUNTIME_PIN.playwright ||
    expectedChromiumRevision(stagedCore) !== BROWSER_RUNTIME_PIN.chromiumRevision
  ) {
    rmrf(staged);
    return { promoted: false, reason: 'pin-mismatch' };
  }
  const revision = expectedChromiumRevision(stagedCore);
  // Promote the JS first: it is what the health gate and all later steps
  // execute. Binaries follow opportunistically below.
  try {
    if (!fs.existsSync(live) && fs.existsSync(prev)) fs.renameSync(prev, live);
    rmrf(prev);
    if (fs.existsSync(live)) fs.renameSync(live, prev);
    fs.renameSync(staged, live);
  } catch {
    if (!fs.existsSync(live) && fs.existsSync(prev)) {
      try { fs.renameSync(prev, live); } catch {}
    }
    return { promoted: false, reason: 'BROWSER_INTERNAL_ERROR' };
  }
  cachedCore = null;
  cachedCoreKey = null;
  // Binaries: live already has them, or staging validated them, or they
  // converge later via ensureManagedBrowsers (never a promotion blocker).
  let browsers = 'absent';
  try {
    if (managedBrowserArtifactStatus({ browsersDir, revision }).ok) {
      browsers = 'live';
    } else if (managedBrowserArtifactStatus({ browsersDir: stagingDir, revision }).ok) {
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
  const effective = applyBrowsersPathEnv(browsersDir);
  if (effective !== browsersDir) {
    const probe = await validateBrowserLaunch({ coreDir: resolveBrowserRuntime({ base }).coreDir,
      browsersDir: effective, headless: true, timeoutMs: 60000 });
    browsers = probe.ok && managedBrowserArtifactStatus({ browsersDir: effective, revision }).ok
      ? 'live' : probe.error || 'BROWSER_INSTALLATION_MISSING';
  }
  return { promoted: true, playwright: BROWSER_RUNTIME_PIN.playwright, revision, browsers };
}

/**
 * Managed browser HOME dirs created by resolveBrowserServiceHome below.
 * Removed on process exit (L06-8: mkdtemp dirs must not accumulate across
 * restarts when the ambient HOME stays unwritable).
 */
const managedBrowserHomes = new Map();
let browserHomeExitHooked = false;
function trackManagedBrowserHome(dir, parentDir) {
  managedBrowserHomes.set(String(dir), parentDir);
  if (!browserHomeExitHooked) {
    browserHomeExitHooked = true;
    try {
      process.once('exit', () => {
        for (const dir of managedBrowserHomes.keys()) {
          try {
            fs.rmSync(dir, { recursive: true, force: true });
          } catch {}
        }
        managedBrowserHomes.clear();
      });
    } catch {}
  }
}
/**
 * Service-user browser HOME (SYN-BRW-004). Chromium CHECK-traps (SIGILL,
 * empty stderr, "browser has been closed") when the daemon user's HOME is
 * missing or unwritable — e.g. macOS `_nc` whose NFSHomeDirectory is
 * /var/empty. Healthy hosts keep their ambient HOME untouched; only an
 * unwritable HOME falls back to a managed 0700 dir under the data tree.
 *
 * L06-8: the ambient HOME is lstat-verified before use — a symlink (plant
 * redirecting Chromium profiles/cache outside the owner's tree) or a
 * foreign-UID directory fails closed with BROWSER_HOME_SECURITY_VIOLATION,
 * UNLESS it is the standard install layout (foreign uid, but the directory
 * belongs to the agent's PRIMARY GROUP and is neither group- nor
 * other-writable — root:_nc 0750). A missing HOME still falls back to a
 * managed dir; managed dirs are reused while valid and removed on exit.
 * @param {{browsersDir?: string|null, home?: string}} [options]
 */
export function resolveBrowserServiceHome({ browsersDir = null, home = undefined } = {}) {
  const ambient = home === undefined ? process.env.HOME : home;
  if (typeof ambient === 'string' && ambient) {
    assertBrowserStateAncestry(ambient);
    // L06-8: lstat (never stat — a symlink must be seen, not followed).
    let lst = null;
    try {
      lst = fs.lstatSync(ambient);
    } catch (e) {
      // Missing HOME (ENOENT) falls through to the managed fallback
      // below; any other lstat failure fails closed — an indeterminable
      // HOME is not trusted.
      if (!e || typeof e !== 'object' || /** @type {{code?: unknown}} */ (e).code !== 'ENOENT')
        throw new Error('BROWSER_HOME_SECURITY_VIOLATION', { cause: e });
    }
    if (lst) {
      if (lst.isSymbolicLink() || !lst.isDirectory()) throw new Error('BROWSER_HOME_SECURITY_VIOLATION');
      if (typeof process.getuid === 'function' && lst.uid !== process.getuid()) {
        // Install-layout exemption (ubuntu live 2026-10-17): the standard
        // tree root (/opt/nc) is root:_nc 0750 — a foreign uid owned by the
        // agent's PRIMARY GROUP with no group/other write bit. Only root
        // can plant entries there, and the threat model is a foreign-USER
        // plant, so the layout is trusted; the W_OK check below still
        // decides usability (the tree root is intentionally not writable
        // for the service user → managed fallback). Group/other-writable or
        // foreign-group owners still fail closed.
        const primaryGid = typeof process.getgid === 'function' ? process.getgid() : null;
        const trustedLayout =
          primaryGid !== null && lst.gid === primaryGid && (lst.mode & 0o022) === 0;
        if (!trustedLayout) throw new Error('BROWSER_HOME_SECURITY_VIOLATION');
      }
      try {
        fs.accessSync(ambient, fs.constants.W_OK);
        return { home: ambient, managed: false };
      } catch {}
    }
  }
  // Reuse a still-valid managed dir instead of mkdtemp-ing a new one per
  // call (bounds accumulation when the ambient HOME stays unwritable).
  const layout = ncLayout();
  const parentDir = path.resolve(browsersDir ? path.dirname(String(browsersDir))
    : (layout?.data && fs.existsSync(layout.data) ? layout.data : os.tmpdir()));
  assertBrowserStateAncestry(parentDir, true);
  for (const [existing, parent] of managedBrowserHomes) {
    if (parent !== parentDir) continue;
    try {
      const st = fs.lstatSync(existing);
      if (st.isSymbolicLink()) continue;
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) continue;
      if (!st.isDirectory()) continue;
      if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) continue;
      fs.accessSync(existing, fs.constants.W_OK);
      return { home: existing, managed: true };
    } catch {
      try {
        managedBrowserHomes.delete(existing);
      } catch {}
    }
  }
  fs.mkdirSync(parentDir, { recursive: true, mode: 0o700 });
  if (typeof process.getuid === 'function') {
    const parent = fs.lstatSync(parentDir);
    const systemTemp = parent.uid === 0 && (parent.mode & 0o1000) !== 0;
    if (parent.uid !== process.getuid() && !systemTemp)
      throw new Error('BROWSER_HOME_SECURITY_VIOLATION');
  }
  const prefix = path.join(parentDir, 'nc-browser-home-');
  const managed = fs.mkdtempSync(prefix);
  const st = fs.lstatSync(managed);
  if (st.isSymbolicLink()) {
    throw new Error('BROWSER_HOME_SECURITY_VIOLATION');
  }
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new Error('BROWSER_HOME_SECURITY_VIOLATION');
  }
  try {
    fs.chmodSync(managed, 0o700);
  } catch {}
  trackManagedBrowserHome(managed, parentDir);
  return { home: managed, managed: true };
}

/**
 * Current-user child environment shared with acquisition/install: verified
 * HOME and private writable cache/temp. The daemon environment is unchanged.
 * @param {{browsersDir?: string|null}} [options]
 */
export function browserLaunchEnv({ browsersDir = null } = {}) {
  return browserBootstrapEnv({ browsersDir });
}

// State must not traverse a user-planted link or writable foreign ancestor.
function assertBrowserStateAncestry(dir, includeLeaf = false) {
  const target = path.resolve(dir);
  let current = includeLeaf ? target : path.dirname(target);
  for (;;) {
    let st;
    try { st = fs.lstatSync(current); } catch (error) {
      if (error.code !== 'ENOENT') throw new Error('BROWSER_HOME_SECURITY_VIOLATION', { cause: error });
    }
    if (st) {
      const systemAlias = process.platform === 'darwin' && current !== target &&
        ['/var', '/tmp', '/etc'].includes(current) && st.uid === 0;
      if ((st.isSymbolicLink() || !st.isDirectory()) && !systemAlias)
        throw new Error('BROWSER_HOME_SECURITY_VIOLATION');
      if (typeof process.getuid === 'function' && !systemAlias) {
        const systemTemp = st.uid === 0 && (st.mode & 0o1000) !== 0;
        if ((st.uid !== process.getuid() && st.uid !== 0) || ((st.mode & 0o022) !== 0 && !systemTemp))
          throw new Error('BROWSER_HOME_SECURITY_VIOLATION');
      }
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

function browserStateDirectory(dir, create = false) {
  assertBrowserStateAncestry(dir);
  let st;
  try { st = fs.lstatSync(dir); } catch (error) {
    if (error.code !== 'ENOENT') throw new Error('BROWSER_HOME_SECURITY_VIOLATION', { cause: error });
    if (!create) return;
    fs.mkdirSync(dir, { mode: 0o700 });
    st = fs.lstatSync(dir);
  }
  if (st.isSymbolicLink() || !st.isDirectory() ||
      (typeof process.getuid === 'function' && st.uid !== process.getuid()) ||
      (create && process.platform !== 'win32' && (st.mode & 0o077) !== 0))
    throw new Error('BROWSER_HOME_SECURITY_VIOLATION');
  try { fs.accessSync(dir, fs.constants.W_OK); } catch (error) {
    if (create) throw new Error('BROWSER_HOME_SECURITY_VIOLATION', { cause: error });
  }
}

/** Current-user child state only; no daemon environment mutation or OS elevation.
 * @param {{browsersDir?: string|null}} [options]
 */
function browserBootstrapEnv({ browsersDir = null } = {}) {
  const { home } = resolveBrowserServiceHome({ browsersDir });
  for (const key of ['npm_config_cache', 'NPM_CONFIG_CACHE']) {
    if (process.env[key]) browserStateDirectory(path.resolve(process.env[key]));
  }
  const state = path.join(home, '.nc-browser-bootstrap');
  const cache = path.join(state, 'npm-cache');
  const temp = path.join(state, 'tmp');
  for (const dir of [state, cache, temp]) browserStateDirectory(dir, true);
  // Keep platform/display/proxy/CA settings, not daemon credentials or Node
  // loader/npm configuration injection. This is not a helper identity boundary.
  const allowed = /^(PATH|Path|PATHEXT|SystemRoot|SYSTEMROOT|WINDIR|ComSpec|COMSPEC|LANG|LANGUAGE|LC_[A-Z_]+|TZ|DISPLAY|WAYLAND_DISPLAY|XAUTHORITY|XDG_RUNTIME_DIR|SSL_CERT_FILE|SSL_CERT_DIR|NODE_EXTRA_CA_CERTS|HTTPS?_PROXY|ALL_PROXY|NO_PROXY|https?_proxy|all_proxy|no_proxy|PLAYWRIGHT_DOWNLOAD_HOST|PLAYWRIGHT_CHROMIUM_DOWNLOAD_HOST|PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT)$/;
  const child = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (allowed.test(key) && typeof value === 'string') child[key] = value;
  }
  return { ...child, HOME: home, USERPROFILE: home, npm_config_cache: cache,
    TMPDIR: temp, TMP: temp, TEMP: temp, XDG_CACHE_HOME: state,
    ...(browsersDir ? { PLAYWRIGHT_BROWSERS_PATH: browsersDir } : {}) };
}

/**
 * Launch validation: blank page open + title read + clean close.
 * Uses explicit executable resolution (same determinism rationale as the
 * manager: never trust registry memoization for validation verdicts).
 * @param {{coreDir: string, browsersDir: string, headless?: boolean, timeoutMs?: number}} options
 */
export async function validateBrowserLaunch(options) {
  const started = Date.now();
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
 * @param {{coreDir?: string, browsersDir?: string, platform?: string, env?: NodeJS.ProcessEnv}} [options]
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
  const selected = await resolveBrowserProvider({ coreDir, browsersDir, platform: options.platform, env: options.env });
  if (selected.installed)
    return { available: true, error: null, playwright: version, revision, installed, provider: selected.provider };
  // Health is the capability gate for browser_* tools: it must verify the
  // executable artifacts a launch actually resolves (headless shell AND full
  // chromium), never a revision directory name. HHC-PC 2026-10-17: a
  // chromium-<rev> dir satisfied the old name check while the headless-shell
  // artifact was missing, so tools were gated on a set that cannot launch.
  const artifacts = managedBrowserArtifactStatus({ browsersDir, revision });
  if (!artifacts.ok)
    return {
      available: false,
      error: 'BROWSER_INSTALLATION_MISSING',
      playwright: version,
      revision,
      installed,
      artifacts
    };
  return { available: true, error: null, playwright: version, revision, installed, artifacts };
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
