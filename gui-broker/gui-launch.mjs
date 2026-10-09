import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { spawn, execFileSync } from 'node:child_process';
import { ncLayout } from '../src/client/nc-paths.mjs';
import { validateEgressUrl } from '../src/policy/egress-policy.mjs';
import { policyFromJob } from '../src/browser/browser-manager.mjs';

/**
 * Synchronous broker-presence probe for capability advertisement: true
 * when at least one broker heartbeat file is fresh (<10s, same window as
 * liveBrokers). Sync so sessionHello can consult it without restructuring.
 * @param {{data?: string}} [layout]
 */
export function hasLiveBrokers(layout = ncLayout()) {
  try {
    if (process.platform !== 'win32') return false;
    const dir = path.join(String(layout?.data || ''), 'gui-brokers');
    const rows = fsSync.readdirSync(dir).filter((x) => x.endsWith('.json'));
    const now = Date.now();
    for (const name of rows) {
      try {
        const b = JSON.parse(fsSync.readFileSync(path.join(dir, name), 'utf8'));
        const ts = Date.parse(b.last_seen || '');
        if (Number.isFinite(ts) && now - ts <= 10000) return true;
      } catch {}
    }
    return false;
  } catch {
    return false;
  }
}

const APPS = new Set([
  'default_browser',
  'edge',
  'chrome',
  'explorer',
  'notepad',
  'code',
  'cursor',
  'terminal'
]);
/**
 * Broker-reported executable stems for PID re-correlation (win32 only).
 * default_browser launches an unknown browser; terminal may be wt.exe or a
 * fallback powershell shared with unrelated processes — both are skipped to
 * avoid attributing a foreign PID.
 */
const GUI_EXE_BY_APP = Object.freeze({
  edge: ['msedge'],
  chrome: ['chrome'],
  explorer: ['explorer'],
  notepad: ['notepad'],
  code: ['Code'],
  cursor: ['Cursor']
});
/**
 * POSIX exe-stem map for re-correlation (see resolveGuiPidPosix). Only apps
 * whose process is unambiguous are listed: terminal spawns shells shared
 * with unrelated processes, default_browser/explorer open unknown targets,
 * and linux notepad goes through xdg-open with an unknown target — the same
 * skip-ambiguous rationale as GUI_EXE_BY_APP above. Matched against the full
 * command line (macOS truncates comm to 16 chars).
 */
const GUI_EXE_BY_APP_POSIX = Object.freeze({
  darwin: Object.freeze({
    notepad: ['TextEdit'],
    code: ['Visual Studio Code'],
    cursor: ['Cursor'],
    edge: ['Microsoft Edge'],
    chrome: ['Google Chrome']
  }),
  linux: Object.freeze({
    code: ['/code', 'code --'],
    cursor: ['/cursor', 'cursor --'],
    edge: ['microsoft-edge', 'msedge'],
    chrome: ['google-chrome', '/chrome', 'chromium']
  })
});
// Re-correlation slop: a same-name process that started more than this
// before our launch is never attributed to us (close must not kill a
// pre-existing user instance on single-instance handoff). Kept >= 65s:
// the phase16 L1 regression test pins attribution at launchedAt+60s.
const GUI_RECORRELATE_SLOP_MS = 120000;
/**
 * @typedef {object} GuiNetworkPolicy
 * @property {boolean} [allowPrivateNetwork]
 * @property {boolean} [allowLoopback]
 * @property {Array<string>} [allowedHosts]
 * @property {Array<string>} [blockedHosts]
 */
/** @typedef {ReturnType<typeof import('../src/client/nc-paths.mjs').ncLayout>} NcLayout */
/**
 * Egress gate for browser URL opens (parity with browser_navigate): a
 * scheme check alone lets the model aim the user/browser context at
 * internal targets (cloud metadata, LAN). Uses the same centrally-curated
 * network policy the browser tools see. Fail-closed on DNS failure.
 * @param {string} target @param {unknown} job
 */
async function checkGuiUrlEgress(target, job) {
  /** @type {GuiNetworkPolicy} */
  let network = {};
  try {
    const fromJob = policyFromJob(job)?.network;
    network = fromJob && typeof fromJob === 'object' ? fromJob : {};
  } catch {}
  const net = network;
  try {
    const verdict = await validateEgressUrl(String(target), {
      allowPrivateNetwork: net.allowPrivateNetwork === true,
      allowLoopback: net.allowLoopback === true,
      allowedHosts: Array.isArray(net.allowedHosts) ? net.allowedHosts : [],
      blockedHosts: Array.isArray(net.blockedHosts) ? net.blockedHosts : [],
      resolve: async (hostname) => {
        const records = await dns.lookup(hostname, { all: true, verbatim: true });
        return records.map((r) => r.address);
      }
    });
    if (!verdict.ok) throw new Error('GUI_URL_EGRESS_DENIED');
  } catch (e) {
    if (e instanceof Error && e.message === 'GUI_URL_EGRESS_DENIED') throw e;
    throw new Error('GUI_URL_EGRESS_DENIED', { cause: e });
  }
}
/**
 * Re-correlate a broker-reported GUI PID (win32 only). Single-instance and
 * Store-packaged apps (Win11 Notepad, browsers) often exit the spawned
 * launcher and activate another process, leaving a stale PID behind. When
 * the reported PID is dead, fall back to the newest same-name process;
 * otherwise (or off Windows) the broker value is returned untouched.
 * With launchedAtMs given, candidates that started before launch (minus
 * slop) never qualify, so close cannot kill a pre-existing user instance
 * on single-instance handoff.
 * @param {string} app
 * @param {unknown} pid
 * @param {string} [platform]
 * @param {number} [launchedAtMs]
 */
export async function resolveGuiPid(app, pid, platform = process.platform, launchedAtMs = 0) {
  const id = Number(pid);
  if (platform !== 'win32') return Number.isInteger(id) && id > 0 ? id : null;
  const names = /** @type {Record<string, Array<string>>} */ (GUI_EXE_BY_APP)[app];
  try {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const run = promisify(execFile);
    const ps = async (/** @type {string} */ script) => {
      const { stdout } = await run(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command', script],
        { timeout: 15000, windowsHide: true }
      );
      return String(stdout || '').trim();
    };
    if (Number.isInteger(id) && id > 0) {
      const probe = await ps(
        `$p = Get-Process -Id ${id} -ErrorAction SilentlyContinue; if ($p) { 'ALIVE' } else { 'DEAD' }`
      );
      if (probe.includes('ALIVE')) return id;
    }
    if (!names) return Number.isInteger(id) && id > 0 ? id : null;
    const floorMs = Number(launchedAtMs) || 0;
    const floorClause =
      floorMs > 0
        ? `| Where-Object { try { $_.StartTime -ge ([DateTime]'${new Date(floorMs - GUI_RECORRELATE_SLOP_MS).toISOString()}') } catch { $false } } `
        : '';
    const found = await ps(
      `$c = Get-Process -Name ${names.join(',')} -ErrorAction SilentlyContinue ${floorClause}| Sort-Object StartTime -Descending | Select-Object -First 1; if ($c) { $c.Id } else { '' }`
    );
    const remapped = Number(found);
    if (Number.isInteger(remapped) && remapped > 0) return remapped;
  } catch {}
  return Number.isInteger(id) && id > 0 ? id : null;
}
/**
 * Parse `ps -Ao pid=,etime=,args=` output into rows. etime shapes:
 * mm:ss, hh:mm:ss, dd-hh:mm:ss (both GNU and BSD ps).
 * @param {unknown} stdout
 * @param {number} [nowMs]
 * @returns {Array<{pid: number, startedAtMs: number, command: string}>}
 */
export function parsePsList(stdout, nowMs = Date.now()) {
  const rows = [];
  for (const line of String(stdout || '').split('\n')) {
    const m = /^\s*(\d+)\s+((?:(\d+)-)?(\d+):(\d+)(?::(\d+))?)\s+(\S.*)?$/.exec(line);
    if (!m) continue;
    const pid = Number(m[1]);
    if (!Number.isInteger(pid) || pid <= 0) continue;
    let elapsed;
    if (m[6] !== undefined) {
      elapsed = Number(m[3] || 0) * 86400 + Number(m[4]) * 3600 + Number(m[5]) * 60 + Number(m[6]);
    } else {
      elapsed = Number(m[4]) * 60 + Number(m[5]);
    }
    if (!Number.isFinite(elapsed) || elapsed < 0) continue;
    rows.push({ pid, startedAtMs: nowMs - elapsed * 1000, command: String(m[7] || '') });
  }
  return rows;
}
/**
 * Newest row whose command contains a stem (case-insensitive) and that
 * started at/after launch (slop-tolerant). The launch-time guard keeps close
 * from killing a pre-existing user instance (e.g. a days-old browser) when
 * the launcher stub already exited.
 * @param {Array<{pid: number, startedAtMs: number, command: string}>} rows
 * @param {Array<string>} stems
 * @param {number} launchedAtMs
 * @param {number} [slopMs]
 * @returns {{pid: number, startedAtMs: number, command: string}|null}
 */
export function selectGuiCandidate(rows, stems, launchedAtMs, slopMs = GUI_RECORRELATE_SLOP_MS) {
  if (!Array.isArray(stems) || stems.length === 0) return null;
  const floor = Number(launchedAtMs) - slopMs;
  let best = null;
  for (const row of rows || []) {
    if (!row || !Number.isInteger(row.pid) || row.pid <= 0) continue;
    if (!(Number(row.startedAtMs) >= floor)) continue;
    const cmd = String(row.command || '').toLowerCase();
    if (!stems.some((s) => cmd.includes(String(s).toLowerCase()))) continue;
    if (!best || row.startedAtMs >= best.startedAtMs) best = row;
  }
  return best;
}
/**
 * Re-correlate a POSIX launcher-stub PID to the real app process (mirrors
 * resolveGuiPid for win32). launchers (/usr/bin/open, xdg-open, editor CLIs)
 * exit right after handoff, so the tracked PID is usually dead at close
 * time. When the stub is alive it is returned untouched; when dead, the
 * newest same-name process started at/after launch wins; anything else
 * falls back to the stub PID (close then fails as before, never touches a
 * foreign process it cannot attribute).
 * @param {string} app
 * @param {unknown} pid
 * @param {string} [platform]
 * @param {number} [launchedAtMs]
 * @param {() => Promise<string>} [runPs]
 * @returns {Promise<number|null>}
 */
export async function resolveGuiPidPosix(
  app,
  pid,
  platform = process.platform,
  launchedAtMs = 0,
  runPs = null
) {
  const id = Number(pid);
  const valid = Number.isInteger(id) && id > 0 ? id : null;
  const run = runPs || (async () => {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const { stdout } = await promisify(execFile)('ps', ['-Ao', 'pid=,etime=,args='], {
      timeout: 15000,
      windowsHide: true
    });
    return String(stdout || '');
  });
  try {
    if (valid !== null) {
      try {
        process.kill(valid, 0);
        return valid;
      } catch {}
    }
  } catch {}
  const stems =
    /** @type {Record<string, Record<string, Array<string>>>} */ (GUI_EXE_BY_APP_POSIX)[
      platform
    ]?.[app];
  if (!stems) return valid;
  try {
    const found = selectGuiCandidate(
      parsePsList(await run()),
      stems,
      Number(launchedAtMs) || 0
    );
    if (found) return found.pid;
  } catch {}
  return valid;
}
/**
 * @param {unknown} result_payload
 */
const ok = (result_payload) => ({
  status: 'completed',
  exit_code: 0,
  stdout: '',
  stderr: '',
  error: null,
  duration_ms: 0,
  result_payload
});
/**
 * @param {unknown} error
 */
const fail = (error) => ({
  status: 'failed',
  exit_code: null,
  stdout: '',
  stderr: '',
  error: String(error),
  duration_ms: 0,
  result_payload: {}
});
/**
 * @param {number} ms
 */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/**
 * @param {unknown} text
 */
const parseJsonText = (text) => JSON.parse(String(text).replace(/^\uFEFF/, ''));

/**
 * PIDs this agent incarnation launched via gui_launch (pid -> {at, app}).
 * gui_close only accepts these: closing foreign PIDs would exceed the
 * granted privilege (launch allowlisted apps, not manage the session).
 * The app tag enables POSIX re-correlation when the launcher stub already
 * exited (see resolveGuiPidPosix).
 */
const launchedGuiPids = /** @type {Map<number, {at: number, app: string}>} */ (new Map());
const LAUNCHED_PID_TTL_MS = 24 * 60 * 60 * 1000;
const LAUNCHED_PID_MAX = 1000;
/** @param {unknown} pid @param {unknown} [app] */
function trackLaunchedGuiPid(pid, app = '') {
  const id = Number(pid);
  if (!Number.isInteger(id) || id <= 0) return;
  launchedGuiPids.set(id, { at: Date.now(), app: String(app || '') });
  if (launchedGuiPids.size > LAUNCHED_PID_MAX) {
    const oldest = [...launchedGuiPids.entries()].sort(
      (/** @type {[number, {at: number}]} */ a, /** @type {[number, {at: number}]} */ b) =>
        a[1].at - b[1].at
    )[0];
    if (oldest) launchedGuiPids.delete(oldest[0]);
  }
}
/** @param {unknown} pid */
function untrackLaunchedGuiPid(pid) {
  launchedGuiPids.delete(Number(pid));
}
/** @param {unknown} pid */
function isLaunchedGuiPid(pid) {
  const id = Number(pid);
  if (!Number.isInteger(id) || id <= 0) return false;
  const rec = launchedGuiPids.get(id);
  if (rec === undefined) return false;
  if (Date.now() - rec.at > LAUNCHED_PID_TTL_MS) {
    launchedGuiPids.delete(id);
    return false;
  }
  return true;
}
/** @param {unknown} pid @returns {{at: number, app: string}|null} */
function launchedGuiRecord(pid) {
  if (!isLaunchedGuiPid(pid)) return null;
  return launchedGuiPids.get(Number(pid)) || null;
}
/**
 * @param {string} app
 * @param {unknown} target
 */
function cleanTarget(app, target) {
  const value = String(target || '').trim();
  if (['default_browser', 'edge', 'chrome'].includes(app)) {
    if (!value) throw new Error('GUI_URL_REQUIRED');
    const u = new URL(value);
    if (!['http:', 'https:'].includes(u.protocol)) throw new Error('GUI_URL_SCHEME_NOT_ALLOWED');
    return u.toString();
  }
  if (app === 'explorer' && value.length > 4096) throw new Error('GUI_TARGET_TOO_LONG');
  return value;
}

/**
 * Direct-launch spec for POSIX platforms (no broker: the agent itself runs in
 * the user's graphical context on LaunchAgent/systemd-user hosts). Pure:
 * returns [cmd, args]. Throws GUI_* errors for unknown apps, missing targets,
 * or headless Linux (no DISPLAY/WAYLAND_DISPLAY).
 * @param {string} app
 * @param {string} [target]
 * @param {string} [platform]
 * @returns {{cmd: string, args: Array<string>}}
 */
export function posixLaunchSpec(app, target = '', platform = process.platform) {
  if (!APPS.has(app)) throw new Error('GUI_APPLICATION_NOT_ALLOWED');
  const t = cleanTarget(app, target);
  if (platform === 'darwin') {
    const open = ['/usr/bin/open'];
    switch (app) {
      case 'default_browser':
        return { cmd: open[0], args: [t] };
      case 'edge':
        return { cmd: open[0], args: ['-a', 'Microsoft Edge', t] };
      case 'chrome':
        return { cmd: open[0], args: ['-a', 'Google Chrome', t] };
      case 'explorer':
        return { cmd: open[0], args: [t || '/'] };
      case 'notepad':
        return { cmd: open[0], args: ['-a', 'TextEdit', ...(t ? [t] : [])] };
      case 'code':
        return { cmd: open[0], args: ['-a', 'Visual Studio Code', ...(t ? [t] : [])] };
      case 'cursor':
        return { cmd: open[0], args: ['-a', 'Cursor', ...(t ? [t] : [])] };
      case 'terminal':
        return { cmd: open[0], args: ['-a', 'Terminal'] };
      default:
        throw new Error('GUI_APPLICATION_NOT_ALLOWED');
    }
  }
  if (platform === 'linux') {
    if (!process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) throw new Error('GUI_NO_DISPLAY');
    switch (app) {
      case 'default_browser':
      case 'explorer':
        return { cmd: 'xdg-open', args: [t || process.env.HOME || '/'] };
      case 'notepad':
        return { cmd: 'xdg-open', args: [t || process.env.HOME || '/'] };
      case 'edge':
        return { cmd: 'microsoft-edge', args: [t] };
      case 'chrome':
        return { cmd: 'google-chrome', args: [t] };
      case 'code':
        return { cmd: 'code', args: t ? [t] : [] };
      case 'cursor':
        return { cmd: 'cursor', args: t ? [t] : [] };
      case 'terminal':
        return { cmd: 'x-terminal-emulator', args: [] };
      default:
        throw new Error('GUI_APPLICATION_NOT_ALLOWED');
    }
  }
  throw new Error('GUI_PLATFORM_UNSUPPORTED');
}
/**
 * @param {NcLayout} layout
 * @param {string} username
 */
async function liveBrokers(layout, username) {
  const dir = path.join(layout.data, 'gui-brokers');
  let rows = [];
  try {
    rows = await fs.readdir(dir);
  } catch {
    return [];
  }
  const now = Date.now(),
    out = [];
  for (const name of rows.filter((x) => x.endsWith('.json'))) {
    try {
      const b = parseJsonText(await fs.readFile(path.join(dir, name), 'utf8'));
      const ts = Date.parse(b.last_seen || '');
      if (!Number.isFinite(ts) || now - ts > 10000) continue;
      if (username && String(b.username || '').toLowerCase() !== username.toLowerCase()) continue;
      out.push(b);
    } catch {}
  }
  return out.sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));
}

/**
 * Console owner on macOS (`stat -f %Su /dev/console`, the same source the
 * installer uses to find the operator). A real GUI session has a non-root
 * login owner; headless Macs (CI, cloud VMs, pre-login LaunchDaemons)
 * show root/empty and cannot show windows.
 * @param {(cmd: string, args: Array<string>, options?: unknown) => unknown} [execSync]
 * @returns {string|null} owner name, or null when undeterminable
 */
export function getDarwinConsoleUser(execSync = execFileSync) {
  try {
    const out = execSync('stat', ['-f', '%Su', '/dev/console'], {
      encoding: 'utf8',
      timeout: 5000,
      windowsHide: true
    });
    const owner = String(out || '').trim();
    return owner || null;
  } catch {
    return null;
  }
}

/**
 * Whether macOS currently has a GUI-capable console session.
 * @param {object} [options]
 * @param {string|null} [options.consoleUser] injected owner (tests / cached probe)
 * @param {(cmd: string, args: Array<string>, options?: unknown) => unknown} [options.execSync]
 */
export function darwinGuiSessionAvailable({ consoleUser = undefined, execSync } = {}) {
  const owner = consoleUser !== undefined ? consoleUser : getDarwinConsoleUser(execSync);
  return Boolean(owner) && owner !== 'root';
}

/**
 * Whether this host can show GUI windows right now: win32 needs a live
 * session broker, darwin needs a real console session (not root/empty),
 * linux needs an X11/Wayland session. Consulted by capability
 * advertisement so hosts never advertise what would fail at call time.
 * @param {string} [platform]
 * @param {Record<string, string|undefined>} [env]
 * @param {{hasBrokers?: boolean, consoleSession?: boolean, consoleUser?: string|null}} [options]
 */
export function hasGuiDisplay(platform = process.platform, env = process.env, options = {}) {
  if (platform === 'win32') return options.hasBrokers === true;
  if (platform === 'darwin') {
    // Cached probe verdict wins (no per-call fork); otherwise check live so
    // the very first advertisement stays truthful.
    if (typeof options.consoleSession === 'boolean') return options.consoleSession;
    if (options.consoleUser !== undefined)
      return darwinGuiSessionAvailable({ consoleUser: options.consoleUser });
    return darwinGuiSessionAvailable({});
  }
  if (platform === 'linux') return Boolean(env.DISPLAY || env.WAYLAND_DISPLAY);
  return false;
}

/**
 * Spawn a GUI app visibly and detached. Resolves with the child PID;
 * rejects with GUI_APP_NOT_FOUND when the executable is missing.
 * @param {string} cmd
 * @param {Array<string>} args
 */
function spawnGuiApp(cmd, args) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      // WIN-HIDE-EXEMPT: the launched app itself must be visible (product
      // behavior); only this line may spawn without windowsHide.
      child = spawn(cmd, args, { detached: true, stdio: 'ignore' });
    } catch (e) {
      reject(new Error('GUI_APP_NOT_FOUND'));
      return;
    }
    child.once('error', (e) =>
      reject(new Error(e && /** @type {NodeJS.ErrnoException} */ (e).code === 'ENOENT' ? 'GUI_APP_NOT_FOUND' : 'GUI_LAUNCH_FAILED'))
    );
    if (child.pid) {
      child.unref();
      resolve(child.pid);
    }
  });
}
/**
 * @param {object} [options]
 * @param {NcLayout} [options.layout]
 * @param {string} [options.platform]
 * @param {boolean|null} [options.consoleSession] cached darwin console verdict
 * (null/undefined = check live at call time)
 */
export function makeGuiLaunchHandler({
  layout = ncLayout(),
  platform = process.platform,
  consoleSession = null
} = {}) {
  return async (/** @type {unknown} */ job) => {
    const started = Date.now();
    try {
      // Defense in depth behind the advertise gate: a headless Mac must
      // fail closed here too, never launch into the void.
      if (platform === 'darwin') {
        const sessionOk =
          typeof consoleSession === 'boolean'
            ? consoleSession
            : darwinGuiSessionAvailable({});
        if (!sessionOk) throw new Error('GUI_DISPLAY_UNAVAILABLE');
      }
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
          jobRecord.request_payload || jobRecord.payload || {}
        ),
        app = String(p.application || '');
      if (!APPS.has(app) && platform === 'win32') throw new Error('GUI_APPLICATION_NOT_ALLOWED');
      // Egress parity with browser_navigate for URL-bearing apps, before
      // any launch or broker queueing on every platform.
      if (['default_browser', 'edge', 'chrome'].includes(app)) {
        const probe = cleanTarget(app, p.target);
        await checkGuiUrlEgress(probe, job);
      }
      if (platform !== 'win32') {
        // POSIX direct launch: the agent runs in the user's graphical
        // context, no broker hop. Visible by design.
        const target = cleanTarget(app, p.target);
        const spec = posixLaunchSpec(app, target, platform);
        const pid = await spawnGuiApp(spec.cmd, spec.args);
        trackLaunchedGuiPid(pid, app);
        return {
          ...ok({ application: app, target, pid }),
          duration_ms: Date.now() - started
        };
      }
      const target = cleanTarget(app, p.target),
        username = p.username ? String(p.username) : '';
      const brokers = await liveBrokers(layout, username);
      if (!brokers.length) throw new Error('GUI_BROKER_NOT_AVAILABLE');
      const broker = brokers[0],
        id = crypto.randomUUID(),
        queue = path.join(layout.data, 'gui-queue', String(broker.session_id)),
        results = path.join(layout.data, 'gui-results');
      await fs.mkdir(queue, { recursive: true });
      await fs.mkdir(results, { recursive: true });
      const req = { id, application: app, target, created_at: new Date().toISOString() };
      const tmp = path.join(queue, `.${id}.tmp`),
        file = path.join(queue, `${id}.json`);
      await fs.writeFile(tmp, JSON.stringify(req) + '\n', { mode: 0o640 });
      await fs.rename(tmp, file);
      const resultFile = path.join(results, `${id}.json`),
        deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        try {
          const r = parseJsonText(await fs.readFile(resultFile, 'utf8'));
          await fs.rm(resultFile, { force: true });
          if (!r.ok) throw new Error(r.error || 'GUI_LAUNCH_FAILED');
          const finalPid = await resolveGuiPid(app, r.pid, platform, started);
          trackLaunchedGuiPid(finalPid, app);
          return {
            ...ok({
              application: app,
              target,
              user: r.username,
              session_id: r.session_id,
              pid: finalPid
            }),
            duration_ms: Date.now() - started
          };
        } catch (e) {
          const errorCode = e && typeof e === 'object' && 'code' in e ? e.code : undefined;
          if (errorCode !== 'ENOENT') throw e;
        }
        await sleep(150);
      }
      throw new Error('GUI_BROKER_TIMEOUT');
    } catch (e) {
      const errorRecord = /** @type {{message?: unknown}} */ (e);
      return { ...fail(errorRecord?.message), duration_ms: Date.now() - started };
    }
  };
}

/**
 * Close a GUI application previously launched via gui_launch. Only PIDs
 * recorded by trackLaunchedGuiPid are accepted; anything else fails closed
 * with GUI_PID_NOT_MANAGED instead of touching foreign processes.
 * POSIX launchers (/usr/bin/open, xdg-open, editor CLIs) exit right after
 * handoff, so a dead stub re-correlates to the real app process when the
 * app is unambiguous and started at/after launch (resolveGuiPidPosix);
 * unmapped apps and pre-existing instances keep failing closed.
 * @param {object} [options]
 * @param {ReturnType<typeof import('../src/client/nc-paths.mjs').ncLayout>} [options.layout]
 * @param {string} [options.platform]
 * @param {boolean|null} [options.consoleSession] cached darwin console verdict
 * (null/undefined = check live at call time)
 */
export function makeGuiCloseHandler({
  layout = ncLayout(),
  platform = process.platform,
  consoleSession = null
} = {}) {
  return async (/** @type {unknown} */ job) => {
    const started = Date.now();
    // Terminal guidance rides in result_payload (error codes stay exact
    // for taxonomy + existing equality assertions).
    /** @type {Record<string, unknown>} */
    let guidancePayload = {};
    try {
      if (platform === 'darwin') {
        const sessionOk =
          typeof consoleSession === 'boolean'
            ? consoleSession
            : darwinGuiSessionAvailable({});
        if (!sessionOk) throw new Error('GUI_DISPLAY_UNAVAILABLE');
      }
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      const pid = Number(p.pid);
      if (!Number.isInteger(pid) || pid <= 0) throw new Error('GUI_PID_REQUIRED');
      if (!isLaunchedGuiPid(pid)) {
        guidancePayload = {
          pid,
          retryable: false,
          suggested_action: 'gui_launch',
          hint:
            `GUI pid ${pid} was not launched by this agent session (or was already closed). ` +
            'It is not ours to close: do not retry gui_close for this pid. ' +
            'Call gui_launch again if a new window is needed.'
        };
        throw new Error('GUI_PID_NOT_MANAGED');
      }
      if (platform !== 'win32') {
        // POSIX kill with re-correlation: the tracked PID is usually the
        // already-exited launcher stub. Resolve it to the live app process
        // first; signal SIGTERM, escalate to SIGKILL, verify gone.
        const rec = launchedGuiRecord(pid);
        const target = await resolveGuiPidPosix(rec?.app || '', pid, platform, rec?.at || 0);
        if (target === null) throw new Error('GUI_CLOSE_FAILED');
        const isDead = async () => {
          try {
            process.kill(target, 0);
            return false;
          } catch {
            return true;
          }
        };
        try {
          process.kill(target);
        } catch {
          // Already dead before we could signal: re-verify instead of
          // failing outright (launcher handoff race).
          if (!(await isDead())) throw new Error('GUI_CLOSE_FAILED');
          untrackLaunchedGuiPid(pid);
          return { ...ok({ pid, closed: true }), duration_ms: Date.now() - started };
        }
        const t0 = Date.now();
        while (Date.now() - t0 < 3000) {
          if (await isDead()) break;
          await sleep(150);
        }
        if (!(await isDead())) {
          try {
            process.kill(target, 'SIGKILL');
          } catch {}
          const t1 = Date.now();
          while (Date.now() - t1 < 3000) {
            if (await isDead()) break;
            await sleep(150);
          }
        }
        if (!(await isDead())) throw new Error('GUI_CLOSE_FAILED');
        untrackLaunchedGuiPid(pid);
        return { ...ok({ pid, closed: true }), duration_ms: Date.now() - started };
      }
      // Single-instance/Store handoff parity with the POSIX branch above:
      // the tracked PID is often the already-exited launcher stub by close
      // time. Re-correlate to the live app process with the same resolver
      // launch used before asking the broker; otherwise close aims at a dead
      // PID the broker refuses as foreign-session while the real window
      // stays open (gui_launch PID unclosable by gui_close).
      const rec = launchedGuiRecord(pid);
      const resolved = await resolveGuiPid(rec?.app || '', pid, platform, rec?.at || 0);
      const target = resolved ?? pid;
      const brokers = await liveBrokers(layout, '');
      if (!brokers.length) throw new Error('GUI_BROKER_NOT_AVAILABLE');
      const broker = brokers[0],
        id = crypto.randomUUID(),
        queue = path.join(layout.data, 'gui-queue', String(broker.session_id)),
        results = path.join(layout.data, 'gui-results');
      await fs.mkdir(queue, { recursive: true });
      await fs.mkdir(results, { recursive: true });
      const req = { id, action: 'close', pid: target, created_at: new Date().toISOString() };
      const tmp = path.join(queue, `.${id}.tmp`),
        file = path.join(queue, `${id}.json`);
      await fs.writeFile(tmp, JSON.stringify(req) + '\n', { mode: 0o640 });
      await fs.rename(tmp, file);
      const resultFile = path.join(results, `${id}.json`),
        deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        try {
          const r = parseJsonText(await fs.readFile(resultFile, 'utf8'));
          await fs.rm(resultFile, { force: true });
          if (!r.ok) {
            const brokerError = String(r.error || 'GUI_CLOSE_FAILED');
            if (brokerError === 'GUI_PID_FOREIGN_SESSION') {
              // The pid belongs to another console session now (operator
              // signed out/in, or the broker restarted elsewhere): this
              // session can never close it. Terminal — say so plainly,
              // forget the pid so later closes fail fast as NOT_MANAGED
              // instead of re-queueing work the broker will refuse.
              untrackLaunchedGuiPid(pid);
              if (target !== pid) untrackLaunchedGuiPid(target);
              guidancePayload = {
                pid: target,
                closed: false,
                retryable: false,
                terminal: true,
                suggested_action: 'gui_launch',
                hint:
                  `GUI pid ${target} belongs to a different console session (the operator signed out/in, ` +
                  'or the broker restarted in another session). It cannot be closed from this session: ' +
                  'do not retry gui_close for this pid. Call gui_launch again if a new window is needed.'
              };
            }
            throw new Error(brokerError);
          }
          untrackLaunchedGuiPid(pid);
          if (target !== pid) untrackLaunchedGuiPid(target);
          return {
            ...ok({ pid: target, closed: r.closed === true }),
            duration_ms: Date.now() - started
          };
        } catch (e) {
          const errorCode = e && typeof e === 'object' && 'code' in e ? e.code : undefined;
          if (errorCode !== 'ENOENT') throw e;
        }
        await sleep(150);
      }
      throw new Error('GUI_BROKER_TIMEOUT');
    } catch (e) {
      const errorRecord = /** @type {{message?: unknown}} */ (e);
      const base = fail(errorRecord?.message);
      return {
        ...base,
        result_payload: { ...base.result_payload, ...guidancePayload },
        duration_ms: Date.now() - started
      };
    }
  };
}
