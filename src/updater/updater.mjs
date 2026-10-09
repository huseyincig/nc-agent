import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { ncLayout } from '../client/nc-paths.mjs';
import { releaseHeldLock } from '../client/singleton.mjs';
// Shared safe tar extractor (also used for npm-fetched browser payloads).
export { extractReleaseArchive } from './tar-extract.mjs';
import { extractReleaseArchive } from './tar-extract.mjs';

export const REQUIRED_UPDATE_FILES = [
  'launcher.mjs',
  'singleton.mjs',
  'tar-extract.mjs',
  'uninstall-ops.mjs',
  'gui-launch.mjs',
  'browser-adapter.mjs',
  'browser-manager.mjs',
  'browser-jobs.mjs',
  'browser-runtime.mjs',
  'egress-policy.mjs',
  'client.mjs',
  'ws-transport.mjs',
  'agent-state.mjs',
  'shell-runner.mjs',
  'shell-ops.mjs',
  'session-reconnect.mjs',
  'ws-client.mjs',
  'structured-ops.mjs',
  'doc-extract.mjs',
  'mutation-ops.mjs',
  'path-auth.mjs',
  'sensitive-paths.mjs',
  'process-sessions.mjs',
  'service-ops.mjs',
  'diagnostics-ops.mjs',
  'system-log-ops.mjs',
  'package-ops.mjs',
  'git-ops.mjs',
  'project-ops.mjs',
  'container-ops.mjs',
  'log-ops.mjs',
  'host-policy.mjs',
  'consolidated-tools.mjs',
  'device-proof.mjs',
  'lifecycle.mjs',
  'updater.mjs',
  'nc-paths.mjs',
  'privileged-helper-contract.mjs',
  'privileged-helper-core.mjs',
  'privileged-helper-ipc.mjs',
  'linux-peer-credentials.mjs',
  'privileged-helper-linux-daemon.mjs',
  'privileged-helper-linux-operations.mjs',
  'privileged-helper-bootstrap.mjs',
  'privileged-helper-client.mjs',
  'privileged-helper-spawn.mjs',
  'privileged-helper-linux-readiness.mjs',
  'privileged-helper-provision.mjs',
  'privileged-helper-transport-proof.mjs',
  'privileged-helper-windows-service.mjs',
  'privileged-helper-windows-operations.mjs',
  'privileged-helper-windows-config.mjs',
  'privileged-helper-windows-readiness.mjs',
  'privileged-helper-darwin-daemon.mjs',
  'privileged-helper-darwin-operations.mjs',
  'privileged-helper-darwin-readiness.mjs',
  'darwin-peer-credentials.mjs',
  'package.json',
  'install/nc-privileged-helper-linux.socket.in',
  'install/nc-privileged-helper-linux.service.in',
  'install/nc-privileged-helper-tmpfiles.in',
  'install/install-linux.sh'
];
const REQUIRED = REQUIRED_UPDATE_FILES;
/**
 * Hard cap on the OTA download body. The gunzip layer already caps
 * decompressed output (128MB); without an input cap a rogue oversized
 * response would be buffered whole via arrayBuffer() and OOM the agent
 * before the sha256 check ever runs. Exported for tests.
 */
export const MAX_UPDATE_DOWNLOAD_BYTES = 64 * 1024 * 1024;
/**
 * Read a fetch Response body with a cumulative size cap. Fails fast on a
 * declared Content-Length over the cap; otherwise streams and aborts past
 * it. The caller's AbortSignal still bounds total time.
 * @param {Response} response @param {number} [maxBytes]
 */
export async function readCappedResponseBody(response, maxBytes = MAX_UPDATE_DOWNLOAD_BYTES) {
  const declared = Number(response?.headers?.get?.('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes)
    throw new Error('UPDATE_PACKAGE_TOO_LARGE');
  if (!response?.body || typeof response.body.getReader !== 'function') {
    const whole = Buffer.from(await response.arrayBuffer());
    if (whole.length > maxBytes) throw new Error('UPDATE_PACKAGE_TOO_LARGE');
    return whole;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value?.byteLength || 0;
    if (total > maxBytes) {
      try {
        await reader.cancel();
      } catch {}
      throw new Error('UPDATE_PACKAGE_TOO_LARGE');
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}
/**
 * @param {unknown} v
 */
const validVersion = (v) => /^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(String(v || ''));

/**
 * @param {string} a
 * @param {string} b
 * @returns {number} negative when a < b, zero when equal, positive when a > b
 */
export function compareAgentVersions(a, b) {
  const core = (/** @type {string} */ v) => String(v).split(/[+-]/, 1)[0].split('.').map(Number);
  const [a1 = 0, a2 = 0, a3 = 0] = core(a);
  const [b1 = 0, b2 = 0, b3 = 0] = core(b);
  if (a1 !== b1) return a1 - b1;
  if (a2 !== b2) return a2 - b2;
  if (a3 !== b3) return a3 - b3;
  const pre = (/** @type {string} */ v) => (String(v).includes('-') ? 0 : 1);
  return pre(a) - pre(b);
}
/**
 * @param {string | Buffer} b
 */
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
/**
 * @param {string} p
 */
const exists = async (p) => {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
};
/**
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {string} cwd
 * @param {number} [timeoutMs] watchdog: never hang staging on a wedged child
 */
const run = (cmd, args, cwd, timeoutMs = 60000) =>
  new Promise((resolve, reject) => {
    let p;
    try {
      p = spawn(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    } catch (e) {
      reject(e);
      return;
    }
    let out = '',
      err = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        p.kill('SIGKILL');
      } catch {}
      try {
        p.stdout?.destroy();
      } catch {}
      try {
        p.stderr?.destroy();
      } catch {}
      reject(new Error(`UPDATE_VALIDATION_TIMEOUT:${cmd}`));
    }, Math.max(5000, Math.min(300000, Math.floor(Number(timeoutMs) || 60000))));
    try {
      timer.unref?.();
    } catch {}
    p.stdout.on('data', (d) => {
      if (out.length < 65536) out += String(d).slice(0, 65536 - out.length);
    });
    p.stderr.on('data', (d) => {
      if (err.length < 65536) err += String(d).slice(0, 65536 - err.length);
    });
    p.once('error', (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(e);
    });
    p.once('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      code === 0
        ? resolve({ out, err })
        : reject(new Error(`UPDATE_VALIDATION_FAILED:${cmd} exited ${code}: ${err.slice(0, 500)}`))
    });
  });
/**
 * Map a staging exception to a stable UPDATE_* code. Raw transport errors
 * (TypeError on refused DNS, AbortError on the 30s fetch abort, node --check
 * stderr) previously leaked verbatim as the job error — uncountable and
 * unactionable. Known codes pass through; the rest become a classified
 * failure that stays failed but carries suggested_action.
 * @param {unknown} error
 */
const UPDATE_KNOWN_RE = /^(UPDATE_[A-Z0-9_]+|INVALID_UPDATE_[A-Z0-9_]+|DEVICE_AUTH_REQUIRED)/;
export function classifyUpdateError(error) {
  const message = error instanceof Error ? error.message : String(error ?? '');
  const head = message.split(':')[0].trim();
  if (UPDATE_KNOWN_RE.test(head)) {
    const suggested_action = /^UPDATE_DOWNLOAD_HTTP_(429|502|503|504)$/.test(head)
      ? 'retry'
      : head === 'DEVICE_AUTH_REQUIRED'
        ? 'reauthorize'
        : head.startsWith('INVALID_UPDATE_')
          ? 'change_input'
          : 'contact_operator';
    return { code: head, detail: message.slice(0, 500), suggested_action };
  }
  if (/abort|aborted|timeout|timed out|hang up|socket hang|ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ECONNRESET|ECONNABORTED|ETIMEDOUT|EPIPE|fetch failed/i.test(message))
    return {
      code: 'UPDATE_DOWNLOAD_FAILED',
      detail: message.slice(0, 500),
      suggested_action: 'retry'
    };
  if (/sha256|checksum|integrity|too large|PACKAGE_TOO_LARGE/i.test(message))
    return {
      code: 'UPDATE_PACKAGE_INVALID',
      detail: message.slice(0, 500),
      suggested_action: 'contact_operator'
    };
  return {
    code: 'UPDATE_STAGE_FAILED',
    detail: message.slice(0, 500),
    suggested_action: 'contact_operator'
  };
}
/**
 * @param {unknown} error
 * @param {Record<string, unknown>} [payload]
 */
const fail = (error, payload = {}) => ({
  status: 'failed',
  exit_code: null,
  stdout: '',
  stderr: '',
  error,
  duration_ms: 0,
  result_payload: { ...payload }
});
// Node-port Windows helpers (2026-09-14 invisible-launch model): refreshed
// from the staged tree into the install root on every activation, next to the
// retired .ps1 originals. Byte-identical to apps/agent/windows/*.mjs (see sync test).
export const WINDOWS_SUPERVISOR_MJS_TEMPLATE = String.raw`// NC Windows supervisor (node port): keeps the agent runtime alive.
// Location-independent: all paths derive from this script's own directory
// (= install root), so the OTA updater can refresh it on every activation.
//
// Runs invisibly by construction: the parent (nc-hide.exe, NC service, or
// a Hidden scheduled task) allocates no console, and the agent itself is
// spawned with windowsHide. No powershell.exe, no conhost.exe rows.
//
// Protocol (shared with the retired .ps1 supervisor, same filenames):
//   data\retired.json       -> exit 0 (uninstalled / replaced)
//   data\update-switch.lock -> wait 500ms (OTA swap in progress)
//   app\launcher.mjs        -> spawn node + launcher, wait for exit, back off on fast death
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function supervisorPaths(scriptPath = fileURLToPath(import.meta.url)) {
  const root = path.dirname(scriptPath);
  return {
    root,
    lock: path.join(root, 'data', 'update-switch.lock'),
    retired: path.join(root, 'data', 'retired.json'),
    launcher: path.join(root, 'app', 'launcher.mjs'),
    appDir: path.join(root, 'app')
  };
}

// Crash-loop backoff (bounded, deterministic): a child that dies before
// HEALTHY_MS never ran healthy, so consecutive fast deaths double the restart
// delay from INITIAL_MS up to MAX_MS. A child that survives the healthy
// window resets the streak to the base 1s delay. Only exit TIMING drives the
// delay — never exit codes, signals, or stdio — so PowerShell/cmd children
// back off exactly like node children.
export const SUPERVISOR_BACKOFF = {
  INITIAL_MS: 2000,
  MAX_MS: 30000,
  HEALTHY_MS: 10000,
  BASE_DELAY_MS: 1000
};

/**
 * Restart delay after NUM consecutive fast deaths (1-based).
 * Pure and deterministic: unit tests assert the 2s doubling and the 30s cap
 * without sleeping. Exported for tests.
 * @param {unknown} failures consecutive fast deaths (>= 1)
 * @param {object} [backoff] override bounds (tests)
 * @returns {number} delay in milliseconds, bounded by MAX_MS
 */
export function nextSupervisorDelayMs(failures, backoff = SUPERVISOR_BACKOFF) {
  const n = Math.max(1, Math.floor(Number(failures) || 1));
  const initial = Math.max(1, Math.floor(Number(backoff && backoff.INITIAL_MS) || 2000));
  const max = Math.max(initial, Math.floor(Number(backoff && backoff.MAX_MS) || 30000));
  let delay = initial;
  for (let i = 1; i < n && delay < max; i++) delay = Math.min(max, delay * 2);
  return Math.min(max, delay);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function spawnAndWait(exe, args, cwd) {
  return new Promise(/** @param {(value?: unknown) => void} resolve */ (resolve) => {
    let child;
    try {
      child = spawn(exe, args, { cwd, stdio: 'ignore', windowsHide: true });
    } catch {
      resolve();
      return;
    }
    child.once('error', () => resolve());
    child.once('exit', () => resolve());
  });
}

export async function runSupervisor({ paths = supervisorPaths(), iterations = Infinity, now = Date.now, sleepFn = sleep, spawnFn = spawnAndWait } = {}) {
  let n = 0;
  let fastDeaths = 0;
  for (;;) {
    if (n++ >= iterations) return 'iterations-done';
    try {
      if (fs.existsSync(paths.retired)) return 'retired';
    } catch {}
    try {
      if (fs.existsSync(paths.lock)) {
        await sleepFn(500);
        continue;
      }
    } catch {}
    try {
      if (!fs.existsSync(paths.launcher)) {
        await sleepFn(2000);
        continue;
      }
    } catch {}
    const started = now();
    await spawnFn(process.execPath, [paths.launcher], paths.appDir);
    const livedMs = now() - started;
    try {
      if (fs.existsSync(paths.retired)) return 'retired';
    } catch {}
    if (livedMs >= SUPERVISOR_BACKOFF.HEALTHY_MS) fastDeaths = 0;
    else fastDeaths += 1;
    await sleepFn(fastDeaths === 0 ? SUPERVISOR_BACKOFF.BASE_DELAY_MS : nextSupervisorDelayMs(fastDeaths));
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runSupervisor().then(
    () => process.exit(0),
    () => process.exit(1)
  );
}
`;

export const WINDOWS_GUI_BROKER_MJS_TEMPLATE = String.raw`// NC Windows interactive GUI broker (node port): runs in the logged-on
// user's session and launches GUI apps on behalf of gui_launch jobs.
//
// Runs invisibly by construction: started via nc-hide.exe (no console), so
// no powershell.exe and no conhost.exe rows. GUI apps the broker launches
// are VISIBLE by design (that is the product); only the broker itself hides.
//
// Root derives from this script's own directory (= install root). This also
// fixes the retired .ps1 broker, which hardcoded %ProgramData%\NC and broke
// per-user installs. Override with NC_BROKER_ROOT for tests.
// NC_BROKER_MAX_BEATS bounds the heartbeat loop for tests (default: forever).
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function brokerRoot() {
  if (process.env.NC_BROKER_ROOT) return process.env.NC_BROKER_ROOT;
  return path.dirname(fileURLToPath(import.meta.url));
}

export function currentSessionId() {
  try {
    const r = spawnSync('query', ['session'], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 8000
    });
    const out = String(r.stdout || '');
    for (const line of out.split(/\r?\n/)) {
      const m = /^\s*>\s*(\S+)/.exec(line);
      if (m) {
        const tail = line.trim().split(/\s+/);
        const id = tail.find((t) => /^\d+$/.test(t));
        if (id) return id;
      }
    }
  } catch {}
  return '1';
}

function runHidden(file, args, timeoutMs = 15000) {
  try {
    const r = spawnSync(file, args, { encoding: 'utf8', windowsHide: true, timeout: timeoutMs });
    return { stdout: String(r.stdout || ''), status: r.status };
  } catch {
    return { stdout: '', status: null };
  }
}

export function processInSession(pid, sessionId) {
  const r = runHidden('tasklist', ['/FI', 'PID eq ' + pid, '/FO', 'CSV', '/NH']);
  for (const line of r.stdout.split(/\r?\n/)) {
    const cols = line.split('","').map((c) => c.replace(/^"|"$/g, ''));
    if (cols.length >= 4 && Number(cols[1]) === Number(pid))
      return String(cols[3]) === String(sessionId);
  }
  return false;
}

export function livePid(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function launchVisible(file, args) {
  // GUI apps launch visibly (product behavior); no console of our own.
  const child = spawn(file, args, { detached: true, stdio: 'ignore', windowsHide: false });
  child.unref();
  return child.pid;
}

export function isSafeBrowserTarget(target) {
  if (typeof target !== 'string' || target.length === 0 || target.length > 2048) return false;
  // Note: backtick is written as \x60 so this file stays embeddable
  // byte-identical inside the OTA updater String.raw template.
  return !/[\s"'\x60\x00-\x1F\x7F]/.test(target);
}

function correlatePid(launcherPid, sessionId) {
  // Single-instance/Store apps may exit the launcher and activate another
  // process. Correlate by name + start time in our session. Rare path
  // (launcher already dead); one-shot hidden powershell, no window.
  // launcherPid arrives from child.pid (numeric); sessionId from
  // currentSessionId() (digits-only). Defensive integer checks keep the
  // PowerShell interpolation below in a numeric-only context (verified-safe).
  if (!Number.isInteger(launcherPid) || launcherPid <= 0) return launcherPid;
  if (!/^\d+$/.test(String(sessionId))) return launcherPid;
  try {
    const ps = runHidden('powershell.exe', [
      '-NoProfile',
      '-WindowStyle',
      'Hidden',
      '-Command',
      '$n=(Get-Process -Id ' +
        launcherPid +
        ' -ErrorAction Stop).ProcessName;' +
        'Get-Process -Name $n -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -eq ' +
        sessionId +
        ' } |' +
        ' Sort-Object StartTime -Descending | Select-Object -First 1 -ExpandProperty Id'
    ]);
    const id = Number(String(ps.stdout || '').trim());
    if (Number.isInteger(id) && id > 0) return id;
  } catch {}
  return launcherPid;
}

const GUI_APPS = new Set([
  'default_browser',
  'edge',
  'chrome',
  'explorer',
  'notepad',
  'code',
  'cursor',
  'terminal'
]);

function firstExisting(paths) {
  for (const p of paths) {
    try {
      if (p && fs.existsSync(p)) return p;
    } catch {}
  }
  return null;
}

function whereExe(name) {
  const r = runHidden('where.exe', [name]);
  const first = r.stdout
    .split(/\r?\n/)
    .map((s) => s.trim())
    .find(Boolean);
  return first || null;
}

function resolveAppTarget(app, target) {
  const env = process.env;
  switch (app) {
    case 'default_browser':
      // rundll32.exe url.dll,FileProtocolHandler re-parses its command line,
      // so a target with spaces/quotes would smuggle extra rundll32 arguments
      // even though spawn passes a single argv. Reject them up front; the
      // http/https scheme gate is enforced by the caller.
      if (!isSafeBrowserTarget(target)) throw new Error('GUI_URL_TARGET_INVALID');
      return { file: 'rundll32.exe', args: ['url.dll,FileProtocolHandler', target] };
    case 'edge': {
      const exe =
        firstExisting([
          path.join(
            env['ProgramFiles(x86)'] || '',
            'Microsoft',
            'Edge',
            'Application',
            'msedge.exe'
          ),
          path.join(env.ProgramFiles || '', 'Microsoft', 'Edge', 'Application', 'msedge.exe')
        ]) || whereExe('msedge.exe');
      if (!exe) throw new Error('EDGE_NOT_FOUND');
      return { file: exe, args: [target] };
    }
    case 'chrome': {
      const exe =
        firstExisting([
          path.join(env.ProgramFiles || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
          path.join(
            env['ProgramFiles(x86)'] || '',
            'Google',
            'Chrome',
            'Application',
            'chrome.exe'
          ),
          path.join(env.LOCALAPPDATA || '', 'Google', 'Chrome', 'Application', 'chrome.exe')
        ]) || whereExe('chrome.exe');
      if (!exe) throw new Error('CHROME_NOT_FOUND');
      return { file: exe, args: [target] };
    }
    case 'explorer':
      return { file: 'explorer.exe', args: target ? [target] : [] };
    case 'notepad':
      return { file: 'notepad.exe', args: target ? [target] : [] };
    case 'code': {
      const exe =
        firstExisting([
          path.join(env.LOCALAPPDATA || '', 'Programs', 'Microsoft VS Code', 'Code.exe'),
          path.join(env.ProgramFiles || '', 'Microsoft VS Code', 'Code.exe')
        ]) ||
        whereExe('code.exe') ||
        firstExisting([
          path.join(env.LOCALAPPDATA || '', 'Programs', 'Microsoft VS Code', 'bin', 'code.cmd')
        ]);
      if (!exe) throw new Error('VSCODE_NOT_FOUND');
      if (exe.toLowerCase().endsWith('.cmd'))
        return {
          file: 'cmd.exe',
          args: ['/d', '/s', '/c', '""' + exe + '"', ...(target ? [target] : [])],
          viaShell: true
        };
      return { file: exe, args: target ? [target] : [] };
    }
    case 'cursor': {
      const exe =
        firstExisting([
          path.join(env.LOCALAPPDATA || '', 'Programs', 'cursor', 'Cursor.exe'),
          path.join(env.LOCALAPPDATA || '', 'cursor', 'Cursor.exe')
        ]) || whereExe('cursor.exe');
      if (!exe) throw new Error('CURSOR_NOT_FOUND');
      return { file: exe, args: target ? [target] : [] };
    }
    case 'terminal': {
      return { file: 'cmd.exe', args: [] };
    }
    default:
      throw new Error('GUI_APPLICATION_NOT_ALLOWED');
  }
}

export async function runBroker({ root = brokerRoot(), maxBeats = null } = {}) {
  const sessionId = currentSessionId();
  let userName = '';
  try {
    userName = os.userInfo().username || '';
  } catch {}
  const data = path.join(root, 'data');
  const brokerDir = path.join(data, 'gui-brokers');
  const queueDir = path.join(data, 'gui-queue', String(sessionId));
  const resultDir = path.join(data, 'gui-results');
  const bootLog = path.join(data, 'gui-broker-boot.log');
  const blog = (line) => {
    try {
      fs.appendFileSync(bootLog, '[' + new Date().toISOString() + '] ' + line + '\n', 'utf8');
    } catch {}
  };
  for (const d of [brokerDir, queueDir, resultDir]) fs.mkdirSync(d, { recursive: true });
  blog(
    'start user=' + userName + ' session=' + sessionId + ' pid=' + process.pid + ' root=' + root
  );
  const lockPath = path.join(brokerDir, 'gui-broker-' + sessionId + '.lock');
  const claimLock = () => {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o600);
      try {
        fs.writeSync(fd, String(process.pid));
      } catch {}
      return fd;
    } catch {
      return null;
    }
  };
  let lockFd = claimLock();
  if (lockFd === null) {
    // Stale-lock takeover: a crashed broker leaves the file behind (same
    // flaw the .ps1 broker had, minus the mystery — PID is recorded now).
    try {
      const owner = Number(String(fs.readFileSync(lockPath, 'utf8')).trim());
      if (!livePid(owner)) {
        try {
          fs.rmSync(lockPath, { force: true });
        } catch {}
        lockFd = claimLock();
      }
    } catch {}
    if (lockFd === null) return 'already-running';
  }
  const releaseLock = () => {
    try {
      fs.closeSync(lockFd);
    } catch {}
    try {
      fs.rmSync(lockPath, { force: true });
    } catch {}
  };
  process.once('exit', releaseLock);
  blog('ready session=' + sessionId);
  const max = maxBeats ?? (Number(process.env.NC_BROKER_MAX_BEATS) || Infinity);
  let beats = 0;
  try {
    for (;;) {
      const heartbeat = path.join(brokerDir, sessionId + '.json');
      try {
        // Unique tmp per writer + wx (P2-D6 pattern): a fixed suffix collides
        // across broker incarnations and admits symlink plants in the data dir.
        const tmp =
          heartbeat + '.tmp-' + process.pid + '-' + Date.now() + '-' + Math.floor(Math.random() * 1000000);
        fs.writeFileSync(
          tmp,
          JSON.stringify({
            session_id: sessionId,
            username: userName,
            pid: process.pid,
            last_seen: new Date().toISOString()
          }),
          { encoding: 'utf8', flag: 'wx' }
        );
        try {
          fs.renameSync(tmp, heartbeat);
        } catch {
          try {
            fs.rmSync(tmp, { force: true });
          } catch {}
        }
      } catch {}
      let files = [];
      try {
        files = fs
          .readdirSync(queueDir)
          .filter((n) => n.endsWith('.json'))
          .map((n) => path.join(queueDir, n))
          .sort();
      } catch {}
      for (const file of files) {
        const claim = file + '.claim-' + process.pid;
        try {
          fs.renameSync(file, claim);
        } catch {
          continue;
        }
        const r = {
          ok: false,
          username: userName,
          session_id: sessionId,
          pid: null,
          error: 'GUI_LAUNCH_FAILED'
        };
        try {
          const q = JSON.parse(fs.readFileSync(claim, 'utf8'));
          if (!q.id) throw new Error('GUI_REQUEST_ID_REQUIRED');
          if (q.action === 'close') {
            const cpid = Number(q.pid) || 0;
            if (cpid <= 0) throw new Error('GUI_PID_REQUIRED');
            if (!processInSession(cpid, sessionId)) throw new Error('GUI_PID_FOREIGN_SESSION');
            let killed = false;
            try {
              process.kill(cpid);
              killed = true;
            } catch {}
            const t0 = Date.now();
            while (killed && livePid(cpid) && Date.now() - t0 < 3000) await sleep(150);
            const gone = !livePid(cpid);
            r.ok = killed && gone;
            r.error = r.ok ? null : 'GUI_CLOSE_FAILED';
            r.pid = cpid;
            r.closed = r.ok;
          } else {
            const app = String(q.application || '');
            const tgt = String(q.target || '');
            if (!GUI_APPS.has(app)) throw new Error('GUI_APPLICATION_NOT_ALLOWED');
            if (['default_browser', 'edge', 'chrome'].includes(app)) {
              let scheme = '';
              try {
                scheme = new URL(tgt).protocol.replace(/:$/, '');
              } catch {}
              if (!['http', 'https'].includes(scheme))
                throw new Error('GUI_URL_SCHEME_NOT_ALLOWED');
            }
            const spec = resolveAppTarget(app, tgt || undefined);
            const pid = launchVisible(spec.file, spec.args);
            await sleep(800);
            let realPid = pid;
            try {
              if (!livePid(pid)) realPid = correlatePid(pid, sessionId);
            } catch {}
            r.ok = true;
            r.error = null;
            r.pid = realPid;
          }
        } catch (e) {
          r.error = e instanceof Error ? e.message : String(e);
        }
        try {
          const id = JSON.parse(fs.readFileSync(claim, 'utf8')).id;
          const result = path.join(resultDir, id + '.json');
          const resultTmp =
            result + '.tmp-' + process.pid + '-' + Date.now() + '-' + Math.floor(Math.random() * 1000000);
          try {
            fs.writeFileSync(resultTmp, JSON.stringify(r), { encoding: 'utf8', flag: 'wx' });
            fs.renameSync(resultTmp, result);
          } catch {
            try {
              fs.rmSync(resultTmp, { force: true });
            } catch {}
          }
        } catch {}
        try {
          fs.rmSync(claim, { force: true });
        } catch {}
      }
      if (++beats >= max) return 'beats-done';
      await sleep(500);
    }
  } finally {
    releaseLock();
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runBroker().then(
    () => process.exit(0),
    () => process.exit(1)
  );
}
`;

/**
 * @param {object} options
 * @param {string} options.serverUrl
 * @param {(method: string, url: string, options: Record<string, unknown>) => Promise<Record<string, string>>} options.authHeaders
 * @param {string} [options.clientId]
 * @param {string} [options.currentVersion]
 * @param {ReturnType<typeof import('../client/nc-paths.mjs').ncLayout>} [options.layout]
 */
export function makeUpdateHandler(options) {
  const { serverUrl, authHeaders, currentVersion } = options,
    layout = options.layout || ncLayout();
  /**
   * @param {unknown} job
   */
  const handler = async (job) => {
    const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
    const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      ),
      version = String(p.version || ''),
      expected = String(p.sha256 || '').toLowerCase(),
      packageUrl = String(p.package_url || '');
    if (!validVersion(version))
      return fail('INVALID_UPDATE_VERSION', {
        error_code: 'INVALID_UPDATE_VERSION',
        failure_class: 'invalid-argument',
        suggested_action: 'change_input'
      });
    if (
      currentVersion &&
      validVersion(currentVersion) &&
      compareAgentVersions(version, String(currentVersion)) <= 0
    )
      return fail('UPDATE_VERSION_NOT_NEWER', {
        error_code: 'UPDATE_VERSION_NOT_NEWER',
        failure_class: 'stale-update',
        suggested_action: 'change_input'
      });
    if (!/^[a-f0-9]{64}$/.test(expected))
      return fail('INVALID_UPDATE_SHA256', {
        error_code: 'INVALID_UPDATE_SHA256',
        failure_class: 'invalid-argument',
        suggested_action: 'change_input'
      });
    if (!packageUrl.startsWith('/'))
      return fail('INVALID_UPDATE_URL', {
        error_code: 'INVALID_UPDATE_URL',
        failure_class: 'invalid-argument',
        suggested_action: 'change_input'
      });
    const dir = path.join(layout.clientReleases, version),
      archive = path.join(dir, 'client.tar.gz'),
      stage = path.join(dir, 'stage');
    try {
      await fs.rm(dir, { recursive: true, force: true });
      await fs.mkdir(stage, { recursive: true });
      if (typeof authHeaders !== 'function') throw new Error('DEVICE_AUTH_REQUIRED');
      const requestUrl = serverUrl + packageUrl,
        headers = await authHeaders('GET', requestUrl, { json: false });
      // Download-phase signal: AbortSignal.timeout covers the FULL body
      // download (headers plus the streaming readCappedResponseBody below),
      // not just connection setup — a 30s budget aborts slow-link release
      // archives repeatedly without ever completing. 5 minutes bounds a truly
      // stuck transfer while letting real downloads finish (size is capped
      // separately by MAX_UPDATE_DOWNLOAD_BYTES).
      const r = await fetch(requestUrl, { headers, signal: AbortSignal.timeout(300000) });
      if (!r.ok) throw new Error(`UPDATE_DOWNLOAD_HTTP_${r.status}`);
      const body = await readCappedResponseBody(r);
      if (sha256(body) !== expected) throw new Error('UPDATE_SHA256_MISMATCH');
      await fs.writeFile(archive, body, { mode: 0o640 });
      await extractReleaseArchive(body, stage);
      for (const name of REQUIRED)
        if (!(await exists(path.join(stage, name)))) throw new Error(`UPDATE_FILE_MISSING:${name}`);
      const pkg = JSON.parse(await fs.readFile(path.join(stage, 'package.json'), 'utf8'));
      if (pkg.version !== version) throw new Error('UPDATE_VERSION_MISMATCH');
      for (const name of REQUIRED.filter((x) => x.endsWith('.mjs')))
        await run(process.execPath, ['--check', name], stage);
      // Legacy bundled runtime (SEA exe era): node+launcher is the only
      // runtime now. Never stage an exe, and drop one carried over from an
      // older tree so it cannot shadow the launcher later. Best-effort:
      // the file may be the running image on exe-booted hosts.
      try {
        await fs.rm(path.join(stage, 'nc-agent.exe'), { force: true });
      } catch {}
      // Bundled browser runtime (when the release carries one) must agree
      // with the staged code pin; a mismatched bundle fails the update
      // instead of stranding the host with a dead engine. Absent bundle is
      // legal (air-gapped rebuilds fall back to the standalone OTA path).
      if (await exists(path.join(stage, 'browser-runtime', 'playwright-core', 'package.json'))) {
        const bundledPkg = JSON.parse(
          await fs.readFile(
            path.join(stage, 'browser-runtime', 'playwright-core', 'package.json'),
            'utf8'
          )
        );
        const stagedPin = await fs.readFile(path.join(stage, 'browser-runtime.mjs'), 'utf8');
        const pinVersion = stagedPin.match(/playwright:\s*'([^']+)'/)?.[1];
        if (!pinVersion || String(bundledPkg.version || '') !== pinVersion)
          throw new Error('UPDATE_BROWSER_RUNTIME_MISMATCH');
      }
      // Browser runtime is never carried by updates: the agent fetches
      // playwright-core from the npm registry and Chromium from the
      // Playwright CDN on first boot / background convergence.
      return {
        status: 'completed',
        exit_code: 0,
        stdout: '',
        stderr: '',
        error: null,
        duration_ms: 0,
        result_payload: {
          version,
          sha256: expected,
          stage_dir: stage,
          activation_pending: true
        }
      };
    } catch (error) {
      const classified = classifyUpdateError(error);
      return fail(classified.code, {
        error_code: classified.code,
        failure_class: 'update-staging',
        suggested_action: classified.suggested_action || 'contact_operator',
        detail: classified.detail
      });
    }
  };
  return handler;
}
/**
 * @param {string} source
 * @param {string} destination
 */
async function moveDirContents(source, destination) {
  await fs.mkdir(source, { recursive: true });
  await fs.mkdir(destination, { recursive: true });
  for (const name of await fs.readdir(source))
    await fs.rename(path.join(source, name), path.join(destination, name));
}

/**
 * @param {string} stage
 * @param {object} [options]
 * @param {ReturnType<typeof import('../client/nc-paths.mjs').ncLayout>} [options.layout]
 * @param {string} [options.previous]
 */
export async function swapAppContents(stage, { layout = ncLayout(), previous } = {}) {
  if (!previous) throw new Error('UPDATE_BACKUP_PATH_REQUIRED');
  await fs.mkdir(layout.app, { recursive: true });
  await fs.mkdir(previous, { recursive: true });
  await moveDirContents(layout.app, previous);
  try {
    await moveDirContents(stage, layout.app);
  } catch (error) {
    try {
      await moveDirContents(layout.app, stage);
    } catch {}
    await moveDirContents(previous, layout.app);
    throw error;
  }
}

/**
 * Windows supervisor template (node.exe + launcher.mjs; Node.js is a
 * silent install prerequisite). Single-sourced with
 * apps/agent/windows/supervisor-windows.ps1 (installer payload); the
 * equality test fails on ANY drift. The OTA updater refreshes the
 * installed supervisor from this copy on every Windows activation.
 */
/**
 * Windows GUI broker template (interactive user-session companion).
 * Single-sourced with apps/agent/windows/nc-gui-broker.ps1 (installer
 * payload); the equality test fails on ANY drift. The OTA updater refreshes
 * the installed broker from this copy on every Windows activation so a stale
 * broker (e.g. pre-ProgramData $Root) can never strand GUI tools again.
 */
export const WINDOWS_GUI_BROKER_TEMPLATE = String.raw`$ErrorActionPreference = 'SilentlyContinue'
$Root = Join-Path $env:ProgramData 'NC'
$SessionId = (Get-Process -Id $PID).SessionId
$UserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$Data = Join-Path $Root 'data'
# Startup self-log: if the broker never heartbeats, this file tells why it
# died at boot (trigger fired but process crashed early). Best-effort only.
try {
  $BootLog = Join-Path $Data 'gui-broker-boot.log'
  "[$(Get-Date -Format o)] start user=$UserName session=$SessionId pid=$PID root=$Root" | Out-File -LiteralPath $BootLog -Append -Encoding utf8
} catch {}
$BrokerDir = Join-Path $Data 'gui-brokers'
$QueueDir = Join-Path $Data ("gui-queue\$SessionId")
$ResultDir = Join-Path $Data 'gui-results'
$Lock = Join-Path $BrokerDir ("gui-broker-$SessionId.lock")
foreach ($d in @($BrokerDir,$QueueDir,$ResultDir)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
try { $LockHandle = [IO.File]::Open($Lock,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::Write,[IO.FileShare]::None) } catch { exit 0 }
try {
  "[$(Get-Date -Format o)] ready session=$SessionId" | Out-File -LiteralPath (Join-Path $Data 'gui-broker-boot.log') -Append -Encoding utf8
} catch {}
try {
  $Heartbeat = Join-Path $BrokerDir ("$SessionId.json")
  while ($true) {
    @{session_id=$SessionId;username=$UserName;pid=$PID;last_seen=(Get-Date).ToUniversalTime().ToString('o')} | ConvertTo-Json -Compress | Set-Content -LiteralPath "$Heartbeat.tmp" -Encoding utf8
    Move-Item -LiteralPath "$Heartbeat.tmp" -Destination $Heartbeat -Force
    foreach ($file in @(Get-ChildItem -LiteralPath $QueueDir -Filter '*.json' -File | Sort-Object CreationTimeUtc)) {
      $claim = "$($file.FullName).claim-$PID"
      try { Move-Item -LiteralPath $file.FullName -Destination $claim -ErrorAction Stop } catch { continue }
      $r = @{ok=$false;username=$UserName;session_id=$SessionId;pid=$null;error='GUI_LAUNCH_FAILED'}
      try {
        $q = Get-Content -LiteralPath $claim -Raw | ConvertFrom-Json
        if (-not $q.id) { throw 'GUI_REQUEST_ID_REQUIRED' }
        if ($q.action -eq 'close') {
          $cpid = 0
          try { $cpid = [int]$q.pid } catch { $cpid = 0 }
          if ($cpid -le 0) { throw 'GUI_PID_REQUIRED' }
          $killed = $false
          try {
            $victim = Get-Process -Id $cpid -ErrorAction Stop
            if ($victim.SessionId -ne $SessionId -and $victim.SessionId -ne 0) { throw 'GUI_PID_FOREIGN_SESSION' }
            Stop-Process -Id $cpid -Force -ErrorAction Stop
            $killed = $true
          } catch {
            if ($_.Exception.Message -eq 'GUI_PID_FOREIGN_SESSION') { throw }
          }
          $stillThere = $false
          try { $stillThere = $null -ne (Get-Process -Id $cpid -ErrorAction Stop) } catch {}
          if ($killed -and $stillThere) {
            # Teardown is async; poll briefly before verdict.
            for ($i = 0; ($i -lt 20) -and $stillThere; $i++) {
              Start-Sleep -Milliseconds 150
              try { $stillThere = $null -ne (Get-Process -Id $cpid -ErrorAction Stop) } catch { $stillThere = $false }
            }
          }
          $r.ok = ($killed -and -not $stillThere); $r.error = $null; $r.pid = $cpid; $r.closed = $r.ok
          if (-not $r.ok) { $r.error = 'GUI_CLOSE_FAILED' }
          $result = Join-Path $ResultDir ("$($q.id).json")
          $r | ConvertTo-Json -Compress | Set-Content -LiteralPath "$result.tmp" -Encoding utf8
          Move-Item -LiteralPath "$result.tmp" -Destination $result -Force
          Remove-Item -LiteralPath $claim -Force -ErrorAction SilentlyContinue
          continue
        }
        $app = [string]$q.application; $target = [string]$q.target
        if ($app -notin @('default_browser','edge','chrome','explorer','notepad','code','cursor','terminal')) { throw 'GUI_APPLICATION_NOT_ALLOWED' }
        if ($app -in @('default_browser','edge','chrome')) { $u=[Uri]$target; if ($u.Scheme -notin @('http','https')) { throw 'GUI_URL_SCHEME_NOT_ALLOWED' } }
        $launchTime = Get-Date
        if ($app -eq 'default_browser') { $p = Start-Process -FilePath $target -PassThru }
        elseif ($app -eq 'edge') {
          $exe = @("$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
          if (-not $exe) { throw 'EDGE_NOT_FOUND' }; $p = Start-Process -FilePath $exe -ArgumentList @($target) -PassThru
        }
        elseif ($app -eq 'chrome') {
          $exe = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","$env:ProgramFiles (x86)\Google\Chrome\Application\chrome.exe","$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
          if (-not $exe) { throw 'CHROME_NOT_FOUND' }; $p = Start-Process -FilePath $exe -ArgumentList @($target) -PassThru
        }
        elseif ($app -eq 'explorer') { $p = Start-Process -FilePath 'explorer.exe' -ArgumentList @($target) -PassThru }
        elseif ($app -eq 'code') {
          $codeExe = @(
            "$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd",
            "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe",
            "$env:ProgramFiles\Microsoft VS Code\bin\code.cmd",
            "$env:ProgramFiles\Microsoft VS Code\Code.exe"
          ) | Where-Object { Test-Path $_ } | Select-Object -First 1
          if (-not $codeExe) { $codeExe = (Get-Command code -ErrorAction SilentlyContinue).Source }
          if (-not $codeExe) { throw 'VSCODE_NOT_FOUND' }
          $p = if ($target) { Start-Process -FilePath $codeExe -ArgumentList @($target) -PassThru } else { Start-Process -FilePath $codeExe -PassThru }
        }
        elseif ($app -eq 'cursor') {
          $cursorExe = @(
            "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe",
            "$env:LOCALAPPDATA\cursor\Cursor.exe"
          ) | Where-Object { Test-Path $_ } | Select-Object -First 1
          if (-not $cursorExe) { $cursorExe = (Get-Command cursor -ErrorAction SilentlyContinue).Source }
          if (-not $cursorExe) { throw 'CURSOR_NOT_FOUND' }
          $p = if ($target) { Start-Process -FilePath $cursorExe -ArgumentList @($target) -PassThru } else { Start-Process -FilePath $cursorExe -PassThru }
        }
        elseif ($app -eq 'terminal') {
          $p = Start-Process -FilePath 'cmd.exe' -PassThru
        }
        else { $p = Start-Process -FilePath 'notepad.exe' -PassThru }
        # Single-instance/Store apps (Win11 Notepad, browsers) may exit the
        # spawned launcher and activate another process. Correlate by process
        # name + start time so the reported PID is the live GUI process;
        # keep the launcher PID when it is still alive.
        $realPid = $p.Id
        try {
          Start-Sleep -Milliseconds 800
          $procName = $null
          try { $procName = (Get-Process -Id $p.Id -ErrorAction Stop).ProcessName } catch {}
          if ($procName) {
            $cand = Get-Process -Name $procName -ErrorAction SilentlyContinue |
              Where-Object { $_.StartTime -ge $launchTime.AddSeconds(-2) -and $_.SessionId -eq $SessionId } |
              Sort-Object StartTime -Descending | Select-Object -First 1
            if ($cand -and $cand.Id -ne $p.Id) {
              $alive = $false
              try { $alive = $null -ne (Get-Process -Id $p.Id -ErrorAction Stop) } catch {}
              if (-not $alive) { $realPid = $cand.Id }
            }
          }
        } catch {}
        $r.ok=$true; $r.error=$null; $r.pid=$realPid
      } catch { $r.error=$_.Exception.Message }
      $result = Join-Path $ResultDir ("$($q.id).json")
      $r | ConvertTo-Json -Compress | Set-Content -LiteralPath "$result.tmp" -Encoding utf8
      Move-Item -LiteralPath "$result.tmp" -Destination $result -Force
      Remove-Item -LiteralPath $claim -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
  }
} finally { $LockHandle.Dispose(); Remove-Item -LiteralPath $Lock -Force -ErrorAction SilentlyContinue }
`;

export const WINDOWS_SUPERVISOR_TEMPLATE = String.raw`# NC Windows supervisor: keeps the agent runtime alive. Location-independent
# (all paths derive from this script's own directory = install root), so the
# OTA updater can refresh it from the staged tree on every activation.
# Node.js is a prerequisite (ensured silently by the installer); the agent
# always runs as node.exe + launcher.mjs.
#
# INVISIBLE BY CONSTRUCTION: the agent runtime must never show a window, in
# any session type. Task -WindowStyle Hidden hides only the powershell
# wrapper; a console child (node.exe) of a console-less parent allocates its
# OWN visible console anyway (-NoNewWindow does not reliably stop that from
# a scheduled task). So node is spawned via raw CreateProcess with
# CREATE_NO_WINDOW (P/Invoke below). If that ever fails to compile, the
# Start-Process fallback keeps the agent alive (possibly visible) instead of
# wedging the host offline.
$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSCommandPath
$Lock = Join-Path $Root 'data\update-switch.lock'
$Retired = Join-Path $Root 'data\retired.json'
$Node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
$UseNoWindow = $false
try {
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class NcNoWindow {
  public const int CREATE_NO_WINDOW = 0x08000000;
  public const int STARTF_USESHOWWINDOW = 0x00000001;
  public const short SW_HIDE = 0;
  public const uint INFINITE = 0xFFFFFFFF;
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct STARTUPINFO {
    public int cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public int dwX;
    public int dwY;
    public int dwXSize;
    public int dwYSize;
    public int dwXCountChars;
    public int dwYCountChars;
    public int dwFillAttribute;
    public int dwFlags;
    public short wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
  }
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool CreateProcess(
    string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
    IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags,
    IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
    out PROCESS_INFORMATION lpProcessInformation);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool CloseHandle(IntPtr hHandle);
}
'@ -ErrorAction Stop
  $UseNoWindow = $true
} catch {}
function Start-AgentHidden([string]$Exe, [string]$CliArgs, [string]$WorkDir) {
  if ($UseNoWindow) {
    try {
      $si = New-Object NcNoWindow+STARTUPINFO
      $si.cb = [Runtime.InteropServices.Marshal]::SizeOf($si)
      $si.dwFlags = [NcNoWindow]::STARTF_USESHOWWINDOW
      $si.wShowWindow = [NcNoWindow]::SW_HIDE
      $pi = New-Object NcNoWindow+PROCESS_INFORMATION
      $ok = [NcNoWindow]::CreateProcess(
        $Exe, ('"' + $Exe + '" ' + $CliArgs), [IntPtr]::Zero, [IntPtr]::Zero, $false,
        [NcNoWindow]::CREATE_NO_WINDOW, [IntPtr]::Zero, $WorkDir, [ref]$si, [ref]$pi)
      if (-not $ok) { throw 'CreateProcess failed' }
      try { [void][NcNoWindow]::WaitForSingleObject($pi.hProcess, [NcNoWindow]::INFINITE) }
      finally {
        [void][NcNoWindow]::CloseHandle($pi.hProcess)
        [void][NcNoWindow]::CloseHandle($pi.hThread)
      }
      return $true
    } catch { return $false }
  }
  return $false
}
while ($true) {
  if (Test-Path -LiteralPath $Retired) { exit 0 }
  while (Test-Path -LiteralPath $Lock) { Start-Sleep -Milliseconds 500 }
  if (Test-Path -LiteralPath $Retired) { exit 0 }
  $Launcher = Join-Path $Root 'app\launcher.mjs'
  if (-not (Test-Path -LiteralPath $Launcher -PathType Leaf)) { Start-Sleep -Seconds 2; continue }
  if (-not $Node) {
    $Node = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
    if (-not $Node) { Start-Sleep -Seconds 5; continue }
  }
  $AppDir = Join-Path $Root 'app'
  if (-not (Start-AgentHidden $Node $Launcher $AppDir)) {
    $p = Start-Process -FilePath $Node -ArgumentList $Launcher -WorkingDirectory $AppDir -NoNewWindow -WindowStyle Hidden -PassThru
    $p.WaitForExit()
  }
  if (Test-Path -LiteralPath $Retired) { exit 0 }
  Start-Sleep -Seconds 1
}
`;

/**
 * @param {object} options
 * @param {ReturnType<typeof import('../client/nc-paths.mjs').ncLayout>} options.layout
 * @param {string} options.stage
 * @param {string} options.previous
 * @param {string} options.failed
 * @param {string} options.marker
 * @param {string} options.lock
 * @param {number} options.parentPid
 * @param {string|null} [options.supervisorTemplate]
 * @param {string|null} [options.supervisorMjsTemplate]
 */
export function windowsActivationHelperSource({
  layout,
  stage,
  previous,
  failed,
  marker,
  lock,
  parentPid,
  supervisorTemplate = null,
  supervisorMjsTemplate = null
}) {
  /** @param {unknown} x */
  const v = (x) => JSON.stringify(x);
  const supervisorWrite = supervisorTemplate
    ? `try{fs.writeFileSync(${v(path.join(layout.root, 'nc-supervisor.ps1'))},${v(supervisorTemplate)})}catch{};`
    : '';
  const supervisorMjsWrite = supervisorMjsTemplate
    ? `try{fs.writeFileSync(${v(path.join(layout.root, 'nc-supervisor.mjs'))},${v(supervisorMjsTemplate)})}catch{};`
    : '';
  return `import fs from 'node:fs';import path from 'node:path';\nconst sleep=ms=>new Promise(r=>setTimeout(r,ms));\nconst app=${v(layout.app)},stage=${v(stage)},previous=${v(previous)},failed=${v(failed)},marker=${v(marker)},lock=${v(lock)},clientLock=${v(layout.lockFile)},pidFile=${v(layout.pidFile)},parentPid=${Number(parentPid)};\nconst alive=pid=>{if(!Number.isInteger(pid)||pid<2)return false;try{process.kill(pid,0);return true}catch{return false}};\nconst move=(a,b)=>{fs.mkdirSync(a,{recursive:true});fs.mkdirSync(b,{recursive:true});for(const n of fs.readdirSync(a))fs.renameSync(path.join(a,n),path.join(b,n))};\nfor(let i=0;i<200&&alive(parentPid);i++)await sleep(100);\nif(alive(parentPid)){fs.rmSync(lock,{force:true});process.exit(3)};fs.rmSync(clientLock,{force:true});\ntry{move(app,previous);move(stage,app);try{fs.rmSync(path.join(app,'nc-agent.exe'),{force:true})}catch{};${supervisorWrite}${supervisorMjsWrite}fs.rmSync(lock,{force:true})}catch(e){try{if(fs.existsSync(previous)){move(app,stage);move(previous,app)}}catch{};fs.rmSync(lock,{force:true});process.exit(2)}\nawait sleep(25000);if(fs.existsSync(marker))process.exit(0);\ntry{fs.writeFileSync(lock,'rollback\\n');let pid=0;try{pid=Number(fs.readFileSync(pidFile,'utf8').trim())}catch{};if(alive(pid))try{process.kill(pid,'SIGTERM')}catch{};for(let i=0;i<100&&alive(pid);i++)await sleep(100);move(app,failed);move(previous,app)}catch{}finally{fs.rmSync(lock,{force:true})}\n`;
}

/**
 * Keep only the newest `keep` backup generations (previous-/failed- dirs).
 * Best-effort: never fails an update over housekeeping.
 * @param {string} dir
 * @param {number} [keep]
 */
export async function pruneOldBackups(dir, keep = 10) {
  let names;
  try {
    names = await fs.readdir(dir);
  } catch {
    return 0;
  }
  const gens = names
    .map((n) => {
      const m = /^(previous|failed)-(\d+)$/.exec(n);
      return m ? { name: n, stamp: Number(m[2]) } : null;
    })
    .filter(Boolean)
    .sort((a, b) => b.stamp - a.stamp);
  let pruned = 0;
  for (const g of gens.slice(Math.max(0, keep))) {
    try {
      await fs.rm(path.join(dir, g.name), { recursive: true, force: true });
      pruned++;
    } catch {}
  }
  return pruned;
}

/**
 * OTA activation interlock probe result.
 * @typedef {object} ActivationInterlock
 * @property {boolean} blocked true while interactive sessions are live.
 * @property {number} active_sessions live session count (-1 when the probe itself failed).
 */
/**
 * OTA activation interlock (NODE_BUSY gate): refuse to swap the running app
 * tree while interactive process sessions are live, so an update cannot sever
 * in-flight builds or tests mid-flight. The refusal uses CLIENT_BUSY — a
 * taxonomy code the control plane already understands (transient / wait /
 * retryable) — so no new contract code is needed. Runs BEFORE any
 * filesystem mutation, keeping activation forward-only and idempotent: a
 * refused activation changes nothing and is retryable later once sessions
 * drain. Exported for tests and for the client deferral path.
 * @param {object} [options]
 * @param {(() => unknown)|null} [options.hasLiveSessions] probe returning a
 * live-session count (number) or liveness flag (boolean). Absent (or a
 * non-function) means "no visibility into sessions" and never blocks, so
 * existing callers without a session table keep today's behavior.
 * @returns {Promise<ActivationInterlock>}
 */
export async function activationInterlock({ hasLiveSessions = null } = {}) {
  if (typeof hasLiveSessions !== 'function') return { blocked: false, active_sessions: 0 };
  let value;
  try {
    value = await hasLiveSessions();
  } catch {
    // Fail closed: an unreadable probe must not green-light a swap that may
    // sever live sessions. The refusal is retryable; the probe is an
    // in-process map read that realistically never throws.
    return { blocked: true, active_sessions: -1 };
  }
  const n = typeof value === 'number' ? Math.floor(value) : value === true ? 1 : 0;
  if (!Number.isFinite(n) || n <= 0) return { blocked: false, active_sessions: 0 };
  return { blocked: true, active_sessions: Math.min(n, 2000) };
}
/**
 * @param {ActivationInterlock} interlock
 */
export function activationBusyError(interlock) {
  const n = interlock && typeof interlock.active_sessions === 'number' ? interlock.active_sessions : -1;
  const detail = n >= 0 ? `${n} interactive session(s) live` : 'session liveness unknown';
  const error = /** @type {Error & {code?: string}} */ (
    new Error(`CLIENT_BUSY: OTA activation deferred (${detail}) — safe_to_retry when idle`)
  );
  error.code = 'CLIENT_BUSY';
  return error;
}
/**
 * @param {unknown} error
 * @returns {boolean} true when the error is an interlock (busy) refusal.
 */
export function isActivationBusyError(error) {
  if (!error) return false;
  if (
    typeof error === 'object' &&
    /** @type {{code?: unknown}} */ (error).code === 'CLIENT_BUSY'
  )
    return true;
  const message = error instanceof Error ? error.message : String(error);
  return message.startsWith('CLIENT_BUSY');
}
/**
 * @typedef {object} ActivationOptions
 * @property {ReturnType<typeof import('../client/nc-paths.mjs').ncLayout>} [layout]
 * @property {string} [clientId]
 * @property {number|null} [serviceUid]
 * @property {number|null} [serviceGid]
 * @property {(() => unknown)|null} [hasLiveSessions] interlock probe (see activationInterlock).
 */
/**
 * @typedef {object} UpdateActivation
 * @property {string} version
 * @property {string} app_dir
 * @property {string} previous_dir
 * @property {string} failed_dir
 * @property {string} healthy_marker
 * @property {string} activated_at
 * @property {boolean} [rolled_back]
 */
/**
 * @param {unknown} result
 * @param {ActivationOptions} [options]
 * @returns {Promise<UpdateActivation>}
 */
export async function activatePreparedUpdate(
  result,
  { layout = ncLayout(), clientId = '', serviceUid = null, serviceGid = null, hasLiveSessions = null } = {}
) {
  // Interlock first: a refused activation must leave zero state behind
  // (no prune, no state file, no swap) so retrying later is always safe.
  const interlock = await activationInterlock({ hasLiveSessions });
  if (interlock.blocked) throw activationBusyError(interlock);
  const resultRecord = /** @type {{result_payload?: {version?: unknown, stage_dir?: unknown}}} */ (
    result || {}
  );
  const version = String(resultRecord.result_payload?.version || ''),
    stage = String(resultRecord.result_payload?.stage_dir || '');
  const releasePrefix = path.resolve(layout.clientReleases) + path.sep;
  if (!validVersion(version) || !path.resolve(stage).startsWith(releasePrefix))
    throw new Error('INVALID_UPDATE_ACTIVATION');
  const stamp = Date.now(),
    previous = path.join(layout.clientBackups, `previous-${stamp}`),
    failed = path.join(layout.clientBackups, `failed-${stamp}`);
  // The posix rollback loop taught us backups grow unbounded (130+ dirs on
  // a stuck host). Cap generations best-effort on every activation.
  try {
    await pruneOldBackups(layout.clientBackups, 10);
  } catch {}
  const marker = path.join(layout.data, `healthy-${version}-${stamp}`);
  await fs.mkdir(layout.clientBackups, { recursive: true });
  await fs.mkdir(layout.data, { recursive: true });
  const activation = {
    version,
    app_dir: layout.app,
    previous_dir: previous,
    failed_dir: failed,
    healthy_marker: marker,
    activated_at: new Date().toISOString()
  };
  await fs.writeFile(layout.updateState, JSON.stringify(activation, null, 2) + '\n', {
    mode: 0o640
  });
  if (process.platform === 'win32') {
    const watchdog = path.join(layout.tmp, `watchdog-${stamp}.mjs`);
    await fs.mkdir(layout.tmp, { recursive: true });
    const supervisor = path.join(layout.root, 'nc-supervisor.ps1'),
      supervisorMjs = path.join(layout.root, 'nc-supervisor.mjs'),
      lock = path.join(layout.data, 'update-switch.lock');
    if (!(await exists(supervisor)) && !(await exists(supervisorMjs)))
      throw new Error('WINDOWS_UPDATE_SUPERVISOR_REQUIRED');
    await fs.writeFile(lock, `update ${version}\n`, { mode: 0o640 });
    // Refresh the installed supervisor from the embedded copy (node-only
    // template). Safe on rollback too (the previous tree runs the same).
    try {
      await fs.writeFile(path.join(layout.root, 'nc-supervisor.ps1'), WINDOWS_SUPERVISOR_TEMPLATE, {
        mode: 0o640
      });
    } catch {}
    // Invisible-launch model: refresh the node supervisor/broker the same way.
    try {
      await fs.writeFile(
        path.join(layout.root, 'nc-supervisor.mjs'),
        WINDOWS_SUPERVISOR_MJS_TEMPLATE,
        {
          mode: 0o640
        }
      );
    } catch {}
    try {
      await fs.writeFile(
        path.join(layout.root, 'nc-gui-broker.mjs'),
        WINDOWS_GUI_BROKER_MJS_TEMPLATE,
        {
          mode: 0o640
        }
      );
    } catch {}
    // Refresh the interactive GUI broker the same way: a stale broker file
    // (wrong root, old queue protocol) fails GUI tools with no other trace.
    try {
      await fs.writeFile(path.join(layout.root, 'nc-gui-broker.ps1'), WINDOWS_GUI_BROKER_TEMPLATE, {
        mode: 0o640
      });
    } catch {}
    await fs.writeFile(
      watchdog,
      windowsActivationHelperSource({
        layout,
        stage,
        previous,
        failed,
        marker,
        lock,
        parentPid: process.pid,
        supervisorTemplate: WINDOWS_SUPERVISOR_TEMPLATE,
        supervisorMjsTemplate: WINDOWS_SUPERVISOR_MJS_TEMPLATE
      }),
      { mode: 0o700 }
    );
    const child = spawn(process.execPath, [watchdog], {
      cwd: layout.root,
      detached: true,
      stdio: 'ignore',
      windowsHide: true
    });
    child.unref();
    setTimeout(() => process.kill(process.pid, 'SIGTERM'), 800).unref();
    return activation;
  }
  await swapAppContents(stage, { layout, previous });
  // Faz 10 (+helper-upgrade fix): reconcile the Linux privileged helper
  // after every activation. Root system installs provision directly;
  // unprivileged agents route the upgrade through the already-running root
  // daemon (poke → daemon restarts into the new tree → boot reconciler
  // refreshes binaries/units). Every outcome lands in an explicit
  // agent-visible state file — never a silent skip.
  try {
    const { ensureLinuxHelperPostSwap, HELPER_UPGRADE_STATE_FILE } = await import(
      './privileged-helper-provision.mjs'
    );
    const helperUpgrade = await ensureLinuxHelperPostSwap({
      layout,
      clientId,
      serviceUid: serviceUid ?? (typeof process.getuid === 'function' ? process.getuid() : 0),
      serviceGid: serviceGid ?? (typeof process.getgid === 'function' ? process.getgid() : 0),
      version
    });
    try {
      const { appendFile, writeFile } = await import('node:fs/promises');
      if (helperUpgrade?.state) {
        await writeFile(
          path.join(layout.data, HELPER_UPGRADE_STATE_FILE),
          JSON.stringify(helperUpgrade.state, null, 2) + '\n',
          { mode: 0o640 }
        );
      }
      if (
        helperUpgrade &&
        helperUpgrade.status !== 'provisioned' &&
        helperUpgrade.status !== 'current'
      ) {
        await appendFile(
          path.join(layout.data, 'update.log'),
          `${new Date().toISOString()} helper-upgrade ${helperUpgrade.status}: ${helperUpgrade.reason || 'unknown'} action=${helperUpgrade.action || 'none'}\n`
        );
      }
    } catch {}
  } catch {}
  // Drop the legacy bundled runtime from the live tree (SEA exe era).
  // Best-effort: it may be the running image on exe-booted hosts, in which
  // case the file is locked and a later update removes it.
  try {
    await fs.rm(path.join(layout.app, 'nc-agent.exe'), { force: true });
  } catch {}
  return superviseActivation({ layout, previous, failed, marker, activation });
}

/**
 * Supervise a freshly swapped app tree: boot it, wait for the healthy
 * marker, roll back to the previous tree when it never arrives. Runs in the
 * updating (proven-stable) process so service managers cannot reap the
 * supervisor along with the old release. Exported for tests (killSelf=false
 * keeps the test runner alive).
 * @param {object} args
 * @param {ReturnType<typeof import('../client/nc-paths.mjs').ncLayout>} args.layout
 * @param {string} args.previous
 * @param {string} args.failed
 * @param {string} args.marker
 * @param {UpdateActivation} args.activation
 * @param {string} [args.entry]
 * @param {number} [args.timeoutMs]
 * @param {boolean} [args.killSelf]
 * @returns {Promise<UpdateActivation>}
 */
export async function superviseActivation({
  layout,
  previous,
  failed,
  marker,
  activation,
  entry = path.join(layout.app, 'launcher.mjs'),
  timeoutMs = 30000,
  killSelf = true
} = /** @type {any} */ ({})) {
  // In-process supervision (replaces the detached watchdog file): the
  // updater is the proven-stable old release, so IT watches for the healthy
  // marker instead of a detached child that service managers can reap with the service.
  // Rationale (2026-09-10 Ubuntu brick): systemd kills the whole service cgroup on main-process exit, murdering
  // detached watchdogs before their 25s sleep elapses — rollback never ran
  // and the host crash-looped. launchd hosts were unaffected, which is why
  // CI plus Mac fleets never caught it.
  //
  // Lock handoff (2026-09-10 posix fleet freeze): the old process holds the
  // singleton client lock, and the staged child requires it at boot. Spawn
  // while holding it and the child dies with NC_CLIENT_ALREADY_RUNNING —
  // no marker, guaranteed rollback, silent 5-minute loop. Release first;
  // the old process is minutes from SIGTERM and needs no lock for watching.
  try {
    await releaseHeldLock(layout.lockFile);
  } catch {}
  const supervised = spawn(process.execPath, [entry], {
    detached: true,
    stdio: 'ignore',
    windowsHide: true
  });
  supervised.unref();
  const bye = () => {
    if (killSelf) setTimeout(() => process.kill(process.pid, 'SIGTERM'), 800).unref();
  };
  const marked = await waitForFile(marker, timeoutMs);
  if (marked) {
    bye();
    return activation;
  }
  // No marker: the new release failed to boot healthy. Roll back to the
  // previous tree (proven running minutes ago), clear the pending state so
  // the restored release boots clean, and exit for the supervisor to relaunch.
  try {
    supervised.kill('SIGKILL');
  } catch {}
  await moveDirContents(layout.app, failed);
  await moveDirContents(previous, layout.app);
  try {
    await fs.rm(layout.updateState, { force: true });
  } catch {}
  bye();
  return { ...activation, rolled_back: true };
}

export async function markUpdateHealthy(layout = ncLayout(), version = '') {
  try {
    const p = JSON.parse(await fs.readFile(layout.updateState, 'utf8'));
    if (p.version !== version || p.app_dir !== layout.app || !p.healthy_marker) return false;
    await fs.writeFile(p.healthy_marker, new Date().toISOString() + '\n', { mode: 0o640 });
    // Consume the activation record: the job is done, and a leftover would
    // confuse the next boot (plus it pins a backup generation forever).
    try {
      await fs.rm(layout.updateState, { force: true });
    } catch {}
    return true;
  } catch {
    return false;
  }
}

/**
 * Poll for a file up to timeoutMs. Used by in-process update supervision
 * (the updater itself watches for the healthy marker instead of spawning a
 * detached watchdog that service managers can reap with the service).
 */
async function waitForFile(marker, timeoutMs) {
  const deadline = Date.now() + Math.max(1000, timeoutMs);
  for (;;) {
    try {
      await fs.access(marker);
      return true;
    } catch {}
    if (Date.now() >= deadline) return false;
    await new Promise((r) => setTimeout(r, 500));
  }
}

export function updaterPolicy(layout = ncLayout()) {
  return {
    integrity: 'sha256',
    activation: 'idle-only-after-result-ack',
    rollback: '30s in-process supervision (posix) / supervisor script (win32)',
    root: layout.root,
    app_dir: layout.app,
    releases_dir: layout.clientReleases,
    backups_dir: layout.clientBackups,
    mutable_data_outside_app: true
  };
}
