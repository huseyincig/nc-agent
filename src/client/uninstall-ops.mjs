import { execFileSync, spawn as nodeSpawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
/** Data-dir uninstall transcript shared by the handler (sync) and the detached trigger (async). */
function triggerLogPath() {
  try {
    if (process.platform === 'win32') {
      const base = process.env.ProgramData || 'C:\\ProgramData';
      return path.join(base, 'NC', 'data', 'uninstall-trigger.log');
    }
    return '/opt/nc/data/uninstall-trigger.log';
  } catch {
    return null;
  }
}
/** @param {string} line */
function appendTriggerLog(line) {
  try {
    const p = triggerLogPath();
    if (!p) return;
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.appendFileSync(p, line + (os.EOL || '\n'));
  } catch {}
}

/**
 * Best-effort recursive tree removal that never throws: deletes what the
 * caller can, reports the rest. `fs.rmSync(ROOT, recursive)` aborts the
 * WHOLE tree on the first privileged file (SYSTEM-owned uninstaller,
 * service exe) leaving a half-deleted host; this walker always finishes
 * and returns `{ removed, leftovers }` so the transcript (and admin sweep)
 * names exactly what stayed behind.
 * @param {string} root
 * @param {( entry : string) => void} [onLeftover]
 */
export function removeTreeBestEffort(root, onLeftover = null) {
  let removed = 0;
  /** @type {string[]} */
  const leftovers = [];
  /** @param {string} p */
  const drop = (p) => {
    let st = null;
    try {
      st = fs.lstatSync(p);
    } catch {
      return;
    }
    if (st.isDirectory() && !st.isSymbolicLink()) {
      let entries = [];
      try {
        entries = fs.readdirSync(p);
      } catch {
        leftovers.push(p);
        return;
      }
      for (const e of entries) drop(path.join(p, e));
      try {
        fs.rmdirSync(p);
        removed++;
      } catch {
        leftovers.push(p);
      }
      return;
    }
    try {
      fs.unlinkSync(p);
      removed++;
    } catch {
      leftovers.push(p);
    }
  };
  try {
    drop(root);
  } catch {
    leftovers.push(root);
  }
  if (typeof onLeftover === 'function') for (const l of leftovers) onLeftover(l);
  return { removed, leftovers };
}

/**
 * Panel-initiated uninstall triggers for unprivileged agents. The agent
 * reports completion FIRST and the privileged removal follows after a
 * delay, so the job result flushes before the tree goes away. All paths
 * are best-effort: a failed trigger simply leaves the host installed
 * (fail-closed, retryable from the panel).
 */

const completedResult = (extra = {}) => ({
  status: 'completed',
  exit_code: 0,
  stdout: '',
  stderr: '',
  error: null,
  duration_ms: 0,
  result_payload: { uninstall_initiated: true, ...extra }
});

/**
 * Windows: the installer pre-registers an on-demand SYSTEM task
 * ("NC Uninstall") with Local-Service start rights; the agent only ever
 * runs `schtasks /run` and cannot touch SCM itself.
 */
export function makeWindowsUninstallHandler({
  spawnImpl = nodeSpawn,
  execImpl = execFileSync,
  scriptPath = null
} = {}) {
  return async () => {
    // Fail loud, not silent: firing `schtasks /run` at a missing task
    // reports success while nothing happens (hosts installed before the
    // 0.4.94 installer have no "NC Uninstall" task). Check first so the
    // panel shows the real precondition instead of a phantom success.
    let taskPresent = false;
    try {
      execImpl('schtasks.exe', ['/query', '/tn', 'NC Uninstall'], {
        stdio: 'ignore',
        windowsHide: true,
        timeout: 15000
      });
      taskPresent = true;
    } catch {}
    if (!taskPresent) {
      // Task-independent fallback: the on-demand SYSTEM task is missing
      // (pre-0.4.94 install, or machine policy/AV blocks task registration).
      // When the installer granted Local Service stop+delete on the service
      // object, the agent removes its own service directly, then best-effort
      // cleans processes and tree. Task/startup leftovers may remain for an
      // admin to sweep; the host is dead either way.
      // Fire-and-forget must stay observable: a synchronous sc.exe query
      // proves (in the job result) that exec works and the service exists,
      // and every async step appends to a transcript under the data dir
      // (readable via file_read), so a silent trigger can be diagnosed
      // post-mortem instead of guessed at.
      let probe = 'sc-query-failed';
      try {
        const out = execImpl('sc.exe', ['query', 'NCClient'], {
          stdio: ['ignore', 'pipe', 'pipe'],
          windowsHide: true,
          timeout: 15000,
          encoding: 'utf8'
        });
        const text = String(out || '');
        probe = /STATE\s*:\s*4/i.test(text) ? 'service-running' : 'service-not-running';
      } catch {}
      let spawned = false;
      appendTriggerLog('handler-spawn-attempt ' + new Date().toISOString());
      // Node-based trigger (watchdog pattern): powershell spawned from the
      // agent proved stillborn on hardened hosts, while node children start
      // reliably (OTA watchdog). The script retires the supervisor via
      // retired.json, removes the service, kills the agent by PID (precise,
      // no cmdline filtering), and best-effort removes the tree.
      const nodeTrigger = [
        "import fs from 'node:fs';",
        "import path from 'node:path';",
        "import { execFileSync } from 'node:child_process';",
        `const LOG = ${JSON.stringify(triggerLogPath())};`,
        `const AGENT_PID = ${Number(process.pid) || 0};`,
        `const ROOT = ${JSON.stringify(triggerLogPath() ? path.dirname(path.dirname(triggerLogPath())) : '')};`,
        "const w = (s) => { try { fs.appendFileSync(LOG, s + '\\n'); } catch {} };",
        'const sleep = (ms) => new Promise((r) => setTimeout(r, ms));',
        "const run = (f, a) => { try { const o = execFileSync(f, a, { encoding: 'utf8', timeout: 20000, windowsHide: true }); w(f + ' ' + a.join(' ') + ' :: ' + String(o).trim().slice(0, 160)); } catch (e) { w(f + ' ' + a.join(' ') + ' FAIL ' + (e.status !== undefined ? e.status : e.message)); } };",
        '(async () => {',
        "  w('node-trigger-start ' + new Date().toISOString());",
        '  await sleep(8000);',
        "  try { fs.writeFileSync(path.join(ROOT, 'data', 'retired.json'), JSON.stringify({ retired: true, reason: 'panel-uninstall', at: new Date().toISOString() })); w('retired-written'); } catch (e) { w('retired FAIL ' + e.message); }",
        "  run('sc.exe', ['stop', 'NCClient']);",
        '  await sleep(3000);',
        "  run('sc.exe', ['delete', 'NCClient']);",
        "  try { process.kill(AGENT_PID, 'SIGTERM'); w('agent-sigterm ' + AGENT_PID); } catch (e) { w('agent-kill FAIL ' + e.message); }",
        '  await sleep(3000);',
        "  let sweep = { removed: 0, leftovers: ['unimported'] };",
        '  try {',
        "    const mod = await import('file://' + path.join(ROOT, 'app', 'uninstall-ops.mjs'));",
        "    if (mod && typeof mod.removeTreeBestEffort === 'function') {",
        "      sweep = mod.removeTreeBestEffort(ROOT, (l) => w('leftover ' + l));",
        '    }',
        "  } catch (e) { w('sweep-import FAIL ' + e.message); }",
        "  if (sweep.leftovers.length > 0 && sweep.leftovers[0] === 'unimported') {",
        "    try { fs.rmSync(ROOT, { recursive: true, force: true }); w('tree-removed'); } catch (e) { w('tree FAIL ' + e.message); }",
        '  } else {',
        "    w('tree-sweep removed=' + sweep.removed + ' leftovers=' + sweep.leftovers.length);",
        '  }',
        "  w('node-trigger-done ' + new Date().toISOString());",
        "})().catch((e) => { try { fs.appendFileSync(LOG, 'FATAL ' + (e && e.message) + '\\n'); } catch {} });"
      ].join('\n');
      try {
        const logPath = triggerLogPath();
        if (!logPath) throw new Error('no trigger log path');
        const dest = scriptPath || path.join(path.dirname(logPath), 'uninstall-trigger.mjs');
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, nodeTrigger + '\n');
        const child = spawnImpl(process.execPath, [dest], {
          cwd: path.dirname(path.dirname(logPath)),
          detached: true,
          stdio: 'ignore',
          // Sibling pattern (updater.mjs): no console window on win32.
          windowsHide: true
        });
        if (child && typeof child.unref === 'function') child.unref();
        spawned = true;
        appendTriggerLog('handler-spawn-ok');
      } catch {}
      if (!spawned) {
        return {
          status: 'failed',
          exit_code: null,
          stdout: '',
          stderr: '',
          error: 'UNINSTALL_TRIGGER_FAILED',
          duration_ms: 0,
          result_payload: { uninstall_initiated: false, mechanism: 'direct-service', probe }
        };
      }
      return completedResult({ mechanism: 'direct-service', probe });
    }
    // Preferred path: the on-demand SYSTEM task does full cleanup (service,
    // tasks, startup entry, tree) as SYSTEM. schtasks /run returns at once
    // (the task runs async), so invoke it synchronously — a throw means the
    // trigger really failed and surfaces honestly instead of phantom success.
    try {
      execImpl('schtasks.exe', ['/run', '/tn', 'NC Uninstall'], {
        stdio: 'ignore',
        windowsHide: true,
        timeout: 30000
      });
    } catch {
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: 'UNINSTALL_TRIGGER_FAILED',
        duration_ms: 0,
        result_payload: { uninstall_initiated: false, mechanism: 'scheduled-task' }
      };
    }
    return completedResult({ mechanism: 'scheduled-task' });
  };
}

/**
 * macOS: the installer leaves a sudoers rule for exactly
 * /opt/nc/uninstall.sh (NOPASSWD, root-owned 0700). No daemon, no helper.
 */
/**
 * User-mode stamp check (macOS uninstall gate): the migration removes the
 * sudoers rule, so the sudoers trigger would be a phantom success.
 * Pure for tests; the handler reads the canonical env file.
 * @param {unknown} text
 */
export function isUserModeStamp(text) {
  return /^NC_SERVICE_MODE=user/m.test(String(text || ''));
}

/**
 * Whether an env-file path names a user-mode install (installer stamp).
 * Pure read of the given file so system and user trees are distinguishable
 * per-install instead of via a hardcoded canonical path.
 * @param {string} envFile
 */
export function isUserModeInstall(envFile) {
  try {
    return isUserModeStamp(fs.readFileSync(envFile, 'utf8'));
  } catch {
    return false;
  }
}

/**
 * Safety gate for user-mode self-removal: the tree must be an absolute path
 * and never the filesystem root. System/user confusion is impossible by
 * construction — the user branch only ever stops user-scope services
 * (`systemctl --user`, per-user `launchctl bootout`) and removes the tree
 * the agent itself runs from; an unprivileged process cannot delete a
 * root-owned system tree, and user-scope service verbs cannot touch system
 * units. A contradictory empty/root path fails closed instead.
 * @param {unknown} root
 */
export function isSafeUserUninstallRoot(root) {
  if (typeof root !== 'string' || !root) return false;
  if (!path.isAbsolute(root)) return false;
  const normalized = path.normalize(root);
  if (normalized === path.parse(normalized).root) return false;
  return true;
}

/**
 * @param {unknown} value
 */
function shQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

/**
 * Delayed user-mode Linux trigger: prefer the tree's own uninstall.sh
 * (self-locating, marker-guarded, user-mode aware — exact parity with a
 * local uninstall), with an inline minimal fallback when the script is
 * absent or not executable (e.g. root-owned 0700 in migrated trees).
 * Mirrors uninstall-linux.sh user section: user bus retire, user unit
 * removal, tree removal. Never touches system units (root-only there).
 * @param {object} [options]
 * @param {string} [options.root]
 * @param {string} [options.home]
 */
export function linuxUserUninstallScript({ root = '', home = '' } = {}) {
  const r = shQuote(root);
  const unit = shQuote(path.join(home || '~', '.config/systemd/user/nc-client.service'));
  return [
    'sleep 8;',
    `ROOT=${r};`,
    'if [ -x "$ROOT/uninstall.sh" ]; then exec "$ROOT/uninstall.sh"; fi;',
    '[ -f "$ROOT/config/nc-client.env" ] || [ -d "$ROOT/app" ] || exit 0;',
    'systemctl --user stop nc-client.service >/dev/null 2>&1 || true;',
    'systemctl --user disable nc-client.service >/dev/null 2>&1 || true;',
    `rm -f ${unit} >/dev/null 2>&1 || true;`,
    'systemctl --user daemon-reload >/dev/null 2>&1 || true;',
    'rm -rf -- "$ROOT";'
  ].join(' ');
}

/**
 * Delayed user-mode macOS trigger: same prefer-script/fallback-inline
 * shape as Linux. Mirrors uninstall-macos.sh user section: gui-domain
 * bootout for the operator uid, agent plist removal, tree removal. Never
 * touches the system daemon (root-only there).
 * @param {object} [options]
 * @param {string} [options.root]
 * @param {string} [options.home]
 * @param {number|null} [options.uid]
 */
export function macosUserUninstallScript({ root = '', home = '', uid = null } = {}) {
  const r = shQuote(root);
  const plist = shQuote(path.join(home || '~', 'Library/LaunchAgents/com.nc.client.plist'));
  const bootout =
    Number.isInteger(uid) && uid !== null
      ? `launchctl bootout gui/${uid}/com.nc.client >/dev/null 2>&1 || true; launchctl disable gui/${uid}/com.nc.client >/dev/null 2>&1 || true;`
      : '';
  return [
    'sleep 8;',
    `ROOT=${r};`,
    'if [ -x "$ROOT/uninstall.sh" ]; then exec "$ROOT/uninstall.sh"; fi;',
    '[ -f "$ROOT/config/nc-client.env" ] || [ -d "$ROOT/app" ] || exit 0;',
    bootout,
    `rm -f ${plist} >/dev/null 2>&1 || true;`,
    'rm -rf -- "$ROOT";'
  ].join(' ');
}

/**
 * Linux user-mode uninstall: `systemctl --user` retire + own-tree removal
 * via a delayed detached trigger (result flushes before the tree goes
 * away). Only runs for stamped user-mode installs with a safe root;
 * anything else fails closed so an unprivileged agent can never be routed
 * into deleting a system install.
 */
export function makeLinuxUserUninstallHandler({
  spawnImpl = nodeSpawn,
  envFile = '/opt/nc/config/nc-client.env',
  root = '/opt/nc',
  home = null
} = {}) {
  return async (/** @type {unknown} */ job) => {
    void job;
    if (!isUserModeInstall(envFile)) {
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: 'UNINSTALL_MECHANISM_UNAVAILABLE',
        duration_ms: 0,
        result_payload: {
          uninstall_initiated: false,
          mechanism: 'not-user-mode'
        }
      };
    }
    if (!isSafeUserUninstallRoot(root)) {
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: 'UNINSTALL_MECHANISM_UNAVAILABLE',
        duration_ms: 0,
        result_payload: {
          uninstall_initiated: false,
          mechanism: 'unsafe-root'
        }
      };
    }
    let operatorHome = home;
    if (!operatorHome) {
      try {
        operatorHome = os.homedir();
      } catch {
        operatorHome = '';
      }
    }
    try {
      const child = spawnImpl('sh', ['-c', linuxUserUninstallScript({ root, home: operatorHome })], {
        detached: true,
        stdio: 'ignore'
      });
      if (child && typeof child.unref === 'function') child.unref();
    } catch {
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: 'UNINSTALL_TRIGGER_FAILED',
        duration_ms: 0,
        result_payload: { uninstall_initiated: false, mechanism: 'user-systemd' }
      };
    }
    return completedResult({ mechanism: 'user-systemd', mode: 'user' });
  };
}

export function makeMacosUninstallHandler({
  spawnImpl = nodeSpawn,
  envFile = '/opt/nc/config/nc-client.env',
  root = '/opt/nc',
  getUid = () => (typeof process.getuid === 'function' ? process.getuid() : null),
  home = null
} = {}) {
  return async () => {
    // User-mode installs remove the sudoers rule at migration time, so the
    // sudoers trigger would fire into the void. Route them to the
    // user-scope branch (gui-domain bootout + own-tree removal) instead of
    // failing: the operator owns the tree, no elevation needed.
    if (isUserModeInstall(envFile)) {
      if (!isSafeUserUninstallRoot(root)) {
        return {
          status: 'failed',
          exit_code: null,
          stdout: '',
          stderr: '',
          error: 'UNINSTALL_MECHANISM_UNAVAILABLE',
          duration_ms: 0,
          result_payload: {
            uninstall_initiated: false,
            mechanism: 'unsafe-root'
          }
        };
      }
      let operatorHome = home;
      if (!operatorHome) {
        try {
          operatorHome = os.homedir();
        } catch {
          operatorHome = '';
        }
      }
      let uid = null;
      try {
        uid = getUid();
      } catch {
        uid = null;
      }
      try {
        const child = spawnImpl(
          'sh',
          ['-c', macosUserUninstallScript({ root, home: operatorHome, uid })],
          {
            detached: true,
            stdio: 'ignore'
          }
        );
        if (child && typeof child.unref === 'function') child.unref();
      } catch {
        return {
          status: 'failed',
          exit_code: null,
          stdout: '',
          stderr: '',
          error: 'UNINSTALL_TRIGGER_FAILED',
          duration_ms: 0,
          result_payload: { uninstall_initiated: false, mechanism: 'user-launchctl' }
        };
      }
      return completedResult({ mechanism: 'user-launchctl', mode: 'user' });
    }
    // System path (preserved exactly): the installer leaves a sudoers rule
    // for exactly /opt/nc/uninstall.sh (NOPASSWD, root-owned 0700).
    try {
      const child = spawnImpl('sh', ['-c', 'sleep 8; exec sudo -n /opt/nc/uninstall.sh'], {
        detached: true,
        stdio: 'ignore'
      });
      if (child && typeof child.unref === 'function') child.unref();
    } catch {}
    return completedResult({ mechanism: 'sudoers' });
  };
}
