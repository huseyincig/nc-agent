import fs from 'node:fs';
import { runPrivilegedCapture } from './privileged-helper-spawn.mjs';

const MAX_OUTPUT = 1024 * 1024;
const UNINSTALL_TIMEOUT_MS = 120000;
/**
 * @param {unknown} payload
 */
function validatePayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  const allowed = ['command', 'cwd', 'timeout_seconds'];
  if (Object.keys(rec).some((k) => !allowed.includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (typeof rec.command !== 'string' || !rec.command.trim() || rec.command.length > 65536)
    throw new Error('PRIVILEGED_COMMAND_INVALID');
  const cwd = rec.cwd ?? '/opt/nc';
  if (typeof cwd !== 'string' || !cwd.startsWith('/') || cwd.length > 4096)
    throw new Error('PRIVILEGED_CWD_INVALID');
  const timeout = Number(rec.timeout_seconds ?? 30);
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 3600)
    throw new Error('PRIVILEGED_TIMEOUT_INVALID');
  return { command: rec.command, cwd, timeout };
}
/**
 * @param {unknown} payload
 */
export async function executeLinuxPrivilegedShell(payload) {
  const { command, cwd, timeout } = validatePayload(payload),
    started = Date.now();
  // Detached group kill (tree:true): the timeout watchdog resolves by
  // itself and SIGTERM-escalates the whole group — grandchildren holding
  // pipes can no longer hang the daemon into an IPC timeout + orphan.
  const r = await runPrivilegedCapture('/bin/sh', ['-lc', command], {
    cwd,
    timeoutMs: timeout * 1000,
    killGraceMs: 3000,
    detached: true,
    tree: true,
    inheritEnv: false,
    maxChars: MAX_OUTPUT,
    maxOutChars: MAX_OUTPUT,
    platform: 'linux'
  });
  const duration_ms = Date.now() - started;
  const base = {
    stdout: r.stdout,
    stderr: r.stderr,
    duration_ms,
    stdout_truncated: r.stdoutTruncated,
    stderr_truncated: r.stderrTruncated
  };
  if (r.error)
    return { ...base, status: 'failed', exit_code: null, error: 'PRIVILEGED_EXEC_SPAWN_FAILED' };
  if (r.timedOut)
    return { ...base, status: 'timeout', exit_code: r.code ?? null, error: 'PRIVILEGED_EXEC_TIMEOUT' };
  const code = r.code;
  return {
    ...base,
    status: code === 0 ? 'completed' : 'failed',
    exit_code: code ?? null,
    error: code === 0 ? null : 'PRIVILEGED_EXEC_NONZERO'
  };
}
/**
 * Path-based denylist for file_permissions operations.
 * Paths matching these patterns are rejected to prevent privilege escalation.
 */
const FILE_PERMS_BACKUP_SUFFIX = '(?:-|~|\\.(?:old|bak|orig|rej|dpkg-dist|dpkg-old|ucf-dist|ucf-old|rpmnew|rpmsave))?';
const FILE_PERMS_DENYLIST_RE = new RegExp(
  '^\\/((etc\\/(shadow|gshadow|group|passwd|sudoers|ssh|pam\\.d|ssl\\/private)' +
    FILE_PERMS_BACKUP_SUFFIX +
    ')|bin|sbin|usr\\/(bin|sbin)|boot|dev|proc|sys|opt\\/nc\\/(libexec|config))(\\/|$)'
);

/**
 * Lexical canonicalization for denylist matching: collapse duplicate
 * slashes and drop '.' segments. '//etc/shadow', '/etc//shadow' and
 * '/etc/./shadow' all reach /etc/shadow through kernel path resolution
 * while evading an anchored denylist. '..' segments are NOT resolved here
 * (the explicit '..' rejection at the call site stays authoritative).
 * @param {string} target
 */
function normalizePosixDenyTarget(target) {
  const parts = [];
  for (const seg of String(target || '').replace(/\/{2,}/g, '/').split('/')) {
    if (seg === '.' || (seg === '' && parts.length > 0)) continue;
    parts.push(seg);
  }
  const out = parts.join('/');
  return out || '/';
}
/**
 * Resolve symlinks to the operated path: chmod/chown follow links, so a
 * lexical denylist test alone is bypassed by link -> /etc/shadow.
 * Falls back to the lexical target when resolution fails (missing file:
 * the exec then fails closed with success:false as before).
 * @param {string} target
 */
function resolveOperatedPath(target) {
  try {
    return fs.realpathSync(target);
  } catch {
    return target;
  }
}
/**
 * V-32.11: narrow the realpath-check -> chmod/chown-exec TOCTOU window.
 * Re-resolve immediately before exec and refuse when the resolution moved
 * (symlink swapped after the initial gate). This cannot close the race
 * fully — chmod/chown take a path, not an fd, and Node's fs.chmod follows
 * symlinks (no O_NOFOLLOW chmod) — but it shrinks the window from
 * milliseconds (stat + validation in between) to microseconds and turns a
 * detected swap into a fail-closed denial. Residual accepted-risk: a swap
 * in the final microseconds still redirects a root chmod/chown; see the
 * call sites. Recursive ops additionally refuse symlink-containing trees.
 * @param {string} target lexical target
 * @param {string} execTarget previously resolved target
 * @returns {string} fresh resolution (== execTarget when stable)
 */
function revalidateOperatedPath(target, execTarget) {
  // P2-03 (fail-closed): a realpath failure here must DENY, never fall back
  // to the lexical target. Falling back waved a missing file through to
  // exec, so an ENOENT-then-recreate-as-symlink plant between the initial
  // gate and this check reached a root chmod/chown. Missing/unresolvable
  // at exec time now throws PRIVILEGED_PATH_DENIED (callers already map
  // that to a denial; plain chmod-on-missing still returns success:false
  // only when the path resolved identically at both checks).
  let fresh;
  try {
    fresh = fs.realpathSync(target);
  } catch {
    throw new Error('PRIVILEGED_PATH_DENIED');
  }
  if (fresh !== execTarget) throw new Error('PRIVILEGED_PATH_DENIED');
  return fresh;
}
/**
 * Refuse recursive operations over trees containing symlinks: chmod -R
 * follows links encountered during traversal, so a planted link inside an
 * allowed directory would redirect a root chmod/chown outside the gated
 * tree. Uses lstat semantics (never follows). Bounded: absurdly deep
 * trees fail closed rather than stalling the daemon event loop.
 * @param {string} target
 */
function assertNoSymlinksRecursive(target) {
  const stack = [target];
  let dirs = 0;
  while (stack.length) {
    const cur = /** @type {string} */ (stack.pop());
    let entries;
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue; // unreadable entries fail closed at exec time
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) throw new Error('PRIVILEGED_PATH_DENIED');
      if (entry.isDirectory()) {
        if (++dirs > 100000) throw new Error('PRIVILEGED_PATH_DENIED');
        stack.push(`${cur}/${entry.name}`);
      }
    }
  }
}
/**
 * SUID/SGID bit mask — these bits must never be set through file_permissions.
 */
const UNSAFE_MODE_BITS = 0o6000; // SUID (04000) + SGID (02000)
/**
 * Reject chmod modes that could set SUID/SGID. Any-width octal is checked
 * numerically (a 5-digit '04644' must not slip past a 3-4 char pattern);
 * symbolic clauses are scanned per [ugoa]*[+-=]: '+'/'=' with s/S can set
 * the bits and are rejected, while '-' only removes them and stays allowed.
 * @param {string} mode
 */
function assertSafeUnixMode(mode) {
  if (/^[0-7]+$/.test(mode)) {
    const numeric = parseInt(mode, 8);
    if (Number.isFinite(numeric) && (numeric & UNSAFE_MODE_BITS) !== 0)
      throw new Error('PRIVILEGED_UNSAFE_MODE');
    return;
  }
  for (const clause of mode.split(',')) {
    const m = /^([ugoa]*)([+=-])(.*)$/.exec(clause);
    if (!m) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    if ((m[2] === '+' || m[2] === '=') && /[sS]/.test(m[3]))
      throw new Error('PRIVILEGED_UNSAFE_MODE');
  }
}

/**
 * Validate and execute file permission changes (chmod/chown) via the
 * privileged helper. Argv-only, never a shell. Path denylist and SUID
 * restrictions are enforced.
 * @param {unknown} payload
 */
export async function executeLinuxFilePermissions(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  const keys = Object.keys(rec);
  if (keys.some((k) => !['action', 'target', 'mode', 'owner', 'group', 'recursive'].includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const action = String(rec.action || '');
  if (action !== 'chmod' && action !== 'chown')
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  const target = String(rec.target || '');
  if (!target || !target.startsWith('/') || target.length > 4096)
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (target.includes('/../') || target.endsWith('/..') || target === '/..')
    throw new Error('PRIVILEGED_PATH_DENIED');
  if (FILE_PERMS_DENYLIST_RE.test(normalizePosixDenyTarget(target)))
    throw new Error('PRIVILEGED_PATH_DENIED');
  const recursive = rec.recursive === true;
  // Operate on the resolved path (chmod/chown follow symlinks) and test
  // THAT against the denylist; fall back to the lexical form only when
  // resolution fails so missing files keep the success:false contract.
  const execTarget = resolveOperatedPath(target);
  if (execTarget !== target && FILE_PERMS_DENYLIST_RE.test(execTarget))
    throw new Error('PRIVILEGED_PATH_DENIED');
  if (recursive) assertNoSymlinksRecursive(execTarget);
  // stat the file first to capture previous state
  const statR = await runLinuxCapture('stat', ['-c', '%a:%U:%G', execTarget]);
  let previousMode = null;
  let previousOwner = null;
  if (statR.code === 0 && statR.out) {
    const parts = statR.out.split(':');
    previousMode = parts[0] || null;
    previousOwner = parts[1] || null;
  }
  if (action === 'chmod') {
    const mode = String(rec.mode || '');
    if (!mode || mode.length > 32) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    assertSafeUnixMode(mode);
    // '--' ends option parsing: a mode/owner starting with '-' is an
    // operand, never a flag (e.g. mode '-R' must not enable recursion).
    const args = recursive ? ['-R', '--', mode, execTarget] : ['--', mode, execTarget];
    // V-32.11: revalidate immediately before exec (see helper above).
    revalidateOperatedPath(target, execTarget);
    const r = await runLinuxCapture('chmod', args, { timeoutMs: 30000 });
    if (r.error) throw new Error(`PRIVILEGED_CHMOD_FAILED:${r.error}`.slice(0, 200));
    if (r.code !== 0)
      return { action, target, success: false, message: (r.out || `chmod exited ${r.code}`).slice(0, 2000) };
    // stat again for current mode
    const afterR = await runLinuxCapture('stat', ['-c', '%a', execTarget]);
    return {
      action,
      target,
      success: true,
      previous_mode: previousMode,
      current_mode: afterR.code === 0 ? afterR.out.trim() : null,
      previous_owner: null,
      current_owner: null
    };
  }
  // chown
  const owner = String(rec.owner || '');
  if (!owner || owner.length > 256) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const group = rec.group != null ? String(rec.group) : null;
  if (group && group.length > 256) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const chownArg = group ? `${owner}:${group}` : owner;
  const args = recursive ? ['-R', '--', chownArg, execTarget] : ['--', chownArg, execTarget];
  // V-32.11: revalidate immediately before exec (see helper above).
  revalidateOperatedPath(target, execTarget);
  const r = await runLinuxCapture('chown', args, { timeoutMs: 30000 });
  if (r.error) throw new Error(`PRIVILEGED_CHOWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code !== 0)
    return { action, target, success: false, message: (r.out || `chown exited ${r.code}`).slice(0, 2000) };
  const afterR = await runLinuxCapture('stat', ['-c', '%U:%G', execTarget]);
  return {
    action,
    target,
    success: true,
    previous_mode: null,
    current_mode: null,
    previous_owner: previousOwner,
    current_owner: afterR.code === 0 ? afterR.out.trim() : null
  };
}
export function linuxPrivilegedHelperHandlers({ uninstallScript = '/opt/nc/uninstall.sh' } = {}) {
  return Object.freeze({
    privileged_shell_exec: executeLinuxPrivilegedShell,
    service_control: executeLinuxServiceControl,
    container_control: executeLinuxContainerControl,
    compose_control: executeLinuxComposeControl,
    package_control: executeLinuxPackageControl,
    system_log_read: executeLinuxSystemLogRead,
    file_permissions: executeLinuxFilePermissions,
    client_uninstall: (/** @type {unknown} */ payload) =>
      executeLinuxPrivilegedUninstall(payload, { script: uninstallScript })
  });
}

const SERVICE_CONTROL_OPS = Object.freeze(['start', 'stop', 'restart']);
// First character excludes '-' and ':': the unit reaches systemctl argv in
// option position, so a leading dash would parse as a flag. Legitimate
// units never start with '-' or ':'.
const SERVICE_CONTROL_UNIT_RE = /^[A-Za-z0-9_@.][\w@.\-:]{0,255}$/;
/**
 * Dedicated allowlisted service verbs via systemctl. The unit/op arrive in
 * the centrally-signed envelope (already policy-bound); the daemon
 * re-validates defensively and spawns systemctl with argv (never a shell),
 * so a signed envelope cannot become arbitrary privileged execution.
 * Systemctl failures are RETURNED (not thrown) so the model sees the real
 * reason; unexpected failures throw into PRIVILEGED_HELPER_EXECUTION_FAILED.
 *
 * @param {unknown} payload
 */
export async function executeLinuxServiceControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (!SERVICE_CONTROL_OPS.includes(/** @type {string} */ (rec.op)))
    throw new Error('PRIVILEGED_SERVICE_OP_INVALID');
  if (typeof rec.unit !== 'string' || !SERVICE_CONTROL_UNIT_RE.test(rec.unit))
    throw new Error('PRIVILEGED_SERVICE_UNIT_INVALID');
  const { op, unit } = { op: String(rec.op), unit: String(rec.unit) };
  const r = await runPrivilegedCapture('systemctl', [op, unit], {
    timeoutMs: 30000,
    platform: 'linux'
  });
  if (r.error) return { unit, op, success: false, message: String(r.error).slice(0, 2000) };
  const scText = r.out.slice(0, 2000);
  if (r.timedOut)
    return {
      unit,
      op,
      success: false,
      message: `SERVICE_CONTROL_TIMEOUT: ${scText || `systemctl ${op} timed out after 30s`}`.slice(0, 2000)
    };
  if (r.code === 0) return { unit, op, success: true, message: scText || null };
  return { unit, op, success: false, message: scText || `systemctl ${op} exited with code ${r.code}` };
}

/**
 * Execute the canonical platform uninstall script. The script path is fixed
 * by the daemon wiring (never taken from the request) so a signed envelope
 * cannot redirect privileged execution anywhere else. Note the script stops
 * the agent itself, so a successful run is observed centrally as the host
 * going dark rather than as a delivered job result.
 *
 * @param {unknown} _payload (ignored by design)
 * @param {object} [options]
 * @param {string} [options.script]
 */
export async function executeLinuxPrivilegedUninstall(
  _payload,
  { script = '/opt/nc/uninstall.sh' } = {}
) {
  const started = Date.now();
  if (!fs.existsSync(script)) {
    return Promise.resolve({
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      duration_ms: 0,
      error: 'PRIVILEGED_UNINSTALL_SCRIPT_MISSING',
      stdout_truncated: false,
      stderr_truncated: false
    });
  }
  // Spawn the script directly so the kernel honors its shebang
  // (uninstall-linux.sh requires bash; forcing /bin/sh is undefined).
  // Never hangs: the watchdog resolves by itself (a wedged uninstall used
  // to pin the daemon until the agent IPC timed out, orphaning the run).
  const r = await runPrivilegedCapture(script, [], {
    timeoutMs: UNINSTALL_TIMEOUT_MS,
    inheritEnv: false,
    maxChars: MAX_OUTPUT,
    maxOutChars: MAX_OUTPUT,
    platform: 'linux'
  });
  const base = {
    stdout: r.stdout,
    stderr: r.stderr,
    duration_ms: Date.now() - started,
    stdout_truncated: r.stdoutTruncated,
    stderr_truncated: r.stderrTruncated
  };
  if (r.error)
    return { ...base, status: 'failed', exit_code: null, error: 'PRIVILEGED_EXEC_SPAWN_FAILED' };
  if (r.timedOut)
    return { ...base, status: 'timeout', exit_code: r.code ?? null, error: 'PRIVILEGED_EXEC_TIMEOUT' };
  return {
    ...base,
    status: r.code === 0 ? 'completed' : 'failed',
    exit_code: r.code ?? null,
    error: r.code === 0 ? null : 'PRIVILEGED_UNINSTALL_NONZERO'
  };
}

const LINUX_CONTAINER_ACTIONS = Object.freeze(['list', 'inspect', 'logs']);
const LINUX_CONTAINER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.\-]{0,255}$/;
const LINUX_COMPOSE_ACTIONS = Object.freeze([
  'list',
  'up',
  'down',
  'restart',
  'pull',
  'stop',
  'start'
]);
const LINUX_PACKAGE_ACTIONS = Object.freeze(['list', 'install', 'remove']);
const LINUX_PACKAGE_MANAGERS = Object.freeze(['auto', 'apt', 'dnf', 'apk', 'pacman', 'zypper']);
const LINUX_PACKAGE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9+_.:~-]{0,127}$/;
const LINUX_LOG_SOURCES = Object.freeze(['system', 'service', 'kernel', 'application']);
const LINUX_LOG_LEVELS = Object.freeze(['all', 'info', 'warning', 'error']);
const LINUX_LOG_UNIT_RE = /^[\w@.\-:]{1,128}$/;

/**
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {object} [options]
 * @param {number} [options.timeoutMs]
 * @param {Record<string, string>} [options.env]
 * @param {string} [options.cwd]
 */
async function runLinuxCapture(cmd, args, { timeoutMs = 30000, env = null, cwd = null } = {}) {
  // Hardened delegate: the old inline version resolved only on `close`, so
  // a killed child with pipe-holding grandchildren hung the daemon until
  // the agent IPC watchdog fired (timeout + orphan). Same {code,out,error}
  // shape, plus timedOut for callers that want the explicit signal.
  const r = await runPrivilegedCapture(cmd, args, { timeoutMs, env, cwd, platform: 'linux' });
  return { code: r.code, out: r.out, error: r.error, timedOut: r.timedOut };
}

/**
 * Bounded container-runtime operations via the docker binary with an
 * explicit daemon socket. Argv only, never a shell. Validation failures
 * throw; engine failures are RETURNED so the model sees the real reason.
 * @param {unknown} payload
 */
export async function executeLinuxContainerControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  const keys = Object.keys(rec);
  if (keys.some((k) => !['action', 'container_name', 'tail'].includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const action = String(rec.action || '');
  if (!LINUX_CONTAINER_ACTIONS.includes(action))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  const env = { DOCKER_HOST: 'unix:///var/run/docker.sock' };
  if (action === 'list') {
    const r = await runLinuxCapture('docker', ['ps', '-a', '--format', '{{json .}}'], { env });
    if (r.error) throw new Error(`PRIVILEGED_CONTAINER_SPAWN_FAILED:${r.error}`.slice(0, 200));
    if (r.code === 0)
      return { engine: 'docker', action, success: true, output_tail: r.out.slice(-8000) || null };
    return {
      engine: 'docker',
      action,
      success: false,
      message: (r.out || `docker ps exited ${r.code}`).slice(0, 2000)
    };
  }
  const containerName = String(rec.container_name || '');
  if (!LINUX_CONTAINER_NAME_RE.test(containerName)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (action === 'inspect') {
    const r = await runLinuxCapture('docker', ['inspect', containerName], { env });
    if (r.error) throw new Error(`PRIVILEGED_CONTAINER_SPAWN_FAILED:${r.error}`.slice(0, 200));
    if (r.code === 0)
      return {
        engine: 'docker',
        action,
        container: containerName,
        success: true,
        output_tail: r.out.slice(-8000) || null
      };
    return {
      engine: 'docker',
      action,
      container: containerName,
      success: false,
      message: (r.out || `docker inspect exited ${r.code}`).slice(0, 2000)
    };
  }
  const tail = rec.tail == null ? 200 : Number(rec.tail);
  if (!Number.isInteger(tail) || tail < 1 || tail > 2000)
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const r = await runLinuxCapture('docker', ['logs', '--tail', String(tail), containerName], {
    env
  });
  if (r.error) throw new Error(`PRIVILEGED_CONTAINER_SPAWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code === 0)
    return {
      engine: 'docker',
      action,
      container: containerName,
      success: true,
      output_tail: r.out.slice(-8000) || null
    };
  return {
    engine: 'docker',
    action,
    container: containerName,
    success: false,
    message: (r.out || `docker logs exited ${r.code}`).slice(0, 2000)
  };
}

/**
 * Bounded compose operations via the docker compose plugin. Argv only.
 * @param {unknown} payload
 */
export async function executeLinuxComposeControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (Object.keys(rec).some((k) => !['action', 'project_dir'].includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const action = String(rec.action || '').toLowerCase();
  if (!LINUX_COMPOSE_ACTIONS.includes(action))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  const env = { DOCKER_HOST: 'unix:///var/run/docker.sock' };
  if (action === 'list') {
    const r = await runLinuxCapture('docker', ['compose', 'ls', '--format', 'json'], { env });
    if (r.error) throw new Error(`PRIVILEGED_COMPOSE_SPAWN_FAILED:${r.error}`.slice(0, 200));
    if (r.code === 0)
      return { frontend: 'docker compose', action, success: true, output_tail: r.out.slice(-8000) || null };
    return {
      frontend: 'docker compose',
      action,
      success: false,
      message: (r.out || `docker compose ls exited ${r.code}`).slice(0, 2000)
    };
  }
  const projectDir = String(rec.project_dir || '');
  if (!projectDir || projectDir.length > 4096 || projectDir.includes('\0'))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (!projectDir.startsWith('/')) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const args = ['compose'];
  if (action === 'up') args.push('up', '-d');
  else args.push(action);
  const r = await runLinuxCapture('docker', args, { env, cwd: projectDir, timeoutMs: 600000 });
  if (r.error) throw new Error(`PRIVILEGED_COMPOSE_SPAWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code === 0)
    return {
      frontend: 'docker compose',
      action,
      project_dir: projectDir,
      success: true,
      output_tail: r.out.slice(-4096) || null
    };
  return {
    frontend: 'docker compose',
    action,
    project_dir: projectDir,
    success: false,
    message: (r.out || `docker compose ${action} exited ${r.code}`).slice(0, 2000)
  };
}

/**
 * @param {string} manager
 */
function resolveLinuxPackageManager(manager) {
  if (manager !== 'auto') return manager;
  if (fs.existsSync('/usr/bin/apt-get')) return 'apt';
  if (fs.existsSync('/usr/bin/dnf')) return 'dnf';
  if (fs.existsSync('/sbin/apk') || fs.existsSync('/usr/bin/apk')) return 'apk';
  if (fs.existsSync('/usr/bin/pacman')) return 'pacman';
  if (fs.existsSync('/usr/bin/zypper')) return 'zypper';
  throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
}

/**
 * Bounded system-scope package operations. Argv only, never a shell.
 * brew/winget are not supported on Linux.
 * @param {unknown} payload
 */
export async function executeLinuxPackageControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (Object.keys(rec).some((k) => !['action', 'manager', 'name', 'contains', 'limit'].includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const action = String(rec.action || '').toLowerCase();
  if (!LINUX_PACKAGE_ACTIONS.includes(action))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  const managerRaw = String(rec.manager || 'auto').toLowerCase();
  if (!LINUX_PACKAGE_MANAGERS.includes(managerRaw))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  if (managerRaw === 'brew' || managerRaw === 'winget')
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  const manager = resolveLinuxPackageManager(managerRaw);
  if (action === 'list') {
    let cmd = 'dpkg-query';
    let args = ['-W', "-f=${Package}\t${Version}\n"];
    if (manager === 'dnf' || manager === 'zypper') {
      cmd = 'rpm';
      args = ['-qa', '--queryformat', '%{NAME}\t%{VERSION}-%{RELEASE}\n'];
    } else if (manager === 'apk') {
      cmd = 'apk';
      args = ['info', '-v'];
    } else if (manager === 'pacman') {
      cmd = 'pacman';
      args = ['-Q'];
    }
    if (rec.contains != null) {
      const contains = String(rec.contains);
      if (!contains || contains.length > 128) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    }
    if (rec.limit != null) {
      const limit = Number(rec.limit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000)
        throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    }
    const r = await runLinuxCapture(cmd, args, { timeoutMs: 30000 });
    if (r.error) throw new Error(`PRIVILEGED_PACKAGE_SPAWN_FAILED:${r.error}`.slice(0, 200));
    if (r.code === 0)
      return { manager, action, success: true, output_tail: r.out.slice(-8000) || null };
    return {
      manager,
      action,
      success: false,
      message: (r.out || `${cmd} exited ${r.code}`).slice(0, 2000)
    };
  }
  const name = String(rec.name || '');
  if (!LINUX_PACKAGE_NAME_RE.test(name)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  let cmd;
  let args;
  if (manager === 'apt') {
    cmd = 'apt-get';
    args = action === 'install' ? ['install', '-y', name] : ['remove', '-y', name];
  } else if (manager === 'dnf') {
    cmd = 'dnf';
    args = action === 'install' ? ['install', '-y', name] : ['remove', '-y', name];
  } else if (manager === 'zypper') {
    cmd = 'zypper';
    args =
      action === 'install'
        ? ['--non-interactive', 'install', name]
        : ['--non-interactive', 'remove', name];
  } else if (manager === 'apk') {
    cmd = 'apk';
    args = action === 'install' ? ['add', name] : ['del', name];
  } else {
    cmd = 'pacman';
    args =
      action === 'install'
        ? ['-S', '--noconfirm', '--needed', name]
        : ['-R', '--noconfirm', name];
  }
  const r = await runLinuxCapture(cmd, args, { timeoutMs: 600000 });
  if (r.error) throw new Error(`PRIVILEGED_PACKAGE_SPAWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code === 0)
    return { manager, action, name, success: true, message: r.out.slice(-2000) || null };
  return {
    manager,
    action,
    name,
    success: false,
    message: (r.out || `${cmd} exited ${r.code}`).slice(0, 2000)
  };
}

/**
 * Bounded privileged system-log reads via journalctl. Argv only.
 * @param {unknown} payload
 */
export async function executeLinuxSystemLogRead(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (
    Object.keys(rec).some(
      (k) => !['source', 'unit', 'lines', 'level', 'contains', 'since'].includes(k)
    )
  )
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const source = String(rec.source || 'system').toLowerCase();
  if (!LINUX_LOG_SOURCES.includes(source))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  const args = ['--no-pager', '-o', 'short-iso'];
  if (rec.unit != null) {
    const unit = String(rec.unit);
    if (!LINUX_LOG_UNIT_RE.test(unit)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    args.push('-u', unit);
  } else if (source === 'service') {
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  }
  if (source === 'kernel') args.push('-k');
  if (rec.level != null) {
    const level = String(rec.level).toLowerCase();
    if (!LINUX_LOG_LEVELS.includes(level)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    if (level === 'error') args.push('-p', 'err');
    else if (level === 'warning') args.push('-p', 'warning');
  }
  if (rec.since != null && String(rec.since) !== '') {
    const since = String(rec.since);
    if (since.length > 64) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    args.push('--since', since.slice(0, 64));
  }
  if (rec.contains != null && String(rec.contains) !== '') {
    const contains = String(rec.contains);
    if (contains.length > 200) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    args.push('--grep', contains.slice(0, 200));
  }
  const lines = rec.lines == null ? 100 : Number(rec.lines);
  if (!Number.isInteger(lines) || lines < 1 || lines > 1000)
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  args.push('-n', String(lines));
  const r = await runLinuxCapture('journalctl', args, { timeoutMs: 30000 });
  if (r.error) throw new Error(`PRIVILEGED_LOG_SPAWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code === 0)
    return {
      source,
      unit: rec.unit != null ? String(rec.unit) : null,
      success: true,
      output_tail: r.out.slice(-8000) || null
    };
  return {
    source,
    unit: rec.unit != null ? String(rec.unit) : null,
    success: false,
    message: (r.out || `journalctl exited ${r.code}`).slice(0, 2000)
  };
}
