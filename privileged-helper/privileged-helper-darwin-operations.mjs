import fs from 'node:fs';
import { runPrivilegedCapture } from './privileged-helper-spawn.mjs';
import { macLogArgs } from '../src/logs/system-log-ops.mjs';

const SERVICE_CONTROL_OPS = Object.freeze(['start', 'stop', 'restart']);
const SERVICE_CONTROL_UNIT_RE = /^[A-Za-z0-9_.\-]{1,256}$/;

/**
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {number} [timeoutMs]
 */
async function runCapture(cmd, args, timeoutMs = 30000) {
  // Hardened delegate: the old inline version resolved only on `close`, so
  // a killed child with pipe-holding grandchildren hung the daemon until
  // the agent IPC watchdog fired (timeout + orphan). Same {code,out,error}
  // shape, plus timedOut for callers that want the explicit signal.
  const r = await runPrivilegedCapture(cmd, args, { timeoutMs, platform: 'darwin' });
  return { code: r.code, out: r.out, error: r.error, timedOut: r.timedOut };
}

/**
 * Dedicated allowlisted service verbs via launchctl (system domain; the
 * daemon runs as root). Mirrors the Linux systemctl wrapper: argv only,
 * failures RETURNED so the model sees the real reason.
 * @param {unknown} payload
 */
export async function executeDarwinServiceControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (!SERVICE_CONTROL_OPS.includes(/** @type {string} */ (rec.op)))
    throw new Error('PRIVILEGED_SERVICE_OP_INVALID');
  if (typeof rec.unit !== 'string' || !SERVICE_CONTROL_UNIT_RE.test(rec.unit))
    throw new Error('PRIVILEGED_SERVICE_UNIT_INVALID');
  const { op, unit } = { op: String(rec.op), unit: String(rec.unit) };
  const label = unit.includes('.') ? unit : 'com.nc.client';
  let r;
  if (op === 'start') r = await runCapture('launchctl', ['kickstart', `system/${label}`]);
  else if (op === 'stop') r = await runCapture('launchctl', ['bootout', `system/${label}`]);
  else r = await runCapture('launchctl', ['kickstart', '-k', `system/${label}`]);
  if (r.error) throw new Error(`PRIVILEGED_SERVICE_SPAWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code === 0) return { unit, op, success: true, message: r.out.slice(0, 2000) || null };
  return { unit, op, success: false, message: (r.out || `launchctl ${op} exited ${r.code}`).slice(0, 2000) };
}

const DARWIN_FILE_PERMS_BACKUP_SUFFIX = '(?:-|~|\\.(?:old|bak|orig|rej))?';
const DARWIN_FILE_PERMS_DENYLIST_RE = new RegExp(
  '^\\/((((private\\/)?etc\\/(shadow|gshadow|group|passwd|sudoers|ssh|pam\\.d))' +
    DARWIN_FILE_PERMS_BACKUP_SUFFIX +
    ')|System\\/Library|bin|sbin|usr\\/(bin|sbin)|opt\\/nc\\/(libexec|config))(\\/|$)'
);
/**
 * Lexical canonicalization for denylist matching: collapse duplicate
 * slashes and drop '.' segments. '//private/etc/shadow' and
 * '/private/etc/./shadow' reach the protected file through kernel path
 * resolution while evading an anchored denylist. '..' segments are NOT
 * resolved here (the explicit '..' rejection at the call site stays
 * authoritative).
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
 * V-32.11b (darwin twin of the linux helper): re-resolve immediately
 * before exec and refuse when the resolution moved. Same accepted residual:
 * chmod/chown take a path, not an fd, and lchmod semantics do not give a
 * fully atomic path-independent chmod — this narrows the window to
 * microseconds and fails closed on a detected swap.
 * @param {string} target lexical target
 * @param {string} execTarget previously resolved target
 * @returns {string} fresh resolution (== execTarget when stable)
 */
function revalidateOperatedPath(target, execTarget) {
  // P2-03b (fail-closed darwin twin of the linux helper): a realpath
  // failure here must DENY, never fall back to the lexical target (same
  // ENOENT-then-recreate-as-symlink plant as P2-03). Missing/unresolvable
  // at exec time throws PRIVILEGED_PATH_DENIED.
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
 * Reject chmod modes that could set SUID/SGID. Any-width octal is checked
 * numerically (a 5-digit '04644' must not slip past a 3-4 char pattern);
 * symbolic clauses are scanned per [ugoa]*[+-=]: '+'/'=' with s/S can set
 * the bits and are rejected, while '-' only removes them and stays allowed.
 * @param {string} mode
 */
function assertSafeUnixMode(mode) {
  if (/^[0-7]+$/.test(mode)) {
    const numeric = parseInt(mode, 8);
    if (Number.isFinite(numeric) && (numeric & 0o6000) !== 0)
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
 * @param {unknown} payload
 */
export async function executeDarwinFilePermissions(payload) {
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
  if (DARWIN_FILE_PERMS_DENYLIST_RE.test(normalizePosixDenyTarget(target)))
    throw new Error('PRIVILEGED_PATH_DENIED');
  const recursive = rec.recursive === true;
  // Operate on the resolved path (chmod/chown follow symlinks) and test
  // THAT against the denylist; fall back to the lexical form only when
  // resolution fails so missing files keep the success:false contract.
  const execTarget = resolveOperatedPath(target);
  if (execTarget !== target && DARWIN_FILE_PERMS_DENYLIST_RE.test(execTarget))
    throw new Error('PRIVILEGED_PATH_DENIED');
  if (recursive) assertNoSymlinksRecursive(execTarget);
  if (action === 'chmod') {
    const mode = String(rec.mode || '');
    if (!mode || mode.length > 32) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    assertSafeUnixMode(mode);
    // '--' ends option parsing: a mode starting with '-' is an operand,
    // never a flag (e.g. mode '-R' must not enable recursion).
    const args = recursive ? ['-R', '--', mode, execTarget] : ['--', mode, execTarget];
    // V-32.11b: revalidate immediately before exec (see helper above).
    revalidateOperatedPath(target, execTarget);
    const r = await runCapture('/bin/chmod', args, 30000);
    if (r.error) throw new Error(`PRIVILEGED_CHMOD_FAILED:${r.error}`.slice(0, 200));
    if (r.code !== 0)
      return { action, target, success: false, message: (r.out || `chmod exited ${r.code}`).slice(0, 2000) };
    const afterR = await runCapture('/usr/bin/stat', ['-f', '%Lp', execTarget]);
    return {
      action,
      target,
      success: true,
      previous_mode: null,
      current_mode: afterR.code === 0 ? afterR.out.trim() : null,
      previous_owner: null,
      current_owner: null
    };
  }
  const owner = String(rec.owner || '');
  if (!owner || owner.length > 256) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const group = rec.group != null ? String(rec.group) : null;
  if (group && group.length > 256) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const chownArg = group ? `${owner}:${group}` : owner;
  const args = recursive ? ['-R', '--', chownArg, execTarget] : ['--', chownArg, execTarget];
  // V-32.11b: revalidate immediately before exec (see helper above).
  revalidateOperatedPath(target, execTarget);
  const r = await runCapture('/usr/sbin/chown', args, 30000);
  if (r.error) throw new Error(`PRIVILEGED_CHOWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code !== 0)
    return { action, target, success: false, message: (r.out || `chown exited ${r.code}`).slice(0, 2000) };
  const afterR = await runCapture('/usr/bin/stat', ['-f', '%Su:%Sg', execTarget]);
  return {
    action,
    target,
    success: true,
    previous_mode: null,
    current_mode: null,
    previous_owner: null,
    current_owner: afterR.code === 0 ? afterR.out.trim() : null
  };
}
/**
 * @param {object} [options]
 * @param {string} [options.uninstallScript]
 */
export function darwinPrivilegedHelperHandlers({
  uninstallScript = '/opt/nc/uninstall.sh'
} = {}) {
  return Object.freeze({
    service_control: executeDarwinServiceControl,
    container_control: executeDarwinContainerControl,
    compose_control: executeDarwinComposeControl,
    package_control: executeDarwinPackageControl,
    system_log_read: executeDarwinSystemLogRead,
    file_permissions: executeDarwinFilePermissions,
    client_uninstall: async (/** @type {unknown} */ payload) => {
      if (!payload || typeof payload !== 'object' || Array.isArray(payload))
        throw new Error('PRIVILEGED_PAYLOAD_INVALID');
      const r = await runCapture('/bin/sh', [String(uninstallScript)]);
      return { success: r.code === 0, message: (r.out || `exit ${r.code}`).slice(0, 2000) };
    }
  });
}

const DARWIN_CONTAINER_ACTIONS = Object.freeze(['list', 'inspect', 'logs']);
const DARWIN_CONTAINER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.\-]{0,255}$/;
const DARWIN_COMPOSE_ACTIONS = Object.freeze([
  'list',
  'up',
  'down',
  'restart',
  'pull',
  'stop',
  'start'
]);
const DARWIN_PACKAGE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9+_.:~-]{0,127}$/;
const DARWIN_LOG_LEVELS = Object.freeze(['all', 'info', 'warning', 'error']);
const DARWIN_LOG_UNIT_RE = /^[\w@.\-:]{1,128}$/;

/**
 * Bounded container-runtime operations via the docker binary. Argv only.
 * On macOS the engine socket is user-scoped (Docker Desktop); the helper
 * uses the ambient docker resolution without forcing a Linux socket path.
 * @param {unknown} payload
 */
export async function executeDarwinContainerControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (Object.keys(rec).some((k) => !['action', 'container_name', 'tail'].includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const action = String(rec.action || '');
  if (!DARWIN_CONTAINER_ACTIONS.includes(action))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  if (action === 'list') {
    const r = await runCapture('docker', ['ps', '-a', '--format', '{{json .}}']);
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
  if (!DARWIN_CONTAINER_NAME_RE.test(containerName)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (action === 'inspect') {
    const r = await runCapture('docker', ['inspect', containerName]);
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
  const r = await runCapture('docker', ['logs', '--tail', String(tail), containerName]);
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
export async function executeDarwinComposeControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (Object.keys(rec).some((k) => !['action', 'project_dir'].includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const action = String(rec.action || '').toLowerCase();
  if (!DARWIN_COMPOSE_ACTIONS.includes(action))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  if (action === 'list') {
    const r = await runCapture('docker', ['compose', 'ls', '--format', 'json']);
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
  // Hardened: the old inline spawn resolved only on `close` (hang + orphan
  // on pipe-holding grandchildren); the shared helper resolves on watchdog.
  const out = await runPrivilegedCapture('docker', args, {
    cwd: projectDir,
    timeoutMs: 600000,
    platform: 'darwin'
  }).then((r) => ({ code: r.code, out: r.out, error: r.error, timedOut: r.timedOut }));
  if (out.error) throw new Error(`PRIVILEGED_COMPOSE_SPAWN_FAILED:${out.error}`.slice(0, 200));
  if (out.code === 0)
    return {
      frontend: 'docker compose',
      action,
      project_dir: projectDir,
      success: true,
      output_tail: String(out.out).slice(-4096) || null
    };
  return {
    frontend: 'docker compose',
    action,
    project_dir: projectDir,
    success: false,
    message: (String(out.out) || `docker compose ${action} exited ${out.code}`).slice(0, 2000)
  };
}

/**
 * Bounded brew operations. Homebrew refuses to run as root by design, so
 * install/remove while euid is 0 fail closed with
 * PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED callers must use a user-domain
 * brew invocation instead. List is attempted best-effort under the same
 * guard to avoid a root-brew bypass.
 * @param {unknown} payload
 */
export async function executeDarwinPackageControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (Object.keys(rec).some((k) => !['action', 'manager', 'name', 'contains', 'limit'].includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const action = String(rec.action || '').toLowerCase();
  if (action !== 'list' && action !== 'install' && action !== 'remove')
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  const manager = String(rec.manager || 'auto').toLowerCase();
  if (manager !== 'auto' && manager !== 'brew')
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  // Homebrew must run as the target user, never as root. The helper daemon
  // runs as root, so brew mutations from root would violate brew safety and
  // user-domain ownership. Fail closed here.
  try {
    if (typeof process.geteuid === 'function' && process.geteuid() === 0)
      throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  } catch (e) {
    if (String(e?.message || e) === 'PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED') throw e;
  }
  if (action === 'list') {
    if (rec.contains != null) {
      const contains = String(rec.contains);
      if (!contains || contains.length > 128) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    }
    if (rec.limit != null) {
      const limit = Number(rec.limit);
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000)
        throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    }
    const r = await runCapture('brew', ['list', '--versions']);
    if (r.error) throw new Error(`PRIVILEGED_PACKAGE_SPAWN_FAILED:${r.error}`.slice(0, 200));
    if (r.code === 0)
      return { manager: 'brew', action, success: true, output_tail: r.out.slice(-8000) || null };
    return {
      manager: 'brew',
      action,
      success: false,
      message: (r.out || `brew list exited ${r.code}`).slice(0, 2000)
    };
  }
  const name = String(rec.name || '');
  if (!DARWIN_PACKAGE_NAME_RE.test(name)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const r = await runCapture('brew', [action === 'install' ? 'install' : 'uninstall', name], 600000);
  if (r.error) throw new Error(`PRIVILEGED_PACKAGE_SPAWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code === 0)
    return { manager: 'brew', action, name, success: true, message: r.out.slice(-2000) || null };
  return {
    manager: 'brew',
    action,
    name,
    success: false,
    message: (r.out || `brew ${action} exited ${r.code}`).slice(0, 2000)
  };
}

/**
 * Bounded privileged Unified Log reads via `log show`. Argv only.
 * @param {unknown} payload
 */
export async function executeDarwinSystemLogRead(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (
    Object.keys(rec).some(
      (k) => !['source', 'unit', 'lines', 'level', 'contains', 'since'].includes(k)
    )
  )
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const source = String(rec.source || 'system');
  let unit = null;
  if (rec.unit != null) {
    unit = String(rec.unit);
    if (!DARWIN_LOG_UNIT_RE.test(unit)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  }
  let level = 'all';
  if (rec.level != null) {
    level = String(rec.level).toLowerCase();
    if (!DARWIN_LOG_LEVELS.includes(level)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  }
  let contains = '';
  if (rec.contains != null && String(rec.contains) !== '') {
    contains = String(rec.contains);
    if (contains.length > 200) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  }
  let since = null;
  if (rec.since != null && String(rec.since) !== '') {
    since = String(rec.since);
    if (since.length > 64) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  }
  const lines = rec.lines == null ? 100 : Number(rec.lines);
  if (!Number.isInteger(lines) || lines < 1 || lines > 1000)
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  // Bound BEFORE capture with the same builder as the direct path: the OS
  // command itself carries the window (--start from since, else a tight
  // --last) and the predicate, so a bounded request never dumps an hour of
  // Unified Log into the capture buffer only to slice it afterwards.
  // Identical params therefore read identically direct or helper-mediated.
  const { args } = macLogArgs({
    unit,
    level,
    contains,
    lines,
    extraPreds: source === 'kernel' ? ['senderImagePath CONTAINS "kernel"'] : [],
    since
  });
  const r = await runCapture('log', args, 30000);
  if (r.error) throw new Error(`PRIVILEGED_LOG_SPAWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code === 0) {
    const rows = String(r.out || '').split('\n').filter(Boolean);
    const tail = rows.slice(-Math.min(lines, 500)).join('\n');
    return {
      source: String(rec.source || 'system'),
      unit: rec.unit != null ? String(rec.unit) : null,
      success: true,
      output_tail: tail.slice(-8000) || null
    };
  }
  return {
    source: String(rec.source || 'system'),
    unit: rec.unit != null ? String(rec.unit) : null,
    success: false,
    message: (r.out || `log show exited ${r.code}`).slice(0, 2000)
  };
}
