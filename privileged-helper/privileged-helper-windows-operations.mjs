import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { runPrivilegedCapture } from './privileged-helper-spawn.mjs';
import { winEventScript } from '../src/logs/system-log-ops.mjs';
import { isSensitivePath } from '../src/filesystem/sensitive-paths.mjs';

const SERVICE_CONTROL_OPS = Object.freeze(['start', 'stop', 'restart']);
// First character excludes '-' and ':': the unit reaches sc.exe argv in
// option position, so a leading dash would parse as a flag. Legitimate
// service names never start with '-' or ':'.
const SERVICE_CONTROL_UNIT_RE = /^[A-Za-z0-9_@.][\w@.\-:]{0,127}$/;

/**
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {number} [timeoutMs]
 */
async function runCapture(cmd, args, timeoutMs = 30000) {
  // Hardened delegate: the old inline version resolved only on `close`, so
  // a taskkilled child with pipe-holding grandchildren hung the daemon
  // until the agent IPC watchdog fired (timeout + orphan). Same
  // {code,out,error} shape, plus timedOut for callers that want it.
  // L01b-3: never inherit the daemon env (tokens included) into privileged
  // children — match the Linux inheritEnv:false policy.
  const r = await runPrivilegedCapture(cmd, args, { timeoutMs, platform: 'win32', inheritEnv: false });
  return { code: r.code, out: r.out, error: r.error, timedOut: r.timedOut };
}

/**
 * Dedicated allowlisted service verbs via sc.exe (mirrors the Linux
 * systemctl wrapper): argv only, never a shell. Failures are RETURNED so
 * the model sees the real reason (e.g. exit 1058 disabled service).
 * @param {unknown} payload
 */
export async function executeWindowsServiceControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (!SERVICE_CONTROL_OPS.includes(/** @type {string} */ (rec.op)))
    throw new Error('PRIVILEGED_SERVICE_OP_INVALID');
  if (typeof rec.unit !== 'string' || !SERVICE_CONTROL_UNIT_RE.test(rec.unit))
    throw new Error('PRIVILEGED_SERVICE_UNIT_INVALID');
  const { op, unit } = { op: String(rec.op), unit: String(rec.unit) };
  const r = await runCapture('sc.exe', [op, unit]);
  if (r.error) throw new Error(`PRIVILEGED_SERVICE_SPAWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code === 0) return { unit, op, success: true, message: r.out.slice(0, 2000) || null };
  return {
    unit,
    op,
    success: false,
    message: (r.out || `sc ${op} exited with code ${r.code}`).slice(0, 2000)
  };
}

/**
 * Privileged shell via PowerShell -EncodedCommand (no cmd.exe quote
 * mangling; proven pattern from the diagnose disk probe). Bounded output.
 * @param {unknown} payload
 */
export async function executeWindowsPrivilegedShell(payload) {
  const rec =
    payload && typeof payload === 'object' && !Array.isArray(payload)
      ? /** @type {Record<string, unknown>} */ (payload)
      : null;
  const command = String(rec?.command || '');
  // NaN-safe clamp with linux parity (was: NaN timeout became setTimeout(NaN)
  // = instant 1ms timeout; max 300s silently truncated legit long commands).
  const rawTimeout = Number(rec?.timeout_seconds ?? 30);
  const timeoutSeconds = Number.isFinite(rawTimeout) ? Math.max(1, Math.min(3600, rawTimeout)) : 30;
  if (!command || command.length > 65536) throw new Error('PRIVILEGED_COMMAND_INVALID');
  const script = Buffer.from(command, 'utf16le').toString('base64');
  const started = Date.now();
  // Aligned with the linux shell shape ({status,error} + real stderr): the
  // old shape reported every nonzero as `completed` agent-side (no status)
  // and conflated spawn errors with timeouts (timed_out: code===null).
  const r = await runPrivilegedCapture(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-EncodedCommand', script],
    // L01b-3: a root PowerShell must never inherit the daemon env.
    { timeoutMs: timeoutSeconds * 1000, platform: 'win32', inheritEnv: false }
  );
  const duration_ms = Date.now() - started;
  if (r.error)
    return {
      status: 'failed',
      exit_code: null,
      stdout: r.stdout,
      stderr: r.stderr,
      duration_ms,
      error: 'PRIVILEGED_EXEC_SPAWN_FAILED',
      timed_out: false
    };
  if (r.timedOut)
    return {
      status: 'timeout',
      exit_code: null,
      stdout: r.stdout,
      stderr: r.stderr,
      duration_ms,
      error: 'PRIVILEGED_EXEC_TIMEOUT',
      timed_out: true
    };
  return {
    status: r.code === 0 ? 'completed' : 'failed',
    exit_code: r.code,
    stdout: r.stdout,
    stderr: r.stderr,
    duration_ms,
    error: r.code === 0 ? null : 'PRIVILEGED_EXEC_NONZERO',
    timed_out: false
  };
}

/**
 * Escape a value for PowerShell single-quoted embedding. Doubling is the
 * only escape single-quoted strings honor ($, backtick and double-quote
 * stay literal inside them), so this is complete for the Get-Acl / takeown
 * / icacls interpolations below. Exported for tests.
 * @param {unknown} value
 */
export function quotePowerShellSingleQuoted(value) {
  return String(value ?? '').replace(/'/g, "''");
}
/**
 * Normalize a Windows target before denylist matching: forward slashes,
 * extended-path/device prefixes (\\?\, \\.\, \??\) and letter case
 * all evade a naive prefix test while reaching the same file through
 * .NET path handling.
 * @param {string} target
 */
function normalizeWindowsDenyTarget(target) {
  let s = String(target || '').replace(/\//g, '\\').toLowerCase();
  s = s.replace(/^\\\\[?.]\\/, '').replace(/^\\\?\?\\/, '');
  return s.replace(/\\+/g, '\\').replace(/\\+$/, '');
}
/**
 * @param {string} target normalized-absolute Windows path check against
 * system and application trust roots (drive-aware via SystemRoot).
 */
function windowsTargetDenied(target) {
  const s = normalizeWindowsDenyTarget(target);
  // 8.3 short-name evasion: C:\WINDO~1\SYSTEM~1\... reaches the same
  // directory while dodging literal prefix matches. Short names are
  // volume-dependent (no alias list can be exhaustive), so any path
  // segment shaped like an 8.3 short name is denied outright — legitimate
  // privileged targets are never addressed that way. Trailing dots/spaces
  // are stripped by Win32 parsing, so they do not excuse the segment.
  if (s.split('\\').some((seg) => /~[0-9]+[.\s]*$/.test(seg))) return true;
  const drive = (process.env.SystemRoot || 'C:\\Windows').slice(0, 2).toLowerCase();
  const prefixes = [
    drive + '\\windows\\system32',
    drive + '\\windows\\syswow64',
    drive + '\\program files',
    drive + '\\program files (x86)',
    drive + '\\progra~1',
    drive + '\\progra~2'
  ];
  return prefixes.some((p) => s === p || s.startsWith(p + '\\'));
}

/**
 * P2-03c (fail-closed windows twin of the linux/darwin revalidate):
 * re-resolve immediately before exec and refuse when the resolution moved
 * (junction/symlink swapped after the initial gate) or when resolution
 * fails (deleted path, or a planted dangling link waved through by the
 * lexical fallback above). The fresh resolution is re-checked against the
 * denylist in addition to the equality comparison, so a move onto a trust
 * root through any alias the first check normalized away still denies.
 * UNC/ADS gates above stay authoritative — this only narrows the
 * resolve→exec window, never widens what may execute.
 * @param {string} target lexical target
 * @param {string} execTarget previously resolved target
 * @returns {string} fresh resolution (== execTarget when stable)
 */
function revalidateWindowsOperatedPath(target, execTarget) {
  let fresh;
  try {
    fresh = fs.realpathSync(target);
  } catch {
    throw new Error('PRIVILEGED_PATH_DENIED');
  }
  if (fresh !== execTarget) throw new Error('PRIVILEGED_PATH_DENIED');
  if (windowsTargetDenied(fresh)) throw new Error('PRIVILEGED_PATH_DENIED');
  return fresh;
}
/**
 * @param {unknown} payload
 */
export async function executeWindowsFilePermissions(payload) {
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
  if (!target || target.length > 4096) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  // Drive-absolute paths only: services start in System32, so a relative
  // target would resolve against a system directory. UNC (\\host\share)
  // is rejected outright for this ownership-changing primitive: shares can
  // alias local trust roots (C$, ADMIN$, or an operator-created share over
  // System32) while neither the drive-letter prefix tests below nor the
  // realpath recheck (which keeps UNC form) can see through the alias.
  // That bar includes UNC smuggled inside the extended form (\\?\UNC\...)
  // and volume-GUID paths (\\?\Volume{...}\...), whose volume cannot be
  // proven disjoint from the system drive lexically: only extended/device
  // prefixes carrying an explicit drive letter are accepted, and the
  // normalizer folds those back to drive form before matching. Control
  // characters can never appear in real Windows filenames
  // (NTFS rejects \x00-\x1f).
  if (!/^(?:[A-Za-z]:[\\/]|\\\\[?.]\\[A-Za-z]:[\\/])/.test(target))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  // P13-D3 ADS parity: the mutation path rejects alternate data streams
  // (PATH_ALTERNATE_STREAM_NOT_ALLOWED) while this primitive accepted them:
  // 'C:\dir\file:stream' sailed through the drive gate into icacls on the
  // stream. No legitimate chmod/chown use addresses an ADS, so reject any
  // post-drive colon (extended-drive-letter prefixes are stripped first).
  const noPrefix = target.replace(/^\\\\[?.]\\/, '');
  const afterDrive = /^[A-Za-z]:/.test(noPrefix) ? noPrefix.slice(2) : noPrefix;
  if (afterDrive.includes(':')) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (/[\x00-\x1f]/.test(target)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (/\.\./.test(target)) throw new Error('PRIVILEGED_PATH_DENIED');
  if (windowsTargetDenied(target)) throw new Error('PRIVILEGED_PATH_DENIED');
  // takeown/icacls follow symlinks and junctions: operate on the resolved
  // path and test THAT against the denylist. Unresolvable (missing)
  // targets keep the lexical form so the exec still fails closed.
  let execTarget = target;
  try {
    execTarget = fs.realpathSync(target);
  } catch {}
  if (execTarget !== target && windowsTargetDenied(execTarget))
    throw new Error('PRIVILEGED_PATH_DENIED');
  // Windows: chmod maps to attrib or icacls; chown maps to takeown/icacls
  if (action === 'chmod') {
    const mode = String(rec.mode || '');
    if (!mode || mode.length > 32) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    // Map octal-like modes to icacls grant/deny
    // For simplicity, support R/W/D meaning read/modify/full
    const modeMap = {
      '0444': 'R',
      '0644': 'R',
      '0755': 'R',
      '0777': 'F',
      '0666': 'M',
      '0400': 'R',
      '0600': 'M',
      '0700': 'F'
    };
    // icacls here can only ADD allow ACEs: owner-only intents would grant
    // Everyone access instead of restricting, so they fail closed. Unknown
    // modes fail closed too (the old 'R' fallback widened on garbage input).
    if (['0400', '0600', '0700'].includes(mode)) throw new Error('PRIVILEGED_MODE_NOT_SUPPORTED');
    if (!Object.prototype.hasOwnProperty.call(modeMap, mode)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    const icaclsPerm = modeMap[mode];
    // P2-03c: revalidate immediately before exec (see helper above).
    revalidateWindowsOperatedPath(target, execTarget);
    const quoted = quotePowerShellSingleQuoted(execTarget);
    const script = `$acl = Get-Acl '${quoted}'; $rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Everyone','${icaclsPerm}','Allow'); $acl.SetAccessRule($rule); Set-Acl '${quoted}' $acl`;
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    const r = await runCapture(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      30000
    );
    if (r.code !== 0)
      return {
        action,
        target,
        success: false,
        message: (r.out || `chmod PowerShell exited ${r.code}`).slice(0, 2000)
      };
    return {
      action,
      target,
      success: true,
      previous_mode: null,
      current_mode: mode,
      previous_owner: null,
      current_owner: null
    };
  }
  // chown via takeown + icacls
  const owner = String(rec.owner || '');
  if (!owner || owner.length > 256) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (/[\x00-\x1f]/.test(owner)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  // P2-03c: revalidate immediately before exec (see helper above).
  revalidateWindowsOperatedPath(target, execTarget);
  const script = `takeown /F '${quotePowerShellSingleQuoted(execTarget)}' /A; icacls '${quotePowerShellSingleQuoted(execTarget)}' /setowner '${quotePowerShellSingleQuoted(owner)}'`;
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const r = await runCapture(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
    30000
  );
  if (r.code !== 0)
    return {
      action,
      target,
      success: false,
      message: (r.out || `chown PowerShell exited ${r.code}`).slice(0, 2000)
    };
  return {
    action,
    target,
    success: true,
    previous_mode: null,
    current_mode: null,
    previous_owner: null,
    current_owner: owner
  };
}

/**
 * @param {string} target
 * @param {object} [options]
 * @param {boolean} [options.allowAll]
 * @param {Array<string>} [options.roots]
 * @param {boolean} [options.checkAncestor]
 */
function validateWindowsHelperPath(
  target,
  { allowAll = false, roots = [], checkAncestor = false } = {}
) {
  if (!target || typeof target !== 'string' || target.length > 4096)
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (/[\x00-\x1f]/.test(target))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (!/^(?:[A-Za-z]:[\\/]|\\\\[?.]\\[A-Za-z]:[\\/])/.test(target))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const noPrefix = target.replace(/^\\\\[?.]\\/, '');
  const afterDrive = /^[A-Za-z]:/.test(noPrefix) ? noPrefix.slice(2) : noPrefix;
  if (afterDrive.includes(':'))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (/\.\./.test(target))
    throw new Error('PRIVILEGED_PATH_DENIED');
  if (windowsTargetDenied(target))
    throw new Error('PRIVILEGED_PATH_DENIED');
  if (isSensitivePath(target, 'win32'))
    throw new Error('PRIVILEGED_PATH_DENIED');

  let resolvedTarget = null;
  let targetExists = false;
  try {
    resolvedTarget = fs.realpathSync(target);
    targetExists = true;
  } catch {
    targetExists = false;
  }

  if (targetExists && resolvedTarget) {
    if (windowsTargetDenied(resolvedTarget))
      throw new Error('PRIVILEGED_PATH_DENIED');
    if (isSensitivePath(resolvedTarget, 'win32'))
      throw new Error('PRIVILEGED_PATH_DENIED');
  } else if (checkAncestor) {
    let cur = path.win32.dirname(target);
    let ancestorResolved = null;
    while (true) {
      try {
        ancestorResolved = fs.realpathSync(cur);
        break;
      } catch {
        const p = path.win32.dirname(cur);
        if (p === cur) throw new Error('PRIVILEGED_PATH_DENIED');
        cur = p;
      }
    }
    if (windowsTargetDenied(ancestorResolved))
      throw new Error('PRIVILEGED_PATH_DENIED');
    if (isSensitivePath(ancestorResolved, 'win32'))
      throw new Error('PRIVILEGED_PATH_DENIED');
    resolvedTarget = ancestorResolved;
  } else {
    throw new Error('PRIVILEGED_FILE_NOT_FOUND');
  }

  if (allowAll !== true) {
    if (!Array.isArray(roots) || roots.length === 0)
      throw new Error('PRIVILEGED_PATH_DENIED');
    const realRoots = [];
    for (const r of roots) {
      try {
        realRoots.push(fs.realpathSync(r));
      } catch {}
    }
    if (realRoots.length === 0)
      throw new Error('PRIVILEGED_PATH_DENIED');
    const normTarget = resolvedTarget.toLowerCase();
    const inside = realRoots.some((rr) => {
      const normRoot = rr.toLowerCase();
      return (
        normTarget === normRoot ||
        normTarget.startsWith(normRoot.endsWith('\\') ? normRoot : normRoot + '\\')
      );
    });
    if (!inside)
      throw new Error('PRIVILEGED_PATH_DENIED');
  }

  return { target, resolvedTarget, exists: targetExists };
}

/**
 * Refuse recursive operations over trees containing symlinks (L06-10
 * Windows parity with the POSIX helpers): junctions and directory links
 * would otherwise redirect a privileged recursive delete outside the
 * gated tree. Uses lstat/dir-ent semantics (never follows). Bounded:
 * absurdly deep trees fail closed rather than stalling the daemon.
 * A readdirSync failure throws PRIVILEGED_PATH_DENIED (fail closed) —
 * an unverifiable subtree is never waved through.
 * @param {string} target
 */
export function assertNoSymlinksRecursive(target) {
  // A file (non-directory) target has no tree to traverse: return early so
  // a recursive op on a single file keeps working. Unresolvable targets
  // fail closed (the exec cannot be verified).
  let root;
  try {
    root = fs.lstatSync(target);
  } catch (e) {
    throw new Error('PRIVILEGED_PATH_DENIED', { cause: e });
  }
  if (!root.isDirectory()) return;
  const stack = [target];
  let dirs = 0;
  while (stack.length) {
    const cur = /** @type {string} */ (stack.pop());
    let entries;
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch (e) {
      throw new Error('PRIVILEGED_PATH_DENIED', { cause: e });
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) throw new Error('PRIVILEGED_PATH_DENIED');
      if (entry.isDirectory()) {
        if (++dirs > 100000) throw new Error('PRIVILEGED_PATH_DENIED');
        stack.push(`${cur}\\${entry.name}`);
      }
    }
  }
}
/**
 * Bounded file read via privileged helper on Windows.
 * @param {unknown} payload
 */
export async function executeWindowsFileRead(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  const target = String(rec.path || rec.target || '');
  if (!target) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const allowAll = rec.allow_all === true || rec.allow_all_filesystem === true;
  const roots = Array.isArray(rec.roots)
    ? /** @type {Array<string>} */ (rec.roots)
    : Array.isArray(rec.allowed_roots)
      ? /** @type {Array<string>} */ (rec.allowed_roots)
      : [];

  validateWindowsHelperPath(target, { allowAll, roots, checkAncestor: false });

  let st;
  try {
    st = fs.lstatSync(target);
  } catch (e) {
    if (e && typeof e === 'object' && /** @type {{code?: unknown}} */ (e).code === 'ENOENT') {
      throw new Error('PRIVILEGED_FILE_NOT_FOUND', { cause: e });
    }
    throw new Error('PRIVILEGED_PATH_DENIED', { cause: e });
  }
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new Error('PRIVILEGED_PATH_DENIED');
  }

  const maxBytes = Math.max(1, Math.min(1024 * 1024, Number(rec.max_bytes || 65536)));
  let fd;
  try {
    fd = fs.openSync(target, 'r');
  } catch (openErr) {
    const code =
      openErr && typeof openErr === 'object'
        ? /** @type {{code?: unknown}} */ (openErr).code
        : null;
    if (code === 'ENOENT') throw new Error('PRIVILEGED_FILE_NOT_FOUND', { cause: openErr });
    throw new Error('PRIVILEGED_PATH_DENIED', { cause: openErr });
  }
  try {
    const buf = Buffer.alloc(Math.min(st.size, maxBytes));
    let readBytes = 0;
    if (buf.length > 0) {
      readBytes = fs.readSync(fd, buf, 0, buf.length, 0);
    }
    return {
      path: target,
      content: buf.subarray(0, readBytes).toString('utf8'),
      bytes: st.size,
      truncated: st.size > maxBytes,
      success: true
    };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Bounded file mutation via privileged helper on Windows (write, edit, move, copy, delete, mkdir).
 * @param {unknown} payload
 */
export async function executeWindowsFileWrite(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  const action = String(rec.action || 'write').toLowerCase();
  const allowAll = rec.allow_all === true || rec.allow_all_filesystem === true;
  const roots = Array.isArray(rec.roots)
    ? /** @type {Array<string>} */ (rec.roots)
    : Array.isArray(rec.allowed_roots)
      ? /** @type {Array<string>} */ (rec.allowed_roots)
      : [];

  if (!['write', 'edit', 'move', 'copy', 'delete', 'mkdir'].includes(action))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');

  if (action === 'delete') {
    const target = String(rec.path || rec.target || '');
    if (!target) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    if (/^[A-Za-z]:[\\/]?$/.test(target)) throw new Error('PRIVILEGED_PATH_DENIED');
    validateWindowsHelperPath(target, { allowAll, roots, checkAncestor: false });
    let st;
    try {
      st = fs.lstatSync(target);
    } catch (e) {
      if (e && typeof e === 'object' && /** @type {{code?: unknown}} */ (e).code === 'ENOENT') {
        return { action, path: target, deleted: false, success: true };
      }
      throw new Error('PRIVILEGED_PATH_DENIED', { cause: e });
    }
    if (st.isDirectory()) {
      if (rec.recursive === true) {
        // L06-10: refuse symlink/junction-containing trees before the
        // privileged recursive delete (fail closed on unverifiable).
        assertNoSymlinksRecursive(target);
        fs.rmSync(target, { recursive: true, force: true });
      } else {
        fs.rmdirSync(target);
      }
    } else {
      fs.unlinkSync(target);
    }
    return { action, path: target, deleted: true, success: true };
  }

  if (action === 'mkdir') {
    const target = String(rec.path || rec.target || '');
    if (!target) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    validateWindowsHelperPath(target, { allowAll, roots, checkAncestor: true });
    let exists = false;
    try {
      exists = fs.existsSync(target);
    } catch {}
    if (exists) {
      return { action, path: target, created: false, success: true };
    }
    fs.mkdirSync(target, { recursive: rec.recursive !== false });
    return { action, path: target, created: true, success: true };
  }

  if (action === 'move') {
    const source = String(rec.source || rec.path || '');
    const destination = String(rec.destination || rec.target || '');
    if (!source || !destination) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    validateWindowsHelperPath(source, { allowAll, roots, checkAncestor: false });
    validateWindowsHelperPath(destination, { allowAll, roots, checkAncestor: true });
    fs.mkdirSync(path.win32.dirname(destination), { recursive: true });
    fs.renameSync(source, destination);
    return { action, source, destination, success: true };
  }

  if (action === 'copy') {
    const source = String(rec.source || rec.path || '');
    const destination = String(rec.destination || rec.target || '');
    if (!source || !destination) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    validateWindowsHelperPath(source, { allowAll, roots, checkAncestor: false });
    validateWindowsHelperPath(destination, { allowAll, roots, checkAncestor: true });
    fs.mkdirSync(path.win32.dirname(destination), { recursive: true });
    fs.cpSync(source, destination, { recursive: true, force: rec.overwrite === true });
    return { action, source, destination, success: true };
  }

  if (action === 'edit') {
    const target = String(rec.path || rec.target || '');
    if (!target) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
    validateWindowsHelperPath(target, { allowAll, roots, checkAncestor: false });
    let st;
    try {
      st = fs.lstatSync(target);
    } catch {
      throw new Error('PRIVILEGED_FILE_NOT_FOUND');
    }
    if (st.isSymbolicLink() || !st.isFile()) throw new Error('PRIVILEGED_PATH_DENIED');
    const before = fs.readFileSync(target, 'utf8');
    const prevSha = crypto.createHash('sha256').update(before).digest('hex');
    if (rec.expected_sha256 && prevSha !== rec.expected_sha256)
      throw new Error('PRIVILEGED_SHA_MISMATCH');
    let after = before;
    if (Array.isArray(rec.edits)) {
      for (const edit of /** @type {Array<Record<string, unknown>>} */ (rec.edits)) {
        const oldText = String(edit.old_text ?? '');
        const newText = String(edit.new_text ?? '');
        after = after.replace(oldText, () => newText);
      }
    } else if (rec.expected_text && rec.replacement_text) {
      after = after.replace(String(rec.expected_text), () => String(rec.replacement_text));
    } else if (typeof rec.content === 'string') {
      after = rec.content;
    }
    const fd = fs.openSync(target, 'w');
    try {
      fs.writeSync(fd, Buffer.from(after, 'utf8'));
    } finally {
      fs.closeSync(fd);
    }
    const afterSha = crypto.createHash('sha256').update(after).digest('hex');
    return {
      action,
      path: target,
      bytes_written: Buffer.byteLength(after, 'utf8'),
      previous_sha256: prevSha,
      sha256: afterSha,
      success: true
    };
  }

  // action === 'write'
  const target = String(rec.path || rec.target || '');
  if (!target) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (typeof rec.content !== 'string' || rec.content.length > 10 * 1024 * 1024)
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  validateWindowsHelperPath(target, { allowAll, roots, checkAncestor: true });

  const parent = path.win32.dirname(target);
  fs.mkdirSync(parent, { recursive: true });

  const mode = String(rec.mode || 'replace');
  let prevSha = null;
  let exists = false;
  try {
    const st = fs.lstatSync(target);
    if (st.isSymbolicLink() || !st.isFile()) throw new Error('PRIVILEGED_PATH_DENIED');
    exists = true;
    if (mode === 'create' && st.size > 0) throw new Error('PRIVILEGED_FILE_EXISTS');
    const existingContent = fs.readFileSync(target);
    prevSha = crypto.createHash('sha256').update(existingContent).digest('hex');
    if (rec.expected_sha256 && prevSha !== rec.expected_sha256)
      throw new Error('PRIVILEGED_SHA_MISMATCH');
  } catch (e) {
    if (e && typeof e === 'object' && /** @type {{code?: unknown}} */ (e).code !== 'ENOENT') {
      if (e instanceof Error && e.message.startsWith('PRIVILEGED_')) throw e;
      throw new Error('PRIVILEGED_PATH_DENIED', { cause: e });
    }
  }

  let fd;
  try {
    fd = fs.openSync(target, mode === 'append' ? 'a' : 'w');
    fs.writeSync(fd, Buffer.from(rec.content, 'utf8'));
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }

  let finalSha;
  if (mode === 'append' && exists) {
    finalSha = crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex');
  } else {
    finalSha = crypto.createHash('sha256').update(rec.content).digest('hex');
  }

  return {
    action: 'write',
    path: target,
    bytes_written: Buffer.byteLength(rec.content, 'utf8'),
    previous_sha256: prevSha,
    sha256: finalSha,
    success: true
  };
}

/**
 * @param {object} [options]
 * @param {string} [options.uninstallScript]
 */
export function windowsPrivilegedHelperHandlers({
  uninstallScript = 'C:\\ProgramData\\NC\\uninstall.ps1'
} = {}) {
  return Object.freeze({
    privileged_shell_exec: executeWindowsPrivilegedShell,
    service_control: executeWindowsServiceControl,
    container_control: executeWindowsContainerControl,
    compose_control: executeWindowsComposeControl,
    package_control: executeWindowsPackageControl,
    system_log_read: executeWindowsSystemLogRead,
    file_permissions: executeWindowsFilePermissions,
    file_read: executeWindowsFileRead,
    file_write: executeWindowsFileWrite,
    client_uninstall: async (/** @type {unknown} */ payload) => {
      if (!payload || typeof payload !== 'object' || Array.isArray(payload))
        throw new Error('PRIVILEGED_PAYLOAD_INVALID');
      const r = await runCapture('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        String(uninstallScript)
      ]);
      return { success: r.code === 0, message: (r.out || `exit ${r.code}`).slice(0, 2000) };
    }
  });
}

const WINDOWS_CONTAINER_ACTIONS = Object.freeze(['list', 'inspect', 'logs']);
const WINDOWS_CONTAINER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.\-]{0,255}$/;
const WINDOWS_COMPOSE_ACTIONS = Object.freeze([
  'list',
  'up',
  'down',
  'restart',
  'pull',
  'stop',
  'start'
]);
const WINDOWS_PACKAGE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9+_.:~-]{0,127}$/;
const WINDOWS_LOG_SOURCES = Object.freeze(['system', 'service', 'kernel', 'application']);
const WINDOWS_LOG_LEVELS = Object.freeze(['all', 'info', 'warning', 'error']);
const WINDOWS_LOG_UNIT_RE = /^[\w@.\-:]{1,128}$/;
const WINDOWS_EVENT_LOGS = Object.freeze(['System', 'Application']);

/**
 * Bounded container-runtime operations via docker.exe. Argv only.
 * @param {unknown} payload
 */
export async function executeWindowsContainerControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (Object.keys(rec).some((k) => !['action', 'container_name', 'tail'].includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const action = String(rec.action || '');
  if (!WINDOWS_CONTAINER_ACTIONS.includes(action))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  if (action === 'list') {
    const r = await runCapture('docker.exe', ['ps', '-a', '--format', '{{json .}}']);
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
  if (!WINDOWS_CONTAINER_NAME_RE.test(containerName)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (action === 'inspect') {
    const r = await runCapture('docker.exe', ['inspect', containerName]);
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
  const r = await runCapture('docker.exe', ['logs', '--tail', String(tail), containerName]);
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
 * Bounded compose operations via docker.exe compose. Argv only.
 * @param {unknown} payload
 */
export async function executeWindowsComposeControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (Object.keys(rec).some((k) => !['action', 'project_dir'].includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const action = String(rec.action || '').toLowerCase();
  if (!WINDOWS_COMPOSE_ACTIONS.includes(action))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  if (action === 'list') {
    const r = await runCapture('docker.exe', ['compose', 'ls', '--format', 'json']);
    if (r.error) throw new Error(`PRIVILEGED_COMPOSE_SPAWN_FAILED:${r.error}`.slice(0, 200));
    if (r.code === 0)
      return {
        frontend: 'docker compose',
        action,
        success: true,
        output_tail: r.out.slice(-8000) || null
      };
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
  if (!/^[A-Za-z]:[\\/]/.test(projectDir) && !projectDir.startsWith('\\\\'))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const args = ['compose'];
  if (action === 'up') args.push('up', '-d');
  else args.push(action);
  // Hardened: the old inline spawn resolved only on `close` (hang + orphan
  // on pipe-holding grandchildren); the shared helper resolves on watchdog.
  const out = await runPrivilegedCapture('docker.exe', args, {
    cwd: projectDir,
    timeoutMs: 600000,
    platform: 'win32'
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
 * Bounded winget operations. Only winget/auto managers are supported on
 * Windows; apt/dnf/brew and friends fail closed with
 * PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED.
 * @param {unknown} payload
 */
export async function executeWindowsPackageControl(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  if (Object.keys(rec).some((k) => !['action', 'manager', 'name', 'contains', 'limit'].includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const action = String(rec.action || '').toLowerCase();
  if (action !== 'list' && action !== 'install' && action !== 'remove')
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  const manager = String(rec.manager || 'auto').toLowerCase();
  if (manager !== 'auto' && manager !== 'winget')
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
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
    const script =
      "$paths = @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); " +
      '$rows = foreach ($p in $paths) { Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion }; ' +
      '$rows | ConvertTo-Json -Compress';
    const r = await runCapture(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      30000
    );
    if (r.error) throw new Error(`PRIVILEGED_PACKAGE_SPAWN_FAILED:${r.error}`.slice(0, 200));
    if (r.code === 0)
      return { manager: 'winget', action, success: true, output_tail: r.out.slice(-8000) || null };
    return {
      manager: 'winget',
      action,
      success: false,
      message: (r.out || `registry list exited ${r.code}`).slice(0, 2000)
    };
  }
  const name = String(rec.name || '');
  if (!WINDOWS_PACKAGE_NAME_RE.test(name)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const verb = action === 'install' ? 'install' : 'uninstall';
  const r = await runCapture(
    'winget.exe',
    [
      verb,
      name,
      '--exact',
      '--silent',
      '--accept-package-agreements',
      '--accept-source-agreements'
    ],
    600000
  );
  if (r.error) throw new Error(`PRIVILEGED_PACKAGE_SPAWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code === 0)
    return { manager: 'winget', action, name, success: true, message: r.out.slice(-2000) || null };
  return {
    manager: 'winget',
    action,
    name,
    success: false,
    message: (r.out || `winget ${verb} exited ${r.code}`).slice(0, 2000)
  };
}

/**
 * Bounded Windows EventLog reads via Get-WinEvent. Argv plus a
 * charset-validated generated script (no caller-supplied script text).
 * journal-style sources map to System/Application logs; kernel maps to
 * System with a Microsoft-Windows-Kernel provider filter.
 * @param {unknown} payload
 */
export async function executeWindowsSystemLogRead(payload) {
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
  if (!WINDOWS_LOG_SOURCES.includes(source))
    throw new Error('PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED');
  const log = source === 'application' ? 'Application' : 'System';
  let provider = null;
  if (rec.unit != null) {
    provider = String(rec.unit);
    if (!WINDOWS_LOG_UNIT_RE.test(provider)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  } else if (source === 'service') {
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  } else if (source === 'kernel') {
    provider = 'Microsoft-Windows-Kernel-General';
  }
  const lines = rec.lines == null ? 100 : Number(rec.lines);
  if (!Number.isInteger(lines) || lines < 1 || lines > 1000)
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const level = rec.level != null ? String(rec.level).toLowerCase() : 'all';
  if (!WINDOWS_LOG_LEVELS.includes(level)) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const contains = rec.contains != null ? String(rec.contains) : '';
  if (contains.length > 200) throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (rec.since != null && String(rec.since).length > 64)
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const n = Math.max(1, Math.min(1000, lines));
  const script = winEventScript({
    log,
    provider,
    level,
    contains,
    lines: n,
    since: rec.since != null && String(rec.since).trim() !== '' ? String(rec.since).trim() : null
  });
  void WINDOWS_EVENT_LOGS;
  const utf8Script = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${script}`;
  // Keep the existing capture budget while retaining its truncation flags.
  const r = await runPrivilegedCapture(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', utf8Script],
    { timeoutMs: 30000, platform: 'win32', inheritEnv: false }
  );
  if (r.error) throw new Error(`PRIVILEGED_LOG_SPAWN_FAILED:${r.error}`.slice(0, 200));
  if (r.code === 0) {
    try {
      if (r.stdoutTruncated || r.stderrTruncated || r.stderr || r.stdout.length > 8000)
        throw new Error('LOG_READ_FAILED');
      const parsed = JSON.parse(r.stdout);
      const rows = Array.isArray(parsed) ? parsed : [parsed];
      if (rows.some((row) => !row || typeof row !== 'object' || Array.isArray(row) || !Object.hasOwn(row, 'Message')))
        throw new Error('LOG_READ_FAILED');
    } catch {
      return { source, unit: provider, success: false, message: 'LOG_READ_FAILED' };
    }
    return {
      source,
      unit: provider,
      success: true,
      output_tail: r.stdout
    };
  }
  // Match only the builder's private exit signal, not an echoed script/marker.
  if (r.code === 65 && !r.stdout && !r.stderr && !r.stdoutTruncated && !r.stderrTruncated && !r.timedOut)
    return { source, unit: provider, success: false, message: 'LOG_READ_FAILED' };
  return {
    source,
    unit: provider,
    success: false,
    message: (r.out || `Get-WinEvent exited ${r.code}`).slice(0, 2000)
  };
}
