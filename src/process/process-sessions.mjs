// Durable process sessions for the NC agent (MCP 5.2.0).
// A session outlives any single MCP connection: the server hands out an
// opaque process_id, the agent owns the OS process + buffers. Reaped by
// exit, explicit terminate, or idle TTL. No shell is ever involved here:
// argv is spawned directly (see process_start contract).
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import {
  filterInheritedEnv,
  guardedCwd,
  shedChildPriority
} from '../client/shell-runner.mjs';
import path from 'node:path';
import os from 'node:os';

/** @type {Map<string, ProcessSession>} */
const sessions = new Map();
// Faz B (tombstone): an explicitly terminated session keeps its final
// transcript readable for 5 minutes so terminate→output chains work.
// Bounded separately from the live table; never persisted to disk.
const tombstones = new Map();
const TOMBSTONE_TTL_MS = 5 * 60 * 1000;
const MAX_TOMBSTONES = 500;

const DEFAULT_IDLE_TTL_MS = 10 * 60 * 1000;
const STREAM_CAP_BYTES = 4 * 1024 * 1024;
const MAX_SESSIONS = 2000;
const MAX_INPUT_BYTES = 256 * 1024;
const SWEEP_KILL_GRACE_MS = 3000;
/** @typedef {{platform: 'linux', bootId: string, startTimeTicks: string}|{platform: 'win32', creationIdentity: string}} ProcessIdentity */
/** @type {WeakMap<object, ProcessIdentity|null>} */
const childIdentities = new WeakMap();

/** Read the kernel identity, never an approximate wall-clock birth time.
 * @param {number} pid
 * @returns {ProcessIdentity|null}
 */
function linuxProcessIdentity(pid) {
  if (!Number.isInteger(pid) || pid < 2) return null;
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    const end = stat.lastIndexOf(')');
    if (end < 0 || !stat.startsWith(`${pid} (`)) return null;
    const ticks = stat.slice(end + 1).trim().split(/\s+/)[19];
    const bootId = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
    if (!/^[0-9]+$/.test(ticks || '') || !/^[a-f0-9-]{36}$/i.test(bootId)) return null;
    return Object.freeze({ platform: 'linux', bootId, startTimeTicks: ticks });
  } catch { return null; }
}

/** Capture synchronously at the spawn boundary, before yielding or PID reuse.
 * Windows/macOS remain unverifiable without a trusted native spawn companion.
 * @param {import('node:child_process').ChildProcess} child
 * @returns {ProcessIdentity|null}
 */
export function captureSpawnIdentity(child) {
  const identity = process.platform === 'linux' ? linuxProcessIdentity(child.pid || 0) : null;
  childIdentities.set(child, identity);
  return identity;
}

/** @param {ProcessIdentity|null} actual @param {ProcessIdentity|null} expected */
function sameLinuxIdentity(actual, expected) {
  if (actual?.platform !== 'linux' || expected?.platform !== 'linux' ||
      !expected.bootId || !/^[0-9]+$/.test(expected.startTimeTicks || '')) return null;
  return actual.bootId === expected.bootId && actual.startTimeTicks === expected.startTimeTicks;
}

/**
 * SEC-002 + Finding 1 (HIGH): child processes must never inherit the
 * host's sensitive environment — the `NC_`/`CONTROL_PLANE_` agent-token
 * strip PLUS the shared credential inherit-blocklist (TOKEN|SECRET|…,
 * DATABASE_URL; see filterInheritedEnv in shell-runner.mjs, the single
 * choke point both spawn paths share). Explicit per-session `env` still
 * applies on top (operator intent wins over defaults).
 *
 * P12-D2: the per-session `env` is model-supplied, so it is validated
 * key-by-key before it reaches spawn(2). Without this, `LD_PRELOAD` /
 * `DYLD_*` / `NODE_OPTIONS` (preloaded code in every child, including
 * interpreters), `KEY=with-equals` / NUL / newline smuggling, NC_ token
 * re-injection past the strip above, and `__proto__` pollution all flowed
 * verbatim into the child environment (probe: sanitizedSessionEnv passed
 * LD_PRELOAD, 'A=B' and NC_FOO straight through). Keys must be strict
 * POSIX identifiers, values plain strings; violations fail closed
 * (INVALID_ENV at the handler) and are dropped here as defense in depth
 * for direct startSession callers. PATH/HOME/etc. stay allowed: blocking
 * preload vectors is the boundary, an exhaustive interpreter-var denylist
 * is not (the caller already holds code exec via shell_exec/process_start
 * itself; the env gate stops smuggling and persistence, not execution).
 */
const SESSION_ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SESSION_ENV_MAX_ENTRIES = 256;
const SESSION_ENV_MAX_KEY_CHARS = 256;
const SESSION_ENV_MAX_VALUE_CHARS = 32768;
const SESSION_ENV_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const SESSION_ENV_PRELOAD_KEYS = new Set([
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'LD_AUDIT',
  'NODE_OPTIONS'
]);
/**
 * @param {unknown} key
 */
export function isDangerousSessionEnvKey(key) {
  if (typeof key !== 'string') return true;
  // P13-D2 (win32 case-insensitivity): the Windows environment block is
  // case-insensitive (SetEnvironmentVariableW/GetEnvironmentVariableW), so
  // node_options reaches a Node child as NODE_OPTIONS and nc_foo shadows
  // NC_FOO. Fold case for the preload/token denylist; POSIX getenv is
  // case-sensitive, where folding is a fail-closed no-op (lowercase
  // variants are inert there). Proto keys stay exact (JS semantics).
  const upper = key.toUpperCase();
  if (upper.startsWith('NC_') || upper.startsWith('CONTROL_PLANE_')) return true;
  if (SESSION_ENV_PROTO_KEYS.has(key)) return true;
  if (SESSION_ENV_PRELOAD_KEYS.has(upper)) return true;
  if (upper.startsWith('DYLD_')) return true;
  return false;
}
/**
 * @param {unknown} key
 */
export function isValidSessionEnvKey(key) {
  if (typeof key !== 'string') return false;
  if (key.length < 1 || key.length > SESSION_ENV_MAX_KEY_CHARS) return false;
  if (!SESSION_ENV_KEY_RE.test(key)) return false;
  if (isDangerousSessionEnvKey(key)) return false;
  return true;
}
/**
 * @param {unknown} value
 */
export function isValidSessionEnvValue(value) {
  if (typeof value !== 'string') return false;
  if (value.includes('\0')) return false;
  if (value.length > SESSION_ENV_MAX_VALUE_CHARS) return false;
  return true;
}
/**
 * Fail-closed validator for model-supplied process_start env (shared by
 * the handler; the sanitizer below re-applies it as a dropping filter).
 * @param {unknown} extra
 */
export function validateSessionEnv(extra) {
  if (extra === undefined || extra === null) return { ok: true };
  if (!extra || typeof extra !== 'object' || Array.isArray(extra))
    return { ok: false, error: 'INVALID_ENV' };
  const entries = Object.entries(extra);
  if (entries.length > SESSION_ENV_MAX_ENTRIES) return { ok: false, error: 'INVALID_ENV' };
  for (const [key, value] of entries) {
    if (!isValidSessionEnvKey(key) || !isValidSessionEnvValue(value))
      return { ok: false, error: 'INVALID_ENV' };
  }
  return { ok: true };
}
export function sanitizedSessionEnv(extra = null) {
  // Finding 1 (HIGH): inherited env filters through the ONE shared
  // choke point in shell-runner.mjs (filterInheritedEnv) — never a local
  // copy of the rule. Explicit per-session `extra` still applies on top:
  // a remote-supplied value is the remote's own value, not a host secret.
  const out = /** @type {NodeJS.ProcessEnv} */ (
    filterInheritedEnv(process.env)
  );
  if (extra && typeof extra === 'object' && !Array.isArray(extra)) {
    for (const [key, value] of Object.entries(extra)) {
      if (!isValidSessionEnvKey(key) || !isValidSessionEnvValue(value)) continue;
      out[key] = value;
    }
  }
  return out;
}

/**
 * @typedef {object} ProcessSession
 * @property {import('node:child_process').ChildProcess} child
 * @property {number} pid
 * @property {string} started_at
 * @property {ProcessIdentity|null} [processIdentity] exact spawn-time kernel identity
 * @property {Array<Buffer>} stdoutChunks
 * @property {Array<Buffer>} stderrChunks
 * @property {number} stdoutBytes
 * @property {number} stderrBytes
 * @property {number} stdoutDroppedBytes bytes discarded past the stream cap
 * @property {number} stderrDroppedBytes bytes discarded past the stream cap
 * @property {boolean} exited
 * @property {boolean} outputClosed
 * @property {boolean} [detached] POSIX detached group leader (A5: group watchdog keeps running after leader exit)
 * @property {number|null} exitCode
 * @property {unknown} exitSignal
 * @property {number} lastActivityMs
 * @property {number} idleTtlMs
 * @property {string} [executable] resolved entrypoint (Finding 2: persisted for the Windows multi-attribute gate)
 * @property {Array<string>} [args] spawn argv (Finding 2: persisted for CommandLine matching)
 * @property {ReturnType<typeof setTimeout>|null} [killTimer] watchdog cleared on exit
 * @property {import('node:events').EventEmitter} [emitter]
 * @param {string} id
 */
/**
 * OTA activation interlock probe: number of currently LIVE process sessions
 * (spawned but not yet exited). Exited-but-unreaped entries and tombstones
 * do not block activation — only in-flight processes do. Bounded: the table
 * itself is capped at MAX_SESSIONS. Exported for the updater interlock.
 * @returns {number}
 */
export function countLiveSessions() {
  let n = 0;
  for (const s of sessions.values()) {
    try {
      if (s && s.exited !== true) n++;
    } catch {}
  }
  return n;
}
/**
 * @returns {boolean} true while any interactive process session is live.
 */
export function hasLiveSessions() {
  return countLiveSessions() > 0;
}

export function getSession(id) {
  const s = sessions.get(id);
  if (!s) return null;
  if (Date.now() - s.lastActivityMs > s.idleTtlMs && s.exited) {
    sessions.delete(id);
    return null;
  }
  return s;
}

/**
 * PID/HANDLE ADDRESSING (process_manage deadlock fix): the served schema
 * historically required an integer `pid` for read/stop/input while this
 * table is keyed by opaque `prc_*` handles, so the schema-mandated form
 * could never resolve (UNKNOWN_HANDLE). The handle stays authoritative
 * (exact match wins); a numeric pid is a convenience alias resolved by a
 * bounded scan of THIS agent's own session table — never a raw OS lookup,
 * so no foreign process can be addressed. Most-recent start wins when two
 * table entries share one pid (pid reuse across entries).
 * @param {unknown} pid
 * @returns {Array<{id: string, session: ProcessSession}>} most-recent first
 */
export function findSessionsByPid(pid) {
  const n = Math.floor(Number(pid));
  if (!Number.isSafeInteger(n) || n < 1 || n > 4194304) return [];
  const now = Date.now();
  /** @type {Array<{id: string, session: ProcessSession, startedMs: number}>} */
  const out = [];
  for (const [id, s] of sessions) {
    if (!s || s.pid !== n) continue;
    // Same TTL reap as getSession: exited-and-idle entries are gone.
    if (now - s.lastActivityMs > s.idleTtlMs && s.exited) continue;
    const startedMs = Date.parse(String(s.started_at || ''));
    out.push({ id, session: s, startedMs: Number.isFinite(startedMs) ? startedMs : 0 });
  }
  out.sort((a, b) => b.startedMs - a.startedMs);
  return out.map(({ id, session }) => ({ id, session }));
}

/**
 * Tombstone half of the pid alias: a terminated handle keeps its final
 * transcript readable, so a pid-form read after stop replays it instead of
 * UNKNOWN_HANDLE. TTL-expiry enforced via getTombstone.
 * @param {unknown} pid
 * @returns {{id: string, tomb: Record<string, unknown>}|null}
 */
export function findTombstoneByPid(pid) {
  const n = Math.floor(Number(pid));
  if (!Number.isSafeInteger(n) || n < 1 || n > 4194304) return null;
  /** @type {{id: string, tomb: Record<string, unknown>}|null} */
  let best = null;
  let bestMs = -1;
  for (const [id, tomb] of tombstones) {
    const rec = /** @type {{session?: {pid?: unknown}, terminated_at?: unknown}} */ (tomb);
    if (!rec || rec.session?.pid !== n) continue;
    const live = getTombstone(id);
    if (!live) continue;
    const ms = Date.parse(String(rec.terminated_at || ''));
    const t = Number.isFinite(ms) ? ms : 0;
    if (!best || t > bestMs) {
      best = { id, tomb: /** @type {Record<string, unknown>} */ (live) };
      bestMs = t;
    }
  }
  return best;
}

/**
 * Resolve any caller-supplied session reference to the authoritative table
 * entry: exact `prc_*` handle first (live, else tombstone), then an integer
 * OS pid alias (digits-only string or number) via the bounded table scan.
 * Anything else — empty, malformed, unknown — is null (caller fails
 * UNKNOWN_HANDLE, never a guess).
 * @param {unknown} ref
 * @returns {{kind: 'live', id: string, session: ProcessSession}|{kind: 'tombstone', id: string, tomb: Record<string, unknown>}|null}
 */
export function resolveSessionRef(ref) {
  const text = typeof ref === 'number' ? String(ref) : String(ref ?? '');
  if (!text) return null;
  // Exact handle match first (any shape, including directly-tracked legacy
  // ids): preserves every previously-resolvable reference verbatim.
  const live = getSession(text);
  if (live) return { kind: 'live', id: text, session: live };
  const tomb = getTombstone(text);
  if (tomb) return { kind: 'tombstone', id: text, tomb };
  // Then the numeric pid alias (digits-only) via the bounded table scan.
  if (!/^\d+$/.test(text)) return null;
  const byPid = findSessionsByPid(text);
  if (byPid.length > 0) return { kind: 'live', id: byPid[0].id, session: byPid[0].session };
  const tombByPid = findTombstoneByPid(text);
  if (tombByPid) return { kind: 'tombstone', id: tombByPid.id, tomb: tombByPid.tomb };
  return null;
}

/** @param {number} [nowMs] */
export function reapSessions(nowMs = Date.now()) {
  let reaped = 0;
  for (const [id, s] of sessions) {
    if (s.exited && nowMs - s.lastActivityMs > s.idleTtlMs) {
      sessions.delete(id);
      reaped++;
    }
  }
  return reaped;
}

/** For tests: drop everything. */
export function clearSessions() {
  sessions.clear();
  tombstones.clear();
}

/**
 * Faz B: retire a live session into a tombstone instead of dropping it.
 * The final transcript stays readable via process_output until the TTL
 * lapses. Returns the tombstone record, or null when the id is not live.
 * @param {string} id
 * @param {{signal?: unknown, graceful?: unknown, forced?: unknown, escalation?: unknown}} [outcome]
 * @param {string|null} [stateDir]
 */
export function retireSession(id, outcome = {}, stateDir = null) {
  const session = sessions.get(id);
  if (!session) return null;
  session.exited = true;
  session.lastActivityMs = Date.now();
  session.emitter?.emit('exit');
  const tomb = {
    session,
    terminated_at: new Date(session.lastActivityMs).toISOString(),
    signal: outcome.signal ?? session.exitSignal ?? null,
    graceful: outcome.graceful ?? null,
    forced: outcome.forced ?? false,
    exit_code: session.exitCode ?? null,
    // P2-06: retain the verify-first escalation so a replayed terminate
    // still reports 'skipped-unverified' instead of hiding it.
    ...(typeof outcome.escalation === 'string' && outcome.escalation
      ? { escalation: outcome.escalation }
      : {})
  };
  // Bound the table: evict the oldest tombstone first (insertion order).
  if (tombstones.size >= MAX_TOMBSTONES) {
    const oldest = tombstones.keys().next();
    if (!oldest.done) tombstones.delete(oldest.value);
  }
  tombstones.set(id, tomb);
  dropSession(id, stateDir);
  return tomb;
}

/**
 * Faz B: fetch a tombstone, expiring it past the TTL.
 * @param {string} id
 */
export function getTombstone(id) {
  const tomb = tombstones.get(id);
  if (!tomb) return null;
  if (Date.now() - Date.parse(tomb.terminated_at) > TOMBSTONE_TTL_MS) {
    tombstones.delete(id);
    return null;
  }
  return tomb;
}

/**
 * Bounded single-PID Windows identity query (Finding 2, MEDIUM).
 * `Get-CimInstance -Filter 'ProcessId = N'` addresses ONE instance — no
 * WMI enumeration, no unbounded scan. Emits a single compressed-JSON row
 * `{StartTime, Path, CommandLine}`; empty/missing output (no such process)
 * or any failure → null (unknown, never guessed).
 * @param {number} pid
 * @param {{execFile?: any}} [options] injectable for deterministic tests
 * @returns {Promise<{startTimeMs: number, creationIdentity: string, path: string|null, commandLine: string|null}|null>}
 */
export async function queryWindowsProcessIdentity(pid, { execFile = null } = {}) {
  const safePid = Math.floor(Number(pid));
  if (!Number.isInteger(safePid) || safePid < 1 || safePid > 4194304) return null;
  try {
    const { execFile: ef } = execFile || (await import('node:child_process'));
    const { promisify } = await import('node:util');
    const run = promisify(ef);
    const { stdout } = await run(
      'powershell',
      [
        '-NoProfile',
        '-Command',
        `$p = Get-CimInstance Win32_Process -Filter 'ProcessId = ${safePid}'; ` +
          `if ($p) { [pscustomobject]@{ StartTime = $p.CreationDate.ToUniversalTime().ToString('o'); ` +
          `Path = $p.ExecutablePath; CommandLine = $p.CommandLine } | ConvertTo-Json -Compress }`
      ],
      { timeout: 10000 }
    );
    const text = String(stdout || '').trim();
    if (!text || text === 'null') return null;
    const row = JSON.parse(text);
    const startTimeMs = Date.parse(String(row?.StartTime || ''));
    if (!Number.isFinite(startTimeMs)) return null;
    return {
      startTimeMs,
      creationIdentity: String(row.StartTime),
      path: typeof row?.Path === 'string' && row.Path ? row.Path : null,
      commandLine:
        typeof row?.CommandLine === 'string' && row.CommandLine ? row.CommandLine : null
    };
  } catch {
    return null;
  }
}
/**
 * Case-insensitive Windows path equality (slash + case folded; the Win32
 * namespace is case-insensitive, so `C:/x/NODE.EXE` === `c:\\x\\node.exe`).
 * @param {string} actual
 * @param {string} expected
 */
export function windowsPathEquals(actual, expected) {
  const norm = (v) => String(v || '').replace(/\//g, '\\').toLowerCase();
  return norm(actual) === norm(expected);
}
/**
 * Multi-attribute Windows process identity (Finding 2, MEDIUM).
 * Require the exact, unrounded creation identity captured at spawn by a
 * trusted native companion. Wall-clock started_at, path and command-line
 * are not a replacement for that identity, even for the same executable.
 *
 * Fail-closed contract (destructive callers MUST `=== true` before
 * signalling; anything else means "do not touch"):
 * - query failed / process gone / time unparseable → null (unknown);
 * - creation identity mismatch → false (different process);
 * - an expected attribute supplied but the live attribute is missing →
 *   null (cannot positively identify — never signal what you cannot see);
 * - expected attribute present and mismatched → false (positively NOT ours).
 * Read-only callers receive the same tri-state: true = identified, false =
 * identified-as-other, null = unknown — they may display null as "unknown"
 * but must never upgrade it to an identity.
 * @param {number} pid
 * @param {{startedAtIso?: unknown, creationIdentity?: unknown, path?: unknown, commandLine?: unknown}} [expected]
 * @param {{execFile?: any}} [options] injectable for deterministic tests
 * @returns {Promise<boolean|null>}
 */
export async function verifyWindowsProcessIdentity(
  pid,
  { creationIdentity = null, path = null, commandLine = null } = {},
  { execFile = null } = {}
) {
  if (typeof creationIdentity !== 'string' || !creationIdentity ||
      !Number.isFinite(Date.parse(creationIdentity))) return null;
  const ident = await queryWindowsProcessIdentity(pid, { execFile });
  if (!ident) return null;
  if (ident.creationIdentity !== creationIdentity) return false;
  if (path !== null && path !== undefined && String(path) !== '') {
    if (!ident.path) return null;
    if (!windowsPathEquals(ident.path, String(path))) return false;
  }
  const wantsCmd =
    commandLine !== null &&
    commandLine !== undefined &&
    (typeof commandLine === 'string' ? commandLine !== '' : true);
  if (wantsCmd) {
    if (!ident.commandLine) return null;
    const actual = ident.commandLine.toLowerCase();
    const wants = Array.isArray(commandLine) ? commandLine : [commandLine];
    // Every expected argv element must appear verbatim (wrapping quotes
    // preserve content, so quoting differences do not false-negative).
    const needles = wants.map(String).filter((s) => s !== '');
    if (needles.length === 0) return true;
    for (const needle of needles) {
      if (!actual.includes(needle.toLowerCase())) return false;
    }
  }
  return true;
}
/**
 * Exact spawn-time identity check. Legacy wall-clock-only records and
 * platforms without an exact identity source are unverifiable (no signal).
 * @param {number} pid
 * @param {string} startedAtIso
 * @param {{platform?: string, execFile?: any, expectedPath?: unknown, expectedCommandLine?: unknown, expectedIdentity?: ProcessIdentity|null}} [options]
 */
export async function verifyProcessStartTime(
  pid,
  startedAtIso,
  { platform = process.platform, execFile = null, expectedPath = null, expectedCommandLine = null, expectedIdentity = null } = {}
) {
  void startedAtIso; // Kept for existing callers; never used as process identity.
  if (!expectedIdentity || expectedIdentity.platform !== platform) return null;
  try {
    if (platform === 'linux') {
      return sameLinuxIdentity(linuxProcessIdentity(pid), expectedIdentity);
    }
    if (platform === 'win32' && expectedIdentity.platform === 'win32') {
      return await verifyWindowsProcessIdentity(
        pid,
        { creationIdentity: expectedIdentity.creationIdentity, path: expectedPath, commandLine: expectedCommandLine },
        { execFile }
      );
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Boot sweep (SYN-PROC-004): adopt-or-kill processes recorded by a previous
 * agent incarnation. Only kills pids that are BOTH alive AND exact-identity
 * verified (PID-reuse guard); dead records are dropped; legacy/unverifiable records
 * are left for the next boot with action `skipped-unverifiable`.
 * On Windows the bar is higher (Finding 2): a record without a recorded
 * entrypoint is NEVER killed on time-only match (fail closed — a recycled
 * PID can share the start-time window), and a path/command-line mismatch
 * is reported as `skipped-identity-mismatch` (positively someone else's
 * process: keep the record, never signal it).
 * @param {{stateDir?: string|null, platform?: string, execFile?: any}} [options]
 */
export async function sweepOrphanedSessions({ stateDir = null, platform = process.platform, execFile = null } = {}) {
  /** @type {Array<{id: string, pid: number, action: string}>} */
  const out = [];
  if (!stateDir) return out;
  const file = path.join(stateDir, 'process-sessions.json');
  /** @type {Record<string, {pid?: unknown, started_at?: unknown, executable?: unknown, args?: unknown, processIdentity?: ProcessIdentity|null}>} */
  let all = {};
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) all = parsed;
  } catch {
    return out;
  }
  const keep = /** @type {Record<string, {pid?: unknown, started_at?: unknown}>} */ ({});
  for (const [id, rec] of Object.entries(all)) {
    const pid = Math.floor(Number(rec?.pid));
    if (!Number.isInteger(pid) || pid < 2 || !isPidAlive(pid, platform)) continue;
    // Recorded entrypoint for the multi-attribute Windows gate (persisted
    // by trackSession; absent on records written before this change).
    const expectedPath = typeof rec?.executable === 'string' && rec.executable ? rec.executable : null;
    const expectedArgs = Array.isArray(rec?.args) ? rec.args.map(String).filter((s) => s !== '') : null;
    if (platform === 'win32' && !expectedPath) {
      // Fail closed: without a recorded path there is no second attribute
      // to check, so a time-only match must never authorize a kill.
      keep[id] = rec;
      out.push({ id, pid, action: 'skipped-unverifiable' });
      continue;
    }
    /** @type {boolean|null} */
    let verdict = null;
    try {
      verdict = await verifyProcessStartTime(pid, String(rec?.started_at || ''), {
        platform,
        execFile,
        expectedPath,
        expectedIdentity: rec.processIdentity || null,
        expectedCommandLine: expectedArgs && expectedArgs.length > 0 ? expectedArgs : null
      });
    } catch {
      verdict = null;
    }
    if (verdict !== true) {
      keep[id] = rec;
      const mismatch = verdict === false && platform === 'win32' && expectedPath;
      out.push({ id, pid, action: mismatch ? 'skipped-identity-mismatch' : 'skipped-unverifiable' });
      continue;
    }
    // V-32.12: thread the recorded start time (and entrypoint on win32)
    // through so the grace-expiry SIGKILL re-verifies PID identity instead
    // of signalling a possibly-reused PID blindly.
    await terminateSessionTreeAsync(
      { pid },
      {
        platform,
        force: false,
        graceMs: SWEEP_KILL_GRACE_MS,
        expectedStartedAt: String(rec?.started_at || ''),
        expectedIdentity: rec.processIdentity || null,
        expectedPath,
        expectedCommandLine: expectedArgs && expectedArgs.length > 0 ? expectedArgs : null,
        execFile
      }
    );
    if (isPidAlive(pid, platform))
      await terminateSessionTreeAsync(
        { pid },
        {
          platform,
          force: true,
          graceMs: 0,
          expectedStartedAt: String(rec?.started_at || ''),
          expectedIdentity: rec.processIdentity || null,
          expectedPath,
          expectedCommandLine: expectedArgs && expectedArgs.length > 0 ? expectedArgs : null,
          execFile
        }
      );
    out.push({ id, pid, action: isPidAlive(pid, platform) ? 'kill-failed' : 'killed' });
    if (!isPidAlive(pid, platform)) continue;
    keep[id] = rec;
  }
  try {
    fs.writeFileSync(file, JSON.stringify(keep), { mode: 0o600 });
  } catch {}
  return out;
}

/**
 * Resolves common executable aliases across platforms (e.g. python <-> python3).
 * @param {string} exe
 * @param {Record<string, string>} [env]
 */
export function resolveExecutable(exe, env = process.env) {
  if (!exe || typeof exe !== 'string') return exe;
  const isWin = process.platform === 'win32';
  const base = path.basename(exe).toLowerCase();
  if (base === 'python' || base === 'python3' || base === 'python.exe' || base === 'python3.exe') {
    const candidates = isWin
      ? [exe, 'python.exe', 'python', 'py.exe', 'py', 'python3.exe', 'python3']
      : [exe, 'python3', 'python'];
    const pathDirs = (env?.PATH || process.env.PATH || '').split(path.delimiter).filter(Boolean);
    for (const name of candidates) {
      if (path.isAbsolute(name)) {
        try {
          if (fs.existsSync(name)) return name;
        } catch {}
        continue;
      }
      for (const dir of pathDirs) {
        const full = path.join(
          dir,
          isWin && !name.toLowerCase().endsWith('.exe') ? `${name}.exe` : name
        );
        try {
          if (fs.existsSync(full)) return full;
        } catch {}
        const direct = path.join(dir, name);
        try {
          if (fs.existsSync(direct)) return direct;
        } catch {}
      }
    }
  }
  return exe;
}

/**
 * @param {string} executable
 * @param {Array<string>} args
 * @param {{cwd?: string, env?: Record<string,string>, timeoutMs?: number, idleTtlMs?: number}} [options]
 */
export function startSession(
  executable,
  args,
  { cwd, env, timeoutMs = 300000, idleTtlMs = DEFAULT_IDLE_TTL_MS } = {}
) {
  let resolved = resolveExecutable(executable, env);
  const childEnv = sanitizedSessionEnv(env);
  if (process.platform === 'win32') {
    // Record and spawn the same full image path; a PATH token cannot equal
    // Win32_Process.ExecutablePath and must never become basename-only trust.
    const pathKey = Object.keys(childEnv).sort().find((key) => key.toLowerCase() === 'path');
    const dirs = /[\\/]/.test(resolved)
      ? ['']
      : [cwd || process.cwd(), ...String(pathKey ? childEnv[pathKey] : '').split(';').filter(Boolean)];
    for (const dir of dirs) {
      const base = path.win32.resolve(cwd || process.cwd(), dir.replace(/^"(.*)"$/, '$1'), resolved);
      const candidates = path.win32.extname(base) ? [base] : [`${base}.com`, `${base}.exe`];
      const found = candidates.find((candidate) => {
        try { return fs.existsSync(candidate); } catch { return false; }
      });
      if (found) {
        resolved = found;
        break;
      }
    }
  }
  const child = spawn(resolved, args, {
    cwd,
    env: childEnv,
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
    windowsHide: true
  });
  // Linux records exact start ticks before yielding to the event loop.
  // Windows/macOS need a retained native handle/creation identity. Until a
  // trusted spawn companion supplies it, fail closed rather than guess.
  const processIdentity = captureSpawnIdentity(child);
  // A8-b: deprioritize the heavy child right after spawn (best-effort,
  // never throws; win32 honestly skips — see shedChildPriority).
  try {
    shedChildPriority(child);
  } catch {}
  child.stdin?.on('error', () => {});
  const stdinRef = /** @type {{ref?: () => void}} */ (child.stdin);
  if (typeof stdinRef?.ref === 'function') {
    stdinRef.ref();
  }
  const now = Date.now();
  const emitter = new EventEmitter();
  emitter.setMaxListeners(0);
  /** @type {ProcessSession} */
  const session = {
    child,
    pid: child.pid || 0,
    detached: process.platform !== 'win32',
    started_at: new Date(now).toISOString(),
    processIdentity,
    executable: resolved,
    args: [...args],
    stdoutChunks: [],
    stderrChunks: [],
    stdoutBytes: 0,
    stderrBytes: 0,
    stdoutDroppedBytes: 0,
    stderrDroppedBytes: 0,
    exited: false,
    outputClosed: false,
    exitCode: null,
    exitSignal: null,
    lastActivityMs: now,
    idleTtlMs,
    emitter
  };
  child.stdout?.on('data', (chunk) => {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (session.stdoutBytes < STREAM_CAP_BYTES) {
      const room = STREAM_CAP_BYTES - session.stdoutBytes;
      if (buf.length <= room) {
        session.stdoutChunks.push(buf);
        session.stdoutBytes += buf.length;
      } else {
        if (room > 0) {
          session.stdoutChunks.push(buf.subarray(0, room));
          session.stdoutBytes += room;
        }
        session.stdoutDroppedBytes += buf.length - room;
      }
    } else {
      session.stdoutDroppedBytes += buf.length;
    }
    session.lastActivityMs = Date.now();
    session.emitter?.emit('output');
  });
  child.stderr?.on('data', (chunk) => {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (session.stderrBytes < STREAM_CAP_BYTES) {
      const room = STREAM_CAP_BYTES - session.stderrBytes;
      if (buf.length <= room) {
        session.stderrChunks.push(buf);
        session.stderrBytes += buf.length;
      } else {
        if (room > 0) {
          session.stderrChunks.push(buf.subarray(0, room));
          session.stderrBytes += room;
        }
        session.stderrDroppedBytes += buf.length - room;
      }
    } else {
      session.stderrDroppedBytes += buf.length;
    }
    session.lastActivityMs = Date.now();
    session.emitter?.emit('output');
  });
  child.on('error', () => {
    // A spawned child's signal/send error is not an exit. Only failure to
    // obtain a PID is terminal here; successful spawns have an exit event.
    if (session.pid > 0) return;
    session.exited = true;
    session.lastActivityMs = Date.now();
    if (session.killTimer) {
      clearTimeout(session.killTimer);
      session.killTimer = null;
    }
    session.emitter?.emit('exit');
  });
  child.once('exit', (code, signal) => {
    session.exited = true;
    session.exitCode = code;
    session.exitSignal = signal;
    session.lastActivityMs = Date.now();
    // Only disarm killTimer if the entire process group is gone.
    // If detached grandchildren survive in the group, keep killTimer armed
    // so the watchdog continues to police surviving group members.
    if (session.killTimer) {
      if (!session.detached || process.platform === 'win32' || !isGroupAlive(session.pid)) {
        clearTimeout(session.killTimer);
        session.killTimer = null;
      }
    }
    session.emitter?.emit('exit');
  });
  child.once('close', () => {
    session.outputClosed = true;
    session.emitter?.emit('exit');
  });
  const timeout = setTimeout(() => {
    session.killTimer = null;
    if (session.exited && !(session.detached && process.platform !== 'win32')) return;
    // P2-05: verified timeout kill (PID-reuse guard). Threads the session's
    // recorded identity; the pre-verify inside terminateSessionTreeAsync
    // fails closed (skipped-unverified, no signal) instead of blind SIGKILL.
    // Residual: an unverifiable PID is left running rather than risk killing
    // an unrelated recycled process/group.
    void terminateSessionTreeAsync(child, {
      platform: process.platform,
      force: true,
      graceMs: 0,
      expectedStartedAt: session.started_at,
      expectedPath: session.executable,
      expectedCommandLine: session.args
    }).catch(() => {});
  }, timeoutMs);
  if (timeout.unref) timeout.unref();
  session.killTimer = timeout;
  return session;
}

/**
 * @param {ProcessSession} session
 * @param {number} stdoutCursor
 * @param {number} stderrCursor
 * @param {number} maxBytes
 */
export function readSession(session, stdoutCursor, stderrCursor, maxBytes) {
  const out = Buffer.concat(session.stdoutChunks);
  const err = Buffer.concat(session.stderrChunks);
  const stdout = out.subarray(
    Math.min(stdoutCursor, out.length),
    Math.min(out.length, Math.min(stdoutCursor, out.length) + maxBytes)
  );
  const stderr = err.subarray(
    Math.min(stderrCursor, err.length),
    Math.min(err.length, Math.min(stderrCursor, err.length) + maxBytes)
  );
  session.lastActivityMs = Date.now();
  const stdoutCut = Math.min(stdoutCursor, out.length) + maxBytes < out.length;
  const stderrCut = Math.min(stderrCursor, err.length) + maxBytes < err.length;
  return {
    stdout: stdout.toString('utf8'),
    stderr: stderr.toString('utf8'),
    stdout_cursor: Math.min(stdoutCursor, out.length) + stdout.length,
    stderr_cursor: Math.min(stderrCursor, err.length) + stderr.length,
    stdout_truncated: session.stdoutDroppedBytes > 0 || stdoutCut,
    stdout_dropped_bytes: session.stdoutDroppedBytes,
    stderr_truncated: session.stderrDroppedBytes > 0 || stderrCut,
    stderr_dropped_bytes: session.stderrDroppedBytes,
    exited: session.exited,
    exit_code: session.exitCode,
    signal: session.exitSignal ?? null,
    // Exit can precede the final pipe data. EOF requires closed streams and
    // a drained page, regardless of whether the child succeeded.
    eof: session.outputClosed === true && !stdoutCut && !stderrCut
  };
}

/**
 * @param {ProcessSession} session
 * @param {string} data
 * @param {boolean} [eof]
 */
export function writeSession(session, data, eof = false) {
  if (typeof data !== 'string' || typeof eof !== 'boolean')
    return { ok: false, error: 'INVALID_ARGUMENT' };
  if (session.exited) return { ok: false, error: 'PROCESS_EXITED' };
  if (!session.child.stdin || session.child.stdin.destroyed || session.child.stdin.writableEnded)
    return { ok: false, error: 'PROCESS_STDIN_CLOSED' };
  if (Buffer.byteLength(data, 'utf8') + (session.child.stdin.writableLength || 0) > MAX_INPUT_BYTES)
    return { ok: false, error: 'INPUT_TOO_LARGE' };
  session.child.stdin.write(data);
  if (eof) session.child.stdin.end();
  session.lastActivityMs = Date.now();
  return { ok: true };
}

/**
 * Synchronous tree kill (R-C1: deprecated — prefer terminateSessionTreeAsync).
 * Requires the spawn-time identity and verifies it synchronously (linux
 * /proc only; every other platform fails closed because a sync check
 * cannot query WMI/ps). A missing, unparseable, mismatched or
 * unverifiable identity sends NO signal (fail closed, `skipped-unverified`).
 * @param {import('node:child_process').ChildProcess|undefined|null} child
 * @param {string} [platform]
 * @param {boolean} [force]
 * @param {{expectedStartedAt?: unknown, expectedPath?: unknown, expectedCommandLine?: unknown, expectedIdentity?: ProcessIdentity|null}} [options] spawn-time identity (REQUIRED)
 */
export function terminateSessionTree(child, platform = process.platform, force = false, options = {}) {
  const pid = Math.floor(Number(child?.pid));
  if (!Number.isInteger(pid) || pid < 2)
    return { signaled: false, signal: null, graceful: false };
  const { expectedStartedAt = null } = options || {};
  const expectedMs = Date.parse(String(expectedStartedAt || ''));
  if (!Number.isFinite(expectedMs))
    return { signaled: false, signal: null, graceful: false, escalation: 'skipped-unverified' };
  let verdict = null;
  try {
    if (platform === 'linux')
      verdict = sameLinuxIdentity(linuxProcessIdentity(pid), options.expectedIdentity || childIdentities.get(child) || null);
  } catch {
    verdict = null;
  }
  if (verdict !== true)
    return { signaled: false, signal: null, graceful: false, escalation: 'skipped-unverified' };
  if (platform === 'win32') {
    // Unreachable today (non-linux always fails closed above); kept as
    // defense in depth so a future sync verifier cannot silently widen.
    return { signaled: false, signal: null, graceful: false, escalation: 'skipped-unverified' };
  }
  try {
    process.kill(-pid, force ? 'SIGKILL' : 'SIGTERM');
  } catch {
    try {
      child.kill(force ? 'SIGKILL' : 'SIGTERM');
    } catch {
      return { signaled: false, signal: null, graceful: false };
    }
  }
  return { signaled: true, signal: force ? 'SIGKILL' : 'SIGTERM', graceful: !force };
}

/**
 * @param {number} pid
 * @param {string} [platform]
 */
function isPidAlive(pid, platform = process.platform) {
  if (!Number.isInteger(pid) || pid < 2) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    // Only ESRCH proves absence; permission/probe failures are not death.
    return /** @type {NodeJS.ErrnoException} */ (e)?.code !== 'ESRCH';
  }
}

/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function isGroupAlive(pid) {
  const id = Math.floor(Number(pid));
  if (!Number.isInteger(id) || id < 2) return false;
  try {
    process.kill(-id, 0);
    return true;
  } catch (e) {
    return /** @type {NodeJS.ErrnoException} */ (e)?.code !== 'ESRCH';
  }
}

/**
 * @param {number|undefined|null} pid group-leader pid
 * @param {string|number} [startedAtIso] expected start time
 * @param {{platform?: string, execFile?: any, expectedIdentity?: ProcessIdentity|null}} [options]
 * @returns {Promise<boolean|null>}
 */
export async function verifyPgidIdentity(
  pid,
  startedAtIso,
  { platform = process.platform, execFile = null, expectedIdentity = null } = {}
) {
  const id = Math.floor(Number(pid));
  if (!Number.isInteger(id) || id < 2) return false;
  // A surviving group member's recent birth is not the leader's identity.
  // Without the original leader, group ownership cannot be established.
  return await verifyProcessStartTime(id, String(startedAtIso), { platform, execFile, expectedIdentity });
}

/**
 * Graceful termination with bounded escalation (SYN-PROC-002): signal gently,
 * wait up to graceMs polling liveness, then force. Never throws; reports how
 * the process actually died so callers (and models) can tell signaled apart
 * from killed.
 * @param {import('node:child_process').ChildProcess|{pid?: unknown, kill?: unknown}|undefined|null} child
 * @param {{platform?: string, force?: boolean, graceMs?: number, expectedStartedAt?: string|null, expectedPath?: string|null, expectedCommandLine?: unknown, expectedIdentity?: ProcessIdentity|null, execFile?: any}} [options]
 */
export async function terminateSessionTreeAsync(
  child,
  {
    platform = process.platform,
    force = false,
    graceMs = 5000,
    expectedStartedAt = null,
    expectedPath = null,
    expectedCommandLine = null,
    expectedIdentity = child ? childIdentities.get(child) || null : null,
    execFile = null
  } = {}
) {
  const pid = Math.floor(Number(child?.pid));
  if (!Number.isInteger(pid) || pid < 2) return { signaled: false, signal: null, graceful: false };
  // R-C1: verify-first PID-reuse guard, FAIL CLOSED. The spawn-time
  // identity is REQUIRED in addition to started_at. A wall-clock timestamp
  // never authorizes a signal; use the captured child identity or an exact
  // persisted identity (a recycled PID must not receive even a gentle signal).
  // Residual: an unverifiable PID is left running rather than risk
  // signalling an unrelated recycled process/group.
  {
    const expectedMs = Date.parse(String(expectedStartedAt || ''));
    if (!Number.isFinite(expectedMs))
      return { signaled: false, signal: null, graceful: false, escalation: 'skipped-unverified' };
    let pre = null;
    try {
      if (isPidAlive(pid, platform)) {
        pre = await verifyProcessStartTime(pid, String(expectedStartedAt), {
          platform,
          execFile,
          expectedPath,
          expectedIdentity,
          expectedCommandLine
        });
      } else if (platform !== 'win32' && isGroupAlive(pid)) {
        pre = await verifyPgidIdentity(pid, String(expectedStartedAt), {
          platform: /** @type {string} */ (platform),
          expectedIdentity,
          execFile
        });
      }
    } catch {
      pre = null;
    }
    if (pre !== true)
      return { signaled: false, signal: null, graceful: false, escalation: 'skipped-unverified' };
  }
  const grace = Math.max(0, Math.min(30000, Math.floor(Number(graceMs ?? 5000) || 0)));
  const gentle = force ? 'SIGKILL' : platform === 'win32' ? null : 'SIGTERM';
  if (platform === 'win32') {
    // Native taskkill via argv (no shell string): gentle pass without /F,
    // escalate with /F after the grace window unless force skips the wait.
    try {
      const args = force ? ['/PID', String(pid), '/T', '/F'] : ['/PID', String(pid), '/T'];
      spawn('taskkill', args, { stdio: 'ignore', windowsHide: true }).unref();
    } catch {}
    if (!force && grace > 0) {
      const deadline = Date.now() + grace;
      while (Date.now() < deadline) {
        if (!isPidAlive(pid, platform))
          return { signaled: true, signal: 'TASKKILL', graceful: true };
        await sleep(100);
      }
    }
    if (!force && isPidAlive(pid, platform)) {
      // V-32.12: verify the PID still belongs to our child before
      // escalating (PID reuse guard, same discipline as
      // sweepOrphanedSessions). When the caller supplied an expected start
      // time and verification fails (false) or is inconclusive (null),
      // fail closed: report the gentle outcome and never TASKKILL/F a
      // possibly-unrelated process.
      if (expectedStartedAt != null) {
        let verdict = null;
        try {
          verdict = await verifyProcessStartTime(pid, String(expectedStartedAt), {
            platform,
            execFile,
            expectedPath,
            expectedIdentity,
            expectedCommandLine
          });
        } catch {
          verdict = null;
        }
        if (verdict !== true)
          return { signaled: true, signal: 'TASKKILL', graceful: false, escalation: 'skipped-unverified' };
      }
      try {
        spawn('taskkill', ['/PID', String(pid), '/T', '/F'], {
          stdio: 'ignore',
          windowsHide: true
        }).unref();
      } catch {}
      return { signaled: true, signal: 'TASKKILL/F', graceful: false };
    }
    return { signaled: true, signal: force ? 'TASKKILL/F' : 'TASKKILL', graceful: !force };
  }
  try {
    process.kill(-pid, force ? 'SIGKILL' : 'SIGTERM');
  } catch {
    try {
      process.kill(pid, force ? 'SIGKILL' : 'SIGTERM');
    } catch {
      try {
        /** @type {{kill?: (signal?: string) => unknown}} */ (child)?.kill?.(
          force ? 'SIGKILL' : 'SIGTERM'
        );
      } catch {
        return { signaled: false, signal: null, graceful: false };
      }
    }
  }
  const isAliveOrGroup = () => {
    if (isPidAlive(pid, platform)) return true;
    if (platform !== 'win32' && isGroupAlive(pid)) return true;
    return false;
  };

  if (!force && grace > 0) {
    const deadline = Date.now() + grace;
    while (Date.now() < deadline) {
      if (!isAliveOrGroup()) return { signaled: true, signal: gentle, graceful: true };
      await sleep(100);
    }
  }
  if (!force && isAliveOrGroup()) {
    // V-32.12: same PID-reuse guard as the win32 path above. The grace
    // window gives the OS time to recycle the PID; escalating to SIGKILL
    // without re-verifying start time could kill an innocent process.
    if (expectedStartedAt != null) {
      let verdict = null;
      try {
        if (isPidAlive(pid, platform)) {
          verdict = await verifyProcessStartTime(pid, String(expectedStartedAt), {
            platform,
            execFile,
            expectedPath,
            expectedIdentity,
            expectedCommandLine
          });
        } else if (platform !== 'win32' && isGroupAlive(pid)) {
          verdict = await verifyPgidIdentity(pid, String(expectedStartedAt), {
            platform: /** @type {string} */ (platform),
            expectedIdentity,
            execFile
          });
        }
      } catch {
        verdict = null;
      }
      if (verdict !== true)
        return { signaled: true, signal: gentle, graceful: false, escalation: 'skipped-unverified' };
    }
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        try {
          /** @type {{kill?: (signal?: string) => unknown}} */ (child)?.kill?.('SIGKILL');
        } catch {}
      }
    }
    return { signaled: true, signal: 'SIGKILL', graceful: false };
  }
  return { signaled: true, signal: gentle, graceful: !force };
}

/**
 * Register a spawned session under an id (server-issued handle).
 * Returns false when the table is full (caller must fail + terminate the
 * spawned child so a refusal never leaks an orphan process).
 * @param {string} id
 * @param {ProcessSession} session
 * @param {string|null} [stateDir] persist pid, wall-clock metadata and exact identity for boot sweep
 */
export function trackSession(id, session, stateDir = null) {
  reapSessions();
  if (sessions.size >= MAX_SESSIONS) return false;
  sessions.set(id, session);
  if (stateDir) {
    try {
      const file = path.join(stateDir, 'process-sessions.json');
      /** @type {Record<string, unknown>} */
      let all = {};
      try {
        all = JSON.parse(fs.readFileSync(file, 'utf8')) || {};
      } catch {}
      if (!all || typeof all !== 'object' || Array.isArray(all)) all = {};
      // Finding 2: persist the entrypoint alongside pid/started_at so a
      // later boot sweep can check path + CommandLine, not just time.
      // Bounded: argv capped at 64 entries by process_start validation.
      /** @type {{pid?: unknown, started_at?: unknown, executable?: unknown, args?: unknown, processIdentity?: ProcessIdentity|null}} */
      const rec = { pid: session.pid, started_at: session.started_at, processIdentity: session.processIdentity || null };
      if (typeof session.executable === 'string' && session.executable) rec.executable = session.executable;
      if (Array.isArray(session.args) && session.args.length > 0)
        rec.args = session.args.map(String).slice(0, 64);
      all[id] = rec;
      fs.mkdirSync(stateDir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(all), { mode: 0o600 });
    } catch {}
  }
  return session;
}

/**
 * @param {string} id
 * @param {string|null} [stateDir]
 */
export function dropSession(id, stateDir = null) {
  const gone = sessions.delete(id);
  if (stateDir) {
    try {
      const file = path.join(stateDir, 'process-sessions.json');
      const all = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (all && typeof all === 'object' && !Array.isArray(all) && all[id]) {
        delete all[id];
        fs.writeFileSync(file, JSON.stringify(all), { mode: 0o600 });
      }
    } catch {}
  }
  return gone;
}

/**
 * @param {unknown} job
 */
function payloadOf(job) {
  const r = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  return /** @type {Record<string, unknown>} */ (r.request_payload || r.payload || {});
}

const ok = (/** @type {unknown} */ result_payload) => ({
  status: 'completed',
  exit_code: 0,
  stdout: '',
  stderr: '',
  error: null,
  duration_ms: 0,
  result_payload
});
const fail = (/** @type {unknown} */ error) => ({
  status: 'failed',
  exit_code: null,
  stdout: '',
  stderr: '',
  error: String(error),
  duration_ms: 0,
  result_payload: {}
});

/**
 * OS-native process listing (system scope). Best-effort parsing, capped.
 * @param {string} [platform]
 */
export async function listSystemProcesses(platform = process.platform) {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const run = promisify(execFile);
  /**
   * @param {string} cmd
   * @param {Array<string>} args
   */
  const capture = async (cmd, args) => {
    const { stdout } = await run(cmd, args, {
      timeout: 15000,
      windowsHide: true,
      maxBuffer: 2 * 1024 * 1024
    });
    return stdout;
  };
  const out = [];
  if (platform === 'win32') {
    const stdout = await capture('tasklist', ['/FO', 'CSV', '/NH']);
    for (const line of stdout.split(/\r?\n/)) {
      const m = line.match(/^"([^"]+)",\s*"(\d+)"/);
      if (m) out.push({ pid: Number(m[2]), name: m[1] });
    }
    return out;
  }
  const stdout = await capture(
    'ps',
    platform === 'darwin'
      ? ['-ax', '-o', 'pid,ppid,comm,etime,pcpu,pmem']
      : ['-eo', 'pid,ppid,comm,etime,pcpu,pmem']
  );
  for (const line of stdout.split('\n').slice(1)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 6 || !/^\d+$/.test(parts[0] || '')) continue;
    out.push({
      pid: Number(parts[0]),
      ppid: Number(parts[1]),
      name: parts[2],
      elapsed: parts[3],
      cpu_percent: Number(parts[4]),
      mem_percent: Number(parts[5])
    });
  }
  return out;
}

/**
 * Detects common REPL prompts in text (Python, Bash/sh, Node.js, etc.).
 * @param {string} text
 * @returns {boolean}
 */
export function hasReplPrompt(text) {
  if (typeof text !== 'string' || !text) return false;
  // Direct check for explicit REPL prompt markers at end of buffer
  if (text.endsWith('>>> ') || text.endsWith('$ ') || text.endsWith('> ')) {
    return true;
  }
  // Prompts waiting for input sit at the tail of the buffer (after newline or start)
  const trimmed = text.trimEnd();
  if (trimmed.endsWith('...')) {
    return /(?:^|\r?\n)\.\.\.\s*$/.test(trimmed);
  }
  const trailingPromptRegex = /(?:^|\r?\n)(?:[A-Za-z0-9_@:~.\-\/\\ ]*[$#]|>>>|>)\s*$/;
  return trailingPromptRegex.test(trimmed);
}

/**
 * Silence early-exit for `processInputJob` wait_for_prompt (ora-7 Finding 2,
 * Termcp EventSilence pattern, design only): when a non-prompt command's
 * output goes quiet for this long, return with the captured output instead
 * of burning the full hard timeout. 2000ms: an order of magnitude above
 * scheduling jitter and typical inter-burst gaps (tens of ms), far below the
 * 60s hard-timeout ceiling and the 5s default prompt wait — a
 * human-perceived "done" pause. The window only arms after the first
 * post-write output byte (first-byte arming IS the startup grace: it cannot
 * fire before the command has plausibly started producing), and the hard
 * timeout remains the backstop for streams that never go quiet. Exported
 * for unit tests.
 */
export const PROCESS_INPUT_SILENCE_MS = 2000;

/**
 * Sends input to a process session, with optional wait_for_prompt snapshot support.
 * @param {unknown} job
 */
export async function processInputJob(job) {
  try {
    const p = payloadOf(job);
    // PID/HANDLE addressing: handle authoritative, numeric pid alias.
    // Input needs a live stdin: tombstones stay UNKNOWN_HANDLE here.
    const resolved = resolveSessionRef(p.process_id ?? p.pid ?? p.handle);
    if (!resolved || resolved.kind !== 'live') return fail('UNKNOWN_HANDLE');
    const session = resolved.session;

    const waitForPrompt = p.wait_for_prompt === true;
    const rawTimeout =
      p.timeout_ms === undefined || p.timeout_ms === null ? 5000 : Number(p.timeout_ms);
    const timeoutMs = Number.isFinite(rawTimeout)
      ? Math.max(100, Math.min(60000, Math.floor(rawTimeout)))
      : 5000;

    const initialStdoutBytes = session.stdoutBytes;
    const initialStderrBytes = session.stderrBytes;

    if (p.data !== undefined && typeof p.data !== 'string') return fail('INVALID_ARGUMENT');
    if (p.eof !== undefined && typeof p.eof !== 'boolean') return fail('INVALID_ARGUMENT');
    const data = typeof p.data === 'string' ? p.data : '';
    const w = writeSession(session, data, p.eof === true);
    if (!w.ok) return fail(w.error);

    if (!waitForPrompt) {
      return ok({ process_id: resolved.id, written: true });
    }

    let promptDetected = false;

    const checkPrompt = () => {
      if (session.exited) return true;
      const out = Buffer.concat(session.stdoutChunks);
      const err = Buffer.concat(session.stderrChunks);

      if (data.length > 0) {
        const newOut = out.subarray(Math.min(initialStdoutBytes, out.length)).toString('utf8');
        const newErr = err.subarray(Math.min(initialStderrBytes, err.length)).toString('utf8');
        if (hasReplPrompt(newOut) || hasReplPrompt(newErr)) {
          promptDetected = true;
          return true;
        }
        if (out.length > initialStdoutBytes || err.length > initialStderrBytes) {
          const fullOut = out.toString('utf8');
          const fullErr = err.toString('utf8');
          if (hasReplPrompt(fullOut) || hasReplPrompt(fullErr)) {
            promptDetected = true;
            return true;
          }
        }
      } else {
        const fullOut = out.toString('utf8');
        const fullErr = err.toString('utf8');
        if (hasReplPrompt(fullOut) || hasReplPrompt(fullErr)) {
          promptDetected = true;
          return true;
        }
      }
      return false;
    };

    if (!checkPrompt() && !session.exited) {
      await new Promise((resolve) => {
        let timer = null;
        let quietTimer = null;
        // First-byte arming: the silence window must not confuse "no output
        // yet" with "output finished". Baseline at pre-write buffer
        // sizes; the quiet timer only exists while post-write bytes have
        // been seen. A never-quiet stream keeps resetting it, so the hard
        // timeout below stays the backstop.
        const baselineBytes = initialStdoutBytes + initialStderrBytes;
        const postWriteBytes = () => session.stdoutBytes + session.stderrBytes;
        const armQuiet = () => {
          if (quietTimer) clearTimeout(quietTimer);
          quietTimer = setTimeout(() => {
            // Final prompt check: a prompt that landed with the last burst
            // still reports prompt_detected accurately on the silence path.
            checkPrompt();
            cleanup();
            resolve(undefined);
          }, PROCESS_INPUT_SILENCE_MS);
          try {
            quietTimer.unref?.();
          } catch {}
        };
        const onActivity = () => {
          // REPL path (pre-existing, prompt → immediate return): checked
          // first and untouched by the silence logic below.
          if (checkPrompt() || session.exited) {
            cleanup();
            resolve(undefined);
            return;
          }
          // Non-prompt burst: (re)start the quiet window.
          if (postWriteBytes() > baselineBytes) armQuiet();
        };
        function cleanup() {
          if (timer) clearTimeout(timer);
          if (quietTimer) clearTimeout(quietTimer);
          timer = null;
          quietTimer = null;
          if (session.emitter) {
            session.emitter.off('output', onActivity);
            session.emitter.off('exit', onActivity);
          }
        }
        timer = setTimeout(() => {
          cleanup();
          resolve(undefined);
        }, timeoutMs);
        // Bounded waiter must not pin the loop alone (leak-free timers).
        try {
          timer.unref?.();
        } catch {}
        if (session.emitter) {
          session.emitter.on('output', onActivity);
          session.emitter.on('exit', onActivity);
        }
        // Gap cover: output that arrived between writeSession and listener
        // attach emits nothing more — arm from the buffers directly so a
        // burst-then-quiet process still early-exits instead of stalling.
        if (!session.exited && !checkPrompt() && postWriteBytes() > baselineBytes) armQuiet();
      });
    }

    const stdoutText = Buffer.concat(session.stdoutChunks).toString('utf8');
    const stderrText = Buffer.concat(session.stderrChunks).toString('utf8');
    const outputText = stdoutText || stderrText;

    const payload = {
      process_id: resolved.id,
      written: true,
      output: outputText,
      stdout: stdoutText,
      stderr: stderrText,
      buffer: outputText,
      prompt_detected: promptDetected,
      status: session.exited ? (session.exitCode === 0 ? 'completed' : 'failed') : 'running',
      exit_code: session.exitCode
    };
    const res = ok(payload);
    res.stdout = stdoutText;
    res.stderr = stderrText;
    return res;
  } catch (e) {
    const errorRecord = /** @type {{message?: unknown}} */ (e);
    return fail(errorRecord?.message);
  }
}

export function makeProcessHandlers(
  /** @type {{stateDir?: string|null}} */ { stateDir = null } = {}
) {
  return {
    process_start: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        const executable = String(p.executable || '');
        if (!executable || executable.includes('\0') || executable.length > 1024)
          throw new Error('INVALID_EXECUTABLE');
        const rawArgs = p.args === undefined ? [] : p.args;
        if (!Array.isArray(rawArgs) || rawArgs.length > 64) throw new Error('INVALID_ARGS');
        const args = rawArgs.map(String);
        // F-05 (mirrors log_follow_start N-01): the consolidated
        // process_manage(action=start) contract declares command, not a
        // caller-supplied handle — the handle is minted here when absent.
        // Legacy callers arrive holding a hub-minted prc_ handle (honored
        // verbatim); present-but-malformed still fails closed.
        const rawProcessId = p.process_id;
        let processId;
        if (rawProcessId === undefined || rawProcessId === null || rawProcessId === '') {
          processId = `prc_${crypto.randomBytes(16).toString('hex')}`;
        } else {
          processId = String(rawProcessId);
          if (!/^prc_[0-9a-f]{32}$/.test(processId)) throw new Error('INVALID_PROCESS_ID');
        }
        // A live handle is never replaced: overwriting the table entry would
        // orphan the old child (still running, no longer reachable).
        if (getSession(processId)) throw new Error('HANDLE_IN_USE');
        const rawTimeout =
          p.timeout_seconds === undefined || p.timeout_seconds === null
            ? 300
            : Number(p.timeout_seconds);
        const timeoutSeconds = Number.isFinite(rawTimeout) && rawTimeout > 0 ? rawTimeout : 300;
        const rawIdle =
          p.idle_timeout_seconds === undefined || p.idle_timeout_seconds === null
            ? 600
            : Number(p.idle_timeout_seconds);
        const idleSeconds = Number.isFinite(rawIdle) && rawIdle > 0 ? rawIdle : 600;
        // P12-D2: model-supplied env fails closed (preload keys, NUL/equals
        // smuggling, NC_ re-injection, non-string values all INVALID_ENV).
        if (!validateSessionEnv(p.env).ok) throw new Error('INVALID_ENV');
        const session = startSession(executable, args, {
          // P3-D2: model-supplied cwd reaches spawn(2) verbatim (same class
          // as shell-runner P3-D1). The Reference promises PATH_NOT_ALLOWED /
          // PATH_DENIED_SENSITIVE for the process working directory.
          cwd: typeof p.cwd === 'string' ? guardedCwd(p.cwd) : undefined,
          env:
            p.env && typeof p.env === 'object'
              ? /** @type {Record<string, string>} */ (p.env)
              : undefined,
          timeoutMs: Math.max(1000, Math.min(3600000, timeoutSeconds * 1000)),
          idleTtlMs: Math.max(30000, Math.min(3600000, idleSeconds * 1000))
        });
        if (!trackSession(processId, session, stateDir)) {
          try {
            await terminateSessionTreeAsync(session.child, {
              platform: process.platform,
              force: true,
              graceMs: 0,
              expectedStartedAt: session.started_at,
              expectedPath: session.executable,
              expectedCommandLine: session.args
            });
          } catch {}
          throw new Error('PROCESS_TABLE_FULL');
        }
        reapSessions();
        return ok({
          process_id: processId,
          status: session.exited ? 'failed' : 'running',
          pid: session.pid,
          started_at: session.started_at,
          stdout_cursor: 0,
          stderr_cursor: 0
        });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    process_output: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        // PID/HANDLE addressing: handle authoritative, numeric pid alias.
        const resolved = resolveSessionRef(p.process_id ?? p.pid ?? p.handle);
        if (!resolved) return fail('UNKNOWN_HANDLE');
        if (resolved.kind === 'tombstone') {
          // Faz B: a terminated handle still serves its final transcript.
          const tomb = resolved.tomb;
          const tombSession = /** @type {ProcessSession} */ (tomb.session);
          const r = readSession(
            tombSession,
            Math.max(0, Number(p.stdout_cursor ?? p.cursor ?? 0)),
            Math.max(0, Number(p.stderr_cursor ?? p.cursor ?? 0)),
            Math.max(1, Math.min(262144, Number(p.max_bytes ?? 65536)))
          );
          return ok({
            process_id: resolved.id,
            status: 'terminated',
            ...r,
            exit_code: tomb.exit_code,
            terminated_at: tomb.terminated_at,
            signal: tomb.signal,
            graceful: tomb.graceful
          });
        }
        const session = resolved.session;
        const stdoutCursor = Math.max(0, Number(p.stdout_cursor ?? p.cursor ?? 0));
        const stderrCursor = Math.max(0, Number(p.stderr_cursor ?? p.cursor ?? 0));
        const maxBytes = Math.max(1, Math.min(262144, Number(p.max_bytes ?? 65536)));
        const rawWait = p.wait_ms === undefined || p.wait_ms === null ? 0 : Number(p.wait_ms);
        const waitMs = Number.isFinite(rawWait)
          ? Math.max(0, Math.min(30000, Math.floor(rawWait)))
          : 0;

        if (
          waitMs > 0 &&
          !session.exited &&
          session.stdoutBytes <= stdoutCursor &&
          session.stderrBytes <= stderrCursor
        ) {
          await new Promise((resolve) => {
            let timer = null;
            const onActivity = () => {
              cleanup();
              resolve();
            };
            function cleanup() {
              if (timer) clearTimeout(timer);
              if (session.emitter) {
                session.emitter.off('output', onActivity);
                session.emitter.off('exit', onActivity);
              }
            }
            timer = setTimeout(onActivity, waitMs);
            try {
              timer.unref?.();
            } catch {}
            if (session.emitter) {
              session.emitter.once('output', onActivity);
              session.emitter.once('exit', onActivity);
            }
          });
        }

        const r = readSession(
          session,
          stdoutCursor,
          stderrCursor,
          maxBytes
        );
        return ok({
          process_id: resolved.id,
          status: session.exited ? (session.exitCode === 0 ? 'completed' : 'failed') : 'running',
          ...r,
          exit_code: session.exitCode
        });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    process_input: async (/** @type {unknown} */ job) => processInputJob(job),
    process_terminate: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        // PID/HANDLE addressing: handle authoritative, numeric pid alias.
        const resolved = resolveSessionRef(p.process_id ?? p.pid ?? p.handle);
        if (!resolved) return fail('UNKNOWN_HANDLE');
        if (resolved.kind === 'tombstone') {
          // Faz B: terminating an already-terminated handle replays the
          // recorded outcome instead of UNKNOWN_HANDLE.
          const tomb = resolved.tomb;
          return ok({
            process_id: resolved.id,
            terminated: true,
            already_terminated: true,
            terminated_at: tomb.terminated_at,
            forced: tomb.forced,
            signal: tomb.signal,
            graceful: tomb.graceful,
            // P2-06: replay the verify-first escalation when present.
            ...(typeof tomb.escalation === 'string' && tomb.escalation
              ? { escalation: tomb.escalation }
              : {})
          });
        }
        const id = resolved.id;
        const session = resolved.session;
        // SYN-PROC-002: graceful by default (SIGTERM + bounded wait, then
        // SIGKILL); force skips the wait. Reports how it actually died.
        const rawGrace = p.grace_ms === undefined || p.grace_ms === null ? NaN : Number(p.grace_ms);
        const graceMs = Number.isFinite(rawGrace)
          ? Math.max(0, Math.min(30000, Math.floor(rawGrace)))
          : 5000;
        // V-32.12: pass the recorded identity so the grace-expiry SIGKILL
        // re-verifies start time (PID-reuse guard) instead of escalating
        // blindly.
        const outcome = await terminateSessionTreeAsync(session.child, {
          platform: process.platform,
          force: p.force === true,
          graceMs,
          expectedStartedAt: typeof session.started_at === 'string' ? session.started_at : null,
          expectedPath: typeof session.executable === 'string' ? session.executable : null,
          expectedCommandLine: Array.isArray(session.args) ? session.args.map(String) : null
        });
        const groupAlive = session.detached && process.platform !== 'win32' && isGroupAlive(session.pid);
        const terminated = !groupAlive && (
          session.exited ||
          (outcome.signaled === true && !outcome.escalation && !isPidAlive(session.pid))
        );
        // A skipped/failed signal is not a terminated process. Keep its live
        // handle, watchdog and transcript so a later authorized stop can retry.
        if (terminated) {
          session.exited = true;
          session.lastActivityMs = Date.now();
          retireSession(
            id,
            {
              signal: outcome.signal,
              graceful: outcome.graceful,
              forced: p.force === true,
              ...(typeof outcome.escalation === 'string' && outcome.escalation
                ? { escalation: outcome.escalation }
                : {})
            },
            stateDir
          );
        }
        // P2-06: surface the verify-first escalation so callers see
        // 'skipped-unverified' instead of a silent graceful:false.
        return ok({
          process_id: id,
          terminated,
          forced: p.force === true,
          signal: outcome.signal,
          graceful: outcome.graceful,
          transcript_retained: true,
          ...(typeof outcome.escalation === 'string' && outcome.escalation
            ? { escalation: outcome.escalation }
            : {})
        });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    process_list: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        // F-06: schema default is managed (packages/contracts/mcp/tools.mjs
        // processManageTool + spec/registry/tools/process_manage.yaml +
        // process_list.yaml all declare default managed). Absent/empty
        // means managed; only explicit 'system' enumerates the OS table.
        // Implementation was wrong (rejected managed, defaulted to system
        // upstream); schema is correct, so no contract change.
        const rawScope = p.scope;
        const scope =
          rawScope === undefined || rawScope === null || rawScope === '' ? 'managed' : String(rawScope);
        if (scope !== 'managed' && scope !== 'system') return fail('SCOPE_INVALID');
        const rawLimit = p.limit === undefined || p.limit === null ? NaN : Number(p.limit);
        const limit = Number.isFinite(rawLimit)
          ? Math.max(1, Math.min(5000, Math.floor(rawLimit)))
          : NaN;
        if (scope === 'system') {
          const all = await listSystemProcesses();
          const processes = Number.isFinite(limit) ? all.slice(0, limit) : all;
          return ok({
            scope: 'system',
            processes,
            total_count: all.length,
            truncated: processes.length < all.length
          });
        }
        reapSessions();
        const all = [];
        for (const [id, s] of sessions) {
          const exe = typeof s.executable === 'string' && s.executable ? s.executable : 'unknown';
          const argv = Array.isArray(s.args) ? s.args.map(String) : [];
          const command = [exe, ...argv].filter((t) => t !== '').join(' ') || 'unknown';
          const state = s.exited ? (s.exitCode === 0 ? 'completed' : 'failed') : 'running';
          all.push({
            process_id: id,
            pid: s.pid,
            command,
            state,
            status: state,
            started_at: s.started_at
          });
        }
        const processes = Number.isFinite(limit) ? all.slice(0, limit) : all;
        return ok({
          scope: 'managed',
          processes,
          total_count: all.length,
          truncated: processes.length < all.length
        });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    }
  };
}
