// Stateful log-follow handles for the NC agent (MCP 5.2.0).
// The server issues opaque log_ handles; the agent tracks byte offsets
// per handle with TTL. Prefer over repeated log_read polling.
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { realAllowed } from '../structured-ops/structured-ops.mjs';
import { parseSince } from './system-log-ops.mjs';

/** @type {Map<string, {file: string, ttlMs: number, updatedMs: number}>} */
const follows = new Map();
const FOLLOW_TTL_MS = 30 * 60 * 1000;
const MAX_FOLLOWS = 1000;

// No cross-session eviction: the table is bounded by refusing new handles
// once full (mirrors trackSession -> PROCESS_TABLE_FULL). Per-caller quotas
// are impossible here — the agent job carries no caller identity, only
// tool + request_payload — so the least invasive bound that actually
// prevents cross-session damage is a fail-closed refusal that never purges
// another session's live handle. TTL reap still frees expired slots.

/** @param {number} [nowMs] */
export function reapFollows(nowMs = Date.now()) {
  let reaped = 0;
  for (const [id, f] of follows) {
    if (nowMs - f.updatedMs > f.ttlMs) {
      follows.delete(id);
      reaped++;
    }
  }
  return reaped;
}

/** For tests. */
export function clearFollows() {
  follows.clear();
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
 * @param {object} [options]
 * @param {Record<string, string>} [options.logSources] name -> absolute file
 * @param {Array<string>} [options.readRoots] allowlisted roots for explicit paths
 */
export function makeLogFollowHandlers({ logSources = {}, readRoots = [] } = {}) {
  /**
   * @param {string} source
   * @param {string} [explicitPath]
   */
  const resolveFile = (source, explicitPath) => {
    if (explicitPath && typeof explicitPath === 'string' && explicitPath.length <= 4096)
      return explicitPath;
    const file = logSources[source];
    if (!file) throw new Error('LOG_SOURCE_NOT_ALLOWED');
    return file;
  };
  /**
   * @param {string} file
   * @param {number} cursor
   * @param {number} maxBytes
   */
  const readFrom = async (file, cursor, maxBytes) => {
    const st = await fs.stat(file);
    let offset = Math.max(0, cursor);
    let truncatedReset = false;
    if (offset > st.size) {
      offset = 0;
      truncatedReset = true;
    }
    const len = Math.min(st.size - offset, maxBytes);
    if (len <= 0) return { content: '', cursor: st.size, eof: true, truncatedReset };
    const handle = await fs.open(file, 'r');
    try {
      const buffer = Buffer.alloc(len);
      const { bytesRead } = await handle.read(buffer, 0, len, offset);
      return {
        content: buffer.subarray(0, bytesRead).toString('utf8'),
        cursor: offset + bytesRead,
        eof: offset + bytesRead >= st.size,
        truncatedReset
      };
    } finally {
      await handle.close();
    }
  };
  return {
    log_follow_start: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        // Contract truth (log_follow_start schema: no `handle` property;
        // log_stream `handle` is "returned by action=start"): start mints
        // the opaque handle when the caller omits it instead of rejecting.
        // Present-but-invalid handles still fail closed (INVALID_HANDLE).
        const rawHandle = p.handle;
        let handle;
        if (rawHandle === undefined || rawHandle === null || rawHandle === '') {
          handle = `log_${crypto.randomBytes(16).toString('hex')}`;
        } else {
          handle = String(rawHandle);
          if (!/^log_[0-9a-f]{32}$/.test(handle)) return fail('INVALID_HANDLE');
        }
        const explicit = typeof p.path === 'string' && p.path ? String(p.path) : null;
        // Explicit paths are caller-controlled: gate them against read
        // roots (+sensitive denylist) exactly like the file tools instead
        // of trusting them verbatim (arbitrary-read hardening).
        const file = explicit
          ? await realAllowed(explicit, readRoots, false)
          : resolveFile(String(p.source || ''), undefined);
        const maxLines = Math.max(1, Math.min(1000, Number(p.max_lines ?? 200)));
        const st = await fs.stat(file);
        const tailBytes = Math.min(st.size, maxLines * 512);
        const windowStart = Math.max(0, st.size - tailBytes);
        // P2-13: read through EOF within the tailBytes window (readFrom caps
        // len to size-offset, so this is bounded to <=512KB, never unbounded).
        // The old 65536 cap read a MIDDLE chunk on files >~64KB and missed
        // the true tail.
        const start = await readFrom(file, windowStart, tailBytes);
        // Contract: at most maxLines COMPLETE lines. The byte window is
        // only a fetch heuristic: drop a leading partial line (the window
        // rarely starts on a line boundary — consumers cannot parse a
        // fragment as JSON), then keep the last maxLines lines.
        let lines = String(start.content || '').split('\n');
        if (windowStart > 0) lines = lines.slice(1);
        if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
        lines = lines.slice(-maxLines);
        const content = lines.length ? lines.join('\n') + '\n' : '';
        reapFollows();
        // Fail closed once full: silently evicting the stalest entry lets
        // one caller starting a thousand tails purge other sessions' live
        // handles. Re-start of an already-held handle still overwrites
        // that same slot instead of refusing.
        if (follows.size >= MAX_FOLLOWS && !follows.has(handle)) return fail('FOLLOW_TABLE_FULL');
        follows.set(handle, { file, ttlMs: FOLLOW_TTL_MS, updatedMs: Date.now() });
        return ok({ handle, content, cursor: start.cursor, eof: start.eof });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown, code?: unknown}} */ (e);
        return fail(errorRecord?.code === 'ENOENT' ? 'LOG_SOURCE_NOT_FOUND' : errorRecord?.message);
      }
    },
    log_follow_read: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        const handle = String(p.handle || '');
        const f = follows.get(handle);
        if (!f) return fail('UNKNOWN_HANDLE');
        f.updatedMs = Date.now();
        const maxBytes = Math.max(1, Math.min(262144, Number(p.max_bytes ?? 65536)));
        const r = await readFrom(f.file, Math.max(0, Number(p.cursor ?? 0)), maxBytes);
        return ok({ handle, ...r });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown, code?: unknown}} */ (e);
        return fail(errorRecord?.code === 'ENOENT' ? 'LOG_SOURCE_NOT_FOUND' : errorRecord?.message);
      }
    },
    log_follow_stop: async (/** @type {unknown} */ job) => {
      const p = payloadOf(job);
      follows.delete(String(p.handle || ''));
      return ok({ stopped: true });
    }
  };
}

// ---------------------------------------------------------------------------
// Agent-plane `since` support for plain log files (log_query action=agent /
// log_read). Unlike the service/system planes (journalctl/PowerShell carry a
// native time bound), these sources are flat files read by tail, so the
// bound is applied here by parsing timestamps out of the lines themselves.
//
// Timestamp coverage per LOG_SOURCES entry (apps/agent/core/client.mjs):
// - `client` (logs/client.log): JSON lines written by log() in client.mjs,
//   every line carries an ISO `ts` field. Structured path below.
// - `mcp-server` (logs/mcp-server.log), `mcp-tunnel` (logs/mcp-tunnel.log):
//   writers are EXTERNAL (MCP server/tunnel processes, none in this repo), so
//   no single format can be assumed. Best-effort layered parse: JSON
//   time-fields first, then an ISO-8601 scan, then syslog "Mmm dd HH:MM:SS".
//   Lines with no parseable timestamp are NOT filterable.
//
// Fail-closed rule: when a `since` bound is active, untimestamped lines are
// DROPPED (never returned), because returning them risks returning rows older
// than the bound — the exact defect this fixes. When no bound is given,
// every line passes through untouched (previous behaviour preserved).
// An unparseable bound never degrades to "no filter": resolveLogSince
// reports it and the caller must fail with LOG_SINCE_INVALID.
// ---------------------------------------------------------------------------

/** JSON time-field names checked (in order) on JSON-encoded lines. */
const AGENT_SINCE_TIME_KEYS = Object.freeze([
  'ts',
  'timestamp',
  'time',
  '@timestamp',
  'datetime',
  'date',
  'created_at',
  'logged_at'
]);

/** ISO-8601-ish instant anywhere in a line (date required, time optional). */
const AGENT_SINCE_ISO_RE =
  /\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:\s?(?:Z|[+-]\d{2}:?\d{2}))?)\b/;

/** Syslog "Oct  4 15:05:01" prefix (year-less, local wall time). */
const AGENT_SINCE_SYSLOG_RE =
  /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/i;

const AGENT_SINCE_MONTHS = Object.freeze({
  jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
  jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11
});

// Numeric timestamps are unit-ambiguous (epoch seconds vs milliseconds), and
// a wrong guess flips ancient<->future. Accept only instants inside a sane
// window around now (2000-01-01 .. now+1h); anything else is unparseable so
// the line is dropped under an active bound instead of mis-sorted.
const AGENT_SINCE_MIN_MS = Date.UTC(2000, 0, 1);
const AGENT_SINCE_FUTURE_SKEW_MS = 3600 * 1000;

/**
 * @param {unknown} v
 * @param {number} [nowMs]
 * @returns {number|null} epoch ms, or null when not a usable instant
 */
export function coerceLogTimestampValue(v, nowMs = Date.now()) {
  if (v === null || v === undefined) return null;
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) return null;
    const ms = v < 1e12 ? v * 1000 : v;
    if (!Number.isFinite(ms)) return null;
    if (ms < AGENT_SINCE_MIN_MS || ms > nowMs + AGENT_SINCE_FUTURE_SKEW_MS) return null;
    return ms;
  }
  if (typeof v === 'string') {
    const t = v.trim();
    if (!t) return null;
    const ms = Date.parse(t);
    return Number.isFinite(ms) ? ms : null;
  }
  return null;
}

/**
 * Best-effort timestamp extraction for one agent-plane log line.
 * @param {unknown} line
 * @param {number} [nowMs]
 * @returns {number|null} epoch ms, or null when the line carries no parseable time
 */
export function lineTimestampMs(line, nowMs = Date.now()) {
  const s = String(line ?? '');
  if (!s.trim()) return null;
  const t = s.trim();
  if (t.startsWith('{')) {
    try {
      const o = JSON.parse(t);
      if (o && typeof o === 'object' && !Array.isArray(o)) {
        for (const k of AGENT_SINCE_TIME_KEYS) {
          if (Object.prototype.hasOwnProperty.call(o, k)) {
            const ms = coerceLogTimestampValue(o[k], nowMs);
            if (ms !== null) return ms;
          }
        }
      }
    } catch {
      // Not JSON after all: fall through to the schemaless scans below.
    }
  }
  const iso = s.match(AGENT_SINCE_ISO_RE);
  if (iso) {
    const ms = Date.parse(iso[1].replace(' ', 'T'));
    if (Number.isFinite(ms)) return ms;
  }
  const sys = s.match(AGENT_SINCE_SYSLOG_RE);
  if (sys) {
    const mon = AGENT_SINCE_MONTHS[String(sys[1]).toLowerCase()];
    if (mon !== undefined) {
      // Year-less stamp in the writer's local wall time; read back in this
      // host's local wall time (same host wrote and reads the file). A stamp
      // more than a day in the future belongs to last year (Dec-probing-Jan).
      const now = new Date(nowMs);
      let d = new Date(
        now.getFullYear(), mon, Number(sys[2]), Number(sys[3]), Number(sys[4]), Number(sys[5])
      );
      if (d.getTime() - nowMs > 24 * 3600 * 1000) {
        d = new Date(
          now.getFullYear() - 1, mon, Number(sys[2]), Number(sys[3]), Number(sys[4]), Number(sys[5])
        );
      }
      if (!isNaN(d.getTime())) return d.getTime();
    }
  }
  return null;
}

/**
 * Resolve a `since` bound using the SAME grammar the schema advertises
 * ("systemd-style relative like '30m ago' on Linux; hours count elsewhere"):
 * parseSince implements bare-digit-hours, s/m/h/d/w units, `ago` suffixes,
 * today/yesterday/now, and absolute dates. Reusing it keeps the agent plane
 * consistent with the system plane instead of inventing a second dialect.
 * @param {unknown} since raw payload value
 * @returns {{present: boolean, ms: number|null}} present=false when no bound
 *   was given; present=true with ms=null when a bound was given but nothing
 *   parseable came out (caller must fail closed, never ignore).
 */
export function resolveLogSince(since) {
  if (since === null || since === undefined) return { present: false, ms: null };
  const raw = String(since);
  if (!raw.trim()) return { present: false, ms: null };
  let iso = null;
  try {
    iso = parseSince(raw);
  } catch {
    iso = null;
  }
  if (!iso) return { present: true, ms: null };
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return { present: true, ms: null };
  return { present: true, ms };
}

/**
 * Keep only rows at or newer than the bound. Rows without a parseable
 * timestamp are dropped (fail-closed: see module note).
 * @param {Array<string>} rows
 * @param {number} sinceMs epoch lower bound (inclusive)
 * @returns {Array<string>}
 */
export function filterLogLinesBySince(rows, sinceMs) {
  return (Array.isArray(rows) ? rows : []).filter((line) => {
    const ts = lineTimestampMs(line);
    return ts !== null && ts >= sinceMs;
  });
}
