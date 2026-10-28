// Structured OS log queries for the NC agent (contract 5.13.0).
// Backends: journald (linux), Windows Event Log (win32), Unified Log
// (darwin). All commands run argv-form (no shell); unit/provider names
// are charset-validated. Pure parsers exported for unit tests.
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { invokePrivilegedHelper as defaultInvokePrivilegedHelper } from '../../privileged-helper/privileged-helper-ipc.mjs';
import { terminateSessionTreeAsync } from '../process/process-sessions.mjs';

const run = promisify(execFile);
const UNIT_RE = /^[\w@.\-:]{1,128}$/;
const MAX_LINES = 500;

function clampLines(v, dflt) {
  const n = Number(v);
  if (!Number.isFinite(n)) return dflt;
  return Math.max(1, Math.min(MAX_LINES, Math.trunc(n)));
}

/**
 * Parse `journalctl --output=short-iso` lines.
 * 2026-09-16T09:00:00+0000 host unit[pid]: message
 * @param {string} text
 */
export function parseJournalShort(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    if (!line.trim()) continue;
    const m = line.match(/^(\S+)\s+\S+\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$/);
    if (!m) {
      // journalctl's empty-result banner is not a journal record.
      if (line.trimEnd() === '-- No entries --') continue;
      out.push({ timestamp: null, level: null, unit: null, message: line.slice(0, 2000) });
      continue;
    }
    out.push({ timestamp: m[1], level: null, unit: m[2], message: m[4].slice(0, 2000) });
  }
  return out;
}

/**
 * Map common priorities to a coarse level.
 * @param {string} v
 */
export function journalLevel(v) {
  const s = String(v || '').toLowerCase();
  if (/^(0|1|2|3|emerg|alert|crit|err|error)$/.test(s)) return 'error';
  if (/^(4|warning|warn)$/.test(s)) return 'warning';
  return 'info';
}

export function normalizeJournalSince(since) {
  if (since === null || since === undefined) return null;
  const raw = String(since);
  if (!raw.trim()) return null;
  let iso = null;
  try {
    iso = parseSince(raw);
  } catch {
    iso = null;
  }
  if (!iso) throw new Error('LOG_SINCE_INVALID');
  return iso;
}

export function journalArgs({
  unit = null,
  kernel = false,
  level = 'all',
  contains = '',
  lines = 100,
  since = null
}) {
  const args = ['--no-pager', '-o', 'short-iso', '-n', String(lines)];
  if (kernel) args.push('-k');
  if (unit) {
    if (!UNIT_RE.test(unit)) throw new Error('LOG_UNIT_INVALID');
    args.push('-u', unit);
  }
  const lv = String(level || 'all').toLowerCase();
  if (lv === 'error') args.push('-p', 'err');
  else if (lv === 'warning') args.push('-p', 'warning');
  else if (lv !== 'all' && lv !== 'info') throw new Error('LOG_LEVEL_INVALID');
  if (since) {
    const normalized = normalizeJournalSince(since);
    if (normalized) args.push('--since', normalized);
  }
  if (contains) args.push('--grep', String(contains).slice(0, 200));
  return args;
}

/**
 * Normalize Windows Event Log timestamps.
 * Converts .NET JSON `/Date(1788...)/` or `/Date(1788...+0300)/` values
 * emitted by PowerShell ConvertTo-Json into ISO-8601 format.
 * @param {unknown} val
 * @returns {string|null}
 */
export function normalizeWinEventTimestamp(val) {
  if (val === null || val === undefined || val === '') return null;
  if (val instanceof Date) {
    return isNaN(val.getTime()) ? null : val.toISOString();
  }
  const s = String(val).trim();
  const m = s.match(/^\/Date\(\s*(-?\d+)(?:[+-]\d+)?\s*\)\/$/);
  if (m) {
    const ms = Number(m[1]);
    if (Number.isFinite(ms)) {
      try {
        const d = new Date(ms);
        if (!isNaN(d.getTime())) return d.toISOString();
      } catch {}
    }
  }
  return s;
}

/**
 * Parse Windows Event Log JSON rows (Get-WinEvent | ConvertTo-Json).
 * @param {Array<Record<string, unknown>>} rows
 */
export function parseWinEvents(rows) {
  const out = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    const lvl = Number(r.Level);
    out.push({
      timestamp: normalizeWinEventTimestamp(r.TimeCreated),
      level: lvl <= 2 ? 'error' : lvl === 3 ? 'warning' : 'info',
      unit: r.ProviderName ? String(r.ProviderName) : null,
      message: String(r.Message || '').slice(0, 2000)
    });
  }
  return out;
}

export function parseSince(since) {
  if (since === null || since === undefined) return null;
  const s = String(since).trim();
  if (!s) return null;
  // Journal/systemd conveniences that `new Date` cannot parse but journalctl
  // honors raw on Linux. Without these, Windows/macOS silently drop the
  // filter (PowerShell/`--last` fallback) while Linux applies it, so the
  // same `since` filters on one OS and is ignored on another. Day words
  // resolve at local midnight to match systemd's local-time reading.
  const lower = s.toLowerCase();
  if (lower === 'now') return new Date().toISOString();
  if (lower === 'today') {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    return d.toISOString();
  }
  if (lower === 'yesterday') {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    d.setDate(d.getDate() - 1);
    return d.toISOString();
  }
  if (lower === 'tomorrow') {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    d.setDate(d.getDate() + 1);
    return d.toISOString();
  }
  const rel = s.match(
    /^(-)?(\d+(?:\.\d+)?|\.\d+)\s*(s(?:ec(?:ond)?s?)?|m(?:in(?:ute)?s?)?|h(?:(?:ou)?rs?)?|d(?:ays?)?|w(?:eeks?)?)?(?:\s*ago)?$/i
  );
  if (rel) {
    const num = Number(rel[2]);
    // Total function: absurd magnitudes (e.g. epoch-ms mistaken for the
    // bare-digit hours default) yield null for the graceful unparseable
    // path instead of throwing RangeError out of winEventScript/macLogArgs.
    // Fractions (e.g. `0.05` bare hours = 3min) are finite non-integers, so
    // the gate is finiteness, not safe-integrality; out-of-range instants
    // still fall through to the null path via the isNaN check below. This
    // also keeps bare fractions out of the `new Date(s)` fallback, which
    // misparses them as calendar dates (e.g. `0.05` -> year 2000) and would
    // otherwise apply a ~26-year StartTime window instead of the stated one.
    if (!Number.isFinite(num)) return null;
    const u = rel[3] ? rel[3].toLowerCase()[0] : 'h';
    const mult =
      u === 's'
        ? 1000
        : u === 'm'
          ? 60 * 1000
          : u === 'h'
            ? 3600 * 1000
            : u === 'd'
              ? 86400 * 1000
              : 7 * 86400 * 1000;
    const ms = num * mult;
    if (!Number.isFinite(ms)) return null;
    const t = Date.now() - ms;
    if (!Number.isFinite(t)) return null;
    const d = new Date(t);
    if (isNaN(d.getTime())) return null;
    // Bare-digit hours magnitudes that cross year 1 (e.g. "99999999",
    // ~11,400 years) yield a valid JS Date with a negative year, and
    // PowerShell [DateTimeOffset]::Parse throws an unhandled
    // FormatException for years < 1. Take the graceful null path like the
    // other out-of-range inputs instead of handing the ISO string to
    // either backend.
    if (d.getUTCFullYear() < 1) return null;
    return d.toISOString();
  }
  const d = new Date(s);
  if (isNaN(d.getTime())) return null;
  // Same pre-year-1 guard for the free-form fallback: a V8-parseable
  // string with year < 1 (e.g. '0000-06-15') would crash the Windows
  // backend the same way, so it takes the same graceful null path.
  if (d.getUTCFullYear() < 1) return null;
  return d.toISOString();
}

export function winEventScript({
  log = 'System',
  provider = null,
  level = 'all',
  contains = '',
  lines = 100,
  since = null
}) {
  const n = Math.max(1, Math.min(MAX_LINES, Number(lines) || 100));
  const esc = (s) => String(s).replace(/'/g, "''");
  let script = `$filter = @{LogName='${esc(log)}'}; `;
  if (since) {
    const parsedSince = parseSince(since);
    if (parsedSince) {
      script += `$since = [DateTime]([DateTimeOffset]::Parse('${parsedSince}').LocalDateTime); $filter.StartTime = $since.ToLocalTime(); `;
    } else {
      script += `$since = try { [DateTime]([DateTimeOffset]::Parse('${esc(since)}').LocalDateTime) } catch { try { [DateTime]::Parse('${esc(since)}') } catch { $null } }; if ($since) { $filter.StartTime = $since.ToLocalTime() }; `;
    }
  }
  if (provider) script += `$filter.ProviderName = '${esc(provider)}'; `;
  const lv = String(level || 'all').toLowerCase();
  if (lv === 'error') script += `$filter.Level = 1,2; `;
  else if (lv === 'warning') script += `$filter.Level = 3; `;
  else if (lv !== 'all' && lv !== 'info') throw new Error('LOG_LEVEL_INVALID');

  script += `$evts = @(try { Get-WinEvent -FilterHashtable $filter -MaxEvents ${n + 1} -ErrorAction Stop } catch { @() }); `;
  // esc() already doubles single quotes; contains is sliced to 200 chars
  // like the journal/mac backends. Literal IndexOf (OrdinalIgnoreCase)
  // instead of -match: `contains` is a literal-substring filter, and a
  // model-controlled -match pattern with nested quantifiers is a ReDoS
  // primitive against agent CPU. Case-insensitivity matches -match
  // defaults; the null guard preserves -match-on-$null evaluating false.
  if (contains) {
    script += `$scanned = $evts.Count; `;
    script += `$evts = @($evts | Where-Object { $_.Message -ne $null -and $_.Message.IndexOf('${esc(String(contains).slice(0, 200))}', [System.StringComparison]::OrdinalIgnoreCase) -ge 0 }); `;
    // A full bounded scan with fewer than n+1 matches cannot prove completeness.
    // Private process signal: exit 65 with empty streams, never diagnostic text.
    script += `if ($scanned -eq ${n + 1} -and @($evts).Count -le ${n}) { exit 65 }; `;
  }
  script += `$evts = @($evts | Sort-Object TimeCreated -Descending); `;
  script += `ConvertTo-Json -InputObject @($evts | Select-Object TimeCreated,Level,ProviderName,@{n='Message';e={$_.Message}}) -Compress -Depth 2`;
  return script;
}

/**
 * Parse a single macOS `log show --style compact` line (best-effort).
 * @param {string} line
 */
export function parseMacLogLine(line) {
  const str = String(line || '');
  if (!str.trim()) return null;
  // Skip the `log show --style compact` column header.
  if (/^Timestamp\s+Ty/.test(str.trim())) return null;
  const m = str.match(
    /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+\S+\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$/
  );
  if (!m) {
    return { timestamp: null, level: null, unit: null, message: str.slice(0, 2000) };
  }
  return { timestamp: m[1], level: null, unit: m[2], message: m[4].slice(0, 2000) };
}

/**
 * Parse macOS `log show --style compact` lines (best-effort).
 * 2026-09-16 09:00:00.123 Df proc[pid]: message
 * @param {string} text
 */
export function parseMacLogCompact(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const entry = parseMacLogLine(line);
    if (entry) out.push(entry);
  }
  return out;
}

/**
 * Stream macOS `log show` output to avoid maxBuffer errors.
 * Keeps a sliding window of the last `limit` entries.
 * @param {Array<string>} args
 * @param {number} limit
 * @param {number} [timeoutMs]
 * @param {typeof spawn} [spawnFn]
 * @returns {Promise<{entries: Array<any>, truncated: boolean}>}
 */
export function runMacLogStream(args, limit, timeoutMs = 30000, spawnFn = spawn) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let child;
    const startedAt = new Date().toISOString();
    try {
      child = spawnFn('log', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
      });
    } catch (err) {
      reject(err);
      return;
    }

    let stdoutRemainder = '';
    const entries = [];
    let totalCount = 0;
    let stderr = '';

    const timer = setTimeout(async () => {
      if (settled) return;
      settled = true;
      try {
        await terminateSessionTreeAsync(child, {
          platform: 'darwin',
          force: true,
          graceMs: 0,
          expectedStartedAt: startedAt,
          expectedPath: 'log',
          expectedCommandLine: args
        });
      } catch {}
      try {
        child.stdout?.destroy();
      } catch {}
      try {
        child.stderr?.destroy();
      } catch {}
      const err = Object.assign(new Error('TIMEOUT'), { code: 'ETIMEDOUT' });
      reject(err);
    }, timeoutMs);
    try {
      timer.unref?.();
    } catch {}

    child.stderr?.on('data', (d) => {
      if (stderr.length < 8192) stderr += String(d);
    });

    child.stdout?.on('data', (chunk) => {
      const text = stdoutRemainder + String(chunk);
      const lines = text.split('\n');
      stdoutRemainder = lines.pop() || '';
      for (const line of lines) {
        const entry = parseMacLogLine(line);
        if (entry) {
          totalCount++;
          entries.push(entry);
          if (entries.length > limit * 2) {
            entries.splice(0, entries.length - limit);
          }
        }
      }
    });

    child.once('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });

    child.once('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (stdoutRemainder.trim()) {
        const entry = parseMacLogLine(stdoutRemainder);
        if (entry) {
          totalCount++;
          entries.push(entry);
        }
      }
      if (code !== 0) {
        const err = Object.assign(new Error(stderr.trim() || `log show exited with code ${code}`), {
          code,
          stdout: '',
          stderr: stderr.trim()
        });
        reject(err);
        return;
      }
      resolve({
        entries: entries.slice(-limit),
        truncated: totalCount > limit
      });
    });
  });
}

export function macLogArgs({
  unit = null,
  level = 'all',
  contains = '',
  lines = 100,
  extraPreds = [],
  since = null
}) {
  // Unbounded `log show` overruns exec buffers: keep the window tight
  // unless a predicate (unit/contains/level/extra) narrows the stream.
  const narrow =
    Boolean(unit) ||
    Boolean(contains) ||
    extraPreds.length > 0 ||
    ['error', 'warning'].includes(String(level || 'all').toLowerCase());
  const parsedSince = since ? parseSince(since) : null;
  const args = ['show', '--style', 'compact'];
  if (parsedSince) {
    // `log show --start` expects `YYYY-MM-DD HH:MM:SS`; derive the UTC wall
    // time from the normalized ISO string (parseSince always emits ISO UTC).
    args.push('--start', String(parsedSince).slice(0, 19).replace('T', ' '));
  } else {
    args.push('--last', narrow ? '1h' : '5m');
  }
  const preds = [...extraPreds];
  if (unit) {
    if (!UNIT_RE.test(unit)) throw new Error('LOG_UNIT_INVALID');
    preds.push(`process == "${unit}"`);
  }
  const lv = String(level || 'all').toLowerCase();
  if (lv === 'error') preds.push('messageType == "Error"');
  else if (lv === 'warning') preds.push('(messageType == "Fault" OR messageType == "Error")');
  else if (lv !== 'all' && lv !== 'info') throw new Error('LOG_LEVEL_INVALID');
  if (contains)
    preds.push(`eventMessage CONTAINS[c] "${String(contains).slice(0, 200).replace(/"/g, '')}"`);
  if (preds.length) args.push('--predicate', preds.join(' AND '));
  return { args, limit: Math.max(1, Math.min(MAX_LINES, Number(lines) || 100)) };
}

function tailCapped(entries, limit) {
  const rows = Array.isArray(entries) ? entries : [];
  return { entries: rows.slice(-limit), truncated: rows.length > limit };
}

const PRIVILEGE_RE =
  /EACCES|EPERM|permission|insufficient permissions|not seeing messages|access denied|operation not permitted|JOURNAL_PRIVILEGE_REQUIRED|PRIVILEGE_REQUIRED/i;

const TIMESTAMP_RE =
  /failed to parse timestamp|failed to parse|invalid timestamp|bad timestamp|invalid\s.*\bsince\b|\bparse\s+timestamp\b/i;

const CLEAN_LOG_CODES = new Set([
  'LOG_UNIT_INVALID',
  'LOG_LEVEL_INVALID',
  'LOG_SINCE_INVALID',
  'LOG_READ_FAILED',
  'UNAUTHORIZED'
]);

/**
 * @param {unknown} job
 */
function payloadOf(job) {
  const r = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  return /** @type {Record<string, unknown>} */ (r.request_payload || r.payload || {});
}

/**
 * Extract the centrally-signed privileged-helper envelope. Accepts both the
 * canonical `privileged_authorization` key and the `privileged_envelope` alias.
 * @param {unknown} job
 */
function extractPrivilegedAuthorization(job) {
  if (!job || typeof job !== 'object' || Array.isArray(job)) return null;
  const rec = /** @type {Record<string, unknown>} */ (job);
  for (const key of ['privileged_authorization', 'privileged_envelope']) {
    const v = rec[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) return v;
  }
  const payload = payloadOf(job);
  for (const key of ['privileged_authorization', 'privileged_envelope']) {
    const v = payload[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) return v;
  }
  return null;
}

/**
 * @param {unknown} e
 */
export function isPrivilegeError(e) {
  const rec =
    /** @type {{code?: unknown, stdout?: unknown, stderr?: unknown, message?: unknown}} */ (
      e && typeof e === 'object' ? e : {}
    );
  if (rec.code === 'EACCES' || rec.code === 'EPERM') return true;
  const parts = [rec.message, rec.stdout, rec.stderr, typeof e === 'string' ? e : '']
    .map((x) => String(x || ''))
    .filter(Boolean);
  return PRIVILEGE_RE.test(parts.join('\n'));
}

export function isTimestampError(e) {
  const rec =
    /** @type {{code?: unknown, stdout?: unknown, stderr?: unknown, message?: unknown}} */ (
      e && typeof e === 'object' ? e : {}
    );
  const parts = [rec.message, rec.stdout, rec.stderr, typeof e === 'string' ? e : '']
    .map((x) => String(x || ''))
    .filter(Boolean);
  if (!parts.length) return false;
  return TIMESTAMP_RE.test(parts.join('\n'));
}

function toSanitizedLogError(e) {
  const msg = String((e && e.message) || e || '');
  if (CLEAN_LOG_CODES.has(msg.trim())) return new Error(msg.trim());
  if (isTimestampError(e)) return new Error('LOG_SINCE_INVALID');
  if (isPrivilegeError(e)) return new Error('UNAUTHORIZED');
  if (/journalctl/i.test(msg)) return new Error('LOG_READ_FAILED');
  return e instanceof Error ? e : new Error(msg.slice(0, 500) || 'LOG_READ_FAILED');
}

/**
 * Dispatch the signed envelope to the helper socket/pipe. Returns the helper
 * `result` on success, throws the ORIGINAL direct error when the helper is
 * unavailable, has no envelope, or reports failure.
 * @param {unknown} job
 * @param {unknown} directError
 * @param {(request: unknown) => Promise<unknown>} invoke
 * @param {(() => boolean)|null} isAvailable
 */
async function dispatchHelperResult(job, directError, invoke, isAvailable) {
  let available = typeof invoke === 'function';
  if (available && typeof isAvailable === 'function') {
    try {
      available = isAvailable();
    } catch {
      available = false;
    }
  }
  const authorization = extractPrivilegedAuthorization(job);
  if (!available || !authorization) throw directError;
  let reply;
  try {
    reply = await invoke(authorization);
  } catch {
    throw directError;
  }
  const rec =
    reply && typeof reply === 'object' ? /** @type {Record<string, any>} */ (reply) : null;
  if (!rec || rec.ok !== true) throw directError;
  const result = rec.result && typeof rec.result === 'object' ? rec.result : null;
  if (result?.success === false && result.message === 'LOG_READ_FAILED')
    throw new Error('LOG_READ_FAILED');
  if (!result || result.success !== true) throw directError;
  return result;
}

/**
 * Parse a helper `output_tail` log dump with the platform-appropriate parser.
 * @param {string} platform
 * @param {unknown} outputTail
 */
function parseHelperLogTail(platform, outputTail) {
  const text = String(outputTail || '');
  if (platform === 'win32') {
    try {
      if (text.length > 8000) throw new Error('LOG_READ_FAILED');
      const v = JSON.parse(text);
      const rows = Array.isArray(v) ? v : [v];
      if (rows.some((row) => !row || typeof row !== 'object' || Array.isArray(row) || !Object.hasOwn(row, 'Message')))
        throw new Error('LOG_READ_FAILED');
      return parseWinEvents(rows);
    } catch {
      throw new Error('LOG_READ_FAILED');
    }
  }
  if (platform === 'darwin') return parseMacLogCompact(text);
  return parseJournalShort(text);
}

async function runJsonPs(script) {
  const utf8Script = `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ${script}`;
  let stdout;
  try {
    ({ stdout } = await run(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', utf8Script],
      { timeout: 30000, windowsHide: true, maxBuffer: 64 * 1024 * 1024 }
    ));
  } catch (e) {
    if (e?.code === 65 && !String(e?.stdout || '').trim() && !String(e?.stderr || '').trim())
      throw new Error('LOG_READ_FAILED', { cause: e });
    throw e;
  }
  const text = String(stdout || '')
    .replace(/^\uFEFF/, '')
    .trim();
  if (!text) return [];
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    throw new Error('LOG_PARSE_FAILED');
  }
}

async function serviceLogs(platform, { unit, lines = 100, since = null, level = 'all' }) {
  if (!unit || !UNIT_RE.test(String(unit))) throw new Error('LOG_UNIT_INVALID');
  const lim = clampLines(lines, 100);
  if (platform === 'win32') {
    const rows = await runJsonPs(
      winEventScript({ provider: String(unit), lines: lim, level, since })
    );
    const fb =
      rows.length === 0
        ? await runJsonPs(
            winEventScript({ log: 'System', lines: lim, level, contains: String(unit), since })
          )
        : [];
    const entries = parseWinEvents(rows.length ? rows : fb);
    const truncated = entries.length > lim;
    return { platform, unit: String(unit), entries: entries.slice(0, lim), truncated };
  }
  if (platform === 'darwin') {
    const { args, limit } = macLogArgs({ unit: String(unit), level, lines: lim, since });
    const { entries, truncated } = await runMacLogStream(args, limit, 30000);
    return { platform, unit: String(unit), entries, truncated };
  }
  const args = journalArgs({ unit: String(unit), lines: lim + 1, since, level });
  let stdout;
  try {
    ({ stdout } = await run('journalctl', args, { timeout: 30000, maxBuffer: 64 * 1024 * 1024 }));
  } catch (e) {
    if (isTimestampError(e)) throw new Error('LOG_SINCE_INVALID', { cause: e });
    throw e;
  }
  const entries = parseJournalShort(stdout).map((e) => ({
    ...e,
    level: e.level || null
  }));
  return { platform, unit: String(unit), ...tailCapped(entries, lim) };
}

async function systemLogQuery(
  platform,
  { source = 'system', unit = null, level = 'all', contains = '', limit = 100, since = null }
) {
  const src = ['system', 'kernel', 'application'].includes(String(source))
    ? String(source)
    : 'system';
  const lim = clampLines(limit, 100);
  if (platform === 'win32') {
    const log = src === 'application' ? 'Application' : 'System';
    const rows = await runJsonPs(
      winEventScript({
        log,
        provider: unit,
        level,
        contains: String(contains || ''),
        lines: lim,
        since
      })
    );
    const parsed = parseWinEvents(rows);
    const truncated = parsed.length > lim;
    return { platform, source: src, entries: parsed.slice(0, lim), truncated };
  }
  if (platform === 'darwin') {
    const { args, limit: capped } = macLogArgs({
      unit,
      level,
      contains: String(contains || ''),
      lines: lim,
      extraPreds: src === 'kernel' ? ['senderImagePath CONTAINS "kernel"'] : [],
      since
    });
    const { entries, truncated } = await runMacLogStream(args, capped, 30000);
    return { platform, source: src, entries, truncated };
  }
  const args = journalArgs({
    kernel: src === 'kernel',
    unit,
    level,
    contains: String(contains || ''),
    lines: lim + 1,
    since
  });
  let stdout;
  try {
    ({ stdout } = await run('journalctl', args, { timeout: 30000, maxBuffer: 64 * 1024 * 1024 }));
  } catch (e) {
    if (isTimestampError(e)) throw new Error('LOG_SINCE_INVALID', { cause: e });
    throw e;
  }
  return { platform, source: src, ...tailCapped(parseJournalShort(stdout), lim) };
}

/**
 * @param {string} [platform]
 * @param {object} [options]
 * @param {(request: unknown) => Promise<unknown>} [options.invokePrivilegedHelper]
 * @param {() => boolean} [options.isPrivilegedHelperAvailable]
 */
export function makeSystemLogHandlers(
  platform = process.platform,
  { invokePrivilegedHelper = null, isPrivilegedHelperAvailable = null } = {}
) {
  const invoke = invokePrivilegedHelper ?? defaultInvokePrivilegedHelper;
  const completed = (r) => ({
    status: 'completed',
    exit_code: 0,
    stdout: '',
    stderr: '',
    error: null,
    duration_ms: 0,
    result_payload: r
  });
  const failed = (e) => {
    const clean = toSanitizedLogError(e);
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      error: String((clean && clean.message) || e),
      duration_ms: 0,
      result_payload: {}
    };
  };
  const withFallback = (kind, direct) => async (job) => {
    const p = payloadOf(job);
    try {
      const r = await direct(p);
      return completed(r);
    } catch (e) {
      const msg = String((e && e.message) || e || '');
      if (msg.trim() === 'LOG_SINCE_INVALID' || isTimestampError(e))
        return failed(new Error('LOG_SINCE_INVALID'));
      if (!isPrivilegeError(e)) return failed(e);
      try {
        const helperResult = await dispatchHelperResult(
          job,
          e,
          invoke,
          isPrivilegedHelperAvailable
        );
        const outputTail = String(helperResult.output_tail || '');
        if (kind === 'service') {
          const unit = String(p.unit || helperResult.unit || '');
          if (!unit || !UNIT_RE.test(unit)) return failed(e);
          const lim = clampLines(p.lines, 100);
          const entries = parseHelperLogTail(platform, outputTail).map((entry) => ({
            ...entry,
            level: entry.level || null
          }));
          const truncated = entries.length > lim;
          const tail =
            platform === 'win32'
              ? { entries: entries.slice(0, lim), truncated }
              : tailCapped(entries, lim);
          return completed({ platform, unit, ...tail, privileged: true });
        }
        const source = String(p.source || helperResult.source || 'system');
        const lim = clampLines(p.limit ?? p.lines, 100);
        const entries = parseHelperLogTail(platform, outputTail);
        const truncated = entries.length > lim;
        const tail =
          platform === 'win32'
            ? { entries: entries.slice(0, lim), truncated }
            : tailCapped(entries, lim);
        return completed({ platform, source, ...tail, privileged: true });
      } catch (helperError) {
        if (helperError?.message === 'LOG_READ_FAILED')
          return failed(new Error('LOG_READ_FAILED'));
        return failed(new Error('UNAUTHORIZED'));
      }
    }
  };
  return {
    service_logs: withFallback('service', (p) =>
      serviceLogs(platform, {
        unit: p.unit,
        lines: p.lines,
        // Non-string since flows to the backend as a string: the Linux
        // journal path normalizes via parseSince and fails closed with
        // LOG_SINCE_INVALID on unparseable input, while win32/darwin
        // keep their graceful fallback.
        since: typeof p.since === 'string' ? p.since : p.since != null ? String(p.since) : null,
        level: p.level
      })
    ),
    system_log_query: withFallback('system', (p) =>
      systemLogQuery(platform, {
        source: p.source,
        unit: typeof p.unit === 'string' ? p.unit : null,
        level: p.level,
        contains: p.contains,
        limit: p.limit ?? p.lines,
        since: typeof p.since === 'string' ? p.since : p.since != null ? String(p.since) : null
      })
    )
  };
}
