import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { redactDiagnosticsSecrets } from '../diagnostics/diagnostics-ops.mjs';

export const MAX_OPERATION_LOG_ENTRIES = 5000;
export const MAX_OUT_PREVIEW_BYTES = 2048;

/** Apply the shared diagnostics redaction plus command/URL credential forms.
 * @param {string} text
 */
function redactOperationLogText(text) {
  const safe = text
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s/@]+@/gi, (match) => `${match.split('://', 1)[0]}://[REDACTED]@`)
    .replace(/([?&](?:token|access_token|refresh_token|api[_-]?key|password|passwd|pwd|secret|client_secret|authorization|credential|signature)=)[^&#\s'"]*/gi, '$1[REDACTED]')
    .replace(/(--(?:token|access[_-]token|refresh[_-]token|api[_-]?key|password|passwd|pwd|secret|client[_-]secret)(?:=|\s+))(?:"(?:\\.|[^"\\])*"|'[^']*'|[^\s;&|'"<>]+)/gi, '$1[REDACTED]')
    .replace(/(Authorization\s*:\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n'"]+)/gi, '$1[REDACTED]')
    .replace(/\bnc_(?:pat_)?[A-Za-z0-9_-]{8,}\b/g, '[REDACTED]');
  return /** @type {string} */ (redactDiagnosticsSecrets(safe));
}

/**
 * Extract target descriptor from tool payload.
 * @param {Record<string, unknown>|null|undefined} payload
 * @returns {string|null}
 */
export function extractTargetFromPayload(payload) {
  if (!payload || typeof payload !== 'object') return null;
  const p = /** @type {Record<string, unknown>} */ (payload);
  const candidate =
    p.target ||
    p.path ||
    p.command ||
    p.unit ||
    p.name ||
    p.url ||
    p.action ||
    null;
  return candidate ? redactOperationLogText(String(candidate)).slice(0, 500) : null;
}

/**
 * Format output preview truncated to 2KB.
 * @param {Record<string, unknown>|null|undefined} result
 * @param {number} [maxChars]
 * @returns {string}
 */
export function formatOutputPreview(result, maxChars = MAX_OUT_PREVIEW_BYTES) {
  if (!result || typeof result !== 'object') return '';
  const r = /** @type {Record<string, unknown>} */ (result);
  let text = '';
  if (typeof r.out_preview === 'string') {
    text = r.out_preview;
  } else if (typeof r.stdout === 'string' && r.stdout) {
    text = r.stdout;
  } else if (typeof r.content === 'string' && r.content) {
    text = r.content;
  } else if (r.result_payload && typeof r.result_payload === 'object') {
    try {
      text = JSON.stringify(r.result_payload, (key, value) => {
        // JSON's recursive traversal also covers objects nested inside arrays.
        if (/^(?:password|passwd|secret|token|access_token|refresh_token|api_key|apikey|authorization|client_secret|private_key|cookie)$/i.test(key)) {
          return '[REDACTED]';
        }
        return typeof value === 'string' ? redactOperationLogText(value) : value;
      });
    } catch {}
  } else if (typeof r.stderr === 'string' && r.stderr) {
    text = r.stderr;
  } else if (typeof r.error === 'string' && r.error) {
    text = r.error;
  } else if (typeof r.message === 'string' && r.message) {
    text = r.message;
  }
  return redactOperationLogText(text).slice(0, maxChars);
}

/**
 * Build structured operation log record.
 * @param {Record<string, unknown>} job
 * @param {Record<string, unknown>} result
 * @returns {Record<string, unknown>}
 */
export function formatOperationLogRecord(job, result) {
  const toolName = String(job?.tool || job?.op || '');
  const opName = String(job?.op || job?.tool || 'operation');
  const rawPayload =
    job?.request_payload && typeof job.request_payload === 'object'
      ? job.request_payload
      : job?.payload && typeof job.payload === 'object'
        ? job.payload
        : {};
  const status = String(result?.status || (result?.error ? 'failed' : 'completed'));
  const durationMs = Number.isFinite(result?.duration_ms) ? Number(result.duration_ms) : 0;
  // Redact the complete text before any length bound can split a credential.
  const outPreview = formatOutputPreview(result, MAX_OUT_PREVIEW_BYTES);
  const target = extractTargetFromPayload(/** @type {Record<string, unknown>} */ (rawPayload));

  return {
    ts: new Date().toISOString(),
    op: redactOperationLogText(opName),
    tool: redactOperationLogText(toolName),
    target,
    status: redactOperationLogText(status),
    duration_ms: durationMs,
    out_preview: outPreview,
    exit_code: Number.isInteger(result?.exit_code) ? result.exit_code : null,
    error: result?.error ? redactOperationLogText(String(result.error)) : null,
    job_id: job?.id ? redactOperationLogText(String(job.id)) : null
  };
}

/**
 * Trim file keeping only the newest keepEntries lines.
 * Uses atomic tmp file replace.
 * @param {string} file
 * @param {number} [keepEntries]
 * @param {number} [maxEntries]
 * @returns {Promise<boolean>} true if trimmed, false if already within bound
 */
export async function trimOperationLog(
  file,
  keepEntries = MAX_OPERATION_LOG_ENTRIES,
  maxEntries = MAX_OPERATION_LOG_ENTRIES
) {
  let text = '';
  try {
    text = await fs.readFile(file, 'utf8');
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err).code === 'ENOENT') return false;
    throw err;
  }
  const lines = text.split('\n').filter(Boolean);
  if (lines.length <= maxEntries) return false;

  const kept = lines.slice(-keepEntries);
  const tmp = `${file}.tmp-${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  await fs.writeFile(tmp, kept.join('\n') + '\n', { mode: 0o640, flag: 'wx' });
  try {
    await fs.rename(tmp, file);
  } catch (error) {
    await fs.unlink(tmp).catch(() => {});
    throw error;
  }
  return true;
}

let writeCounter = 0;

/**
 * Append a structured operation log record to the specified file and roll when exceeding cap.
 * @param {string} file
 * @param {Record<string, unknown>} job
 * @param {Record<string, unknown>} result
 * @param {{trimInterval?: number, keepEntries?: number, maxEntries?: number, forceTrim?: boolean}} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export async function recordOperationLog(file, job, result, options = {}) {
  const record = formatOperationLogRecord(job, result);
  const line = `${JSON.stringify(record)}\n`;
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.appendFile(file, line, { mode: 0o640 });
  writeCounter++;
  const trimInterval = options.trimInterval ?? 50;
  if (options.forceTrim || writeCounter % trimInterval === 0) {
    const keep = options.keepEntries ?? MAX_OPERATION_LOG_ENTRIES;
    const max = options.maxEntries ?? MAX_OPERATION_LOG_ENTRIES;
    await trimOperationLog(file, keep, max);
  }
  return record;
}

/**
 * Read the last `limit` operation log entries from the file tail.
 * Returns parsed structured records in reverse chronological order (newest first).
 * @param {string} file
 * @param {number} [limit]
 * @returns {Promise<Array<Record<string, unknown>>>}
 */
export async function readOperationLogTail(file, limit = 100) {
  let text = '';
  try {
    text = await fs.readFile(file, 'utf8');
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err).code === 'ENOENT') return [];
    throw err;
  }
  const lines = text.split('\n').filter(Boolean);
  const entries = [];
  for (let i = lines.length - 1; i >= 0 && entries.length < limit; i--) {
    const line = lines[i].trim();
    if (!line) continue;
    try {
      const obj = JSON.parse(line);
      if (obj && typeof obj === 'object') {
        // Require a real operation marker: diagnostic lines sharing this file
        // (e.g. session_result_ack meta with ts+status but no tool/op) must
        // not parse as operations, and pre-fix operation_log_read self-records
        // (dashboard polls writing into the file they read: observer effect)
        // are retroactively excluded so polluted tails read clean.
        const marker = obj.tool || obj.op;
        if (
          obj.ts &&
          typeof marker === 'string' &&
          marker.trim() !== '' &&
          marker.trim() !== 'operation_log_read'
        ) {
          entries.push(obj);
        }
      }
    } catch {}
  }
  return entries;
}
