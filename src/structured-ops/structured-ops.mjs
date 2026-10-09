import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { runtimeRoot } from '../client/nc-paths.mjs';
import { DOC_FORMATS, MAX_TEXT_CHARS, extractDocument, readDocFile } from './doc-extract.mjs';
import { policyExtraRoots } from '../policy/host-policy.mjs';
import { isSensitivePath } from '../filesystem/sensitive-paths.mjs';
import { MutationError, resolveTargetPath } from '../filesystem/path-auth.mjs';
import { spawn } from 'node:child_process';

/**
 * Positional read loop: a single fh.read may return fewer bytes than asked
 * (short reads on some filesystems). Without the loop the tail stays
 * zero-filled and chunk base64 / finalize hashes silently corrupt.
 * Returns bytes actually read. Exported for tests.
 * @param {{read: (buf: Buffer, off: number, len: number, pos: number) => Promise<{bytesRead: number}>}} fh
 * @param {Buffer} buf @param {number} length @param {number} position
 */
export async function readExact(fh, buf, length, position) {
  let read = 0;
  while (read < length) {
    const { bytesRead } = await fh.read(buf, read, length - read, position + read);
    if (!bytesRead) break;
    read += bytesRead;
  }
  return read;
}
/**
 * RES-001: bounded file read. Reads at most `max` bytes via a file handle
 * instead of buffering the whole file (multi-GB files OOMed the agent).
 * Return shape matches the old readFile+subarray behavior exactly.
 * @param {string} file @param {number} max
 */
export async function readBounded(file, max) {
  const limit = Math.max(1, Math.min(65536, Number(max) || 65536));
  // P28-S2: pre-open regular-file guard. Opening a FIFO for reading blocks
  // until a writer appears and this path has no timeout, so a planted FIFO
  // inside the workspace would hang the job. Reject non-regular files
  // (FIFO/socket/device/directory) before open. Callers pass realpath-
  // resolved paths; stat follows a final-component swap to the same verdict.
  const pre = await fs.stat(file);
  if (!pre.isFile()) throw new Error('PATH_TYPE_NOT_SUPPORTED');
  const fh = await fs.open(file, 'r');
  try {
    const st = await fh.stat();
    const n = Math.min(st.size, limit);
    const buf = Buffer.alloc(n);
    const read = n > 0 ? await readExact(fh, buf, n, 0) : 0;
    return {
      content: buf.subarray(0, read).toString('utf8'),
      bytes: st.size,
      truncated: st.size > limit
    };
  } finally {
    await fh.close();
  }
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
 * Failure envelope. `extra.reason` rides top-level (like the mutation
 * handlerFail) so the hub mapper surfaces actionable guidance to the
 * model; `extra.details` rides inside result_payload for job_get/audit
 * diagnosis. Both are additive — the legacy shape is unchanged when absent.
 * @param {unknown} error
 * @param {{reason?: string, details?: Record<string, unknown>}} [extra]
 */
const fail = (error, extra = {}) => ({
  status: 'failed',
  exit_code: null,
  stdout: '',
  stderr: '',
  error: String(error),
  ...(typeof extra.reason === 'string' && extra.reason ? { reason: extra.reason } : {}),
  duration_ms: 0,
  result_payload: {
    ...(extra.details && typeof extra.details === 'object' ? { details: extra.details } : {})
  }
});

/**
 * Structured context carried on read-path failures (L8 actionable
 * rejections). Codes stay stable; only the envelope gains guidance.
 * @param {unknown} e
 */
function denialContext(e) {
  if (e instanceof MutationError && e.details && typeof e.details === 'object')
    return /** @type {Record<string, unknown>} */ (e.details);
  return null;
}

/**
 * Human-readable recovery guidance for a read-path failure code.
 * @param {string} code @param {Record<string, unknown>|null} details
 */
function readFailureReason(code, details) {
  const roots = details && Array.isArray(details.configured_roots)
    ? /** @type {Array<unknown>} */ (details.configured_roots)
    : null;
  const rootsHint =
    roots && roots.length
      ? ` Permitted roots: ${roots.map((r) => String(r)).join(', ')} — reroute the path inside one of them.`
      : '';
  switch (code) {
    case 'PATH_NOT_ALLOWED':
      return `Path is outside the allowlisted filesystem roots.${rootsHint}`;
    case 'FILE_NOT_FOUND': {
      const missing =
        details && typeof details.missing_ancestor === 'string' ? details.missing_ancestor : null;
      const at =
        details && typeof details.path === 'string' ? ` '${details.path}'` : '';
      return missing
        ? `Path${at} does not exist: ancestor directory '${missing}' is missing — create it first (directory_create) or verify the path with file_browse.`
        : `Path${at} does not exist — verify the path with file_browse before retrying.`;
    }
    case 'ACCESS_DENIED':
      return `Operating system denied access to the path.${rootsHint}`;
    default:
      return null;
  }
}

/**
 * Map a read-path throw to the stable envelope: preserve the code,
 * attach denial context + actionable reason when present.
 * @param {unknown} e @param {string} [fallback]
 */
function failFor(e, fallback = 'READ_ERROR') {
  const code = mapFileError(e, fallback);
  const details = denialContext(e);
  const reason = readFailureReason(code, details);
  return fail(code, {
    ...(reason ? { reason } : {}),
    ...(details ? { details } : {})
  });
}

/**
 * Resolve the deepest existing ancestor of a (possibly missing) target and
 * report the topmost missing directory below it. The allowlist is enforced
 * against the realpath-resolved ancestor, so non-existent targets inside
 * the roots validate instead of failing closed (TOOL_DESIGN L1 ancestor
 * walk). Returns null when the direct parent exists (plain missing leaf).
 * @param {string} normalized absolute normalized target
 */
async function ancestorForMissing(normalized) {
  const missing = [];
  let cur = normalized;
  while (true) {
    try {
      const realAncestor = await fs.realpath(cur);
      return {
        ancestor: cur,
        realAncestor,
        missing_ancestor: missing.length > 1 ? missing[0] : null
      };
    } catch (e) {
      if (!e || typeof e !== 'object' || /** @type {{code?: unknown}} */ (e).code !== 'ENOENT')
        throw e;
      missing.unshift(cur);
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
  }
  // Nothing resolvable up to the filesystem root: fail closed outside the
  // catch block (cause-chain lint). Such a target cannot be inside roots.
  throw new MutationError('PATH_NOT_ALLOWED', { path: normalized });
}

/**
 * @param {string} target
 * @param {Array<string>} roots
 * @param {boolean} [allowAll]
 * @param {{cwd?: string|null, homedir?: string}} [options] pre-flight
 * normalization context (L1): `~` is always expanded; bare relative paths
 * resolve against `cwd` when supplied, otherwise keep the strict
 * PATH_NOT_ABSOLUTE gate (pinned by nc-001/phase3 suites).
 */
export async function realAllowed(target, roots, allowAll = false, options = {}) {
  const { cwd = null, homedir = undefined } = options || {};
  // Pre-flight normalization (L1) runs BEFORE the check, never around it.
  const normalized = resolveTargetPath(target, { pathApi: path, cwd, homedir });
  // Credential denylist (SEC-001): precedes allowlist AND allow_all.
  const platform = process.platform;
  if (isSensitivePath(normalized, platform)) throw new Error('PATH_DENIED_SENSITIVE');
  /** @type {Array<string>} */
  const realRoots = [];
  for (const root of roots || []) {
    try {
      realRoots.push(await fs.realpath(root));
    } catch {
      continue;
    }
  }
  /** @param {string} real */
  const inside = (real) => realRoots.some((rr) => real === rr || real.startsWith(rr + path.sep));
  /** @param {string} real */
  const deny = (real) => {
    throw new MutationError('PATH_NOT_ALLOWED', {
      path: normalized,
      ...(real !== normalized ? { resolved_path: real } : {}),
      configured_roots: [...realRoots]
    });
  };
  let real;
  /** @type {Record<string, unknown>|null} */
  let missingInfo = null;
  try {
    real = await fs.realpath(normalized);
  } catch (e) {
    if (!e || typeof e !== 'object' || /** @type {{code?: unknown}} */ (e).code !== 'ENOENT')
      throw e;
    // Missing target: validate the deepest existing ancestor (L1 walk)
    // instead of failing on the unresolved path. Fresh throws stay outside
    // the catch block (cause-chain lint); shared checks below still apply.
    const found = await ancestorForMissing(normalized);
    real = found.realAncestor;
    missingInfo = {
      path: normalized,
      ...(found.missing_ancestor ? { missing_ancestor: found.missing_ancestor } : {})
    };
  }
  if (isSensitivePath(real, platform)) throw new Error('PATH_DENIED_SENSITIVE');
  if (allowAll !== true && !inside(real)) deny(real);
  if (missingInfo) throw new MutationError('FILE_NOT_FOUND', missingInfo);
  if (allowAll === true) return real;
  return real;
}
/**
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {number} [timeoutMs]
 */
async function capture(cmd, args, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '',
      err = '';
    const t = setTimeout(() => {
      try {
        p.kill('SIGKILL');
      } catch {}
    }, timeoutMs);
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('error', (e) => {
      clearTimeout(t);
      resolve({ code: null, out, err, error: e.message });
    });
    p.on('close', (code) => {
      clearTimeout(t);
      resolve({ code, out: out.trim(), err: err.trim() });
    });
  });
}

/**
 * Maps OS errors (ENOENT, EACCES, etc.) to stable protocol error codes.
 * @param {unknown} e
 * @param {string} [fallback]
 */
function mapFileError(e, fallback = 'READ_ERROR') {
  const errorRecord = /** @type {{message?: unknown, code?: unknown}} */ (e);
  const osCode = errorRecord?.code;
  /** @type {Record<string, string>} */
  const mapped = {
    EACCES: 'ACCESS_DENIED',
    EPERM: 'ACCESS_DENIED',
    ENOENT: 'FILE_NOT_FOUND',
    EEXIST: 'FILE_EXISTS',
    ENOTDIR: 'PATH_TYPE_NOT_SUPPORTED',
    EISDIR: 'PATH_TYPE_NOT_SUPPORTED'
  };
  return (
    (typeof osCode === 'string' && mapped[osCode]) ||
    (typeof errorRecord?.message === 'string' && /^[A-Z0-9_]+$/.test(errorRecord.message)
      ? errorRecord.message
      : fallback)
  );
}

/**
 * Canonical-target extras for resolve=true (the `readlink -f` equivalent
 * without a shell). The allowlist already resolves symlinks before
 * listing; this surfaces the canonical target to the model. Best-effort:
 * falls back to the resolved path alone when the raw target cannot be
 * pre-normalized (relative without cwd, `~` without homedir, ...).
 * @param {unknown} rawTarget @param {string} resolved
 * @param {{cwd?: string|null, homedir?: string}} readOpts
 */
function resolveExtras(rawTarget, resolved, readOpts) {
  try {
    const requested = resolveTargetPath(String(rawTarget || ''), {
      pathApi: path,
      cwd: readOpts?.cwd ?? null,
      homedir: readOpts?.homedir
    });
    if (requested && requested !== resolved)
      return { resolved_path: resolved, requested_path: requested };
  } catch {
    // Fall through: report the canonical path alone.
  }
  return { resolved_path: resolved };
}

/**
 * @param {object} [options]
 * @param {Array<string>} [options.readRoots]
 * @param {string|null} [options.cwd] pre-flight relative-resolution base
 * (null keeps the strict PATH_NOT_ABSOLUTE gate)
 * @param {string} [options.homedir] `~` expansion base (defaults to os.homedir())
 */
export function makeStructuredHandlers({ readRoots = [runtimeRoot()], cwd, homedir } = {}) {
  const readOpts = { cwd, homedir };
  return {
    system_snapshot: async () =>
      ok({
        hostname: os.hostname(),
        platform: os.platform(),
        release: os.release(),
        arch: os.arch(),
        cpus: os.cpus()?.length || null,
        total_memory_bytes: os.totalmem(),
        free_memory_bytes: os.freemem(),
        uptime_seconds: Math.floor(os.uptime()),
        loadavg: os.loadavg()
      }),
    file_read: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const extraRoots = policyExtraRoots(job);
        const roots = [...readRoots, ...extraRoots.read];
        const allowAllRoots = extraRoots.allowAll === true;
        const file = await realAllowed(String(p.path || ''), roots, allowAllRoots, readOpts),
          max = Math.max(1, Math.min(65536, Number(p.max_bytes || 65536))),
          r = await readBounded(file, max);
        return ok({
          path: file,
          content: r.content,
          bytes: r.bytes,
          truncated: r.truncated
        });
      } catch (e) {
        return failFor(e, 'READ_ERROR');
      }
    },
    file_read_many: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const rawPaths = Array.isArray(p.paths) ? p.paths : [];
        if (rawPaths.length < 1 || rawPaths.length > 10) throw new Error('PATH_COUNT_INVALID');
        const max = Math.max(1, Math.min(65536, Number(p.max_bytes || 65536)));
        const extraRoots = policyExtraRoots(job);
        const roots = [...readRoots, ...extraRoots.read];
        const allowAllRoots = extraRoots.allowAll === true;
        const results = [];
        for (const raw of rawPaths.slice(0, 10)) {
          try {
            const file = await realAllowed(String(raw || ''), roots, allowAllRoots, readOpts),
              r = await readBounded(file, max);
            results.push({
              path: file,
              content: r.content,
              bytes: r.bytes,
              truncated: r.truncated,
              error: null
            });
          } catch (e) {
            const errorRecord = /** @type {{message?: unknown}} */ (e);
            results.push({
              path: String(raw || ''),
              content: '',
              bytes: 0,
              truncated: false,
              error: String(errorRecord?.message || e)
            });
          }
        }
        return ok({ results });
      } catch (e) {
        return failFor(e, 'READ_ERROR');
      }
    },
    doc_extract: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const extraRoots = policyExtraRoots(job);
        const roots = [...readRoots, ...extraRoots.read];
        const allowAllRoots = extraRoots.allowAll === true;
        const file = await realAllowed(String(p.path || ''), roots, allowAllRoots, readOpts);
        const hint = String(p.format || 'auto').toLowerCase();
        if (!['auto', ...DOC_FORMATS].includes(hint)) throw new Error('INVALID_DOC_FORMAT');
        const maxChars = Math.max(
          1,
          Math.min(MAX_TEXT_CHARS, Math.trunc(Number(p.max_chars ?? MAX_TEXT_CHARS)) || MAX_TEXT_CHARS)
        );
        const { bytes, buffer } = await readDocFile(file);
        const out = extractDocument(buffer, { filename: file, format: hint, maxChars });
        return ok({
          path: file,
          format: out.format,
          text: out.text,
          chars: out.text.length,
          bytes,
          truncated: out.truncated === true,
          ...('sheets' in out && typeof out.sheets === 'number' ? { sheets: out.sheets } : {}),
          ...('pages' in out && typeof out.pages === 'number' ? { pages: out.pages } : {}),
          warnings: Array.isArray(out.warnings) ? out.warnings : []
        });
      } catch (e) {
        return failFor(e, 'DOC_PARSE_FAILED');
      }
    },
    transfer_read: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const extraRoots = policyExtraRoots(job);
        const roots = [...readRoots, ...extraRoots.read];
        const allowAllRoots = extraRoots.allowAll === true;
        const file = await realAllowed(String(p.path || ''), roots, allowAllRoots, readOpts);
        const offset = Number(p.offset ?? 0);
        if (!Number.isInteger(offset) || offset < 0) throw new Error('INVALID_OFFSET');
        const length = Number(p.length ?? 49152);
        if (!Number.isInteger(length) || length < 1 || length > 49152)
          throw new Error('INVALID_LENGTH');
        // P28-S2: pre-open regular-file guard (same FIFO-block rationale as
        // readBounded). The post-open fh.stat() isFile check below is kept
        // as defense-in-depth against a lstat/open swap; this pre-check is
        // what prevents the blocking open itself.
        const pre = await fs.stat(file);
        if (!pre.isFile()) throw new Error('PATH_TYPE_NOT_SUPPORTED');
        const fh = await fs.open(file, 'r');
        try {
          const st = await fh.stat();
          if (!st.isFile()) throw new Error('PATH_TYPE_NOT_SUPPORTED');
          if (offset > st.size) throw new Error('TRANSFER_OFFSET_BEYOND_EOF');
          const n = Math.min(st.size - offset, length);
          const buf = Buffer.alloc(n);
          const read = n > 0 ? await readExact(fh, buf, n, offset) : 0;
          const done = offset + read >= st.size;
          let sha256 = null;
          if (done) {
            const hash = crypto.createHash('sha256');
            const slice = 1048576;
            for (let pos = 0; pos < st.size; pos += slice) {
              const want = Math.min(slice, st.size - pos);
              const tmp = Buffer.alloc(want);
              const got = await readExact(fh, tmp, want, pos);
              hash.update(tmp.subarray(0, got));
            }
            sha256 = hash.digest('hex');
          }
          // Base64 stays the default agent wire encoding (backward
          // compatible with HTTP-poll and older agents). When the hub
          // requests the binary leg (`binary: true`), the same bytes are
          // additionally emitted as __binary_payload__: the WS transport
          // (sessionResponse) pops it into a real 20-byte-header binary
          // frame while JSON metadata travels as JSON.
          const chunkBytes = Buffer.from(buf.subarray(0, read));
          const resultPayload = {
            path: file,
            offset,
            bytes: read,
            total_size: st.size,
            base64: chunkBytes.toString('base64'),
            done,
            sha256
          };
          if (p.binary !== true) return ok(resultPayload);
          const rawTransferId = String(p.binary_transfer_id || '');
          const transferId =
            rawTransferId.length > 0 && rawTransferId.length <= 64
              ? rawTransferId
              : crypto.randomUUID();
          const chunkIndex =
            Number.isInteger(p.binary_chunk_index) &&
            /** @type {number} */ (p.binary_chunk_index) >= 0
              ? /** @type {number} */ (p.binary_chunk_index)
              : 0;
          return {
            ...ok({
              ...resultPayload,
              transfer_id: transferId,
              chunk_index: chunkIndex
            }),
            __binary_payload__: {
              transfer_id: transferId,
              chunk_index: chunkIndex,
              offset,
              data: chunkBytes
            }
          };
        } finally {
          await fh.close();
        }
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    file_stat: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const extraRoots = policyExtraRoots(job);
        const roots = [...readRoots, ...extraRoots.read];
        const allowAllRoots = extraRoots.allowAll === true;
        const file = await realAllowed(String(p.path || ''), roots, allowAllRoots, readOpts),
          st = await fs.stat(file);
        return ok({
          path: file,
          size_bytes: st.size,
          mtime: st.mtime?.toISOString?.() || null,
          mode: (st.mode & 0o777).toString(8),
          is_directory: st.isDirectory(),
          ...(p.resolve === true ? resolveExtras(p.path, file, readOpts) : {})
        });
      } catch (e) {
        return failFor(e, 'READ_ERROR');
      }
    },
    directory_tree: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const extraRoots = policyExtraRoots(job);
        const roots = [...readRoots, ...extraRoots.read];
        const allowAllRoots = extraRoots.allowAll === true;
        const root = await realAllowed(String(p.path || ''), roots, allowAllRoots, readOpts),
          maxDepth = Math.max(1, Math.min(10, Number(p.max_depth ?? 5))),
          maxEntries = Math.max(1, Math.min(2000, Number(p.max_entries ?? 500)));
        /** @type {Array<{path: string, name: string, type: string, depth: number}>} */
        const entries = [];
        let truncated = false;
        /** @param {string} dir @param {number} depth */
        const walk = async (dir, depth) => {
          if (depth > maxDepth || entries.length >= maxEntries) {
            truncated = true;
            return;
          }
          let rows;
          try {
            rows = await fs.readdir(dir, { withFileTypes: true });
          } catch {
            return;
          }
          for (const d of rows) {
            if (entries.length >= maxEntries) {
              truncated = true;
              return;
            }
            const full = path.join(dir, d.name);
            entries.push({
              path: full,
              name: d.name,
              type: d.isDirectory() ? 'directory' : d.isFile() ? 'file' : 'other',
              depth
            });
            if (d.isDirectory()) await walk(full, depth + 1);
          }
        };
        await walk(root, 0);
        return ok({
          path: root,
          entries,
          truncated,
          ...(p.resolve === true ? resolveExtras(p.path, root, readOpts) : {})
        });
      } catch (e) {
        return failFor(e, 'READ_ERROR');
      }
    },
    file_list: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const extraRoots = policyExtraRoots(job);
        const roots = [...readRoots, ...extraRoots.read];
        const allowAllRoots = extraRoots.allowAll === true;
        const dir = await realAllowed(String(p.path || ''), roots, allowAllRoots, readOpts),
          limit = Math.max(1, Math.min(500, Number(p.limit || 200))),
          rows = await fs.readdir(dir, { withFileTypes: true }),
          entries = [];
        for (const d of rows.slice(0, limit)) {
          let st = null;
          try {
            st = await fs.stat(path.join(dir, d.name));
          } catch {}
          entries.push({
            name: d.name,
            type: d.isDirectory()
              ? 'directory'
              : d.isFile()
                ? 'file'
                : d.isSymbolicLink()
                  ? 'symlink'
                  : 'other',
            size: st?.size ?? null,
            mtime: st?.mtime?.toISOString?.() || null
          });
        }
        return ok({
          path: dir,
          entries,
          truncated: rows.length > limit,
          ...(p.resolve === true ? resolveExtras(p.path, dir, readOpts) : {})
        });
      } catch (e) {
        return failFor(e, 'READ_ERROR');
      }
    }
  };
}
/**
 * @param {unknown} job
 * @param {object} [options]
 * @param {Array<string>} [options.readRoots]
 * @param {string|null} [options.cwd]
 * @param {string} [options.homedir]
 */
export async function fileSearchJob(job, { readRoots = [runtimeRoot()], cwd, homedir } = {}) {
  const readOpts = { cwd, homedir };
  const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  const p = /** @type {Record<string, unknown>} */ (
    jobRecord.request_payload || jobRecord.payload || {}
  );
  const query = String(p.query || '').slice(0, 200);
  if (!query) return fail('QUERY_REQUIRED');
  // Stateless walk with a hard time budget (SYN-FS-001): worst-case latency
  // stays bounded without session machinery; exhaustion reports honestly.
  const startedAt = Date.now();
  const rawBudget = Number(p.timeout_ms ?? 25000);
  const budgetMs = Number.isFinite(rawBudget) ? Math.max(1000, Math.min(60000, rawBudget)) : 25000;
  const timedOut = () => Date.now() - startedAt > budgetMs;
  try {
    const extraRoots = policyExtraRoots(job);
    const roots = [...readRoots, ...extraRoots.read];
    const allowAllRoots = extraRoots.allowAll === true;
    const root = await realAllowed(String(p.path || ''), roots, allowAllRoots, readOpts);

    const rawOffset = p.offset !== undefined && p.offset !== null ? Number(p.offset) : 0;
    const offset = Number.isFinite(rawOffset) ? Math.max(0, Math.floor(rawOffset)) : 0;

    const rawLimit =
      p.limit !== undefined && p.limit !== null
        ? Number(p.limit)
        : p.max_results !== undefined && p.max_results !== null
          ? Number(p.max_results)
          : 100;
    const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(500, Math.floor(rawLimit))) : 100;

    const stack = [root];
    const results = [];
    let files = 0;
    let timeExceeded = false;
    let matchIndex = 0;
    let hasMore = false;

    while (stack.length && files < 2000 && !hasMore) {
      if (timedOut()) {
        timeExceeded = true;
        break;
      }
      const dir = /** @type {string} */ (stack.pop());
      let rows = [];
      try {
        rows = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const d of rows) {
        const full = path.join(dir, d.name);
        if (d.isDirectory() && !d.isSymbolicLink()) {
          stack.push(full);
          continue;
        }
        if (!d.isFile()) {
          continue;
        }
        files++;
        if (files > 2000) break;
        let st;
        try {
          st = await fs.stat(full);
        } catch {
          continue;
        }
        if (st.size > 512 * 1024) continue;
        let text;
        try {
          text = await fs.readFile(full, 'utf8');
        } catch {
          continue;
        }
        const idx = text.indexOf(query);
        if (idx >= 0) {
          if (matchIndex >= offset) {
            if (results.length < limit) {
              const before = text.slice(0, idx),
                line = before.split('\n').length,
                preview = text
                  .slice(Math.max(0, idx - 80), Math.min(text.length, idx + query.length + 120))
                  .replace(/\s+/g, ' ');
              results.push({ path: full, line, preview });
            } else {
              hasMore = true;
              break;
            }
          }
          matchIndex++;
        }
      }
    }

    if (!hasMore && results.length >= limit && (stack.length > 0 || files >= 2000)) {
      hasMore = true;
    }

    return ok({
      path: root,
      query,
      results,
      offset,
      limit,
      has_more: hasMore,
      files_searched: files,
      truncated: stack.length > 0 || files >= 2000 || hasMore,
      timed_out: timeExceeded,
      ...(p.resolve === true ? resolveExtras(p.path, root, readOpts) : {})
    });
  } catch (e) {
    const errorRecord = /** @type {{message?: unknown}} */ (e);
    return fail(errorRecord?.message);
  }
}

/**
 * macOS unit alias: only our own agent names resolve to com.nc.client;
 * every other unit passes through verbatim (a catch-all default once
 * reported the NC agent for com.apple.Finder).
 * @param {string} unit
 */
export function resolveMacUnit(unit) {
  return unit === 'NC Client' ||
    unit === 'nc-client' ||
    unit === 'nc-client.service' ||
    unit === 'com.nc.client'
    ? 'com.nc.client'
    : unit;
}
/**
 * @param {unknown} job
 * @param {object} [options] reserved for handler uniformity (unused)
 */
export async function serviceStatusJob(job, options = {}) {
  void options;
  const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  const p = /** @type {Record<string, unknown>} */ (
    jobRecord.request_payload || jobRecord.payload || {}
  );
  const unit = String(p.unit || '').trim();
  // No name allowlist: the job is already gated by host-policy admission
  // (service_status capability), service_list discloses the full inventory
  // anyway, and mutations (stop/restart) were never name-restricted — so a
  // status gate only blocked verify-after-mutate workflows without adding
  // any confidentiality.
  if (!unit) return fail('SERVICE_UNIT_REQUIRED');

  const platform = os.platform();

  if (platform === 'linux') {
    const linuxUnit = unit.endsWith('.service')
      ? unit
      : unit === 'NC Client' || unit === 'com.nc.client'
        ? 'nc-client.service'
        : `${unit}.service`;
    const [active, enabled] = await Promise.all([
      capture('systemctl', ['is-active', linuxUnit]),
      capture('systemctl', ['is-enabled', linuxUnit])
    ]);
    return ok({
      unit,
      resolved_unit: linuxUnit,
      platform: 'linux',
      active: active.out || 'unknown',
      enabled: enabled.out || 'unknown',
      active_exit_code: active.code,
      enabled_exit_code: enabled.code
    });
  }

  if (platform === 'darwin') {
    // Alias only our own agent names (mirrors the linux branch above);
    // Alias only our own agent names (mirrors the linux branch above);
    // every other unit passes through verbatim (see resolveMacUnit).
    const macUnit = resolveMacUnit(unit);
    const res = await capture('launchctl', ['list', macUnit]);
    // Exit 0 means LOADED, not running: a loaded-but-idle daemon prints
    // PID "-" (this once reported active for a stopped service). Active
    // requires a numeric live PID.
    const pidMatch = String(res.out || '').match(/"PID"\s*=\s*(\S+?);/);
    const pidValue = pidMatch ? pidMatch[1] : null;
    const pidAlive = pidValue !== null && /^\d+$/.test(pidValue) && Number(pidValue) > 0;
    let isActive = 'unknown';
    let isEnabled = 'enabled';
    if (res.code === 0 && res.out && pidAlive) {
      isActive = 'active';
    } else if (res.code === 0 && res.out && !pidAlive) {
      isActive = 'inactive';
    } else if (res.code === 113 || (res.err && res.err.includes('Could not find'))) {
      isActive = 'inactive';
      isEnabled = 'disabled';
    } else {
      try {
        await fs.access(`/Library/LaunchDaemons/${macUnit}.plist`);
        isEnabled = 'enabled';
        isActive = pidAlive ? 'active' : 'inactive';
      } catch {
        isEnabled = 'unknown';
      }
    }
    return ok({
      unit,
      resolved_unit: macUnit,
      platform: 'darwin',
      active: isActive,
      enabled: isEnabled,
      active_exit_code: res.code,
      raw_output: res.out || res.err || ''
    });
  }

  if (platform === 'win32') {
    if (/[';\r\n]/.test(unit)) return fail('INVALID_SERVICE');
    const taskName =
      unit === 'nc-client.service' ||
      unit === 'com.nc.client' ||
      unit === 'NC Client' ||
      unit === 'NCClient' ||
      unit === 'nc-client'
        ? 'NC Client'
        : unit;
    // SCM service first (Faz 3 runs the agent as a service; the scheduled
    // task remains only as a disabled fallback). Task-first ordering
    // reported inactive/disabled for a healthy service-hosted agent.
    const res = await capture('powershell.exe', [
      '-NoProfile',
      '-Command',
      `$s = Get-Service -Name '${unit}' -ErrorAction SilentlyContinue; if ($s) { Write-Output ('SVC_STATUS:' + $s.Status) } else { $t = Get-ScheduledTask -TaskName '${taskName}' -ErrorAction SilentlyContinue; if ($t) { Write-Output ('TASK_STATE:' + $t.State) } else { Write-Output 'NOT_FOUND' } }`
    ]);
    let isActive = 'unknown';
    let isEnabled = 'enabled';
    const out = (res.out || '').trim();
    if (out.includes('TASK_STATE:Running')) {
      isActive = 'active';
      isEnabled = 'enabled';
    } else if (out.includes('TASK_STATE:Ready')) {
      isActive = 'active';
      isEnabled = 'enabled';
    } else if (out.includes('TASK_STATE:Disabled')) {
      isActive = 'inactive';
      isEnabled = 'disabled';
    } else if (out.includes('SVC_STATUS:Running')) {
      isActive = 'active';
      isEnabled = 'enabled';
    } else if (out.includes('SVC_STATUS:Stopped')) {
      isActive = 'inactive';
      isEnabled = 'enabled';
    } else if (out.includes('NOT_FOUND')) {
      isActive = 'inactive';
      isEnabled = 'unknown';
    }
    return ok({
      unit,
      resolved_unit: unit,
      platform: 'win32',
      active: isActive,
      enabled: isEnabled,
      active_exit_code: res.code,
      raw_output: out
    });
  }

  return fail('PLATFORM_NOT_SUPPORTED');
}

const COMMAND_NAME_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.\-+]*$/;

/**
 * PATH lookup for file_browse action=which: the `command -v` equivalent
 * without a shell. Only bare command names are accepted (any slash is
 * rejected as INVALID_COMMAND_NAME), so traversal is impossible by
 * construction. Existence/executability only: file contents are never
 * read. A miss is still status completed with found:false.
 * @param {unknown} job
 * @param {{searchPaths?: string|null}} [options] PATH override for tests
 */
export async function commandLookupJob(job, { searchPaths = null } = {}) {
  const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  const p = /** @type {Record<string, unknown>} */ (
    jobRecord.request_payload || jobRecord.payload || {}
  );
  const name = String(p.path || '').slice(0, 256);
  if (!COMMAND_NAME_PATTERN.test(name)) return fail('INVALID_COMMAND_NAME');
  const rawPath =
    typeof searchPaths === 'string' ? searchPaths : String(process.env.PATH || '');
  const sep = process.platform === 'win32' ? ';' : ':';
  const dirs = rawPath
    .split(sep)
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, 256);
  const exts =
    process.platform === 'win32'
      ? String(process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM;.PS1')
          .split(';')
          .map((e) => e.trim().toLowerCase())
          .filter(Boolean)
      : [''];
  for (const dir of dirs) {
    const candidates =
      process.platform === 'win32' && !/\.[a-z0-9]+$/i.test(name)
        ? [name, ...exts.map((e) => name + e)]
        : [name];
    for (const candidate of candidates.slice(0, 8)) {
      const full = path.join(dir, candidate);
      try {
        const st = await fs.stat(full);
        if (!st.isFile()) continue;
        if (process.platform !== 'win32') await fs.access(full, fsConstants.X_OK);
        return ok({ command: name, found: true, resolved_path: full });
      } catch {
        continue;
      }
    }
  }
  return ok({ command: name, found: false, resolved_path: null });
}

/**
 * @param {Record<string, (job: any, ...args: Array<any>) => unknown>} base
 * @param {object} [options]
 * @param {Array<string>} [options.readRoots]
 * @param {string|null} [options.searchPaths] PATH override for file_which tests
 */
export function extendStructuredHandlers(base, options) {
  return {
    ...base,
    file_search: (/** @type {unknown} */ job) => fileSearchJob(job, options),
    file_which: (/** @type {unknown} */ job) => commandLookupJob(job, options),
    service_status: (/** @type {unknown} */ job) => serviceStatusJob(job, options)
  };
}
