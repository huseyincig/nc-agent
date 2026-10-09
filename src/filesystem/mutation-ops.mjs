import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { policyExtraRoots } from '../policy/host-policy.mjs';
import { isSensitivePath } from './sensitive-paths.mjs';
import { MutationError, authorizeMutationPath, err, forbidAgentTreeWrite, lstatOrNull, mutationTargets, normCase, normalizeMutationPath, realAllowedRoots } from './path-auth.mjs';
import { normalizeServiceMode } from '../client/shell-runner.mjs';


export const MAX_WRITE_BYTES = 1024 * 1024;

/**
 * @param {unknown} o @param {string} k
 */
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o || {}, k);
/**
 * @param {unknown} o @param {string} key @param {string} errorCode
 */
function optionalBoolean(o, key, errorCode) {
  const rec = o && typeof o === 'object' ? /** @type {Record<string, unknown>} */ (o) : null;
  if (!rec || !hasOwn(rec, key)) return false;
  if (typeof rec[key] !== 'boolean') err(errorCode);
  return rec[key] === true;
}

/**
 * @param {string} target @param {{roots?: Array<string>, fsApi: typeof import('node:fs/promises'), pathApi: typeof import('node:path')}} options
 */
async function authorizeLeafParent(target, options) {
  const { fsApi = fs, pathApi = path } = options;
  const normalized = normalizeMutationPath(target, { pathApi });
  const parent = pathApi.dirname(normalized);
  const auth = await authorizeMutationPath(parent, options);
  return { ...auth, path: normalized, parent };
}
/**
 * @param {unknown} value @param {boolean} [present]
 */
function validateSha(value, present = value !== undefined) {
  if (!present) return null;
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(/** @type {string} */ (value))) err('INVALID_SHA256');
  return /** @type {string} */ (value).toLowerCase();
}
/**
 * Positional read loop (short-read safe): a single handle.read may return
 * fewer bytes than asked; without the loop the tail stays zero-filled and
 * the finalize hash silently corrupts (spurious TRANSFER_CHECKSUM_MISMATCH
 * plus deletion of a good file). Mirrors readExact in structured-ops.mjs.
 */
async function readExactHandle(rh, buf, length, position) {
  let read = 0;
  while (read < length) {
    const { bytesRead } = await rh.read(buf, read, length - read, position + read);
    if (!bytesRead) break;
    read += bytesRead;
  }
  return read;
}
/**
 * V-32.8: open with O_NOFOLLOW so a symlink swapped in between the lstat
 * gate above and the open cannot redirect the truncate/write outside the
 * gated tree. fs.promises.open accepts a numeric flags value (Node 24/26).
 * ELOOP/EMLINK (path is a symlink) maps to the existing symlink-denied
 * style; EEXIST on create-exclusive maps to DESTINATION_EXISTS. On
 * platforms where O_NOFOLLOW is unsupported (Windows: EINVAL/ENOSYS),
 * fall back to the string flag — the lstat gate above still applies.
 * @param {string} target
 * @param {number} numericFlags
 * @param {string} fallbackFlag
 * @param {{fsApi?: typeof import('node:fs/promises')}} [options]
 */
async function openNoFollow(target, numericFlags, fallbackFlag, { fsApi = fs } = {}) {
  try {
    return await fsApi.open(target, numericFlags);
  } catch (openError) {
    // NOTE: the catch binding must NOT shadow the imported `err` helper
    // (P2-01: `catch (err)` turned `err('...')` into a TypeError by calling
    // the caught exception). `err` below is always path-auth's thrower,
    // so these map to MutationError codes exactly like every other site in
    // this file (normalizeMutationError renders them as stable `error`
    // codes; a plain Error here would fall through to MUTATION_IO_ERROR).
    const code = /** @type {NodeJS.ErrnoException} */ (openError).code;
    if (code === 'ELOOP' || code === 'EMLINK') err('PATH_TYPE_NOT_SUPPORTED');
    if ((code === 'EINVAL' || code === 'ENOSYS' || code === 'EOPNOTSUPP') && fsConstants.O_NOFOLLOW) {
      return await fsApi.open(target, fallbackFlag);
    }
    throw openError;
  }
}
/**
 * @param {string} file @param {typeof import('node:fs/promises')} fsApi
 */
async function shaFile(file, fsApi) {
  const h = crypto.createHash('sha256');
  const handle = await fsApi.open(file, 'r');
  try {
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (!bytesRead) break;
      h.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    return h.digest('hex');
  } finally {
    await handle.close();
  }
}
/**
 * Best-effort durability sync for a just-written sibling temp file: the bytes
 * must reach the filesystem before the atomic rename publishes them, or a
 * crash can publish a torn file. Best-effort by design ("where supported"):
 * filesystems or minimal fsApi doubles without open/sync must never fail an
 * otherwise valid write over a durability hint.
 * @param {string} tmp sibling temp path
 * @param {typeof import('node:fs/promises')} fsApi
 */
async function fsyncTempFile(tmp, fsApi) {
  if (!fsApi || typeof fsApi.open !== 'function') return;
  let fh = null;
  try {
    fh = await fsApi.open(tmp, 'r');
    if (fh && typeof fh.sync === 'function') await fh.sync();
  } catch {
    // Durability hint only — the rename still provides atomicity.
  } finally {
    try {
      if (fh && typeof fh.close === 'function') await fh.close();
    } catch {}
  }
}
/**
 * @param {unknown} content
 */
function contentBytes(content) {
  if (typeof content !== 'string') err('CONTENT_REQUIRED');
  const bytes = Buffer.byteLength(/** @type {string} */ (content), 'utf8');
  if (bytes > MAX_WRITE_BYTES) err('CONTENT_TOO_LARGE');
  return bytes;
}
/**
 * @param {unknown} encoding @param {boolean} [present]
 */
function ensureEncoding(encoding, present = encoding !== undefined) {
  if (!present) return;
  if (encoding !== 'utf8') err('ENCODING_NOT_SUPPORTED');
}
/**
 * @param {string} target @param {Array<string>} realRoots @param {typeof import('node:path')} pathApi
 */
function rootTargetForbidden(target, realRoots, pathApi) {
  const t = normCase(target, pathApi);
  if (realRoots.some((root) => t === normCase(root, pathApi))) err('ROOT_MUTATION_FORBIDDEN');
}
/**
 * @param {string} target @param {object} [options] @param {Array<string>} [options.roots] @param {boolean} [options.allowAll] @param {typeof import('node:fs/promises')} [options.fsApi] @param {any} [options.pathApi]
 */
async function forbidConfiguredRootTarget(
  target,
  { roots, allowAll = false, fsApi = fs, pathApi = path } = {}
) {
  const normalized = normalizeMutationPath(target, { pathApi });
  if (allowAll === true && !(roots || []).length) return [];
  const realRoots = await realAllowedRoots(roots, fsApi);
  const configured = (roots || []).map((root) =>
    normCase(pathApi.normalize(String(root)), pathApi)
  );
  const t = normCase(normalized, pathApi);
  if (configured.includes(t) || realRoots.some((root) => t === normCase(root, pathApi)))
    err('ROOT_MUTATION_FORBIDDEN');
  return realRoots;
}
const queues = new Map();

/**
 * @param {Record<string, unknown>} [job]
 * @returns {{policy_contract_version: string|null, policy_revision: number|null, policy_digest: string|null}}
 */
export function policyIdentityFromJob(job = {}) {
  const contract =
    typeof job?.policy_contract_version === 'string' ? job.policy_contract_version : null;
  const revision =
    typeof job?.policy_revision === 'number' &&
    Number.isInteger(job.policy_revision) &&
    job.policy_revision > 0
      ? job.policy_revision
      : null;
  const digest =
    typeof job?.policy_digest === 'string' && /^[0-9a-f]{64}$/.test(job.policy_digest)
      ? job.policy_digest
      : null;
  return { policy_contract_version: contract, policy_revision: revision, policy_digest: digest };
}
/**
 * @param {string} key @param {() => unknown} fn
 */
async function serialized(key, fn) {
  const prior = queues.get(key) || Promise.resolve();
  /** @type {(value?: unknown) => void} */
  let release = () => {};
  const gate = new Promise((r) => (release = r));
  const tail = prior.then(() => gate);
  queues.set(key, tail);
  await prior;
  try {
    return await fn();
  } finally {
    release();
    if (queues.get(key) === tail) queues.delete(key);
  }
}
/**
 * @param {Array<string>} keys @param {(index?: number) => unknown} fn
 */
async function serializedMany(keys, fn) {
  const ordered = [...new Set(keys)].sort();
  /**
   * @param {number} index
   * @returns {unknown}
   */
  const take = (index) =>
    index >= ordered.length ? fn() : serialized(ordered[index], () => take(index + 1));
  return take(0);
}

/**
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {boolean} [options.allowAll]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {any} [options.pathApi]
 * @param {string} [options.platform]
 * @param {{tool?: string, appRoot?: string|null, workspace?: string|null, pathApi?: any}|null} [options.treeBan]
 * @param {string|null} [options.cwd] pre-flight relative-resolution base
 * @param {string} [options.homedir] `~` expansion base
 */
export async function fileWriteMutation(
  payload,
  { roots, allowAll = false, fsApi = fs, pathApi = path, platform = process.platform, treeBan = null, cwd = null, homedir = null } = {}
) {
  ensureEncoding(payload?.encoding, hasOwn(payload, 'encoding'));
  const hasMode = hasOwn(payload, 'mode');
  const mode = hasMode ? String(payload?.mode) : '';
  if (hasMode && !['create', 'replace', 'append'].includes(mode)) err('WRITE_MODE_INVALID');
  const bytes = contentBytes(payload?.content);
  const expected = validateSha(payload?.expected_sha256, hasOwn(payload, 'expected_sha256'));
  if (mode === 'create' && hasOwn(payload, 'expected_sha256'))
    err('EXPECTED_SHA_NOT_ALLOWED_FOR_CREATE');
  // Accepted for backward compatibility (capability derivation still reads
  // it); parent directories are now ALWAYS provisioned (TOOL_DESIGN L2),
  // so the value no longer gates success.
  optionalBoolean(payload, 'create_parents', 'INVALID_CREATE_PARENTS');
  const normalized = normalizeMutationPath(/** @type {string} */ (payload?.path), {
    pathApi,
    cwd,
    homedir
  });
  return serialized(normCase(normalized, pathApi), async () => {
    const options = { roots, allowAll, fsApi, pathApi, treeBan };
    await forbidConfiguredRootTarget(normalized, options);
    // Authorize the parent FIRST (before any mkdir): a planted symlink on
    // the parent resolves outside the gated tree and trips the ban here,
    // before anything is created (P13-D5).
    const parent = pathApi.dirname(normalized);
    let parentAuth = await authorizeMutationPath(parent, options);
    rootTargetForbidden(normalized, parentAuth.real_roots, pathApi);
    let st = await lstatOrNull(normalized, fsApi);
    if (st && st.isSymbolicLink()) err('PATH_SYMLINK_NOT_ALLOWED_FOR_WRITE');
    if (st && !st.isFile()) err('PATH_TYPE_NOT_SUPPORTED');
    const exists = !!st;
    const emptyFile = exists && (st.size || 0) === 0;
    // Unified write semantics (TOOL_DESIGN L3): new and empty files are
    // created/overwritten freely; an explicit mode is required only to
    // overwrite an existing NON-EMPTY file (the real overwrite risk).
    let effectiveMode = mode;
    if (!hasMode) {
      if (exists && !emptyFile)
        err('WRITE_MODE_REQUIRED', {
          path: normalized,
          size_bytes: st.size,
          hint: "Refusing to overwrite a non-empty file without an explicit mode — retry with mode 'replace' to overwrite or 'append' to add to the end."
        });
      effectiveMode = exists ? 'replace' : 'create';
    } else if (mode === 'create' && exists && !emptyFile) {
      err('FILE_EXISTS');
    }
    if (expected && !exists) {
      // An optimistic-concurrency guard cannot match a file that is not
      // there; creating anyway would silently ignore the guard.
      if (!hasMode || mode === 'create') err('EXPECTED_SHA_NOT_ALLOWED_FOR_CREATE');
      err('FILE_SHA256_MISMATCH');
    }
    let previousSha = null;
    const needsCreate = !exists;
    if (needsCreate) {
      // Automatic parent provisioning (L2): never fail closed with
      // PARENT_NOT_FOUND on a standard write; re-authorize afterwards so
      // the ban still sees the final resolved ancestor.
      await fsApi.mkdir(parent, { recursive: true });
      parentAuth = await authorizeMutationPath(parent, options);
      rootTargetForbidden(normalized, parentAuth.real_roots, pathApi);
      st = await lstatOrNull(normalized, fsApi);
      if (st) err('FILE_EXISTS');
      try {
        await fsApi.writeFile(normalized, /** @type {string} */ (payload.content), {
          encoding: 'utf8',
          flag: 'wx'
        });
      } catch (error) {
        // A failed create must not leave a partial file: the next retry
        // would fail closed with FILE_EXISTS on our own rubbish. EEXIST
        // means the file pre-existed us, so it is never unlinked.
        const code =
          error && typeof error === 'object'
            ? /** @type {{code?: unknown}} */ (error).code
            : null;
        if (code !== 'EEXIST') {
          try {
            await fsApi.unlink(normalized);
          } catch {}
        }
        throw error;
      }
    } else {
      const leaf = await authorizeLeafParent(normalized, options);
      rootTargetForbidden(normalized, leaf.real_roots, pathApi);
      st = await lstatOrNull(normalized, fsApi);
      if (!st) err('FILE_NOT_FOUND');
      if (st.isSymbolicLink()) err('PATH_SYMLINK_NOT_ALLOWED_FOR_WRITE');
      if (!st.isFile()) err('PATH_TYPE_NOT_SUPPORTED');
      const before = await shaFile(normalized, fsApi);
      previousSha = before;
      if (expected && before !== expected) err('FILE_SHA256_MISMATCH');
      if (effectiveMode === 'append') {
        if (Number(st.nlink || 1) > 1) err('PATH_HARDLINK_NOT_ALLOWED_FOR_APPEND');
        const appendLeaf = await authorizeLeafParent(normalized, options);
        rootTargetForbidden(normalized, appendLeaf.real_roots, pathApi);
        const appendStat = await lstatOrNull(normalized, fsApi);
        if (!appendStat) err('FILE_NOT_FOUND');
        if (appendStat.isSymbolicLink()) err('PATH_SYMLINK_NOT_ALLOWED_FOR_WRITE');
        if (!appendStat.isFile()) err('PATH_TYPE_NOT_SUPPORTED');
        if (Number(appendStat.nlink || 1) > 1) err('PATH_HARDLINK_NOT_ALLOWED_FOR_APPEND');
        if (expected && (await shaFile(normalized, fsApi)) !== expected)
          err('FILE_SHA256_MISMATCH');
        await fsApi.appendFile(normalized, /** @type {string} */ (payload.content), {
          encoding: 'utf8'
        });
      } else {
        const tmp = pathApi.join(
          pathApi.dirname(normalized),
          '.nc-' +
            pathApi.basename(normalized) +
            '.' +
            process.pid +
            '.' +
            crypto.randomBytes(6).toString('hex') +
            '.tmp'
        );
        try {
          await fsApi.writeFile(tmp, /** @type {string} */ (payload.content), {
            encoding: 'utf8',
            flag: 'wx'
          });
          await fsyncTempFile(tmp, fsApi);
          if (platform !== 'win32') await fsApi.chmod(tmp, st.mode & 0o7777);
          if (expected && (await shaFile(normalized, fsApi)) !== expected)
            err('FILE_SHA256_MISMATCH');
          await fsApi.rename(tmp, normalized);
        } finally {
          try {
            await fsApi.unlink(tmp);
          } catch {}
        }
      }
    }
    const resultSha = await shaFile(normalized, fsApi);
    return {
      path: normalized,
      mode: effectiveMode,
      bytes_written: bytes,
      previous_sha256: previousSha,
      expected_sha256: expected,
      sha256: resultSha
    };
  });
}

/**
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {boolean} [options.allowAll]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {any} [options.pathApi]
 * @param {string} [options.platform]
 * @param {{tool?: string, appRoot?: string|null, workspace?: string|null, pathApi?: any}|null} [options.treeBan]
 * @param {string|null} [options.cwd] pre-flight relative-resolution base
 * @param {string} [options.homedir] `~` expansion base
 */
export async function directoryCreateMutation(payload, { roots, allowAll = false, fsApi = fs, pathApi = path, treeBan = null, cwd = null, homedir = null } = {}) {
  // Accepted for backward compatibility; intermediate directories are now
  // ALWAYS created (TOOL_DESIGN L2), so the value no longer gates success.
  optionalBoolean(payload, 'parents', 'INVALID_PARENTS');
  const normalized = normalizeMutationPath(/** @type {string} */ (payload?.path), {
    pathApi,
    cwd,
    homedir
  });
  const options = { roots, allowAll, fsApi, pathApi, treeBan };
  return serialized(normCase(normalized, pathApi), async () => {
    await forbidConfiguredRootTarget(normalized, options);
    const leaf = await authorizeLeafParent(normalized, options);
    rootTargetForbidden(normalized, leaf.real_roots, pathApi);
    const current = await lstatOrNull(normalized, fsApi);
    if (current) {
      if (!current.isDirectory() || current.isSymbolicLink()) err('PATH_TYPE_NOT_SUPPORTED');
      return { path: normalized, created: false };
    }
    await fsApi.mkdir(normalized, { recursive: true });
    const created = await lstatOrNull(normalized, fsApi);
    if (!created || !created.isDirectory() || created.isSymbolicLink())
      err('PATH_TYPE_NOT_SUPPORTED');
    const auth = await authorizeMutationPath(normalized, options);
    rootTargetForbidden(normalized, auth.real_roots, pathApi);
    return { path: normalized, created: true };
  });
}

/**
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {boolean} [options.allowAll]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {any} [options.pathApi]
 * @param {string} [options.platform]
 * @param {{tool?: string, appRoot?: string|null, workspace?: string|null, pathApi?: any}|null} [options.treeBan]
 */
export async function fileMoveMutation(payload, { roots, allowAll = false, fsApi = fs, pathApi = path, treeBan = null } = {}) {
  const overwrite = optionalBoolean(payload, 'overwrite', 'INVALID_OVERWRITE');
  const source = normalizeMutationPath(/** @type {string} */ (payload?.source), { pathApi });
  const destination = normalizeMutationPath(/** @type {string} */ (payload?.destination), {
    pathApi
  });
  if (normCase(source, pathApi) === normCase(destination, pathApi))
    err('SOURCE_EQUALS_DESTINATION');
  const sourceOptions = { roots, allowAll, fsApi, pathApi, treeBan };
  await forbidConfiguredRootTarget(source, sourceOptions);
  const srcAuth = await authorizeLeafParent(source, sourceOptions);
  rootTargetForbidden(source, srcAuth.real_roots, pathApi);
  const srcStat = await lstatOrNull(source, fsApi);
  if (!srcStat) err('FILE_NOT_FOUND');
  if (srcStat.isDirectory() || (!srcStat.isFile() && !srcStat.isSymbolicLink()))
    err('PATH_TYPE_NOT_SUPPORTED');

  await forbidConfiguredRootTarget(destination, sourceOptions);
  const dstAuth = await authorizeLeafParent(destination, sourceOptions);
  rootTargetForbidden(destination, dstAuth.real_roots, pathApi);
  const dstParent = pathApi.dirname(destination);
  const dstParentStat = await lstatOrNull(dstParent, fsApi);
  if (!dstParentStat || !dstParentStat.isDirectory() || dstParentStat.isSymbolicLink())
    err('PARENT_NOT_FOUND');
  await authorizeMutationPath(dstParent, sourceOptions);

  const dstStat = await lstatOrNull(destination, fsApi);
  if (dstStat && !overwrite) err('DESTINATION_EXISTS');
  if (dstStat && (dstStat.isDirectory() || (!dstStat.isFile() && !dstStat.isSymbolicLink())))
    err('PATH_TYPE_NOT_SUPPORTED');

  return serializedMany([normCase(source, pathApi), normCase(destination, pathApi)], async () => {
    await forbidConfiguredRootTarget(source, sourceOptions);
    const srcLeafNow = await authorizeLeafParent(source, sourceOptions);
    rootTargetForbidden(source, srcLeafNow.real_roots, pathApi);
    await forbidConfiguredRootTarget(destination, sourceOptions);
    const dstLeafNow = await authorizeLeafParent(destination, sourceOptions);
    rootTargetForbidden(destination, dstLeafNow.real_roots, pathApi);
    const srcNow = await lstatOrNull(source, fsApi);
    if (!srcNow) err('FILE_NOT_FOUND');
    if (srcNow.isDirectory() || (!srcNow.isFile() && !srcNow.isSymbolicLink()))
      err('PATH_TYPE_NOT_SUPPORTED');
    const dstNow = await lstatOrNull(destination, fsApi);
    if (dstNow && !overwrite) err('DESTINATION_EXISTS');
    if (dstNow && (dstNow.isDirectory() || (!dstNow.isFile() && !dstNow.isSymbolicLink())))
      err('PATH_TYPE_NOT_SUPPORTED');
    try {
      await fsApi.rename(source, destination);
    } catch (e) {
      const moveCode = e && typeof e === 'object' && 'code' in e ? e.code : undefined;
      if (moveCode === 'EXDEV') err('CROSS_DEVICE_MOVE_NOT_SUPPORTED');
      throw e;
    }
    return { source, destination, overwritten: Boolean(dstNow) };
  });
}

/**
 * Same-host copy. Mirrors the move guards on both ends (write roots for
 * source and destination); `overwrite=true` additionally requires the
 * `file_delete` capability, exactly like file_move. Bulk content uses the
 * transfer ops; copies over MAX_WRITE_BYTES refuse with CONTENT_TOO_LARGE.
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {boolean} [options.allowAll]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {any} [options.pathApi]
 * @param {string} [options.platform]
 * @param {{tool?: string, appRoot?: string|null, workspace?: string|null, pathApi?: any}|null} [options.treeBan]
 */
export async function fileCopyMutation(payload, { roots, allowAll = false, fsApi = fs, pathApi = path, treeBan = null } = {}) {
  const overwrite = optionalBoolean(payload, 'overwrite', 'INVALID_OVERWRITE');
  const source = normalizeMutationPath(/** @type {string} */ (payload?.source), { pathApi });
  const destination = normalizeMutationPath(/** @type {string} */ (payload?.destination), {
    pathApi
  });
  if (normCase(source, pathApi) === normCase(destination, pathApi))
    err('SOURCE_EQUALS_DESTINATION');
  const sourceOptions = { roots, allowAll, fsApi, pathApi, treeBan };
  await forbidConfiguredRootTarget(source, sourceOptions);
  const srcAuth = await authorizeLeafParent(source, sourceOptions);
  rootTargetForbidden(source, srcAuth.real_roots, pathApi);
  const srcStat = await lstatOrNull(source, fsApi);
  if (!srcStat) err('FILE_NOT_FOUND');
  if (srcStat.isDirectory() || (!srcStat.isFile() && !srcStat.isSymbolicLink()))
    err('PATH_TYPE_NOT_SUPPORTED');
  if (srcStat.size > MAX_WRITE_BYTES) err('CONTENT_TOO_LARGE');

  await forbidConfiguredRootTarget(destination, sourceOptions);
  const dstAuth = await authorizeLeafParent(destination, sourceOptions);
  rootTargetForbidden(destination, dstAuth.real_roots, pathApi);
  const dstParent = pathApi.dirname(destination);
  const dstParentStat = await lstatOrNull(dstParent, fsApi);
  if (!dstParentStat || !dstParentStat.isDirectory() || dstParentStat.isSymbolicLink())
    err('PARENT_NOT_FOUND');
  await authorizeMutationPath(dstParent, sourceOptions);

  const dstStat = await lstatOrNull(destination, fsApi);
  if (dstStat && !overwrite) err('DESTINATION_EXISTS');
  // copyFile follows links while rename replaces them: never write through.
  if (dstStat && dstStat.isSymbolicLink()) err('PATH_TYPE_NOT_SUPPORTED');
  if (dstStat && (dstStat.isDirectory() || (!dstStat.isFile() && !dstStat.isSymbolicLink())))
    err('PATH_TYPE_NOT_SUPPORTED');

  return serializedMany([normCase(source, pathApi), normCase(destination, pathApi)], async () => {
    await forbidConfiguredRootTarget(source, sourceOptions);
    const srcLeafNow = await authorizeLeafParent(source, sourceOptions);
    rootTargetForbidden(source, srcLeafNow.real_roots, pathApi);
    await forbidConfiguredRootTarget(destination, sourceOptions);
    const dstLeafNow = await authorizeLeafParent(destination, sourceOptions);
    rootTargetForbidden(destination, dstLeafNow.real_roots, pathApi);
    const srcNow = await lstatOrNull(source, fsApi);
    if (!srcNow) err('FILE_NOT_FOUND');
    if (srcNow.isDirectory() || (!srcNow.isFile() && !srcNow.isSymbolicLink()))
      err('PATH_TYPE_NOT_SUPPORTED');
    if (srcNow.size > MAX_WRITE_BYTES) err('CONTENT_TOO_LARGE');
    const dstNow = await lstatOrNull(destination, fsApi);
    if (dstNow && !overwrite) err('DESTINATION_EXISTS');
    if (dstNow && dstNow.isSymbolicLink()) err('PATH_TYPE_NOT_SUPPORTED');
    if (dstNow && (dstNow.isDirectory() || (!dstNow.isFile() && !dstNow.isSymbolicLink())))
      err('PATH_TYPE_NOT_SUPPORTED');
    await fsApi.copyFile(source, destination);
    const after = await lstatOrNull(destination, fsApi);
    return {
      source,
      destination,
      bytes: after ? after.size : srcNow.size,
      overwritten: Boolean(dstNow)
    };
  });
}

/**
 * Single relay chunk of a hub-orchestrated transfer. Offset 0 truncates (or
 * creates); later offsets require the existing size to match exactly, so a
 * retried or reordered chunk can neither gap nor duplicate bytes. Finalize
 * verifies the full-file sha256 when expected_sha256 is given; a mismatch
 * removes the partial file so no corrupt residue survives.
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {boolean} [options.allowAll]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {any} [options.pathApi]
 * @param {string} [options.platform]
 * @param {{tool?: string, appRoot?: string|null, workspace?: string|null, pathApi?: any}|null} [options.treeBan]
 */
export async function transferWriteMutation(payload, { roots, allowAll = false, fsApi = fs, pathApi = path, treeBan = null } = {}) {
  const target = normalizeMutationPath(/** @type {string} */ (payload?.path), { pathApi });
  const overwrite = optionalBoolean(payload, 'overwrite', 'INVALID_OVERWRITE');
  const offset = Number(payload?.offset ?? 0);
  if (!Number.isInteger(offset) || offset < 0) err('INVALID_OFFSET');
  const raw = String(payload?.base64 ?? '');
  if (raw.length > 65536) err('INVALID_CHUNK');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(raw) || raw.length % 4 === 1) err('INVALID_CHUNK');
  let chunk;
  try {
    chunk = Buffer.from(raw, 'base64');
  } catch {
    err('INVALID_CHUNK');
  }
  const finalize = payload?.finalize === true;
  const expectedSha =
    typeof payload?.expected_sha256 === 'string' && payload.expected_sha256
      ? String(payload.expected_sha256)
      : null;
  if (expectedSha && !/^[0-9a-fA-F]{64}$/.test(expectedSha)) err('INVALID_SHA256');
  if (!chunk || chunk.length > 49152) err('INVALID_CHUNK');
  if (chunk.length === 0 && !finalize) err('INVALID_CHUNK');
  const options = { roots, allowAll, fsApi, pathApi, treeBan };
  await forbidConfiguredRootTarget(target, options);
  const auth = await authorizeLeafParent(target, options);
  rootTargetForbidden(target, auth.real_roots, pathApi);
  const parent = pathApi.dirname(target);
  const parentStat = await lstatOrNull(parent, fsApi);
  if (!parentStat || !parentStat.isDirectory() || parentStat.isSymbolicLink())
    err('PARENT_NOT_FOUND');
  await authorizeMutationPath(parent, options);
  return serialized(normCase(target, pathApi), async () => {
    await forbidConfiguredRootTarget(target, options);
    const leafNow = await authorizeLeafParent(target, options);
    rootTargetForbidden(target, leafNow.real_roots, pathApi);
    const existing = await lstatOrNull(target, fsApi);
    if (offset === 0) {
      // Symlink destinations are never followed: an offset-0 open('w')
      // would truncate through the link outside the gated tree.
      if (existing && existing.isSymbolicLink()) err('PATH_TYPE_NOT_SUPPORTED');
      if (existing && (existing.isDirectory() || (!existing.isFile() && !existing.isSymbolicLink())))
        err('PATH_TYPE_NOT_SUPPORTED');
      if (existing && existing.isFile() && !overwrite) err('DESTINATION_EXISTS');
    } else {
      if (!existing || !existing.isFile()) err('TRANSFER_OFFSET_MISMATCH');
      if (existing.size !== offset) err('TRANSFER_OFFSET_MISMATCH');
    }
    // V-32.8: numeric flags with O_NOFOLLOW close the lstat->open TOCTOU:
    // a symlink planted after the gate above fails with ELOOP (mapped to
    // PATH_TYPE_NOT_SUPPORTED) instead of truncating outside the tree.
    // Fresh create-exclusive (!overwrite) adds O_EXCL so a file created
    // after the gate maps EEXIST -> DESTINATION_EXISTS atomically.
    const C = fsConstants;
    let fh;
    try {
      if (offset === 0) {
        const flags = overwrite
          ? C.O_WRONLY | C.O_CREAT | C.O_TRUNC | (C.O_NOFOLLOW || 0)
          : C.O_WRONLY | C.O_CREAT | C.O_EXCL | (C.O_NOFOLLOW || 0);
        fh = await openNoFollow(target, flags, overwrite ? 'w' : 'wx', { fsApi });
      } else {
        fh = await openNoFollow(target, C.O_RDWR | (C.O_NOFOLLOW || 0), 'r+', { fsApi });
      }
    } catch (writeError) {
      // Same P2-01 shadow fix as openNoFollow: `err` is the imported
      // MutationError thrower, never the caught exception. EEXIST maps to
      // DESTINATION_EXISTS only for a fresh create-exclusive (offset 0,
      // no overwrite) exactly as the pre-flight gate above; every other
      // failure rethrows untouched.
      if (/** @type {NodeJS.ErrnoException} */ (writeError).code === 'EEXIST' && offset === 0 && !overwrite)
        err('DESTINATION_EXISTS');
      throw writeError;
    }
    try {
      await fh.write(chunk, 0, chunk.length, offset);
      await fh.sync();
    } finally {
      await fh.close();
    }
    const after = await lstatOrNull(target, fsApi);
    const size = after ? after.size : offset + chunk.length;
    let sha256 = null;
    if (finalize) {
      const hash = crypto.createHash('sha256');
      const rh = await openNoFollow(target, C.O_RDONLY | (C.O_NOFOLLOW || 0), 'r', { fsApi });
      try {
        const slice = 1048576;
        for (let pos = 0; pos < size; pos += slice) {
          const want = Math.min(slice, size - pos);
          const tmp = Buffer.alloc(want);
          const got = await readExactHandle(rh, tmp, want, pos);
          hash.update(tmp.subarray(0, got));
        }
      } finally {
        await rh.close();
      }
      sha256 = hash.digest('hex');
      if (expectedSha && sha256.toLowerCase() !== expectedSha.toLowerCase()) {
        try {
          await fsApi.unlink(target);
        } catch {}
        err('TRANSFER_CHECKSUM_MISMATCH');
      }
    }
    return { path: target, offset, bytes: chunk.length, size, finalized: finalize, sha256, existed: Boolean(existing) };
  });
}

/**
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {boolean} [options.allowAll]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {any} [options.pathApi]
 * @param {string} [options.platform]
 * @param {{tool?: string, appRoot?: string|null, workspace?: string|null, pathApi?: any}|null} [options.treeBan]
 */
export async function fileDeleteMutation(payload, { roots, allowAll = false, fsApi = fs, pathApi = path, treeBan = null } = {}) {
  const recursive = optionalBoolean(payload, 'recursive', 'INVALID_RECURSIVE');
  const target = normalizeMutationPath(/** @type {string} */ (payload?.path), { pathApi });
  const options = { roots, allowAll, fsApi, pathApi, treeBan };
  await forbidConfiguredRootTarget(target, options);
  const auth = await authorizeLeafParent(target, options);
  rootTargetForbidden(target, auth.real_roots, pathApi);
  return serialized(normCase(target, pathApi), async () => {
    await forbidConfiguredRootTarget(target, options);
    const leafNow = await authorizeLeafParent(target, options);
    rootTargetForbidden(target, leafNow.real_roots, pathApi);
    const st = await lstatOrNull(target, fsApi);
    if (!st) err('FILE_NOT_FOUND');
    if (st.isDirectory() && !st.isSymbolicLink()) {
      if (!recursive) err('DIRECTORY_RECURSIVE_REQUIRED');
      await fsApi.rm(target, { recursive: true, force: false });
      return { path: target, type: 'directory', recursive: true, deleted: true };
    }
    if (!st.isFile() && !st.isSymbolicLink()) err('PATH_TYPE_NOT_SUPPORTED');
    await fsApi.unlink(target);
    return {
      path: target,
      type: st.isSymbolicLink() ? 'symlink' : 'file',
      recursive: false,
      deleted: true
    };
  });
}

/**
 * Privilege snapshot for EACCES/EPERM failures: install mode, identity and
 * elevation, evaluated live with node APIs only (same rules as the
 * privilege_status job). No live privileged-helper probe here — that needs
 * client runtime state; a non-elevated user-mode agent implies USER_INSTALL,
 * otherwise NOT_ELEVATED. Exported for tests.
 * @returns {{install_mode: string, username: string|null, uid: number|null, is_elevated: boolean, reason: string|null}}
 */
export function privilegeContext() {
  let username = null;
  let uid = null;
  try {
    const info = os.userInfo();
    if (typeof info.username === 'string') username = info.username;
    if (Number.isInteger(info.uid)) uid = info.uid;
  } catch {}
  if (uid === null && typeof process.getuid === 'function') {
    try {
      const g = process.getuid();
      if (Number.isInteger(g)) uid = g;
    } catch {}
  }
  const isElevated =
    process.platform === 'win32'
      ? ['system', 'administrator'].includes(String(username || '').toLowerCase())
      : uid === 0;
  const installMode = normalizeServiceMode(process.env.NC_SERVICE_MODE, 'NC_SERVICE_MODE');
  return {
    install_mode: installMode,
    username,
    uid,
    is_elevated: Boolean(isElevated),
    reason: isElevated ? null : installMode === 'user' ? 'USER_INSTALL' : 'NOT_ELEVATED'
  };
}

/**
 * Render permitted roots as actionable guidance (TOOL_DESIGN L8).
 * @param {Array<string>|unknown} roots
 */
function rootsHint(roots) {
  if (!Array.isArray(roots) || !roots.length) return null;
  const list = roots.map((r) => String(r)).filter(Boolean);
  if (!list.length) return null;
  return `Permitted roots: ${list.join(', ')} — reroute the path inside one of them.`;
}

/**
 * @param {unknown} error
 * @param {{configuredRoots?: Array<string>}} [context] allowlist known at
 * the call site; attached to denial payloads so the model can reroute
 * immediately (L8). Additive only — absent context changes nothing.
 */
export function normalizeMutationError(error, context = {}) {
  if (error instanceof MutationError) {
    /** @type {Record<string, unknown>} */
    const denied = { error: error.code, os_error_code: null };
    /** @type {Record<string, unknown>|null} */
    const details =
      error.details && typeof error.details === 'object' ? { ...error.details } : null;
    const contextRoots = Array.isArray(context?.configuredRoots) ? context.configuredRoots : null;
    if (details && !Array.isArray(details.configured_roots) && contextRoots)
      details.configured_roots = [...contextRoots];
    const effectiveDetails =
      details || (contextRoots && error.code === 'PATH_NOT_ALLOWED'
        ? { configured_roots: [...contextRoots] }
        : null);
    if (effectiveDetails) denied.details = effectiveDetails;
    if (error.code === 'PATH_NOT_ALLOWED') {
      const hint = rootsHint(
        (effectiveDetails && effectiveDetails.configured_roots) || contextRoots
      );
      const where =
        effectiveDetails && typeof effectiveDetails.path === 'string'
          ? ` '${effectiveDetails.path}'`
          : '';
      denied.reason =
        `Path${where} is outside the allowlisted filesystem roots.` +
        (hint ? ` ${hint}` : '');
    }
    if (error.code === 'EXPECTED_TEXT_AMBIGUOUS' && effectiveDetails) {
      const matches =
        typeof effectiveDetails.matches === 'number' ? effectiveDetails.matches : 'multiple';
      const what =
        typeof effectiveDetails.snippet === 'string' && effectiveDetails.snippet
          ? ` for ${JSON.stringify(effectiveDetails.snippet)}`
          : '';
      const where =
        typeof effectiveDetails.path === 'string' ? ` in ${effectiveDetails.path}` : '';
      const lines = Array.isArray(effectiveDetails.lines)
        ? effectiveDetails.lines.filter((n) => typeof n === 'number')
        : [];
      denied.reason =
        `EXPECTED_TEXT_AMBIGUOUS: ${matches} matches${what}${where}` +
        (lines.length > 0 ? ` (lines ${lines.join(', ')})` : '') +
        '. Provide more surrounding context or an occurrence index.';
    }
    return denied;
  }
  const osCode =
    error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
      ? error.code
      : null;
  /** @type {Record<string, string>} */
  const mapped = {
    EACCES: 'ACCESS_DENIED',
    EPERM: 'ACCESS_DENIED',
    ENOENT: 'FILE_NOT_FOUND',
    EEXIST: 'FILE_EXISTS',
    ENOTDIR: 'PATH_TYPE_NOT_SUPPORTED',
    EISDIR: 'PATH_TYPE_NOT_SUPPORTED',
    ENOTEMPTY: 'DIRECTORY_NOT_EMPTY',
    EROFS: 'READ_ONLY_FILESYSTEM',
    ENOSPC: 'NO_SPACE_LEFT',
    EBUSY: 'PATH_BUSY',
    ENAMETOOLONG: 'PATH_TOO_LONG',
    ELOOP: 'PATH_SYMLINK_LOOP',
    EMFILE: 'RESOURCE_LIMIT',
    ENFILE: 'RESOURCE_LIMIT',
    EXDEV: 'CROSS_DEVICE_MOVE_NOT_SUPPORTED'
  };
  const code = (osCode && mapped[osCode]) || 'MUTATION_IO_ERROR';
  // ACCESS_DENIED rides with privilege context so the model sees WHY the OS
  // refused (user install, no elevation) instead of a bare code. The reason
  // sentence flows into the hub mapper message via `reason`. Username stays
  // in the structured privilege object only (no PII duplication in text).
  // NOTE: reason vocabulary here is {USER_INSTALL, NOT_ELEVATED, null};
  // privilege_status reports HELPER_NOT_READY for the same underlying state
  // because it probes the helper live, which this leaf module cannot do.
  if (code !== 'ACCESS_DENIED') return { error: code, os_error_code: osCode };
  const privilege = privilegeContext();
  const who = privilege.uid === null ? 'unknown uid' : `uid ${privilege.uid}`;
  const contextRoots = Array.isArray(context?.configuredRoots) ? context.configuredRoots : null;
  const hint = rootsHint(contextRoots);
  return {
    error: code,
    os_error_code: osCode,
    privilege,
    reason:
      `${osCode} as ${who}: ${privilege.install_mode}-mode install without elevation` +
      (privilege.reason ? ` (${privilege.reason})` : '') +
      '; target needs privileges this agent lacks — retry under the home-rooted workspace or reinstall with privileged helper' +
      (hint ? ` ${hint}` : ''),
    ...(hint ? { details: { configured_roots: [...contextRoots] } } : {})
  };
}
/**
 * @param {unknown} result_payload @param {number} duration_ms
 */
function handlerOk(result_payload, duration_ms) {
  return {
    status: 'completed',
    exit_code: 0,
    stdout: '',
    stderr: '',
    error: null,
    duration_ms,
    result_payload
  };
}
/**
 * @param {unknown} error @param {number} duration_ms
 * @param {{configuredRoots?: Array<string>}} [context] denial-guidance roots (L8)
 */
function handlerFail(error, duration_ms, context = {}) {
  const normalized = /** @type {Record<string, unknown>} */ (
    normalizeMutationError(error, context)
  );
  const payload = normalized.os_error_code ? { os_error_code: normalized.os_error_code } : {};
  if (normalized.privilege) payload.privilege = normalized.privilege;
  // finishJob persists result_payload but drops top-level business keys;
  // the hub mapper reads this copy back into the public message.
  if (normalized.reason) payload.reason = normalized.reason;
  if (normalized.details) payload.details = normalized.details;
  return {
    status: 'failed',
    exit_code: null,
    stdout: '',
    stderr: '',
    error: normalized.error,
    ...(normalized.reason ? { reason: normalized.reason } : {}),
    duration_ms,
    result_payload: payload
  };
}
/**
 * @param {unknown} job @returns {Record<string, unknown>}
 */
function jobPayload(job) {
  const holder = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job);
  const p = holder?.request_payload ?? holder?.payload ?? {};
  if (!p || typeof p !== 'object' || Array.isArray(p)) err('INVALID_ARGUMENTS');
  return /** @type {Record<string, unknown>} */ (p);
}

/**
 * @param {string} tool @param {Record<string, unknown>} [payload] @returns {Array<string>}
 */
export function requiredMutationCapabilities(tool, payload = {}) {
  if (tool === 'file_write') {
    const v = optionalBoolean(payload, 'create_parents', 'INVALID_CREATE_PARENTS');
    return ['file_write', ...(v ? ['directory_manage'] : [])];
  }
  if (tool === 'file_mutate') {
    const action = String(payload?.action || '').toLowerCase();
    if (action === 'write') return requiredMutationCapabilities('file_write', payload);
    if (action === 'edit') return requiredMutationCapabilities('file_edit', payload);
    if (action === 'move') return requiredMutationCapabilities('file_move', payload);
    if (action === 'copy') return requiredMutationCapabilities('file_copy', payload);
    return ['file_write'];
  }
  // file_edit is a bounded write: same capability as file_write (mirrors the
  // central requiredCapabilitiesForOperation mapping). Missing branch used to
  // return [] which the policy gate rejects (deny-by-default on empty).
  if (tool === 'file_edit') return ['file_write'];
  if (tool === 'directory_create') {
    optionalBoolean(payload, 'parents', 'INVALID_PARENTS');
    return ['directory_manage'];
  }
  if (tool === 'file_move') {
    const v = optionalBoolean(payload, 'overwrite', 'INVALID_OVERWRITE');
    return ['file_move', ...(v ? ['file_delete'] : [])];
  }
  if (tool === 'file_copy') {
    const v = optionalBoolean(payload, 'overwrite', 'INVALID_OVERWRITE');
    return [...new Set(['file_move', ...(v ? ['file_delete'] : [])])].sort();
  }
  if (tool === 'transfer_write') {
    const v = optionalBoolean(payload, 'overwrite', 'INVALID_OVERWRITE');
    return [...new Set(['file_write', ...(v ? ['file_delete'] : [])])].sort();
  }
  if (tool === 'file_delete') {
    const v = optionalBoolean(payload, 'recursive', 'INVALID_RECURSIVE');
    return ['file_delete', ...(v ? ['directory_manage'] : [])];
  }
  return [];
}



/**
 * @param {(args: Record<string, unknown>) => unknown} policyGate
 * @param {string} tool
 * @param {Record<string, unknown>} payload
 * @param {Record<string, unknown>} job
 */
async function requirePolicy(policyGate, tool, payload, job) {
  if (typeof policyGate !== 'function') err('HOST_POLICY_NOT_READY');
  const identity = policyIdentityFromJob(job);
  if (!identity.policy_contract_version || !identity.policy_revision || !identity.policy_digest)
    err('HOST_POLICY_NOT_READY');
  const capabilities = requiredMutationCapabilities(tool, payload);
  let allowed;
  try {
    allowed = await policyGate({ tool, capabilities, policy_identity: identity });
  } catch {
    err('HOST_POLICY_NOT_READY');
  }
  if (allowed !== true) err('HOST_POLICY_DENIED');
}

/**
 * Line numbers (1-based) of the first few occurrences of needle in
 * content. Bounded: stops after max hits; the total count travels
 * separately so giant match sets stay cheap.
 * @param {string} content @param {string} needle @param {number} [max]
 */
function firstMatchLines(content, needle, max = 4) {
  const lines = [];
  let from = 0;
  while (lines.length < max) {
    const idx = content.indexOf(needle, from);
    if (idx < 0) break;
    let line = 1;
    for (let i = 0; i < idx; i++) if (content.charCodeAt(i) === 10) line++;
    lines.push(line);
    from = idx + needle.length;
    if (needle.length === 0) break;
  }
  return lines;
}

/**
 * EXPECTED_TEXT_AMBIGUOUS with actionable context: match count plus the
 * first line numbers, so the model can narrow the expected block instead
 * of guessing. The stable code is preserved exactly (message and details
 * both start from it); only guidance is added. Other codes are untouched.
 * @param {string} file normalized target path
 * @param {string} oldText the ambiguous expected block
 * @param {number} occurrences total match count (>1)
 * @param {string} content file content the matches were counted in
 * @param {{index: number, total: number}} batchInfo position inside edits[]
 */
function ambiguousEditError(file, oldText, occurrences, content, batchInfo) {
  const lines = firstMatchLines(content, oldText);
  const snippet = String(oldText).replace(/\s+/g, ' ').trim().slice(0, 80);
  const where = batchInfo && batchInfo.total > 1 ? ` [edit ${batchInfo.index + 1}/${batchInfo.total}]` : '';
  const merr = new MutationError('EXPECTED_TEXT_AMBIGUOUS', {
    path: file,
    matches: occurrences,
    lines,
    snippet
  });
  merr.message =
    `EXPECTED_TEXT_AMBIGUOUS: ${occurrences} matches for ${JSON.stringify(snippet)}` +
    ` in ${file} (lines ${lines.join(', ')})${where}.` +
    ' Provide more surrounding context or an occurrence index.';
  return merr;
}

/**
 * Surgical single-block edit with optimistic concurrency: the expected block
 * must occur exactly once, and optional sha/mtime guards must still hold.
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {boolean} [options.allowAll]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {any} [options.pathApi]
 * @param {{tool?: string, appRoot?: string|null, workspace?: string|null, pathApi?: any}|null} [options.treeBan]
 */
export async function fileEditMutation(payload, { roots, allowAll = false, fsApi = fs, pathApi = path, treeBan = null } = {}) {
  const normalized = normalizeMutationPath(/** @type {string} */ (payload?.path), { pathApi });
  return serialized(normCase(normalized, pathApi), async () => {
    const options = { roots, allowAll, fsApi, pathApi, treeBan };
    const leaf = await authorizeLeafParent(normalized, options);
    rootTargetForbidden(normalized, leaf.real_roots, pathApi);
    const st = await lstatOrNull(normalized, fsApi);
    if (!st) err('FILE_NOT_FOUND');
    if (st.isSymbolicLink()) err('PATH_SYMLINK_NOT_ALLOWED_FOR_WRITE');
    if (!st.isFile()) err('PATH_TYPE_NOT_SUPPORTED');
    const expectedSha = validateSha(payload?.expected_sha256, hasOwn(payload, 'expected_sha256'));
    const expectedMtime =
      payload?.expected_mtime === undefined ? null : String(payload.expected_mtime);
    if (expectedSha && (await shaFile(normalized, fsApi)) !== expectedSha)
      err('FILE_SHA256_MISMATCH');
    if (expectedMtime != null) {
      const actual = [String(st.mtimeMs), st.mtime?.toISOString?.()].filter(Boolean);
      if (!actual.includes(expectedMtime)) err('FILE_MTIME_MISMATCH');
    }
    const before = await fsApi.readFile(normalized, 'utf8');
    const bytesBefore = Buffer.byteLength(before);
    // Batch XOR single: `edits[]` runs atomically, legacy expected_text/
    // replacement_text keeps working unchanged. Mixed modes are rejected.
    const batch = Array.isArray(payload?.edits) ? payload.edits : null;
    let edits;
    if (batch) {
      if (batch.length === 0 || batch.length > 32) err('EDIT_BATCH_INVALID');
      if (payload?.expected_text !== undefined || payload?.replacement_text !== undefined)
        err('EDIT_MODE_CONFLICT');
      edits = batch.map((e) => {
        const o = String(e?.old_text ?? '');
        const n = String(e?.new_text ?? '');
        if (!o || o.length > 65536 || n.length > 65536) err('EDIT_BLOCK_INVALID');
        return { old_text: o, new_text: n };
      });
    } else {
      const expectedText = String(payload?.expected_text ?? '');
      const replacementText = String(payload?.replacement_text ?? '');
      if (!expectedText || expectedText.length > 65536 || replacementText.length > 65536)
        err('EDIT_BLOCK_INVALID');
      edits = [{ old_text: expectedText, new_text: replacementText }];
    }
    const dry = payload?.dry_run === true;
    // Simulate every edit in memory first: any failure throws BEFORE any
    // filesystem write, so partial mutation is impossible by construction.
    let after = before;
    for (const [index, e] of edits.entries()) {
      const occurrences = after.split(e.old_text).length - 1;
      if (occurrences === 0) err('EXPECTED_TEXT_NOT_FOUND');
      if (occurrences !== 1)
        throw ambiguousEditError(normalized, e.old_text, occurrences, after, {
          index,
          total: edits.length
        });
      after = after.replace(e.old_text, () => e.new_text);
    }
    const changed = after !== before;
    const diffed = changed ? unifiedDiff(before, after) : { diff: '', truncated: false };
    const out = {
      path: normalized,
      changed,
      edits_applied: edits.length,
      diff: diffed.diff,
      diff_truncated: diffed.truncated,
      bytes_before: bytesBefore,
      bytes_after: Buffer.byteLength(after)
    };
    if (dry || !changed) return out;
    const tmp = normalized + `.nc-edit-${Date.now()}-${Math.floor(Math.random() * 1e6)}.tmp`;
    try {
      await fsApi.writeFile(tmp, after, { encoding: 'utf8', flag: 'wx' });
      await fsyncTempFile(tmp, fsApi);
      await fsApi.rename(tmp, normalized);
    } catch (e) {
      // A failed edit must not leave its temp sibling behind: the next
      // attempt reuses a fresh unique name, but orphans accumulate.
      try {
        await fsApi.rm(tmp, { force: true });
      } catch {}
      throw e;
    }
    return out;
  });
}

/**
 * Bounded unified diff (Myers O(ND), capped). Returns '' when there is no
 * change or the input is too large for an in-memory diff.
 * @param {string} before @param {string} after
 */
export function unifiedDiff(before, after) {
  const split = (t) => {
    if (t === '') return [];
    const lines = String(t).split('\n');
    // Drop the phantom element a terminal newline produces.
    if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
    return lines;
  };
  const A = split(before);
  const B = split(after);
  if (A.length > 2000 || B.length > 2000) return { diff: '', truncated: true };
  const N = A.length;
  const M = B.length;
  const max = N + M;
  const size = 2 * max + 1;
  const offset = max;
  const v = new Array(size).fill(-1);
  v[offset + 1] = 0;
  const trace = [];
  let done = -1;
  const cap = Math.min(max, 2000);
  for (let d = 0; d <= cap; d++) {
    for (let k = -d; k <= d; k += 2) {
      let x;
      if (k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1])) {
        x = v[offset + k + 1];
      } else {
        x = v[offset + k - 1] + 1;
      }
      let y = x - k;
      while (x < N && y < M && A[x] === B[y]) {
        x++;
        y++;
      }
      v[offset + k] = x;
    }
    trace.push(v.slice());
    const kd = N - M;
    if (kd >= -d && kd <= d && v[offset + kd] >= N) {
      done = d;
      break;
    }
  }
  if (done < 0) return { diff: '', truncated: true };
  const ops = [];
  let x = N;
  let y = M;
  for (let d = done; d > 0; d--) {
    const prev = trace[d - 1];
    const k = x - y;
    let prevK;
    if (k === -d || (k !== d && prev[offset + k - 1] < prev[offset + k + 1])) {
      prevK = k + 1;
    } else {
      prevK = k - 1;
    }
    const xPrev = prev[offset + prevK];
    const yPrev = xPrev - prevK;
    while (x > xPrev && y > yPrev) {
      ops.push({ t: ' ', a: A[x - 1] });
      x--;
      y--;
    }
    if (x > xPrev) {
      ops.push({ t: '-', a: A[x - 1] });
      x--;
    } else if (y > yPrev) {
      ops.push({ t: '+', a: B[y - 1] });
      y--;
    }
  }
  ops.reverse();
  // Render hunks with 3 lines of context.
  const out = [];
  let i = 0;
  while (i < ops.length) {
    if (ops[i].t === ' ') {
      i++;
      continue;
    }
    let s = Math.max(0, i - 3);
    let e = i;
    while (e < ops.length && (ops[e].t !== ' ' || e - i < 7)) e++;
    e = Math.min(ops.length, e + 3);
    let aStart = 0;
    let bStart = 0;
    for (let j = 0; j < s; j++) {
      if (ops[j].t !== '+') aStart++;
      if (ops[j].t !== '-') bStart++;
    }
    let aCount = 0;
    let bCount = 0;
    for (let j = s; j < e; j++) {
      if (ops[j].t !== '+') aCount++;
      if (ops[j].t !== '-') bCount++;
    }
    out.push(`@@ -${aStart + 1},${aCount} +${bStart + 1},${bCount} @@`);
    for (let j = s; j < e; j++) out.push(ops[j].t + ops[j].a);
    i = e;
  }
  const text = out.join('\n');
  return text.length > 32768
    ? { diff: text.slice(0, 32768), truncated: true }
    : { diff: text, truncated: false };
}

/**
 * Consolidated file_mutate job handler (Phase 16.2).
 * Verifies optimistic concurrency (expected_sha256) before mutation,
 * then dispatches to file_write, file_edit, file_move, or file_copy.
 *
 * @param {unknown} job
 * @param {object} [options]
 * @param {Array<string>} [options.writeRoots]
 * @param {Array<string>} [options.roots]
 * @param {boolean} [options.allowAll]
 * @param {(args: Record<string, unknown>) => unknown} [options.policyGate]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {any} [options.pathApi]
 * @param {string} [options.platform]
 * @param {string|null} [options.appRoot]
 * @param {string|null} [options.workspace]
 * @param {{tool?: string, appRoot?: string|null, workspace?: string|null, pathApi?: any}|null} [options.treeBan]
 * @param {string|null} [options.cwd] pre-flight relative-resolution base
 * @param {string} [options.homedir] `~` expansion base
 */
export async function fileMutateJob(job, options = {}) {
  const started = Date.now();
  let contextRoots = [];
  try {
    const jobRecord =
      job && typeof job === 'object' ? /** @type {Record<string, unknown>} */ (job) : {};
    const holder = /** @type {{request_payload?: unknown, payload?: unknown}} */ (jobRecord);
    const p = /** @type {Record<string, unknown>} */ (
      (holder.request_payload && typeof holder.request_payload === 'object' && !Array.isArray(holder.request_payload)
        ? holder.request_payload
        : null) ||
      (holder.payload && typeof holder.payload === 'object' && !Array.isArray(holder.payload)
        ? holder.payload
        : null) ||
      jobRecord
    );
    if (!p || typeof p !== 'object' || Array.isArray(p)) err('INVALID_ARGUMENTS');

    const fsApi = options.fsApi || fs;
    const pathApi = options.pathApi || path;
    const platform = options.platform || process.platform;
    const targetPath =
      typeof p.path === 'string' ? p.path : typeof p.source === 'string' ? p.source : '';
    if (!targetPath) err('PATH_REQUIRED');

    // Optimistic concurrency guard (Phase 16.2):
    // Before applying the mutation, hash the file (SHA256).
    // If p.expected_sha256 is provided and does not match the actual hash, return a failure.
    if (p.expected_sha256 !== undefined && p.expected_sha256 !== null) {
      const expected = String(p.expected_sha256).toLowerCase().trim();
      let actualHash = null;
      try {
        const normalized = normalizeMutationPath(targetPath, { pathApi });
        actualHash = await shaFile(normalized, fsApi);
      } catch {
        actualHash = null;
      }
      if (!actualHash || actualHash.toLowerCase() !== expected) {
        return {
          status: 'failed',
          exit_code: null,
          stdout: '',
          stderr: '',
          error: 'EXPECTED_SHA256_MISMATCH',
          reason: 'FILE_CHANGED_SINCE_READ',
          duration_ms: Date.now() - started,
          result_payload: {
            error: 'EXPECTED_SHA256_MISMATCH',
            code: 'EXPECTED_SHA256_MISMATCH',
            reason: 'FILE_CHANGED_SINCE_READ',
            expected_sha256: expected,
            actual_sha256: actualHash
          }
        };
      }
    }

    const action = String(
      p.action || (p.edits || p.expected_text ? 'edit' : p.destination ? 'move' : 'write')
    ).toLowerCase();
    const toolName =
      action === 'write' ? 'file_write' :
      action === 'edit' ? 'file_edit' :
      action === 'move' ? 'file_move' :
      action === 'copy' ? 'file_copy' :
      'file_write';

    if (options.policyGate && jobRecord.policy_digest) {
      await requirePolicy(
        /** @type {(args: Record<string, unknown>) => unknown} */ (options.policyGate),
        toolName,
        p,
        jobRecord
      );
    }
    const appRoot = options.appRoot ?? null;
    const workspace = options.workspace ?? null;
    const treeBan = options.treeBan || { appRoot, workspace, pathApi };
    forbidAgentTreeWrite(toolName, mutationTargets(toolName, p), treeBan);

    const extra = policyExtraRoots(jobRecord);
    const writeRoots = options.writeRoots || options.roots || [];
    const roots = [...writeRoots, ...(extra?.write || [])];
    const allowAll = options.allowAll || extra?.allowAll === true;
    const ban = { appRoot, workspace, tool: toolName };
    // Production entry points resolve bare relative paths against the agent
    // cwd (L1); direct low-level calls keep the strict PATH_NOT_ABSOLUTE
    // gate (pinned by phase3 suites), as does the whole read path (nc-001).
    const cwd = options.cwd === undefined ? process.cwd() : options.cwd;
    contextRoots = [...roots];
    const mutOpts = { roots, allowAll, fsApi, pathApi, platform, treeBan: ban, cwd, homedir: options.homedir };

    let res;
    if (action === 'write') {
      res = await fileWriteMutation(p, mutOpts);
    } else if (action === 'edit') {
      res = await fileEditMutation(p, mutOpts);
    } else if (action === 'move') {
      res = await fileMoveMutation(p, mutOpts);
    } else if (action === 'copy') {
      res = await fileCopyMutation(p, mutOpts);
    } else {
      err('INVALID_ACTION');
    }
    return handlerOk(res, Date.now() - started);
  } catch (e) {
    return handlerFail(e, Date.now() - started, { configuredRoots: contextRoots });
  }
}

/**
 * @param {object} [options]
 * @param {Array<string>} [options.writeRoots]
 * @param {(args: Record<string, unknown>) => unknown} [options.policyGate]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {any} [options.pathApi]
 * @param {string} [options.platform]
 * @param {string|null} [options.appRoot] agent tree root for the write ban (null disables)
 * @param {string|null} [options.workspace] writable sanctuary inside the tree
 * @param {string|null} [options.cwd] pre-flight relative-resolution base
 * @param {string} [options.homedir] `~` expansion base
 */

export function makeMutationHandlers({
  writeRoots = [],
  policyGate,
  fsApi = fs,
  pathApi = path,
  platform = process.platform,
  appRoot = null,
  workspace = null,
  cwd = process.cwd(),
  homedir = undefined
} = {}) {
  const options = { roots: writeRoots, fsApi, pathApi, platform, cwd, homedir };
  const treeBan = { appRoot, workspace, pathApi };
  /** @type {(tool: string, fn: (payload: Record<string, unknown>, options: object) => unknown) => (job: unknown) => Promise<unknown>} */
  const wrap = (tool, fn) => async (job) => {
    const started = Date.now();
    let contextRoots = [];
    try {
      const payload = jobPayload(job);
      await requirePolicy(
        /** @type {(args: Record<string, unknown>) => unknown} */ (policyGate),
        tool,
        payload,
        /** @type {Record<string, unknown>} */ (job)
      );
      forbidAgentTreeWrite(tool, mutationTargets(tool, payload), treeBan);
      const extra = policyExtraRoots(job);
      const roots = [...writeRoots, ...extra.write];
      contextRoots = [...roots];
      const allowAll = extra.allowAll === true;
      // pathApi intentionally omitted: authorizeMutationPath enforces the tree
      // ban with the OUTER pathApi (same object); a pathApi key inside the
      // treeBan object would be inert there (only appRoot/workspace/tool are
      // read). The pre-check above uses treeBan (which carries pathApi as
      // call options, not as ban data).
      const ban = { appRoot, workspace, tool };
      return handlerOk(await fn(payload, { ...options, roots, allowAll, treeBan: ban }), Date.now() - started);
    } catch (e) {
      return handlerFail(e, Date.now() - started, { configuredRoots: contextRoots });
    }
  };
  return {
    file_write: wrap('file_write', fileWriteMutation),
    file_edit: wrap('file_edit', fileEditMutation),
    directory_create: wrap('directory_create', directoryCreateMutation),
    file_move: wrap('file_move', fileMoveMutation),
    file_copy: wrap('file_copy', fileCopyMutation),
    transfer_write: wrap('transfer_write', transferWriteMutation),
    file_delete: wrap('file_delete', fileDeleteMutation),
    file_mutate: (job) =>
      fileMutateJob(job, {
        writeRoots,
        policyGate,
        fsApi,
        pathApi,
        platform,
        appRoot,
        workspace,
        treeBan
      })
  };
}
export { normalizeMutationPath, resolveTargetPath, authorizeMutationPath, forbidAgentTreeWrite, mutationTargets, MutationError } from './path-auth.mjs';
