import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

/**
 * @param {Buffer} buf
 * @param {number} start
 * @param {number} length
 */
function tarString(buf, start, length) {
  return buf
    .subarray(start, start + length)
    .toString('utf8')
    .replace(/\0.*$/s, '')
    .trim();
}
/**
 * @param {Buffer} buf
 * @param {number} start
 * @param {number} length
 */
function tarOctal(buf, start, length) {
  const raw = buf.subarray(start, start + length);
  // POSIX base-256 sizes (top bit set) exceed the 8GB-1 octal range our
  // releases never approach: reject explicitly instead of parseInt-ing
  // garbage into NaN (silent empty file + early stop: every NaN comparison
  // is false) or a truncated octal prefix (wrong size, wrong content).
  // Fail closed on malformed size fields.
  if (raw.length && raw[0] & 0x80) throw new Error('UPDATE_TAR_SIZE_ENCODING');
  const v = tarString(buf, start, length).replace(/\s/g, '');
  if (!v) return 0;
  if (!/^[0-7]+$/.test(v)) throw new Error('UPDATE_TAR_SIZE_INVALID');
  return parseInt(v, 8);
}
/**
 * @param {string} target
 * @param {number} numericFlags
 * @param {string} fallbackFlag
 * @param {number} [mode]
 * @param {typeof import('node:fs/promises')} [fsApi]
 */
async function openNoFollow(target, numericFlags, fallbackFlag, mode = 0o640, fsApi = fs) {
  try {
    return await fsApi.open(target, numericFlags, mode);
  } catch (openError) {
    const code = /** @type {NodeJS.ErrnoException} */ (openError)?.code;
    if (code === 'ELOOP' || code === 'EMLINK') {
      throw new Error('UPDATE_TAR_PATH_ESCAPE', { cause: openError });
    }
    if ((code === 'EINVAL' || code === 'ENOSYS' || code === 'EOPNOTSUPP') && fsConstants.O_NOFOLLOW) {
      // L01b-10: the fallback drops O_NOFOLLOW, so re-lstat and refuse
      // symlinks before retrying — otherwise a link planted after the
      // pre-check sails through the fallback open.
      try {
        const rst = await fsApi.lstat(target);
        if (rst && rst.isSymbolicLink()) throw new Error('UPDATE_TAR_PATH_ESCAPE', { cause: openError });
      } catch (lstatError) {
        const lcode = /** @type {NodeJS.ErrnoException} */ (lstatError)?.code;
        if (lcode === 'ELOOP' || lcode === 'EMLINK')
          throw new Error('UPDATE_TAR_PATH_ESCAPE', { cause: lstatError });
        if (lstatError instanceof Error && lstatError.message === 'UPDATE_TAR_PATH_ESCAPE')
          throw lstatError;
        // ENOENT (fresh file) and other lstat failures: fall through to
        // the fallback open, which surfaces the authoritative verdict.
      }
      return await fsApi.open(target, fallbackFlag, mode);
    }
    throw openError;
  }
}

/**
 * Re-walk, re-lstat and verify a directory component against symlink, drift, and type.
 * Opens with O_DIRECTORY | O_NOFOLLOW where supported (RA-03-09).
 * @param {string} dirPath
 * @param {string} expectedReal
 * @param {string} realDestRoot
 * @param {typeof import('node:fs/promises')} [fsApi]
 */
async function verifyDirectoryComponent(dirPath, expectedReal, realDestRoot, fsApi = fs) {
  let st;
  try {
    st = await fsApi.lstat(dirPath);
  } catch (e) {
    const code = /** @type {NodeJS.ErrnoException} */ (e)?.code;
    if (code === 'ELOOP' || code === 'EMLINK') {
      throw new Error('UPDATE_TAR_PATH_ESCAPE', { cause: e });
    }
    throw e;
  }
  if (!st || st.isSymbolicLink() || !st.isDirectory()) {
    throw new Error('UPDATE_TAR_PATH_ESCAPE');
  }
  let realDir;
  try {
    realDir = await fsApi.realpath(dirPath);
  } catch (err) {
    throw new Error('UPDATE_TAR_PATH_ESCAPE', { cause: err });
  }
  if (realDir !== expectedReal) {
    throw new Error('UPDATE_TAR_PATH_ESCAPE');
  }
  const realDirWithSep = realDir.endsWith(path.sep) ? realDir : realDir + path.sep;
  if (!realDirWithSep.startsWith(realDestRoot)) {
    throw new Error('UPDATE_TAR_PATH_ESCAPE');
  }
  if (fsConstants.O_DIRECTORY || fsConstants.O_NOFOLLOW) {
    const dirFlags =
      (fsConstants.O_RDONLY || 0) |
      (fsConstants.O_DIRECTORY || 0) |
      (fsConstants.O_NOFOLLOW || 0);
    try {
      const dh = await fsApi.open(dirPath, dirFlags);
      await dh.close();
    } catch (openErr) {
      const code = /** @type {NodeJS.ErrnoException} */ (openErr)?.code;
      if (code === 'ELOOP' || code === 'EMLINK' || code === 'ENOTDIR') {
        throw new Error('UPDATE_TAR_PATH_ESCAPE', { cause: openErr });
      }
      if (
        (code === 'EINVAL' || code === 'ENOSYS' || code === 'EOPNOTSUPP') &&
        (process.platform === 'win32' || !fsConstants.O_DIRECTORY)
      ) {
        // Platform unsupported flag fallback
      } else {
        throw new Error('UPDATE_TAR_PATH_ESCAPE', { cause: openErr });
      }
    }
  }
}
/**
 * @param {Buffer} gzipBytes
 * @param {string} destination
 * @param {object} [options]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 */
export async function extractReleaseArchive(gzipBytes, destination, { fsApi = fs } = {}) {
  const tar = zlib.gunzipSync(gzipBytes, { maxOutputLength: 128 * 1024 * 1024 });
  let offset = 0,
    entries = 0;

  // Destination validation (NC-AUD-008): fail closed if destination already exists as a symlink.
  let preStat = null;
  try {
    preStat = await fsApi.lstat(destination);
  } catch (err) {
    if (/** @type {NodeJS.ErrnoException} */ (err)?.code !== 'ENOENT') throw err;
  }
  if (preStat && (preStat.isSymbolicLink() || !preStat.isDirectory())) {
    throw new Error('UPDATE_TAR_PATH_ESCAPE');
  }

  await fsApi.mkdir(destination, { recursive: true });
  const destStat = await fsApi.lstat(destination);
  if (destStat.isSymbolicLink() || !destStat.isDirectory()) {
    throw new Error('UPDATE_TAR_PATH_ESCAPE');
  }
  const realDest = await fsApi.realpath(destination);
  const realDestRoot = realDest.endsWith(path.sep) ? realDest : realDest + path.sep;

  while (offset + 512 <= tar.length) {
    const h = tar.subarray(offset, offset + 512);
    if (h.every((x) => x === 0)) break;
    const name = tarString(h, 0, 100),
      prefix = tarString(h, 345, 155),
      type = String.fromCharCode(h[156] || 48),
      size = tarOctal(h, 124, 12);
    const rel = (prefix ? prefix + '/' : '') + name;
    if (!rel) throw new Error('UPDATE_TAR_EMPTY_PATH');
    const normalized = path.posix.normalize(rel.replace(/\\/g, '/'));
    if (
      normalized.startsWith('/') ||
      normalized === '..' ||
      normalized.startsWith('../') ||
      normalized.includes('/../')
    )
      throw new Error('UPDATE_TAR_PATH_ESCAPE');
    if (!['0', '\0', '5'].includes(type)) throw new Error('UPDATE_TAR_UNSAFE_TYPE:' + type);
    const target = path.join(destination, ...normalized.split('/'));
    const destRoot = path.resolve(destination) + path.sep;
    if (!(path.resolve(target) + (type === '5' ? path.sep : '')).startsWith(destRoot))
      throw new Error('UPDATE_TAR_PATH_ESCAPE');

    // RA-03-09: Top-down verification and creation of every directory component
    const parts = normalized.split('/').filter(Boolean);
    await verifyDirectoryComponent(destination, realDest, realDestRoot, fsApi);

    const dirCount = type === '5' ? parts.length : parts.length - 1;
    for (let i = 0; i < dirCount; i++) {
      const check = path.join(destination, ...parts.slice(0, i + 1));
      const expectedReal = path.resolve(realDest, ...parts.slice(0, i + 1));
      const parentDir = path.dirname(check);
      const expectedParentReal = path.resolve(realDest, ...parts.slice(0, i));
      await verifyDirectoryComponent(parentDir, expectedParentReal, realDestRoot, fsApi);
      try {
        await fsApi.mkdir(check);
      } catch (mkdirErr) {
        const code = /** @type {NodeJS.ErrnoException} */ (mkdirErr)?.code;
        if (code !== 'EEXIST') {
          throw new Error('UPDATE_TAR_PATH_ESCAPE', { cause: mkdirErr });
        }
      }
      await verifyDirectoryComponent(check, expectedReal, realDestRoot, fsApi);
    }

    offset += 512;
    if (!Number.isSafeInteger(size) || size < 0 || offset + size > tar.length)
      throw new Error('UPDATE_TAR_TRUNCATED');

    if (type !== '5') {
      // Re-walk and re-lstat EVERY path component (including parent chain) immediately before opening target
      await verifyDirectoryComponent(destination, realDest, realDestRoot, fsApi);
      for (let i = 0; i < parts.length - 1; i++) {
        const walk = path.join(destination, ...parts.slice(0, i + 1));
        const expectedWalk = path.resolve(realDest, ...parts.slice(0, i + 1));
        await verifyDirectoryComponent(walk, expectedWalk, realDestRoot, fsApi);
      }

      let targetStat = null;
      try {
        targetStat = await fsApi.lstat(target);
      } catch (e) {
        const code = /** @type {NodeJS.ErrnoException} */ (e)?.code;
        if (code === 'ELOOP' || code === 'EMLINK') {
          throw new Error('UPDATE_TAR_PATH_ESCAPE', { cause: e });
        }
        if (code !== 'ENOENT') throw e;
      }
      if (targetStat && (targetStat.isSymbolicLink() || !targetStat.isFile())) {
        throw new Error('UPDATE_TAR_PATH_ESCAPE');
      }

      const flags =
        fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_TRUNC |
        (fsConstants.O_NOFOLLOW || 0);
      const handle = await openNoFollow(target, flags, 'w', 0o640, fsApi);
      try {
        await handle.writeFile(tar.subarray(offset, offset + size));
      } finally {
        await handle.close();
      }
    }

    entries++;
    if (entries > 20000) throw new Error('UPDATE_TAR_TOO_MANY_ENTRIES');
    offset += Math.ceil(size / 512) * 512;
  }
  return entries;
}
