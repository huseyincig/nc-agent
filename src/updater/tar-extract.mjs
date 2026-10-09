import fs from 'node:fs/promises';
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
 * @param {Buffer} gzipBytes
 * @param {string} destination
 */
export async function extractReleaseArchive(gzipBytes, destination) {
  const tar = zlib.gunzipSync(gzipBytes, { maxOutputLength: 128 * 1024 * 1024 });
  let offset = 0,
    entries = 0;
  await fs.mkdir(destination, { recursive: true });
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
    offset += 512;
    if (!Number.isSafeInteger(size) || size < 0 || offset + size > tar.length)
      throw new Error('UPDATE_TAR_TRUNCATED');
    if (type === '5') await fs.mkdir(target, { recursive: true });
    else {
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, tar.subarray(offset, offset + size), { mode: 0o640 });
    }
    entries++;
    if (entries > 20000) throw new Error('UPDATE_TAR_TOO_MANY_ENTRIES');
    offset += Math.ceil(size / 512) * 512;
  }
  return entries;
}
