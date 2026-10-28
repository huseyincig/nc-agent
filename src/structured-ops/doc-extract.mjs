/**
 * doc-extract: zero-dependency document text extraction (agent side).
 *
 * Supported formats (read-only):
 * - DOCX (WordprocessingML): main document + headers/footers/footnotes/
 *   endnotes/comments, located via `[Content_Types].xml` relationship
 *   discovery with conventional-path fallback (never blind path guessing).
 * - XLSX (SpreadsheetML): shared-string table + per-sheet grid rendered as
 *   tab-separated rows; sheets discovered via workbook + workbook rels with
 *   conventional-path fallback.
 * - PDF (text-based subset): literal/hex strings inside BT/ET content blocks
 *   from uncompressed and FlateDecode streams (built-in `node:zlib` only).
 *
 * Honesty rules (never silently return garbage):
 * - Encrypted PDFs, unknown containers (e.g. PPTX) and unsupported
 *   compression methods fail with DOC_UNSUPPORTED_FORMAT.
 * - Corrupt archives, undecodable streams and zero-text results fail with
 *   DOC_PARSE_FAILED (callers must surface the failure, not an empty page).
 * - Oversized inputs fail with DOC_TOO_LARGE before any parsing.
 *
 * DoS bounds: max file size 8 MiB, max central-directory entries 2000,
 * max total inflated bytes 32 MiB, max output 65536 chars, max sheets 100,
 * max PDF streams scanned 500. All scanning loops are indexOf-driven
 * (no backtracking regexes over untrusted input).
 */
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import zlib from 'node:zlib';
import { authorizeMutationPath } from '../filesystem/path-auth.mjs';

export const MAX_DOC_BYTES = 8 * 1024 * 1024;
export const MAX_TEXT_CHARS = 65536;
export const MAX_ZIP_ENTRIES = 2000;
export const MAX_INFLATED_BYTES = 32 * 1024 * 1024;
export const MAX_SHEETS = 100;
export const MAX_SHEET_CELLS = 20000;
export const MAX_PDF_STREAMS = 500;
export const DOC_FORMATS = Object.freeze(['docx', 'xlsx', 'pdf']);

/**
 * Bounded whole-file read with the same pre-open regular-file guard as
 * readBounded (a planted FIFO inside the workspace must not hang the job).
 * @param {string} file realpath-resolved absolute path
 * @param {typeof fs} [fsApi]
 * @returns {Promise<{bytes: number, buffer: Buffer}>}
 */
export async function readDocFile(file, fsApi = fs) {
  // Recheck the resolved spelling immediately before open, then read only the
  // verified handle. No-follow alone cannot protect mutable parent directories.
  await authorizeMutationPath(file, { allowAll: true, fsApi });
  const fh = await fsApi.open(file,
    fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK || 0) | (fsConstants.O_NOFOLLOW || 0));
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new Error('PATH_TYPE_NOT_SUPPORTED');
    if (st.size > MAX_DOC_BYTES) throw new Error('DOC_TOO_LARGE');
    if (st.size < 1) throw new Error('DOC_PARSE_FAILED');
    const buf = Buffer.alloc(Math.max(0, Math.trunc(st.size)));
    let read = 0;
    while (read < buf.length) {
      const { bytesRead } = await fh.read(buf, read, buf.length - read, read);
      if (!bytesRead) break;
      read += bytesRead;
    }
    return { bytes: st.size, buffer: buf.subarray(0, read) };
  } finally {
    await fh.close();
  }
}

/**
 * @param {string} name
 */
function normZipName(name) {
  return String(name || '').replace(/\\/g, '/').replace(/^\//, '');
}

/**
 * Minimal ZIP central-directory reader. Only entries the caller asks for
 * are inflated, so a hostile archive cannot force full decompression.
 * @param {Buffer} buf whole-file bytes (already size-bounded by readDocFile)
 * @returns {Map<string, {method: number, compSize: number, uncompSize: number, offset: number}>}
 */
export function parseZipEntries(buf) {
  const EOCD_SIG = 0x06054b50;
  const CD_SIG = 0x02014b50;
  const LOCAL_SIG = 0x04034b50;
  // EOCD lives in the last 64 KiB + 22 bytes (comment may follow it).
  const tailLen = Math.min(buf.length, 65536 + 22);
  let eocd = -1;
  for (let i = buf.length - 22; i >= buf.length - tailLen; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('DOC_PARSE_FAILED');
  const count = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (count > MAX_ZIP_ENTRIES) throw new Error('DOC_PARSE_FAILED');
  /** @type {Map<string, {method: number, compSize: number, uncompSize: number, offset: number}>} */
  const entries = new Map();
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== CD_SIG) throw new Error('DOC_PARSE_FAILED');
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const uncompSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const offset = buf.readUInt32LE(p + 42);
    if (p + 46 + nameLen > buf.length) throw new Error('DOC_PARSE_FAILED');
    const name = normZipName(buf.toString('utf8', p + 46, p + 46 + nameLen));
    if (name && !name.endsWith('/')) {
      entries.set(name, { method, compSize, uncompSize, offset });
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  // Stash the local-header signature check target count for inflateZipEntry.
  void LOCAL_SIG;
  return entries;
}

/**
 * Inflate a single entry with zip-bomb guards. Data descriptors
 * (streaming flag) are rejected: Office writers always fill sizes.
 * @param {Buffer} buf
 * @param {Map<string, {method: number, compSize: number, uncompSize: number, offset: number}>} entries
 * @param {string} name
 * @param {{value: number}} [budget]
 */
export function inflateZipEntry(buf, entries, name, budget = { value: 0 }) {
  const e = entries.get(normZipName(name));
  if (!e) throw new Error('DOC_PARSE_FAILED');
  if (e.uncompSize > MAX_INFLATED_BYTES) throw new Error('DOC_PARSE_FAILED');
  if (budget.value + e.uncompSize > MAX_INFLATED_BYTES)
    throw new Error('DOC_PARSE_FAILED');
  if (e.offset + 30 > buf.length || buf.readUInt32LE(e.offset) !== 0x04034b50)
    throw new Error('DOC_PARSE_FAILED');
  const flags = buf.readUInt16LE(e.offset + 6);
  if ((flags & 0x08) !== 0) throw new Error('DOC_PARSE_FAILED');
  const localNameLen = buf.readUInt16LE(e.offset + 26);
  const localExtraLen = buf.readUInt16LE(e.offset + 28);
  const dataStart = e.offset + 30 + localNameLen + localExtraLen;
  if (dataStart + e.compSize > buf.length) throw new Error('DOC_PARSE_FAILED');
  const raw = buf.subarray(dataStart, dataStart + e.compSize);
  const remaining = MAX_INFLATED_BYTES - budget.value;
  let out;
  if (e.method === 0) {
    if (raw.length > remaining) throw new Error('DOC_PARSE_FAILED');
    out = Buffer.from(raw);
  } else if (e.method === 8) {
    if (remaining <= 0) throw new Error('DOC_PARSE_FAILED');
    try {
      out = zlib.inflateRawSync(raw, { maxOutputLength: remaining });
    } catch {
      throw new Error('DOC_PARSE_FAILED');
    }
  } else {
    throw new Error('DOC_UNSUPPORTED_FORMAT');
  }
  if (out.length !== e.uncompSize && e.method !== 0) {
    // Size mismatch on deflated data signals a malformed entry; stored
    // entries are compared loosely (some writers disagree by trailing bytes).
    throw new Error('DOC_PARSE_FAILED');
  }
  if (out.length > remaining) throw new Error('DOC_PARSE_FAILED');
  budget.value += out.length;
  return out;
}

/**
 * @param {string} xml
 */
function unescapeXml(xml) {
  return String(xml)
    .replace(/&(lt|gt|amp|quot|apos);/g, (/** @type {string} */ _m, e) =>
      e === 'lt' ? '<' : e === 'gt' ? '>' : e === 'amp' ? '&' : e === 'quot' ? '"' : "'"
    )
    .replace(/&#(\d+);/g, (/** @type {string} */ _m, d) => {
      const n = Number(d);
      return Number.isFinite(n) && n > 0 && n < 0x10ffff ? String.fromCodePoint(n) : '';
    })
    .replace(/&#x([0-9a-fA-F]+);/g, (/** @type {string} */ _m, h) => {
      const n = parseInt(h, 16);
      return Number.isFinite(n) && n > 0 && n < 0x10ffff ? String.fromCodePoint(n) : '';
    });
}

/**
 * Collect <w:t> runs from WordprocessingML. Tabs/breaks become whitespace
 * so words on both sides never fuse.
 * @param {string} xml
 */
function wordTextRuns(xml) {
  const parts = [];
  const tags = /<w:(t|tab|br)(?=[\s/>])/g;
  let tag;
  while ((tag = tags.exec(xml)) !== null) {
    const start = xml.indexOf('>', tags.lastIndex);
    if (start < 0) break;
    if (tag[1] === 't') {
      if (xml[start - 1] === '/') {
        tags.lastIndex = start + 1;
        continue;
      }
      const end = xml.indexOf('</w:t>', start);
      if (end < 0) break;
      parts.push(unescapeXml(xml.slice(start + 1, end)));
      tags.lastIndex = end + 6;
    } else {
      parts.push(tag[1] === 'tab' ? '\t' : '\n');
      tags.lastIndex = start + 1;
    }
  }
  return parts.join('');
}

/**
 * Paragraph-aware join: split on </w:p> so paragraph boundaries survive
 * as newlines even when the XML carries no explicit breaks.
 * @param {string} xml
 */
function wordParagraphs(xml) {
  return String(xml)
    .split(/<\/w:p\s*>/)
    .map((p) => wordTextRuns(p).replace(/[ \t]+/g, ' ').trim())
    .filter((p) => p.length > 0)
    .join('\n');
}

/**
 * Relationship-driven main-document discovery: prefer the
 * OfficeDocument relationship target, fall back to content-type override,
 * fall back to the conventional path.
 * @param {Map<string, {method: number, compSize: number, uncompSize: number, offset: number}>} entries
 * @param {Buffer} buf
 * @param {{value: number}} budget
 */
function discoverWordDocument(entries, buf, budget) {
  try {
    if (entries.has('_rels/.rels')) {
      const rels = inflateZipEntry(buf, entries, '_rels/.rels', budget).toString(
        'utf8'
      );
      const m = rels.match(
        /<Relationship[^>]*Type="[^"]*officeDocument"[^>]*Target="([^"]+)"/
      );
      if (m) {
        const target = normZipName(m[1]);
        if (entries.has(target)) return target;
      }
    }
  } catch {
    // Fall through to content-type discovery.
  }
  try {
    if (entries.has('[Content_Types].xml')) {
      const ct = inflateZipEntry(buf, entries, '[Content_Types].xml', budget).toString('utf8');
      const m = ct.match(
        /<Override[^>]*ContentType="[^"]*wordprocessingml\.document\.main[^"]*"[^>]*PartName="([^"]+)"/
      );
      if (m) {
        const target = normZipName(m[1]);
        if (entries.has(target)) return target;
      }
    }
  } catch {
    // Fall through to the conventional path.
  }
  if (entries.has('word/document.xml')) return 'word/document.xml';
  throw new Error('DOC_UNSUPPORTED_FORMAT');
}

/**
 * @param {Buffer} buf
 * @param {{maxChars?: number}} [options]
 */
export function extractDocx(buf, { maxChars = MAX_TEXT_CHARS } = {}) {
  const budget = { value: 0 };
  const entries = parseZipEntries(buf);
  const main = discoverWordDocument(entries, buf, budget);
  const dir = main.includes('/') ? main.slice(0, main.lastIndexOf('/') + 1) : '';
  const parts = [main];
  // Supplementary narrative parts share the <w:t> shape; headers/footers
  // first, notes/comments after the body.
  for (const [name] of entries) {
    if (name === main) continue;
    if (
      /^word\/(header\d*|footer\d*)\.xml$/.test(name) ||
      /word\/(footnotes|endnotes|comments)\.xml$/.test(name) ||
      (dir && name.startsWith(dir) && /header|footer/.test(name) && name.endsWith('.xml'))
    ) {
      parts.push(name);
    }
  }
  const texts = [];
  let truncated = false;
  for (const name of parts.slice(0, 32)) {
    let xml;
    try {
      xml = inflateZipEntry(buf, entries, name, budget).toString('utf8');
    } catch (e) {
      if (name === main) throw e;
      continue;
    }
    texts.push(wordParagraphs(xml));
    if (texts.join('\n\n').length >= maxChars) {
      truncated = true;
      break;
    }
  }
  const text = texts
    .join('\n\n')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
    .slice(0, maxChars);
  if (!text) throw new Error('DOC_PARSE_FAILED');
  return { format: 'docx', text, truncated: truncated || texts.join('\n\n').length > maxChars };
}

/**
 * @param {string} xml
 */
function parseSharedStrings(xml) {
  const out = [];
  let i = 0;
  while (i < xml.length) {
    const si = xml.indexOf('<si', i);
    if (si < 0) break;
    const end = xml.indexOf('</si>', si);
    if (end < 0) break;
    const body = xml.slice(si, end);
    const runs = [];
    let j = 0;
    while (j < body.length) {
      const t = body.indexOf('<t', j);
      if (t < 0) break;
      const start = body.indexOf('>', t);
      const close = body.indexOf('</t>', start);
      if (start < 0 || close < 0) break;
      runs.push(unescapeXml(body.slice(start + 1, close)));
      j = close + 4;
    }
    out.push(runs.join(''));
    i = end + 5;
    if (out.length > 200000) break;
  }
  return out;
}

/**
 * Render one worksheet grid as tab-separated rows. Shared-string cells
 * (t="s") resolve through the table; inline strings, numbers and booleans
 * render literally. Excel date serials stay numeric (flagged in warnings).
 * @param {string} xml
 * @param {Array<string>} shared
 * @param {number} maxChars
 */
function sheetToText(xml, shared, maxChars) {
  const rows = [];
  let i = 0;
  let cells = 0;
  while (i < xml.length && cells < MAX_SHEET_CELLS) {
    const rowStart = xml.indexOf('<row', i);
    if (rowStart < 0) break;
    const rowEnd = xml.indexOf('</row>', rowStart);
    if (rowEnd < 0) break;
    const body = xml.slice(rowStart, rowEnd);
    const cellsOut = [];
    let j = 0;
    while (j < body.length && cells < MAX_SHEET_CELLS) {
      const c = body.indexOf('<c ', j);
      const c2 = body.indexOf('<c>', j);
      const cs = [c, c2].filter((x) => x >= 0).sort((a, b) => a - b)[0];
      if (cs === undefined) break;
      const tagEnd = body.indexOf('>', cs);
      const cEnd = body.indexOf('</c>', tagEnd);
      if (tagEnd < 0 || cEnd < 0) break;
      const tag = body.slice(cs, tagEnd + 1);
      const inner = body.slice(tagEnd + 1, cEnd);
      const type = /t="([^"]*)"/.exec(tag)?.[1] || '';
      let value = '';
      if (type === 'inlineStr') {
        const t = inner.indexOf('<t');
        if (t >= 0) {
          const s = inner.indexOf('>', t);
          const e = inner.indexOf('</t>', s);
          if (s >= 0 && e >= 0) value = unescapeXml(inner.slice(s + 1, e));
        }
      } else {
        const v = inner.indexOf('<v');
        if (v >= 0) {
          const s = inner.indexOf('>', v);
          const e = inner.indexOf('</v>', s);
          if (s >= 0 && e >= 0) {
            const raw = inner.slice(s + 1, e).trim();
            if (type === 's') {
              const idx = Number(raw);
              value =
                Number.isInteger(idx) && idx >= 0 && idx < shared.length
                  ? (shared[idx] ?? '')
                  : '';
            } else if (type === 'b') {
              value = raw === '1' ? 'TRUE' : raw === '0' ? 'FALSE' : raw;
            } else {
              value = raw;
            }
          }
        }
      }
      cellsOut.push(value);
      cells++;
      j = cEnd + 4;
    }
    while (cellsOut.length > 0 && cellsOut[cellsOut.length - 1] === '') cellsOut.pop();
    if (cellsOut.length > 0) rows.push(cellsOut.join('\t'));
    i = rowEnd + 6;
    if (rows.join('\n').length >= maxChars) break;
  }
  return rows.join('\n');
}

/**
 * @param {Map<string, {method: number, compSize: number, uncompSize: number, offset: number}>} entries
 * @param {Buffer} buf
 * @param {{value: number}} budget
 */
function discoverSheets(entries, buf, budget) {
  const found = [];
  try {
    const wbName = entries.has('xl/workbook.xml') ? 'xl/workbook.xml' : null;
    if (wbName) {
      const wb = inflateZipEntry(buf, entries, wbName, budget).toString('utf8');
      let rels = '';
      try {
        if (entries.has('xl/_rels/workbook.xml.rels')) {
          rels = inflateZipEntry(buf, entries, 'xl/_rels/workbook.xml.rels', budget).toString('utf8');
        }
      } catch {
        rels = '';
      }
      const idToTarget = new Map();
      let k = 0;
      while (k < rels.length) {
        const r = rels.indexOf('<Relationship', k);
        if (r < 0) break;
        const e = rels.indexOf('/>', r);
        if (e < 0) break;
        const tag = rels.slice(r, e);
        const id = /Id="([^"]*)"/.exec(tag)?.[1];
        const target = /Target="([^"]*)"/.exec(tag)?.[1];
        if (id && target) idToTarget.set(id, normZipName('xl/' + target.replace(/^\//, '')));
        k = e + 2;
      }
      let s = 0;
      while (s < wb.length && found.length < MAX_SHEETS) {
        let sh = wb.indexOf('<sheet', s);
        // Tag-boundary guard: '<sheets>' and '<sheetData>' are not sheets.
        while (sh >= 0 && !/[\s/>]/.test(wb[sh + 6] || '')) {
          sh = wb.indexOf('<sheet', sh + 1);
        }
        if (sh < 0) break;
        const e = wb.indexOf('/>', sh);
        const e2 = wb.indexOf('>', sh);
        const end = e >= 0 && e < e2 + 1 ? e : e2;
        if (end < 0) break;
        const tag = wb.slice(sh, end + (e >= 0 && e < e2 + 1 ? 2 : 1));
        const rid = /r:id="([^"]*)"/.exec(tag)?.[1];
        const name = /name="([^"]*)"/.exec(tag)?.[1] || `sheet${found.length + 1}`;
        const target = (rid && idToTarget.get(rid)) || `xl/worksheets/sheet${found.length + 1}.xml`;
        found.push({ name: unescapeXml(name), part: normZipName(target) });
        s = end + 1;
      }
    }
  } catch {
    // Fall through to conventional-path fallback.
  }
  if (found.length === 0) {
    for (const [name] of entries) {
      if (/^xl\/worksheets\/sheet\d+\.xml$/.test(name)) {
        found.push({ name: name.replace(/^xl\/worksheets\//, '').replace(/\.xml$/, ''), part: name });
      }
      if (found.length >= MAX_SHEETS) break;
    }
  }
  return found.filter((f) => entries.has(f.part)).slice(0, MAX_SHEETS);
}

/**
 * @param {Buffer} buf
 * @param {{maxChars?: number}} [options]
 */
export function extractXlsx(buf, { maxChars = MAX_TEXT_CHARS } = {}) {
  const budget = { value: 0 };
  const entries = parseZipEntries(buf);
  if (!entries.has('xl/workbook.xml') && ![...entries.keys()].some((n) => n.startsWith('xl/'))) {
    throw new Error('DOC_UNSUPPORTED_FORMAT');
  }
  let shared = [];
  try {
    if (entries.has('xl/sharedStrings.xml')) {
      shared = parseSharedStrings(
        inflateZipEntry(buf, entries, 'xl/sharedStrings.xml', budget).toString(
          'utf8'
        )
      );
    }
  } catch {
    shared = [];
  }
  const sheets = discoverSheets(entries, buf, budget);
  if (sheets.length === 0) throw new Error('DOC_PARSE_FAILED');
  const chunks = [];
  let truncated = false;
  for (const sheet of sheets) {
    let xml;
    try {
      xml = inflateZipEntry(buf, entries, sheet.part, budget).toString('utf8');
    } catch {
      continue;
    }
    const grid = sheetToText(xml, shared, maxChars);
    chunks.push(`# ${sheet.name}\n${grid}`);
    if (chunks.join('\n\n').length >= maxChars) {
      truncated = true;
      break;
    }
  }
  const text = chunks.join('\n\n').trim().slice(0, maxChars);
  if (!text) throw new Error('DOC_PARSE_FAILED');
  return {
    format: 'xlsx',
    text,
    truncated: truncated || chunks.join('\n\n').length > maxChars,
    sheets: sheets.length
  };
}

/**
 * Decode one PDF content stream body (already sliced between stream/endstream).
 * @param {Buffer} data
 * @param {string} filter raw /Filter value from the owning dict ('' when absent)
 * @param {{value: number}} [budget]
 */
export function decodePdfStream(data, filter, budget = { value: 0 }) {
  const f = String(filter || '').trim();
  const remaining = MAX_INFLATED_BYTES - budget.value;
  if (!f || f === '/None') {
    if (data.length > remaining) throw new Error('DOC_PARSE_FAILED');
    budget.value += data.length;
    return { bytes: Buffer.from(data), skipped: false };
  }
  if (/FlateDecode/.test(f)) {
    if (remaining <= 0) throw new Error('DOC_PARSE_FAILED');
    try {
      // T-C5: bound inflation (zip-bomb/OOM): inflateSync without
      // maxOutputLength lets a tiny stream expand without limit.
      const bytes = zlib.inflateSync(data, { maxOutputLength: remaining });
      budget.value += bytes.length;
      return { bytes, skipped: false };
    } catch {
      throw new Error('DOC_PARSE_FAILED');
    }
  }
  // Image and exotic filters (DCTDecode, LZWDecode, ...) carry no page text.
  return { bytes: null, skipped: true };
}

/**
 * @param {number} code
 */
function pdfEscapeChar(code) {
  if (code === 110) return '\n';
  if (code === 114) return '\r';
  if (code === 116) return '\t';
  if (code === 98) return '\b';
  if (code === 102) return '\f';
  return String.fromCharCode(code);
}

/**
 * Extract literal (...) and hex <...> strings inside BT/ET text blocks.
 * Only printable runs survive; glyph-mapped custom encodings stay approximate.
 * @param {string} content latin-1 decoded content stream
 */
function pdfContentText(content) {
  const out = [];
  let bi = 0;
  while (bi < content.length) {
    const bt = content.indexOf('BT', bi);
    if (bt < 0) break;
    // Avoid matching operators that merely contain BT (e.g. BTableau): require
    // a non-letter boundary on both sides.
    const before = bt > 0 ? content[bt - 1] : ' ';
    const after = content[bt + 2] || ' ';
    if (/[A-Za-z]/.test(before) || /[A-Za-z]/.test(after)) {
      bi = bt + 2;
      continue;
    }
    let et = content.indexOf('ET', bt + 2);
    while (et >= 0) {
      const eb = content[et - 1] || ' ';
      const ea = content[et + 2] || ' ';
      if (!/[A-Za-z]/.test(eb) && !/[A-Za-z]/.test(ea)) break;
      et = content.indexOf('ET', et + 2);
    }
    if (et < 0) break;
    const block = content.slice(bt + 2, et);
    let i = 0;
    let tjPending = '';
    const flushTj = () => {
      if (tjPending) {
        out.push(tjPending);
        tjPending = '';
      }
    };
    while (i < block.length) {
      const ch = block[i];
      if (ch === '(') {
        let s = '';
        i++;
        let depth = 1;
        while (i < block.length && depth > 0) {
          const c = block[i];
          if (c === '\\' && i + 1 < block.length) {
            const n = block[i + 1];
            if (n >= '0' && n <= '7') {
              let oct = '';
              let k = i + 1;
              while (k < block.length && k < i + 4 && block[k] >= '0' && block[k] <= '7') {
                oct += block[k];
                k++;
              }
              s += String.fromCharCode(parseInt(oct, 8) & 0xff);
              i = k;
              continue;
            }
            s += pdfEscapeChar(n.charCodeAt(0));
            i += 2;
            continue;
          }
          if (c === '(') depth++;
          else if (c === ')') {
            depth--;
            if (depth === 0) {
              i++;
              break;
            }
          }
          if (depth > 0) s += c;
          i++;
        }
        // Keep printable runs (letters, digits, punctuation, spaces).
        const kept = s.replace(/[^\x20-\x7e\xa0-\xff]/g, '');
        if (kept.trim()) {
          // Caller decides Tj vs TJ spacing at operator time; accumulate.
          tjPending += (tjPending && !tjPending.endsWith(' ') ? ' ' : '') + kept;
        }
      } else if (ch === '<' && block[i + 1] === '<') {
        i += 2; // dict open; strings inside still parse via the '(' branch.
      } else if (ch === '<') {
        const e = block.indexOf('>', i + 1);
        if (e < 0) break;
        const hex = block.slice(i + 1, e).replace(/\s+/g, '');
        if (/^[0-9a-fA-F]*$/.test(hex) && hex.length > 0) {
          const bytes = [];
          for (let h = 0; h < hex.length; h += 2) {
            bytes.push(parseInt(hex.slice(h, h + 2).padEnd(2, '0'), 16));
          }
          // Skip UTF-16BE BOM-prefixed strings we cannot map without ToUnicode.
          const start = bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff ? 2 : 0;
          let s = '';
          for (let b = start; b < bytes.length; b++) s += String.fromCharCode(bytes[b]);
          const kept = s.replace(/[^\x20-\x7e\xa0-\xff]/g, '');
          if (kept.trim()) tjPending += (tjPending && !tjPending.endsWith(' ') ? ' ' : '') + kept;
        }
        i = e + 1;
      } else if (ch === '[') {
        // TJ array: strings inside accumulate; the operator flushes a word gap.
        i++;
      } else if (ch === ']') {
        const rest = block.slice(i + 1, i + 6);
        if (/^\s*TJ/.test(rest)) {
          flushTj();
          out.push(' ');
        }
        i++;
      } else if (
        (ch === 'T' && block.startsWith('Tj', i)) ||
        (ch === "'" && true) ||
        (ch === '"' && true)
      ) {
        if (ch === 'T') {
          flushTj();
          out.push(' ');
          i += 2;
        } else {
          flushTj();
          out.push('\n');
          i++;
        }
      } else {
        i++;
      }
    }
    flushTj();
    out.push('\n');
    bi = et + 2;
  }
  return out
    .join('')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

/**
 * @param {Buffer} buf
 * @param {{maxChars?: number}} [options]
 */
export function extractPdf(buf, { maxChars = MAX_TEXT_CHARS } = {}) {
  const head = buf.subarray(0, Math.min(buf.length, 1024)).toString('latin1');
  if (!head.startsWith('%PDF-')) throw new Error('DOC_UNSUPPORTED_FORMAT');
  if (/\/Encrypt\b/.test(head) || /\/Encrypt\s/.test(buf.subarray(0, 65536).toString('latin1'))) {
    throw new Error('DOC_UNSUPPORTED_FORMAT');
  }
  const warnings = [];
  if (/\/ToUnicode\b/.test(buf.subarray(0, Math.min(buf.length, 65536)).toString('latin1'))) {
    warnings.push('custom font encodings present; some glyphs may be approximate');
  }
  const latin = buf.toString('latin1');
  let pages = 0;
  const countMatch = /\/Type\s*\/Pages[^>]*?\/Count\s+(\d+)/.exec(latin);
  if (countMatch) pages = Math.max(0, Math.min(100000, Number(countMatch[1])));
  if (!pages) {
    const pageObjs = latin.match(/\/Type\s*\/Page[^s]/g);
    pages = pageObjs ? Math.min(pageObjs.length, 100000) : 0;
  }
  const texts = [];
  let scanned = 0;
  const budget = { value: 0 };
  let skipped = 0;
  let i = 0;
  while (i < latin.length && scanned < MAX_PDF_STREAMS) {
    const s = latin.indexOf('stream', i);
    if (s < 0) break;
    // 'stream' must be keyword-boundaried (else it matches inside words).
    const afterKw = latin[s + 6] || '';
    if (/[A-Za-z]/.test(afterKw)) {
      i = s + 6;
      continue;
    }
    let dataStart = s + 6;
    if (latin.startsWith('\r\n', dataStart)) dataStart += 2;
    else if (latin[dataStart] === '\n' || latin[dataStart] === '\r') dataStart += 1;
    const e = latin.indexOf('endstream', dataStart);
    if (e < 0) break;
    const dictStart = Math.max(0, s - 512);
    const dict = latin.slice(dictStart, s);
    const filter = /\/Filter\s*(\/[A-Za-z0-9]+|\[[^\]]*\])/.exec(dict)?.[1] || '';
    // Byte-exact slice: latin1 maps 1:1 onto bytes.
    const data = buf.subarray(dataStart, Math.max(dataStart, e - (latin[e - 1] === '\n' ? 1 : 0)));
    scanned++;
    try {
      const { bytes, skipped: wasSkipped } = decodePdfStream(data, filter, budget);
      if (wasSkipped) {
        skipped++;
        i = e + 9;
        continue;
      }
      const t = pdfContentText((bytes || Buffer.alloc(0)).toString('latin1'));
      if (t) texts.push(t);
    } catch {
      throw new Error('DOC_PARSE_FAILED');
    }
    if (texts.join('\n').length >= maxChars) break;
    i = e + 9;
  }
  if (skipped > 0) warnings.push(`${skipped} non-text stream(s) skipped (image/exotic filters)`);
  const text = texts.join('\n').replace(/\n{3,}/g, '\n\n').trim().slice(0, maxChars);
  if (!text) throw new Error('DOC_PARSE_FAILED');
  return {
    format: 'pdf',
    text,
    truncated: texts.join('\n').length > maxChars,
    pages,
    warnings
  };
}

/**
 * Detect container format by magic bytes first, filename hint second.
 * @param {Buffer} buf
 * @param {string} filenameHint
 */
export function detectDocFormat(buf, filenameHint = '') {
  const lower = String(filenameHint || '').toLowerCase();
  if (buf.length >= 5 && buf.subarray(0, 5).toString('latin1') === '%PDF-') return 'pdf';
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) {
    // OOXML container: distinguish by content types, not by extension.
    try {
      const entries = parseZipEntries(buf);
      if (entries.has('[Content_Types].xml')) {
        const budget = { value: 0 };
        const ct = inflateZipEntry(buf, entries, '[Content_Types].xml', budget).toString('utf8');
        if (/wordprocessingml/.test(ct)) return 'docx';
        if (/spreadsheetml/.test(ct)) return 'xlsx';
      }
      if (entries.has('word/document.xml')) return 'docx';
      if (entries.has('xl/workbook.xml')) return 'xlsx';
    } catch {
      // Fall through to the hint below.
    }
    if (lower.endsWith('.docx')) return 'docx';
    if (lower.endsWith('.xlsx')) return 'xlsx';
    throw new Error('DOC_UNSUPPORTED_FORMAT');
  }
  if (lower.endsWith('.pdf')) throw new Error('DOC_PARSE_FAILED');
  throw new Error('DOC_UNSUPPORTED_FORMAT');
}

/**
 * @param {Buffer} buffer whole-file bytes (size-bounded by the caller)
 * @param {{filename?: string, format?: string, maxChars?: number}} [options]
 */
export function extractDocument(buffer, { filename = '', format = 'auto', maxChars = MAX_TEXT_CHARS } = {}) {
  const hint = String(format || 'auto').toLowerCase();
  if (!['auto', 'docx', 'xlsx', 'pdf'].includes(hint)) throw new Error('INVALID_DOC_FORMAT');
  const clamped = Math.max(1, Math.min(MAX_TEXT_CHARS, Math.trunc(Number(maxChars) || MAX_TEXT_CHARS)));
  const detected = hint === 'auto' ? detectDocFormat(buffer, filename) : hint;
  if (hint !== 'auto') {
    // Explicit hints still verify magic so a mislabeled file fails loudly.
    const actual = detectDocFormat(buffer, filename);
    if (actual !== detected) throw new Error('DOC_UNSUPPORTED_FORMAT');
  }
  const warnings = [];
  if (detected === 'docx') {
    const r = extractDocx(buffer, { maxChars: clamped });
    return { ...r, warnings };
  }
  if (detected === 'xlsx') {
    const r = extractXlsx(buffer, { maxChars: clamped });
    warnings.push('dates render as Excel serial numbers; formulas render as cached values');
    return { ...r, warnings };
  }
  const r = extractPdf(buffer, { maxChars: clamped });
  return { ...r, warnings: [...r.warnings, ...warnings] };
}
