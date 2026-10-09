// Structured host diagnostics for the NC agent (contract 5.13.0).
// Pure parsers are exported for unit tests; handlers exec argv-form
// commands (no shell) with bounded output, mirroring service-ops.mjs.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';

const run = promisify(execFile);
const MAX_ROWS = 50;

/**
 * Parse `df -P -B1` (POSIX) or `df -P -B1 -T` (GNU -T adds fstype).
 * df -P columns: filesystem 1B-blocks used available capacity mounted-on.
 * macOS df has no -B flag: callers pass `df -P -k` output with scale 1024.
 * @param {string} text @param {boolean} [hasFstype] @param {number} [scale]
 */
export function parseDfPosix(text, hasFstype = false, scale = 1) {
  const mult = Number.isFinite(scale) && scale > 0 ? scale : 1;
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < (hasFstype ? 7 : 6)) continue;
    if (/^Filesystem$/i.test(parts[0])) continue;
    const o = hasFstype
      ? {
          mount: parts[6],
          fstype: parts[1],
          total: Number(parts[2]),
          used: Number(parts[3]),
          free: Number(parts[4]),
          pct: parts[5]
        }
      : {
          mount: parts[5],
          fstype: null,
          total: Number(parts[1]),
          used: Number(parts[2]),
          free: Number(parts[3]),
          pct: parts[4]
        };
    if (!o.mount || !Number.isFinite(o.total) || !Number.isFinite(o.used) || !Number.isFinite(o.free))
      continue;
    const pctNum = Number(String(o.pct).replace('%', ''));
    out.push({
      mount: o.mount,
      fstype: o.fstype,
      total_bytes: o.total * mult,
      used_bytes: o.used * mult,
      free_bytes: o.free * mult,
      used_percent: Number.isFinite(pctNum) ? pctNum : o.total > 0 ? (o.used / o.total) * 100 : 0
    });
  }
  out.sort((a, b) => b.used_percent - a.used_percent);
  return out.slice(0, MAX_ROWS);
}

/**
 * Parse `Get-PSDrive -PSProvider FileSystem` JSON rows.
 * @param {Array<Record<string, unknown>>} rows
 */
export function parsePsDrives(rows) {
  const out = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    const used = Number(r.Used);
    const free = Number(r.Free);
    if (!Number.isFinite(used) || !Number.isFinite(free)) continue;
    const total = used + free;
    out.push({
      mount: String(r.Root || r.Name || ''),
      fstype: typeof r.Provider === 'string' ? 'FileSystem' : null,
      total_bytes: total,
      used_bytes: used,
      free_bytes: free,
      used_percent: total > 0 ? (used / total) * 100 : 0
    });
  }
  out.sort((a, b) => b.used_percent - a.used_percent);
  return out.slice(0, MAX_ROWS);
}

/**
 * Clamp an optional du-style depth to the contract range 1..8. Absent or
 * non-numeric input means "no du traversal" (null). The hub schema
 * already rejects out-of-range integers; this is defense in depth.
 * @param {unknown} value
 * @returns {number|null}
 */
export function clampDepth(value) {
  if (value === undefined || value === null || value === '') return null;
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return Math.max(1, Math.min(8, Math.floor(n)));
}

/**
 * Argv for a du-style per-directory breakdown (execFile argv form, no
 * shell). Mirrors `du --max-depth=N -x` (GNU) / `du -d N -x` (BSD).
 * Returns null when no traversal was requested or on win32 (no du
 * binary; callers use the portable fs walk instead).
 * @param {{platform?: string, depth?: unknown, oneFileSystem?: boolean}} [options]
 * @returns {Array<string>|null}
 */
export function buildDuArgs({ platform = process.platform, depth = null, oneFileSystem = false } = {}) {
  const d = clampDepth(depth);
  if (d == null) return null;
  if (platform === 'win32') return null;
  if (platform === 'darwin')
    return oneFileSystem === true ? ['-k', '-d', String(d), '-x'] : ['-k', '-d', String(d)];
  return oneFileSystem === true
    ? ['--block-size=1', `--max-depth=${d}`, '-x']
    : ['--block-size=1', `--max-depth=${d}`];
}

/**
 * Parse `du` size/path lines into directory byte totals. GNU
 * --block-size=1 reports bytes (scale 1); BSD -k reports 1K blocks.
 * @param {string} text @param {number} [scale]
 */
export function parseDuLines(text, scale = 1) {
  const mult = Number.isFinite(scale) && scale > 0 ? scale : 1;
  const out = [];
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trimEnd();
    if (!line) continue;
    const m = line.match(/^(\d+)\s+(.*\S)\s*$/);
    if (!m) continue;
    const bytes = Number(m[1]) * mult;
    if (!Number.isFinite(bytes)) continue;
    out.push({ path: m[2], bytes });
    if (out.length >= 500) break;
  }
  return out;
}

/**
 * Portable du-style fallback: depth-limited directory sizes via an fs walk
 * (no du binary on win32; also used when du fails). Symlinked
 * directories are never descended (loop-safe) and symlinks add no bytes.
 * @param {string} root @param {unknown} maxDepth @param {boolean} [oneFileSystem]
 */
export async function fsWalkSizes(root, maxDepth, oneFileSystem = false) {
  const depth = clampDepth(maxDepth) ?? 1;
  /** @type {Map<string, number>} */
  const sizes = new Map([[root, 0]]);
  /** @type {Array<{dir: string, level: number}>} */
  const stack = [{ dir: root, level: 0 }];
  let rootDev = null;
  try {
    const st = await fs.stat(root);
    rootDev = typeof st.dev === 'number' ? st.dev : null;
  } catch {
    return { entries: [], truncated: true };
  }
  const rootBase =
    process.platform === 'win32' ? path.parse(path.resolve(root)).root.toLowerCase() : null;
  let files = 0;
  let truncated = false;
  /** @param {string} fileDir @param {number} n */
  const addBytes = (fileDir, n) => {
    let cur = fileDir;
    for (;;) {
      sizes.set(cur, (sizes.get(cur) ?? 0) + n);
      if (cur === root) break;
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
  };
  while (stack.length > 0) {
    const next = stack.pop();
    if (!next || next.level >= depth) continue;
    let rows;
    try {
      rows = await fs.readdir(next.dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const d of rows) {
      const full = path.join(next.dir, d.name);
      if (d.isSymbolicLink()) continue;
      if (d.isDirectory()) {
        if (oneFileSystem === true) {
          if (process.platform === 'win32') {
            if (rootBase !== null && path.parse(path.resolve(full)).root.toLowerCase() !== rootBase)
              continue;
          } else {
            try {
              const st = await fs.stat(full);
              if (rootDev !== null && typeof st.dev === 'number' && st.dev !== rootDev) continue;
            } catch {
              continue;
            }
          }
        }
        if (!sizes.has(full)) sizes.set(full, 0);
        stack.push({ dir: full, level: next.level + 1 });
      } else if (d.isFile()) {
        if (files >= 5000) {
          truncated = true;
          break;
        }
        files++;
        let size = 0;
        let ok = true;
        try {
          const st = await fs.lstat(full);
          if (oneFileSystem === true && process.platform !== 'win32' && rootDev !== null) {
            if (typeof st.dev === 'number' && st.dev !== rootDev) ok = false;
            else size = st.size;
          } else {
            size = st.size;
          }
        } catch {
          ok = false;
        }
        if (ok && Number.isFinite(size)) addBytes(next.dir, size);
      }
      if (truncated) break;
    }
  }
  const entries = [...sizes.entries()].map(([p, bytes]) => ({ path: p, bytes }));
  entries.sort((a, b) => b.bytes - a.bytes);
  return { entries: entries.slice(0, 500), truncated };
}

/**
 * du-style per-directory breakdown of target, bounded by depth. Prefers
 * the platform du binary (argv form, no shell); falls back to a portable
 * fs walk when du is missing or fails.
 * @param {{platform?: string, target?: string, depth?: unknown, oneFileSystem?: boolean, timeoutMs?: number}} [options]
 */
export async function duDirectories({
  platform = process.platform,
  target = '/',
  depth = null,
  oneFileSystem = false,
  timeoutMs = 20000
} = {}) {
  const d = clampDepth(depth) ?? (oneFileSystem === true ? 1 : null);
  const at = typeof target === 'string' && target ? target : '/';
  if (d == null) return { entries: [], truncated: false };
  const args = platform === 'win32' ? null : buildDuArgs({ platform, depth: d, oneFileSystem });
  if (args) {
    try {
      const { stdout } = await run('du', [...args, at], { timeout: timeoutMs });
      return { entries: parseDuLines(stdout, platform === 'darwin' ? 1024 : 1), truncated: false };
    } catch {
      // Fall through to the portable walk below.
    }
  }
  try {
    return await fsWalkSizes(at, d, oneFileSystem === true);
  } catch {
    return { entries: [], truncated: true };
  }
}

async function diskUsage(platform, focusPath, options = {}) {
  const { depth = null, oneFileSystem = false } = options || {};
  if (platform === 'win32') {
    const ps =
      'Get-PSDrive -PSProvider FileSystem | Select-Object Root,Used,Free,Provider | ConvertTo-Json -Compress';
    const { stdout } = await run(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', ps],
      { timeout: 20000, windowsHide: true }
    );
    let rows = [];
    try {
      const parsed = JSON.parse(String(stdout || '').trim() || '[]');
      rows = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      throw new Error('DISK_PARSE_FAILED');
    }
    const parsed = focusPath
      ? parsePsDrives(rows).filter((f) => f.mount === focusPath)
      : parsePsDrives(rows);
    return withDirectories(platform, focusPath, { platform, filesystems: parsed }, { depth, oneFileSystem });
  }
  if (platform === 'darwin') {
    // macOS df has no -B flag: -k reports 1K blocks, scaled to bytes.
    const { stdout: darwinOut } = await run('df', ['-P', '-k'], { timeout: 20000 });
    let rows = parseDfPosix(darwinOut, false, 1024);
    rows = rows.filter((r) => !r.mount.startsWith('/dev'));
    if (focusPath) rows = rows.filter((r) => r.mount === focusPath);
    return withDirectories(platform, focusPath, { platform, filesystems: rows }, { depth, oneFileSystem });
  }
  const args =
    platform === 'linux'
      ? ['-B1', '-P', '-T', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'squashfs', '-x', 'overlay']
      : ['-P', '-B1'];
  let stdout = '';
  try {
    ({ stdout } = await run('df', args, { timeout: 20000 }));
  } catch {
    ({ stdout } = await run('df', ['-P'], { timeout: 20000 }));
  }
  let rows = parseDfPosix(stdout, platform === 'linux');
  if (focusPath) rows = rows.filter((r) => r.mount === focusPath);
  return withDirectories(platform, focusPath, { platform, filesystems: rows }, { depth, oneFileSystem });
}

/**
 * Attach a du-style per-directory breakdown when depth/one_file_system was
 * requested. Absent both flags the df-only report is returned unchanged
 * (backward compatible by construction).
 * @param {string} platform @param {string|null} focusPath
 * @param {{platform: string, filesystems: Array<Record<string, unknown>>}} report
 * @param {{depth?: unknown, oneFileSystem?: boolean}} [options]
 */
async function withDirectories(platform, focusPath, report, { depth = null, oneFileSystem = false } = {}) {
  const want = clampDepth(depth) ?? (oneFileSystem === true ? 1 : null);
  if (want == null) return report;
  const fallbackTarget =
    platform === 'win32' ? path.parse(process.cwd()).root || '/' : '/';
  const breakdown = await duDirectories({
    platform,
    target: focusPath || fallbackTarget,
    depth: want,
    oneFileSystem: oneFileSystem === true
  });
  if (!breakdown.entries || breakdown.entries.length === 0) return report;
  return {
    ...report,
    directories: breakdown.entries,
    ...(breakdown.truncated ? { directories_truncated: true } : {})
  };
}

/**
 * Parse `ss -tlnpH` lines. Modern iproute2 `ss` omits the Netid column when
 * filtering with `-t`, so the first column is the state, not `tcp`:
 * LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("node",pid=8452,fd=21))
 * Older output (e.g. `ss -tunlp`) keeps the Netid prefix and is also accepted:
 * tcp LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:(("node",pid=8452,fd=21))
 * IPv6 appears bracketed (`[::]:22`); multi-process entries keep the first.
 * @param {string} text
 */
export function parseSsTcp(text) {
  const out = [];
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    if (/^(?:netid\s+)?state\s+recv-q\b/i.test(line)) continue;
    const parts = line.split(/\s+/);
    let i = 0;
    let proto = 'tcp';
    if (/^(?:tcp[46]?|udp[46]?)$/i.test(parts[0])) {
      proto = parts[0].toLowerCase();
      i = 1;
    }
    if (parts.length < i + 5) continue;
    const state = parts[i];
    const recvQ = parts[i + 1];
    const sendQ = parts[i + 2];
    const local = parts[i + 3];
    if (!/^[A-Za-z-]+$/.test(state)) continue;
    if (!/^\d+$/.test(recvQ) || !/^\d+$/.test(sendQ)) continue;
    if (!local || !local.includes(':')) continue;
    const pm = line.match(/users:\(\("([^"]+)",pid=(\d+)/);
    const { host, port } = splitHostPort(local);
    const upper = state.toUpperCase();
    out.push({
      proto,
      local_address: host,
      local_port: port,
      remote_address: null,
      remote_port: null,
      state: upper === 'ESTAB' ? 'ESTABLISHED' : upper,
      pid: pm ? Number(pm[2]) : null,
      process: pm ? pm[1] : null
    });
  }
  return out;
}

/**
 * Split an `ss`/`netstat` `host:port` token. Handles IPv4 (`0.0.0.0:22`),
 * bracketed IPv6 (`[::]:22`), bare IPv6 (`:::22`), interface scopes
 * (`127.0.0.53%lo:53`), and wildcard ports (`*` -> null).
 * @param {string} s
 */
function splitHostPort(s) {
  const v = String(s || '');
  const lp = v.lastIndexOf(':');
  if (lp <= 0) return { host: v, port: null };
  let host = v.slice(0, lp);
  const portText = v.slice(lp + 1);
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  return { host, port: /^\d+$/.test(portText) ? Number(portText) : null };
}

/**
 * Parse Linux `netstat -tlnp` lines (fallback when ss is absent).
 * tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN 123/sshd
 * @param {string} text
 */
export function parseNetstatLinux(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const m = line.match(/^(tcp[46]?)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\d+)\/(\S+))?/);
    if (!m) continue;
    const [, proto, local, , state, pid, proc] = m;
    const lp = String(local).lastIndexOf(':');
    out.push({
      proto,
      local_address: lp > 0 ? String(local).slice(0, lp) : String(local),
      local_port: lp > 0 ? Number(String(local).slice(lp + 1)) || null : null,
      remote_address: null,
      remote_port: null,
      state: String(state || 'UNKNOWN').toUpperCase(),
      pid: pid ? Number(pid) : null,
      process: proc ? String(proc).split(' ')[0] : null
    });
  }
  return out;
}

/**
 * Parse `netstat -an` style lines (darwin fallback, no pid).
 * tcp4 0 0 *.8080 *.* LISTEN
 * @param {string} text
 */
export function parseNetstatTcp(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5 || !/^tcp/i.test(parts[0])) continue;
    const local = parts[3] || '';
    const state = (parts[5] || parts[4] || '').toUpperCase();
    const dot = local.lastIndexOf('.');
    const colon = local.lastIndexOf(':');
    const sep = Math.max(dot, colon);
    out.push({
      proto: parts[0],
      local_address: sep > 0 ? local.slice(0, sep) : local,
      local_port: sep > 0 ? Number(local.slice(sep + 1)) || null : null,
      remote_address: null,
      remote_port: null,
      state: state || 'UNKNOWN',
      pid: null,
      process: null
    });
  }
  return out;
}

async function networkConnections(platform, { state = 'listen', port = null, limit = 100 } = {}) {
  const lim = Math.max(1, Math.min(500, Number(limit) || 100));
  let rows = [];
  if (platform === 'win32') {
    const states = state === 'all' ? "'Listen','Established'" : state === 'established' ? "'Established'" : "'Listen'";
    const ps =
      `Get-NetTCPConnection -State ${states} | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Compress -Depth 2`;
    const { stdout } = await run(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', ps],
      { timeout: 25000, windowsHide: true }
    );
    let parsed = [];
    try {
      const p = JSON.parse(String(stdout || '').trim() || '[]');
      parsed = Array.isArray(p) ? p : [p];
    } catch {
      throw new Error('NETSTAT_PARSE_FAILED');
    }
    rows = parsed.map((r) => ({
      proto: 'tcp',
      local_address: String(r.LocalAddress || ''),
      local_port: Number(r.LocalPort) || null,
      remote_address: String(r.RemoteAddress || ''),
      remote_port: Number(r.RemotePort) || null,
      state: (String(r.State || '') === '2' ? 'LISTEN' : String(r.State || '') === '5' ? 'ESTABLISHED' : String(r.State || '').toUpperCase()),
      pid: Number(r.OwningProcess) || null,
      process: null
    }));
  } else if (platform === 'darwin') {
    let text = '';
    if (state === 'listen' || state === 'all') {
      try {
        ({ stdout: text } = await run('lsof', ['-iTCP', '-sTCP:LISTEN', '-P', '-n', '-F', 'pcnT'], {
          timeout: 25000
        }));
        rows = parseLsofTcp(text);
      } catch {
        rows = [];
      }
    }
    if (state !== 'listen' || !rows.length) {
      try {
        ({ stdout: text } = await run('netstat', ['-an', '-p', 'tcp'], { timeout: 25000 }));
        const fb = parseNetstatTcp(text).filter(
          (r) => state === 'all' || r.state === (state === 'listen' ? 'LISTEN' : 'ESTABLISHED')
        );
        rows = state === 'listen' && rows.length ? rows : fb;
      } catch {
        if (!rows.length) throw new Error('NETSTAT_FAILED');
      }
    }
  } else {
    let text = '';
    try {
      ({ stdout: text } = await run('ss', ['-tlnpH'], { timeout: 25000 }));
      rows = parseSsTcp(text);
    } catch {
      ({ stdout: text } = await run('netstat', ['-tlnp'], { timeout: 25000 }));
      rows = parseNetstatLinux(text);
    }
    if (state === 'established') rows = [];
  }
  if (port != null) rows = rows.filter((r) => r.local_port === Number(port));
  const truncated = rows.length > lim;
  return { platform, truncated, connections: rows.slice(0, lim) };
}

/**
 * Parse `lsof -F pcnT` blocks for listening TCP sockets.
 * pPID\ncCOMMAND\nnNODE\nTST=STATE per file block.
 * @param {string} text @param {string} state
 */
export function parseLsofTcp(text, state = 'listen') {
  const out = [];
  /** @type {{pid?: number|null, proc?: string, node?: string, st?: string}} */
  let cur = {};
  const flush = () => {
    if (cur.pid != null && (state === 'all' || (cur.st || '').toUpperCase().includes('LISTEN') === (state === 'listen'))) {
      if (state === 'established' && (cur.st || '').toUpperCase().includes('LISTEN')) {
        cur = {};
        return;
      }
      const node = String(cur.node || '');
      const lp = node.lastIndexOf(':');
      out.push({
        proto: 'tcp',
        local_address: lp > 0 ? node.slice(0, lp) : node,
        local_port: lp > 0 ? Number(node.slice(lp + 1)) || null : null,
        remote_address: null,
        remote_port: null,
        state: (cur.st || 'LISTEN').toUpperCase(),
        pid: cur.pid,
        process: cur.proc || null
      });
    }
    cur = {};
  };
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trimEnd();
    if (!line) {
      flush();
      continue;
    }
    const k = line[0];
    if (k === 'p') {
      flush();
      cur.pid = Number(line.slice(1)) || null;
    } else if (k === 'c') cur.proc = line.slice(1).replace(/\\x20/g, ' ');
    else if (k === 'n') cur.node = line.slice(1);
    else if (k === 'T' && line.startsWith('TST=')) cur.st = line.slice(4);
  }
  flush();
  return out;
}

/**
 * @param {string} [platform]
 */
export function makeDiagnosticsHandlers(platform = process.platform) {
  return {
    disk_usage: async (job) => {
      const p = (job && (job.request_payload || job.payload)) || {};
      const focus = typeof p.path === 'string' && p.path ? p.path.slice(0, 4096) : null;
      const depth = clampDepth(p.depth);
      const oneFileSystem = p.one_file_system === true;
      try {
        const r = await diskUsage(platform, focus, { depth, oneFileSystem });
        return {
          status: 'completed',
          exit_code: 0,
          stdout: '',
          stderr: '',
          error: null,
          duration_ms: 0,
          result_payload: r
        };
      } catch (e) {
        return {
          status: 'failed',
          exit_code: null,
          stdout: '',
          stderr: '',
          error: String((e && e.message) || e),
          duration_ms: 0,
          result_payload: {}
        };
      }
    },
    network_connections: async (job) => {
      const p = (job && (job.request_payload || job.payload)) || {};
      const st = ['listen', 'established', 'all'].includes(String(p.state)) ? String(p.state) : 'listen';
      const port = p.port == null ? null : Number(p.port);
      const limit = p.limit == null ? 100 : Number(p.limit);
      try {
        const r = await networkConnections(platform, {
          state: st,
          port: Number.isFinite(port) ? port : null,
          limit
        });
        return {
          status: 'completed',
          exit_code: 0,
          stdout: '',
          stderr: '',
          error: null,
          duration_ms: 0,
          result_payload: r
        };
      } catch (e) {
        return {
          status: 'failed',
          exit_code: null,
          stdout: '',
          stderr: '',
          error: String((e && e.message) || e),
          duration_ms: 0,
          result_payload: {}
        };
      }
    }
  };
}
// ---------------------------------------------------------------------------
// Diagnostics bundle (`nodecommand --diagnostics` support story).
//
// The beta UX contract requires a CLI tool that safely collects logs
// without leaking secrets. This section builds that bundle: agent
// layout/version/paths, platform facts, service status, bounded log tails,
// redacted config keys, connectivity state, and the diagnostics-ops reader
// output above. Dry-run/preview is the default; writing the `.tar.gz`
// archive requires an explicit apply flag (rule #43).
//
// Redaction vocabulary is aligned VERBATIM with the central sanitizer in
// apps/control-plane/lib/feedback-service.mjs (REDACT_PATTERNS plus
// redactSecrets): the same secret shapes must redact identically whether
// they leave the machine in a bundle file or in an nc_feedback report.
// A parity test asserts both sanitizers agree on a shared fixture set.
// ---------------------------------------------------------------------------

export const DIAGNOSTICS_BUNDLE_VERSION = '1.0.0';
export const DIAGNOSTICS_MAX_LOG_BYTES = 65536;
export const DIAGNOSTICS_MAX_LOG_FILES = 4;
export const DIAGNOSTICS_MAX_LOG_LINES = 500;
export const DIAGNOSTICS_MAX_OUTPUT_BYTES = 2 * 1024 * 1024;

// PEM block pattern rebuilt from `-{5}` fragments so no literal
// five-dash private-key header sits in source (credential scanners flag
// the header itself). Semantics are identical to SECRET_PATTERNS in
// lib/mcp/errors.mjs and the PEM arm of redactSecrets in
// lib/feedback-service.mjs:61-73 — pasted PEM blocks still match.
const PEM_PRIVATE_KEY_BLOCK_RE = new RegExp(
  '-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}[^-]*-{5}END [A-Z ]*PRIVATE KEY-{5}',
  'g'
);

const DIAGNOSTICS_REDACT_PATTERNS = [
  /Authorization\s*:\s*Bearer\s+[A-Za-z0-9\-._~+/=]+/gi,
  /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  /\btoken\s*[:=]\s*['"]?[^'"\s;,}]+['"]?/gi,
  /(access_token|refresh_token|api_key|apikey|client_secret|enrollment_token|private_key)\s*[:=]\s*['"]?[^'"\s,}]+['"]?/gi,
  /(password|passwd|pwd|secret|cookie|set-cookie)\s*[:=]\s*['"]?[^'"\s;,}]+['"]?/gi,
  /nc_(tok|enr|pat|rfk|code|live)_[0-9a-f]{8,}/gi,
  /xox[bap]-[A-Za-z0-9-]+/g,
  /\bsk-(?:proj|ant|live|test)-[A-Za-z0-9_-]+/g,
  /\bsk-[A-Za-z0-9_-]{8,}/g
];

// Env/config keys whose VALUES are secrets by construction. Anything
// matching is replaced wholesale with `[REDACTED]` (the key name is kept
// so the bundle still inventories which settings exist).
const SENSITIVE_ENV_KEY_RE =
  /(token|secret|passwd|password|cookie|hmac|private[_-]?key|api[_-]?key|auth|turnstile|stripe|session|credential|bearer|signing)/i;

/**
 * Redact secret shapes from free text. Same vocabulary as
 * `redactSecrets` in apps/control-plane/lib/feedback-service.mjs.
 * @param {unknown} value
 */
export function redactDiagnosticsSecrets(value) {
  if (typeof value !== 'string') return value;
  let out = value;
  // PEM blocks are redacted WHOLE, before the shared k=v callback runs:
  // that callback keys off `[:=]`, and real PEMs carry base64 `=` padding,
  // which would otherwise keep the armor header + prefix visible. Same
  // vocabulary as feedback-service.mjs (same shapes flagged), strictly
  // stricter replacement — never looser.
  PEM_PRIVATE_KEY_BLOCK_RE.lastIndex = 0;
  out = out.replace(PEM_PRIVATE_KEY_BLOCK_RE, '[REDACTED]');
  for (const re of DIAGNOSTICS_REDACT_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, (m) => {
      if (!/[:=]/.test(m)) return '[REDACTED]';
      const key = m.split(/[:=]/, 1)[0];
      return `${key}: [REDACTED]`;
    });
  }
  return out;
}

/**
 * Redact an env/config record: sensitive keys lose their value entirely,
 * every other value still passes through the free-text sanitizer (catches
 * pasted tokens) and is length-bounded.
 * @param {Record<string, unknown>} record
 * @returns {Record<string, string>}
 */
export function redactEnvRecord(record) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const [key, raw] of Object.entries(record || {})) {
    const k = String(key);
    if (SENSITIVE_ENV_KEY_RE.test(k)) {
      out[k] = '[REDACTED]';
      continue;
    }
    const text = typeof raw === 'string' ? raw : String(raw ?? '');
    const cleaned = String(redactDiagnosticsSecrets(text) ?? '');
    out[k] = cleaned.length > 512 ? cleaned.slice(0, 512) + '…[truncated]' : cleaned;
  }
  return out;
}

/**
 * Replace a leading home directory with `~` so absolute user-identifying
 * paths do not leave the machine where avoidable.
 * @param {unknown} value @param {string} [home]
 */
export function sanitizePathForBundle(value, home = '') {
  if (typeof value !== 'string' || !value) return value;
  let out = value;
  try {
    const h = home || os.homedir();
    if (h && out.includes(h)) out = out.split(h).join('~');
  } catch {
    // Home resolution is best-effort; keep the raw value when it fails.
  }
  return out;
}

/**
 * Recursively fold home directories out of a bundle value.
 * @param {unknown} value @param {string} [home]
 */
export function sanitizeBundleValue(value, home = '') {
  if (typeof value === 'string') return sanitizePathForBundle(value, home);
  if (Array.isArray(value)) return value.map((v) => sanitizeBundleValue(v, home));
  if (value && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = sanitizeBundleValue(v, home);
    return out;
  }
  return value;
}

/**
 * Parse diagnostics CLI flags. Preview (dry-run) is the default; nothing
 * is written unless `--apply` is present.
 * @param {Array<string>} [argv]
 */
export function parseDiagnosticsArgv(argv = []) {
  const args = Array.isArray(argv) ? argv.map(String) : [];
  let enabled = false;
  let apply = false;
  let output = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--diagnostics' || a.startsWith('--diagnostics=')) enabled = true;
    if (a === '--apply') apply = true;
    if (a === '--output' && i + 1 < args.length) {
      output = args[i + 1];
      i++;
    } else if (a.startsWith('--output=')) {
      output = a.slice('--output='.length);
    }
  }
  return { enabled, apply, output };
}

/**
 * True when this invocation asks for a diagnostics bundle.
 * @param {Array<string>} [argv]
 */
export function shouldHandleDiagnosticsCli(argv = []) {
  return parseDiagnosticsArgv(argv).enabled;
}

/**
 * Read the tail of a file, bounded by bytes and lines. Missing files
 * resolve to `{ missing: true }` so one absent log never fails the bundle.
 * @param {string} file @param {number} [maxBytes]
 * @param {(f: string, o?: object) => Promise<Buffer|string>} [readFile]
 */
export async function readBoundedLogTail(file, maxBytes = DIAGNOSTICS_MAX_LOG_BYTES, readFile = null) {
  try {
    const reader =
      readFile ||
      (async (f, o) => {
        return fs.readFile(f, o);
      });
    let size = null;
    try {
      const st = await fs.stat(file);
      size = Number(st.size) || 0;
    } catch {
      size = null;
    }
    let text = '';
    if (size != null && size > maxBytes) {
      const handle = await fs.open(file, 'r');
      try {
        const start = Math.max(0, size - maxBytes);
        const buffer = Buffer.alloc(Math.min(size - start, maxBytes));
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, start);
        text = buffer.subarray(0, bytesRead).toString('utf8');
        const firstNl = text.indexOf('\n');
        if (start > 0 && firstNl >= 0) text = text.slice(firstNl + 1);
      } finally {
        await handle.close();
      }
    } else {
      text = String((await reader(file, 'utf8')) ?? '');
      if (text.length > maxBytes) text = text.slice(text.length - maxBytes);
    }
    let rows = text.split(/\r?\n/);
    if (rows.length && rows[rows.length - 1] === '') rows.pop();
    const truncated = rows.length > DIAGNOSTICS_MAX_LOG_LINES || (size != null && size > maxBytes);
    rows = rows.slice(-DIAGNOSTICS_MAX_LOG_LINES).map((line) => String(redactDiagnosticsSecrets(line)));
    return { content: rows.join('\n'), lines_returned: rows.length, truncated, missing: false };
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error ? error.code : null;
    return {
      content: '',
      lines_returned: 0,
      truncated: false,
      missing: true,
      error: code === 'ENOENT' ? 'LOG_SOURCE_NOT_FOUND' : code === 'EACCES' ? 'LOG_PERMISSION_DENIED' : 'LOG_READ_FAILED'
    };
  }
}

/**
 * Best-effort daemon/service status. Every probe is argv-form with a short
 * timeout and degrades to `state: 'unknown'` — never throws.
 * @param {string} [platform]
 * @param {(file: string, args: Array<string>, opts?: object) => Promise<{stdout?: unknown}>} [execFn]
 */
export async function probeServiceStatus(platform = process.platform, execFn = null) {
  const invoke = execFn || ((file, args, opts) => run(file, args, opts));
  const checks = [];
  try {
    if (platform === 'linux') {
      /** @type {Array<[string, Array<string>]>} */
      const units = [
        ['systemctl', ['is-active', 'nc-client.service']],
        ['systemctl', ['--user', 'is-active', 'nc-client.service']]
      ];
      for (const [cmd, args] of units) {
        try {
          const r = await invoke(cmd, args, { timeout: 8000 });
          const out = String(r?.stdout || '').trim().toLowerCase();
          checks.push({
            unit: [cmd, ...args].join(' '),
            state: out === 'active' ? 'active' : 'inactive',
            detail: null
          });
        } catch {
          checks.push({ unit: [cmd, ...args].join(' '), state: 'unknown', detail: 'probe failed or unit absent' });
        }
      }
    } else if (platform === 'darwin') {
      try {
        await invoke('launchctl', ['print', 'system/com.nc.client'], { timeout: 8000 });
        checks.push({ unit: 'system/com.nc.client', state: 'active', detail: null });
      } catch {
        checks.push({ unit: 'system/com.nc.client', state: 'unknown', detail: 'probe failed or daemon absent' });
      }
    } else if (platform === 'win32') {
      try {
        const r = await invoke('sc.exe', ['query', 'NCClient'], { timeout: 8000 });
        const out = String(r?.stdout || '');
        checks.push({
          unit: 'NCClient',
          state: /RUNNING/.test(out) ? 'active' : 'unknown',
          detail: null
        });
      } catch {
        checks.push({ unit: 'NCClient', state: 'unknown', detail: 'probe failed or service absent' });
      }
    } else {
      checks.push({ unit: String(platform), state: 'unknown', detail: 'unsupported platform for service probe' });
    }
  } catch {
    checks.push({ unit: 'probe', state: 'unknown', detail: 'service probe harness failed' });
  }
  return checks;
}
/**
 * Collect the diagnostics bundle. Every section is guarded: a permission
 * error, a missing file, or a failed reader lands in `collection_notes`
 * and the bundle stays usable.
 * @param {object} [options]
 * @param {string} [options.platform]
 * @param {Record<string, string>} [options.layout]
 * @param {string} [options.version]
 * @param {Record<string, string|undefined>} [options.env]
 * @param {string} [options.home]
 * @param {(f: string, o?: object) => Promise<Buffer|string>} [options.readFile]
 * @param {(platform?: string) => Promise<Array<Record<string, unknown>>>} [options.serviceProbe]
 * @param {Record<string, unknown>} [options.readers]
 * @param {{ serverUrl?: string|null, reachable?: boolean|null, note?: string|null }} [options.connectivity]
 */
export async function collectDiagnosticsBundle({
  platform = process.platform,
  layout = null,
  version = 'unknown',
  env = process.env,
  home = '',
  readFile = null,
  serviceProbe = null,
  readers = null,
  connectivity = null
} = {}) {
  const notes = [];
  const note = (section, error) => {
    const msg = error instanceof Error ? error.message : String(error ?? 'unknown');
    notes.push({ section, error: msg.slice(0, 300) });
  };
  let resolvedHome = home;
  try {
    resolvedHome = home || os.homedir();
  } catch {
    resolvedHome = home || '';
  }
  let effectiveLayout = layout;
  if (!effectiveLayout) {
    try {
      const paths = await import('../client/nc-paths.mjs');
      effectiveLayout = paths.ncLayout();
    } catch (e) {
      note('layout', e);
      effectiveLayout = { root: 'unknown' };
    }
  }
  const reader =
    readFile ||
    (async (f, o) => {
      return fs.readFile(f, o);
    });
  // -- agent identity / layout (paths sanitized, key material never read) --
  /** @type {Record<string, unknown>} */
  let agent = { version: String(version || 'unknown'), root: null, files: {}, state: null };
  try {
    /** @type {Record<string, unknown>} */
    const files = {};
    const watched = {
      env_file: effectiveLayout.envFile,
      device_key: effectiveLayout.deviceKey,
      state_file: effectiveLayout.stateFile,
      pid_file: effectiveLayout.pidFile,
      lock_file: effectiveLayout.lockFile,
      client_log: effectiveLayout.clientLog,
      audit_log: effectiveLayout.auditLog,
      server_log: effectiveLayout.serverLog,
      tunnel_log: effectiveLayout.tunnelLog
    };
    for (const [label, file] of Object.entries(watched)) {
      if (!file) {
        files[label] = { present: false };
        continue;
      }
      try {
        const st = await fs.stat(String(file));
        files[label] = {
          present: true,
          size_bytes: Number(st.size) || 0,
          path: sanitizePathForBundle(String(file), resolvedHome)
        };
      } catch (e) {
        const code = e && typeof e === 'object' && 'code' in e ? e.code : null;
        files[label] = {
          present: false,
          error: code === 'ENOENT' ? 'not_found' : code === 'EACCES' ? 'permission_denied' : 'stat_failed'
        };
      }
    }
    let state = null;
    try {
      const stateFile = /** @type {Record<string, unknown>} */ (files.state_file || {});
      if (effectiveLayout.stateFile && stateFile.present) {
        const raw = JSON.parse(String(await reader(String(effectiveLayout.stateFile), 'utf8')));
        state = {
          registered: Boolean(raw && raw.registered),
          jobs_tracked: raw && typeof raw.jobs === 'object' ? Object.keys(raw.jobs).length : 0,
          pending_results:
            raw && typeof raw.pendingResults === 'object' ? Object.keys(raw.pendingResults).length : 0
        };
      }
    } catch (e) {
      note('agent.state', e);
    }
    agent = {
      version: String(version || 'unknown'),
      root: sanitizePathForBundle(String(effectiveLayout.root || 'unknown'), resolvedHome),
      files,
      state
    };
  } catch (e) {
    note('agent', e);
  }
  // -- platform / runtime facts (no secrets live here) --
  /** @type {Record<string, unknown>} */
  let platformFacts = {};
  try {
    const cpus = os.cpus();
    platformFacts = {
      platform,
      arch: os.arch(),
      release: os.release(),
      type: os.type(),
      cpus: (cpus && cpus.length) || null,
      total_memory_bytes: os.totalmem(),
      free_memory_bytes: os.freemem(),
      uptime_seconds: Math.floor(os.uptime()),
      node_version: process.version,
      hostname: os.hostname()
    };
  } catch (e) {
    note('platform', e);
  }
  // -- service / daemon status --
  /** @type {Array<Record<string, unknown>>} */
  let service = [];
  try {
    if (readers && readers.service) {
      service = /** @type {Array<Record<string, unknown>>} */ (readers.service);
    } else if (serviceProbe) {
      service = await serviceProbe(platform);
    } else {
      service = await probeServiceStatus(platform);
    }
  } catch (e) {
    note('service', e);
    service = [{ unit: 'probe', state: 'unknown', detail: 'service probe failed' }];
  }
  // -- bounded, redacted log tails --
  /** @type {Record<string, unknown>} */
  const logs = {};
  try {
    const candidates = [
      ['client', effectiveLayout.clientLog],
      ['mcp-server', effectiveLayout.serverLog],
      ['mcp-tunnel', effectiveLayout.tunnelLog],
      ['audit', effectiveLayout.auditLog]
    ].slice(0, DIAGNOSTICS_MAX_LOG_FILES);
    for (const [label, file] of candidates) {
      if (!file) {
        logs[label] = { missing: true, error: 'no path for platform' };
        continue;
      }
      logs[label] = await readBoundedLogTail(String(file), DIAGNOSTICS_MAX_LOG_BYTES, reader);
    }
  } catch (e) {
    note('logs', e);
  }
  // -- config keys with secrets stripped (values redacted, never raw) --
  /** @type {Record<string, unknown>} */
  let config = {};
  try {
    /** @type {Record<string, unknown>} */
    const live = {};
    const source = env || {};
    for (const k of Object.keys(source)) {
      if (!k.startsWith('NC_')) continue;
      if (Object.keys(live).length >= 100) break;
      live[k] = source[k];
    }
    /** @type {Record<string, unknown>} */
    let fileKeys = {};
    try {
      if (effectiveLayout.envFile) {
        const text = String(await reader(String(effectiveLayout.envFile), 'utf8'));
        /** @type {Record<string, unknown>} */
        const parsed = {};
        for (const line of text.split(/\r?\n/)) {
          const t = line.trim();
          if (!t || t.startsWith('#')) continue;
          const i = t.indexOf('=');
          if (i > 0) parsed[t.slice(0, i).trim()] = t.slice(i + 1).trim();
        }
        fileKeys = parsed;
      }
    } catch (e) {
      note('config.env_file', e);
    }
    config = { env: redactEnvRecord(live), env_file: redactEnvRecord(fileKeys) };
  } catch (e) {
    note('config', e);
  }
  // -- connectivity state (configured endpoints; no credential echo) --
  /** @type {Record<string, unknown>} */
  let connectivityState = { server_url: null, probe: 'not_probed', note: null };
  try {
    const source = env || {};
    const serverUrl = String(source.NC_SERVER_URL || 'https://mcp.nodecommand.app').replace(/\/$/, '');
    if (connectivity && typeof connectivity === 'object') {
      connectivityState = {
        server_url: redactDiagnosticsSecrets(serverUrl),
        probe: connectivity.reachable == null ? 'not_probed' : connectivity.reachable ? 'reachable' : 'unreachable',
        note: typeof connectivity.note === 'string' ? connectivity.note.slice(0, 300) : null
      };
    } else {
      connectivityState = { server_url: redactDiagnosticsSecrets(serverUrl), probe: 'not_probed', note: null };
    }
  } catch (e) {
    note('connectivity', e);
  }
  // -- diagnostics-ops reader output (disk / network) --
  /** @type {Record<string, unknown>} */
  let readerOutput = {};
  try {
    if (readers && (readers.disk_usage || readers.network_connections)) {
      readerOutput = {
        disk_usage: readers.disk_usage || null,
        network_connections: readers.network_connections || null
      };
    } else {
      const handlers = makeDiagnosticsHandlers(platform);
      const disk = await handlers
        .disk_usage({ request_payload: {} })
        .catch((e) => ({ status: 'failed', error: String((e && e.message) || e) }));
      const net = await handlers
        .network_connections({ request_payload: { limit: 50 } })
        .catch((e) => ({ status: 'failed', error: String((e && e.message) || e) }));
      const diskPayload =
        disk && typeof disk === 'object' && 'result_payload' in disk ? disk.result_payload : null;
      const diskError =
        disk && typeof disk === 'object' && 'error' in disk ? disk.error : null;
      const netPayload =
        net && typeof net === 'object' && 'result_payload' in net ? net.result_payload : null;
      const netError = net && typeof net === 'object' && 'error' in net ? net.error : null;
      readerOutput = {
        disk_usage: diskPayload || { error: diskError || 'unknown' },
        network_connections: netPayload || { error: netError || 'unknown' }
      };
    }
  } catch (e) {
    note('readers', e);
  }
  const bundle = sanitizeBundleValue(
    {
      bundle_format: DIAGNOSTICS_BUNDLE_VERSION,
      generated_at: new Date().toISOString(),
      agent,
      platform: platformFacts,
      service,
      logs,
      config,
      connectivity: connectivityState,
      diagnostics_readers: readerOutput,
      collection_notes: notes,
      redaction:
        'values of secret-shaped keys replaced with [REDACTED]; free-text secret patterns redacted per feedback-service vocabulary'
    },
    resolvedHome
  );
  return bundle;
}
/**
 * Minimal ustar writer (regular files only, portable names):
 * dependency-free `.tar.gz` output without shelling out to `tar`.
 * @param {Record<string, string>} files name -> utf8 content
 */
export function packDiagnosticsTar(files) {
  const blocks = [];
  for (const [name, content] of Object.entries(files || {})) {
    const safeName = String(name).replace(/^\/+/, '').slice(0, 100);
    if (!safeName) continue;
    const data = Buffer.from(String(content ?? ''), 'utf8');
    const header = Buffer.alloc(512, 0);
    header.write(safeName, 0, 'utf8');
    header.write('0000600', 100, 'utf8');
    header.write('0000000', 108, 'utf8');
    header.write('0000000', 116, 'utf8');
    header.write(data.length.toString(8).padStart(11, '0'), 124, 'utf8');
    header.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0'), 136, 'utf8');
    header[156] = 0x30;
    header.write('ustar', 257, 'utf8');
    header.write('00', 263, 'utf8');
    header.write('nc', 265, 'utf8');
    header.write('nc', 297, 'utf8');
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : header[i];
    header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'utf8');
    blocks.push(header);
    if (data.length) {
      blocks.push(data);
      const pad = (512 - (data.length % 512)) % 512;
      if (pad) blocks.push(Buffer.alloc(pad, 0));
    }
  }
  blocks.push(Buffer.alloc(1024, 0));
  return Buffer.concat(blocks);
}

/**
 * @param {Record<string, string>} files name -> utf8 content
 */
export function packDiagnosticsTarGz(files) {
  return zlib.gzipSync(packDiagnosticsTar(files));
}

/**
 * Render the stdout summary: bundle inventory plus exactly what was
 * redacted, so the user knows what they are about to attach to a ticket.
 * @param {Record<string, unknown>} bundle
 * @param {{ wrote?: string|null, dryRun?: boolean }} [options]
 */
export function renderDiagnosticsSummary(bundle, { wrote = null, dryRun = true } = {}) {
  const b = bundle || {};
  /** @param {unknown} v @returns {Record<string, unknown>} */
  const rec = (v) => (v && typeof v === 'object' ? /** @type {Record<string, unknown>} */ (v) : {});
  const logs = rec(b.logs);
  /** @type {Array<string>} */
  const logLines = [];
  for (const [label, tail] of Object.entries(logs)) {
    const t = rec(tail);
    if (tail && typeof tail === 'object' && t.missing) {
      logLines.push(`${label}: unavailable (${t.error || 'missing'})`);
    } else {
      const n = typeof t.lines_returned === 'number' ? t.lines_returned : 0;
      const trunc = t.truncated ? ' (truncated)' : '';
      logLines.push(`${label}: ${n} lines${trunc}`);
    }
  }
  const config = rec(b.config);
  const envKeys = typeof config.env === 'object' ? Object.keys(rec(config.env)).length : 0;
  const fileKeys = typeof config.env_file === 'object' ? Object.keys(rec(config.env_file)).length : 0;
  const notes = Array.isArray(b.notes) ? b.notes : Array.isArray(b.collection_notes) ? b.collection_notes : [];
  const agent = rec(b.agent);
  const plat = rec(b.platform);
  const conn = rec(b.connectivity);
  const readers = rec(b.diagnostics_readers);
  const svcRows = /** @type {Array<Record<string, unknown>>} */ (Array.isArray(b.service) ? b.service : []);
  const svc = svcRows.length ? svcRows.map((s) => `${s.unit}=${s.state}`).join(', ') : 'unknown';
  const lines = [
    'Node Command diagnostics bundle' + (dryRun && !wrote ? ' - preview (dry-run, nothing written)' : ''),
    `format: ${b.bundle_format || DIAGNOSTICS_BUNDLE_VERSION}; generated: ${b.generated_at || 'unknown'}`,
    `agent: version ${agent.version || 'unknown'}; root ${agent.root || 'unknown'}`,
    `platform: ${plat.type || plat.platform || process.platform} ${plat.arch || ''} node ${plat.node_version || process.version}`.trim(),
    `service: ${svc}`,
    `logs: ${logLines.length ? logLines.join('; ') : 'none'}`,
    `config: ${envKeys} live NC_* keys + ${fileKeys} env-file keys (secret values replaced with [REDACTED])`,
    `connectivity: ${conn.server_url || 'unknown'} (${conn.probe || 'not_probed'})`,
    `readers: disk_usage + network_connections ${readers.disk_usage ? 'included' : 'unavailable'}`,
    'redaction: secret-shaped values (tokens nc_tok_*/nc_enr_*, HMAC keys, client secrets, cookies, private keys) replaced with [REDACTED]; home dir folded to ~',
    notes.length
      ? `partial failures (${notes.length}): ${notes.map((n) => `${n && n.section}: ${n && n.error}`).join('; ')}`
      : 'partial failures: none - all sections collected',
    wrote
      ? `wrote: ${wrote} - attach this file to your support ticket`
      : 'not written: re-run with --diagnostics --apply [--output <path>] to write the .tar.gz archive'
  ];
  return lines.join('\n');
}

/**
 * Run the `--diagnostics` command: collect, then preview (default) or
 * write the archive with `--apply`. Never throws a stack trace to the
 * caller: failures resolve to `{ ok: false }` with a friendly summary.
 * @param {object} [options]
 * @param {Array<string>} [options.argv]
 * @param {string} [options.platform]
 * @param {string} [options.root]
 * @param {Record<string, string|undefined>} [options.env]
 * @param {string} [options.version]
 * @param {(f: string, d: Uint8Array) => Promise<void>} [options.writeFile]
 * @param {object} [options.collectOptions]
 */
export async function runDiagnosticsCommand({
  argv = [],
  platform = process.platform,
  root = undefined,
  env = process.env,
  version = 'unknown',
  writeFile = null,
  collectOptions = {}
} = {}) {
  const parsed = parseDiagnosticsArgv(argv);
  if (!parsed.enabled) return { handled: false, ok: false, summary: '', outputPath: null };
  try {
    let layout = null;
    try {
      const paths = await import('../client/nc-paths.mjs');
      const base = root !== undefined && root !== null ? root : paths.runtimeRoot(platform);
      layout = paths.ncLayout(base, platform);
    } catch (e) {
      return {
        handled: true,
        ok: false,
        outputPath: null,
        summary: `diagnostics collection failed: could not resolve the agent layout (${e instanceof Error ? e.message : String(e)}). Suggested action: verify the install directory is readable and re-run.`
      };
    }
    const bundle = await collectDiagnosticsBundle({
      platform,
      layout,
      version,
      env,
      ...(collectOptions || {})
    });
    if (!parsed.apply) {
      return {
        handled: true,
        ok: true,
        outputPath: null,
        dryRun: true,
        bundle,
        summary: renderDiagnosticsSummary(bundle, { dryRun: true })
      };
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    let outPath = parsed.output || path.join(process.cwd(), `nodecommand-diagnostics-${stamp}.tar.gz`);
    if (!outPath.endsWith('.tar.gz')) outPath += '.tar.gz';
    const summaryForFile = renderDiagnosticsSummary(bundle, { dryRun: false, wrote: outPath });
    const files = {
      'manifest.json': JSON.stringify(bundle, null, 2) + '\n',
      'summary.txt': summaryForFile + '\n',
      'config-redacted.json': JSON.stringify(bundle.config || {}, null, 2) + '\n',
      'platform.json': JSON.stringify(bundle.platform || {}, null, 2) + '\n',
      'readers.json': JSON.stringify(bundle.diagnostics_readers || {}, null, 2) + '\n'
    };
    const bundleLogs = bundle.logs && typeof bundle.logs === 'object' ? bundle.logs : {};
    for (const [label, tail] of Object.entries(bundleLogs)) {
      files[`logs/${label}.log`] = String((tail && tail.content) || '');
    }
    let archive = packDiagnosticsTarGz(files);
    if (archive.length > DIAGNOSTICS_MAX_OUTPUT_BYTES) {
      const slim = { ...files };
      for (const k of Object.keys(slim)) {
        if (k.startsWith('logs/')) slim[k] = '[omitted: bundle exceeded size bound]\n';
      }
      archive = packDiagnosticsTarGz(slim);
    }
    const writer =
      writeFile ||
      (async (f, d) => {
        await fs.writeFile(f, d, { mode: 0o600 });
      });
    try {
      await writer(outPath, archive);
    } catch (e) {
      const code = e && typeof e === 'object' && 'code' in e ? e.code : null;
      const hint =
        code === 'EACCES'
          ? 'Suggested action: choose a writable --output path or re-run with permission to write there.'
          : code === 'ENOSPC'
            ? 'Suggested action: free disk space and re-run.'
            : 'Suggested action: choose a different --output path and re-run.';
      return {
        handled: true,
        ok: false,
        outputPath: null,
        bundle,
        summary: `diagnostics bundle collected but the archive could not be written to ${outPath} (${code || (e instanceof Error ? e.message : String(e))}). ${hint}`
      };
    }
    return {
      handled: true,
      ok: true,
      outputPath: outPath,
      dryRun: false,
      bundle,
      summary: renderDiagnosticsSummary(bundle, { dryRun: false, wrote: outPath })
    };
  } catch (e) {
    return {
      handled: true,
      ok: false,
      outputPath: null,
      summary: `diagnostics collection failed (${e instanceof Error ? e.message : String(e)}). Suggested action: re-run with --diagnostics to preview; if the failure repeats, report the error text (no secrets are included) via nc_feedback.`
    };
  }
}
