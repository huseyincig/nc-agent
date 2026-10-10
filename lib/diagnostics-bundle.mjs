// nodecommand --diagnostics bundle builder (CLI side).
//
// Self-contained by design: this CLI ships as a dependency-free binary, so
// it cannot import the agent tree or the control plane. The redaction
// vocabulary below is aligned VERBATIM with the central sanitizer in
// apps/control-plane/lib/feedback-service.mjs (REDACT_PATTERNS /
// redactSecrets) and with redactDiagnosticsSecrets in
// apps/agent/core/diagnostics-ops.mjs; a parity test asserts all three
// agree on a shared fixture set.
//
// Default is dry-run/preview (rule #43): `nodecommand --diagnostics`
// prints an inventory summary and writes nothing. Add `--apply` to write
// the `.tar.gz` archive, optionally with `--output <path>`.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import child_process from 'node:child_process';

export const CLI_DIAGNOSTICS_VERSION = '1.0.0';
export const CLI_DIAGNOSTICS_MAX_LOG_BYTES = 65536;
export const CLI_DIAGNOSTICS_MAX_LOG_LINES = 500;

// PEM block pattern rebuilt from `-{5}` fragments so no literal
// five-dash private-key header sits in source (credential scanners flag
// the header itself). Semantics are identical to the PEM arm of
// redactSecrets in lib/feedback-service.mjs:61-73 — pasted PEM blocks
// still match; the shared parity test pins cross-sanitizer equality.
const PEM_PRIVATE_KEY_BLOCK_RE = new RegExp(
  '-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}[^-]*-{5}END [A-Z ]*PRIVATE KEY-{5}',
  'g'
);

const REDACT_PATTERNS = [
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

const SENSITIVE_KEY_RE =
  /(token|secret|passwd|password|cookie|hmac|private[_-]?key|api[_-]?key|auth|turnstile|stripe|session|credential|bearer|signing)/i;

/** @param {unknown} value */
export function redactCliSecrets(value) {
  if (typeof value !== 'string') return value;
  let out = value;
  // PEM blocks are redacted WHOLE, before the shared k=v callback runs:
  // that callback keys off `[:=]`, and real PEMs carry base64 `=` padding,
  // which would otherwise keep the armor header + prefix visible. Same
  // vocabulary as feedback-service.mjs (same shapes flagged), strictly
  // stricter replacement — never looser.
  PEM_PRIVATE_KEY_BLOCK_RE.lastIndex = 0;
  out = out.replace(PEM_PRIVATE_KEY_BLOCK_RE, '[REDACTED]');
  for (const re of REDACT_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, (m) => {
      if (!/[:=]/.test(m)) return '[REDACTED]';
      const key = m.split(/[:=]/, 1)[0];
      return `${key}: [REDACTED]`;
    });
  }
  return out;
}

/** @param {Record<string, unknown>} record */
export function redactCliEnvRecord(record) {
  const out = {};
  for (const [key, raw] of Object.entries(record || {})) {
    const k = String(key);
    if (SENSITIVE_KEY_RE.test(k)) {
      out[k] = '[REDACTED]';
      continue;
    }
    const cleaned = redactCliSecrets(typeof raw === 'string' ? raw : String(raw ?? ''));
    out[k] =
      typeof cleaned === 'string' && cleaned.length > 512
        ? cleaned.slice(0, 512) + '…[truncated]'
        : cleaned;
  }
  return out;
}

/** @param {unknown} value @param {string} [home] */
export function foldHomeDir(value, home = '') {
  if (typeof value !== 'string' || !value) return value;
  let h = home;
  if (!h) {
    try {
      h = os.homedir();
    } catch {
      h = '';
    }
  }
  if (h && value.includes(h)) return value.split(h).join('~');
  return value;
}

/** @param {Array<string>} [argv] */
export function parseCliDiagnosticsArgs(argv = []) {
  const args = Array.isArray(argv) ? argv.map(String) : [];
  let enabled = false;
  let apply = false;
  let output = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--diagnostics' || a.startsWith('--diagnostics=')) enabled = true;
    if (a === '--apply') apply = true;
    if (a === '--output' && i + 1 < args.length) output = args[++i];
    else if (a.startsWith('--output=')) output = a.slice('--output='.length);
  }
  return { enabled, apply, output };
}

/**
 * Best-effort service status for the platform agent units. Never throws.
 * @param {string} [platform]
 */
export function probeCliServiceStatus(platform = os.platform()) {
  const checks = [];
  const tryRun = (cmd, args) => {
    try {
      const out = child_process.execFileSync(cmd, args, {
        timeout: 8000,
        stdio: ['ignore', 'pipe', 'pipe']
      });
      return { ok: true, stdout: String(out || '') };
    } catch (err) {
      return { ok: false, stdout: String(err?.stdout || '') };
    }
  };
  if (platform === 'linux') {
    for (const args of [['is-active', 'nc-client.service'], ['--user', 'is-active', 'nc-client.service']]) {
      const r = tryRun('systemctl', args);
      const state = r.stdout.trim().toLowerCase();
      checks.push({
        unit: `systemctl ${args.join(' ')}`,
        state: state === 'active' ? 'active' : r.ok ? state || 'unknown' : 'unknown',
        detail: r.ok ? null : 'probe failed or unit absent'
      });
    }
  } else if (platform === 'darwin') {
    const r = tryRun('launchctl', ['print', 'system/com.nc.client']);
    checks.push({
      unit: 'system/com.nc.client',
      state: r.ok ? 'active' : 'unknown',
      detail: r.ok ? null : 'probe failed or daemon absent'
    });
  } else if (platform === 'win32') {
    const r = tryRun('sc.exe', ['query', 'NCClient']);
    checks.push({
      unit: 'NCClient',
      state: /RUNNING/.test(r.stdout) ? 'active' : /1060|FAILED/.test(r.stdout) ? 'absent' : 'unknown',
      detail: r.ok ? null : 'probe failed or service absent'
    });
  } else {
    checks.push({ unit: String(platform), state: 'unknown', detail: 'unsupported platform for service probe' });
  }
  return checks;
}

/**
 * @param {string} file
 * @param {number} [maxBytes]
 */
export function readCliLogTail(file, maxBytes = CLI_DIAGNOSTICS_MAX_LOG_BYTES) {
  try {
    let text = '';
    let truncated = false;
    try {
      const size = fs.statSync(file).size;
      if (size > maxBytes) {
        const fd = fs.openSync(file, 'r');
        try {
          const start = size - maxBytes;
          const buf = Buffer.alloc(maxBytes);
          const n = fs.readSync(fd, buf, 0, maxBytes, start);
          text = buf.subarray(0, n).toString('utf8');
          const nl = text.indexOf('\n');
          if (nl >= 0) text = text.slice(nl + 1);
          truncated = true;
        } finally {
          fs.closeSync(fd);
        }
      } else {
        text = fs.readFileSync(file, 'utf8');
      }
    } catch (err) {
      const code = err?.code;
      return {
        content: '',
        lines_returned: 0,
        truncated: false,
        missing: true,
        error: code === 'ENOENT' ? 'LOG_SOURCE_NOT_FOUND' : code === 'EACCES' ? 'LOG_PERMISSION_DENIED' : 'LOG_READ_FAILED'
      };
    }
    let rows = text.split(/\r?\n/);
    if (rows.length && rows[rows.length - 1] === '') rows.pop();
    if (rows.length > CLI_DIAGNOSTICS_MAX_LOG_LINES) {
      rows = rows.slice(-CLI_DIAGNOSTICS_MAX_LOG_LINES);
      truncated = true;
    }
    rows = rows.map((line) => redactCliSecrets(line));
    return { content: rows.join('\n'), lines_returned: rows.length, truncated, missing: false };
  } catch {
    return { content: '', lines_returned: 0, truncated: false, missing: true, error: 'LOG_READ_FAILED' };
  }
}

/**
 * Collect the CLI-side diagnostics bundle. Every section is guarded so a
 * permission error or missing file degrades to a note, never a crash.
 * @param {object} [options]
 * @param {string} [options.ncRoot]
 * @param {string} [options.platform]
 * @param {string} [options.home]
 * @param {Record<string, string|undefined>} [options.env]
 * @param {string} [options.cliVersion]
 * @param {string} [options.baseUrl]
 */
export function collectCliDiagnostics({
  ncRoot = null,
  platform = os.platform(),
  home = '',
  env = process.env,
  cliVersion = '0.1.0',
  baseUrl = null
} = {}) {
  const notes = [];
  const note = (section, error) => {
    notes.push({ section, error: String(error?.message || error || 'unknown').slice(0, 300) });
  };
  let resolvedHome = home;
  try {
    resolvedHome = home || os.homedir();
  } catch {
    resolvedHome = home || '';
  }
  const fold = (v) => {
    if (typeof v === 'string') return foldHomeDir(v, resolvedHome);
    if (Array.isArray(v)) return v.map(fold);
    if (v && typeof v === 'object') {
      const out = {};
      for (const [k, val] of Object.entries(v)) out[k] = fold(val);
      return out;
    }
    return v;
  };
  const root = ncRoot || process.env.NC_ROOT || null;
  const layoutPaths = root
    ? {
        root,
        config: path.join(root, 'config'),
        data: path.join(root, 'data'),
        logs: path.join(root, 'logs'),
        env_file: path.join(root, 'config', 'nc-client.env'),
        device_key: path.join(root, 'config', 'nc-device-key.pem'),
        enroll_state: path.join(root, 'config', 'nc-enroll-state.json'),
        client_log: path.join(root, 'logs', 'client.log')
      }
    : {};
  // -- agent files: presence + size only; key files are never opened --
  const files = {};
  try {
    for (const [label, file] of Object.entries(layoutPaths)) {
      if (label === 'root' || label === 'config' || label === 'data' || label === 'logs') continue;
      try {
        const st = fs.statSync(file);
        files[label] = { present: true, size_bytes: st.size, path: fold(file) };
      } catch (err) {
        files[label] = {
          present: false,
          error: err?.code === 'ENOENT' ? 'not_found' : err?.code === 'EACCES' ? 'permission_denied' : 'stat_failed'
        };
      }
    }
  } catch (err) {
    note('agent.files', err);
  }
  // -- enroll state: phase/host only, never tokens --
  let pairing = null;
  try {
    if (layoutPaths.enroll_state && files.enroll_state?.present) {
      const parsed = JSON.parse(fs.readFileSync(layoutPaths.enroll_state, 'utf8'));
      pairing = {
        phase: typeof parsed?.phase === 'string' ? parsed.phase : null,
        host_configured: Boolean(files.env_file?.present)
      };
    } else {
      pairing = { phase: null, host_configured: Boolean(files.env_file?.present) };
    }
  } catch (err) {
    note('agent.pairing', err);
    pairing = { phase: null, host_configured: Boolean(files.env_file?.present) };
  }
  // -- platform / runtime facts --
  let platformFacts = {};
  try {
    platformFacts = {
      platform,
      arch: os.arch(),
      release: os.release(),
      type: os.type(),
      cpus: os.cpus()?.length || null,
      total_memory_bytes: os.totalmem(),
      free_memory_bytes: os.freemem(),
      uptime_seconds: Math.floor(os.uptime()),
      node_version: process.version,
      hostname: os.hostname()
    };
  } catch (err) {
    note('platform', err);
  }
  // -- service status --
  let service = [];
  try {
    service = probeCliServiceStatus(platform);
  } catch (err) {
    note('service', err);
    service = [{ unit: 'probe', state: 'unknown', detail: 'service probe failed' }];
  }
  // -- bounded, redacted log tails --
  const logs = {};
  try {
    const candidates = [];
    if (layoutPaths.client_log) candidates.push(['client', layoutPaths.client_log]);
    for (const [label, file] of candidates.slice(0, 4)) {
      logs[label] = readCliLogTail(file);
    }
    if (!candidates.length) logs.client = { content: '', lines_returned: 0, truncated: false, missing: true, error: 'no agent root resolved' };
  } catch (err) {
    note('logs', err);
  }
  // -- config keys with secrets stripped --
  let config = {};
  try {
    const live = {};
    for (const [k, v] of Object.entries(env || {})) {
      if (!k.startsWith('NC_')) continue;
      if (Object.keys(live).length >= 100) break;
      live[k] = v;
    }
    let fileKeys = {};
    try {
      if (layoutPaths.env_file && files.env_file?.present) {
        const text = fs.readFileSync(layoutPaths.env_file, 'utf8');
        const parsed = {};
        for (const line of String(text).split(/\r?\n/)) {
          const t = line.trim();
          if (!t || t.startsWith('#')) continue;
          const i = t.indexOf('=');
          if (i > 0) parsed[t.slice(0, i).trim()] = t.slice(i + 1).trim();
        }
        fileKeys = parsed;
      }
    } catch (err) {
      note('config.env_file', err);
    }
    config = { env: redactCliEnvRecord(live), env_file: redactCliEnvRecord(fileKeys) };
  } catch (err) {
    note('config', err);
  }
  // -- connectivity state (endpoints only; reachability is a live probe) --
  let connectivity = { server_url: null, probe: 'not_probed', note: null };
  try {
    const serverUrl = String(
      baseUrl || env?.NC_SERVER_URL || env?.NC_BASE_URL || 'https://agent.nodecommand.app'
    ).replace(/\/$/, '');
    connectivity = { server_url: redactCliSecrets(serverUrl), probe: 'not_probed', note: null };
  } catch (err) {
    note('connectivity', err);
  }
  return fold({
    bundle_format: CLI_DIAGNOSTICS_VERSION,
    generated_at: new Date().toISOString(),
    cli_version: cliVersion,
    agent: { root: root ? fold(root) : null, files, pairing },
    platform: platformFacts,
    service,
    logs,
    config,
    connectivity,
    collection_notes: notes,
    redaction:
      'values of secret-shaped keys replaced with [REDACTED]; free-text secret patterns redacted per feedback-service vocabulary'
  });
}

/**
 * Minimal ustar writer (regular files only). Mirrors packDiagnosticsTar in
 * apps/agent/core/diagnostics-ops.mjs without importing it.
 * @param {Record<string, string>} files
 */
export function packCliTar(files) {
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

/** @param {Record<string, string>} files */
export function packCliTarGz(files) {
  return zlib.gzipSync(packCliTar(files));
}

/**
 * @param {Record<string, unknown>} bundle
 * @param {{ wrote?: string|null, dryRun?: boolean }} [options]
 */
export function renderCliSummary(bundle, { wrote = null, dryRun = true } = {}) {
  const b = bundle || {};
  const logLines = [];
  for (const [label, tail] of Object.entries(b.logs || {})) {
    logLines.push(
      `${label}: ${tail?.missing ? `unavailable (${tail?.error || 'missing'})` : `${tail?.lines_returned ?? 0} lines${tail?.truncated ? ' (truncated)' : ''}`}`
    );
  }
  const envKeys = b.config?.env ? Object.keys(b.config.env).length : 0;
  const fileKeys = b.config?.env_file ? Object.keys(b.config.env_file).length : 0;
  const notes = Array.isArray(b.collection_notes) ? b.collection_notes : [];
  const service = Array.isArray(b.service)
    ? b.service.map((s) => `${s?.unit}=${s?.state}`).join(', ')
    : 'unknown';
  return [
    'Node Command diagnostics bundle' + (dryRun && !wrote ? ' — preview (dry-run, nothing written)' : ''),
    `cli: ${b.cli_version || 'unknown'}; agent root: ${b.agent?.root || 'not resolved (set NC_ROOT)'}`,
    `platform: ${b.platform?.type || process.platform} ${b.platform?.arch || ''} node ${b.platform?.node_version || process.version}`.trim(),
    `service: ${service}`,
    `logs: ${logLines.length ? logLines.join('; ') : 'none'}`,
    `config: ${envKeys} live NC_* keys + ${fileKeys} env-file keys (secret values replaced with [REDACTED])`,
    `pairing: ${b.agent?.pairing?.phase || 'no state'}; host configured: ${b.agent?.pairing?.host_configured ? 'yes' : 'no'}`,
    `connectivity: ${b.connectivity?.server_url || 'unknown'} (${b.connectivity?.probe || 'not_probed'})`,
    'redaction: tokens (nc_tok_*/nc_enr_*/nc_pat_*/nc_rfk_*), HMAC keys, client secrets, Turnstile secrets, cookies, private keys → [REDACTED]; home dir folded to ~',
    notes.length
      ? `partial failures (${notes.length}): ${notes.map((n) => `${n?.section}: ${n?.error}`).join('; ')}`
      : 'partial failures: none — all sections collected',
    'next: attach the redacted summary above to your nc_feedback report (include_diagnostics: true adds the server-side event window).',
    wrote
      ? `wrote: ${wrote} — attach this file to your support ticket`
      : 'not written: re-run with --diagnostics --apply [--output <path>] to write the .tar.gz archive'
  ].join('\n');
}

/**
 * Run `nodecommand --diagnostics`. Never throws: failures resolve to
 * `{ ok: false }` with a user-facing summary (no stack traces).
 * @param {Array<string>} [argv]
 * @param {object} [options]
 * @param {string} [options.ncRoot]
 * @param {Record<string, string|undefined>} [options.env]
 * @param {string} [options.cliVersion]
 * @param {string} [options.baseUrl]
 * @param {(file: string, data: Uint8Array) => void} [options.writeFile]
 * @param {string} [options.cwd]
 */
export function runCliDiagnostics(argv = [], { ncRoot = null, env = process.env, cliVersion = '0.1.0', baseUrl = null, writeFile = null, cwd = null } = {}) {
  const parsed = parseCliDiagnosticsArgs(argv);
  if (!parsed.enabled) return { handled: false, ok: false, summary: '', outputPath: null };
  try {
    let root = ncRoot;
    if (!root) {
      const e = env || {};
      if (e.NC_ROOT) root = e.NC_ROOT;
      else {
        const plat = os.platform();
        if (plat === 'win32') root = path.join(e.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'nc');
        else if (plat === 'darwin') root = path.join(os.homedir(), 'Library', 'Application Support', 'nc');
        else root = path.join(os.homedir(), '.local', 'share', 'nc');
      }
    }
    const bundle = collectCliDiagnostics({ ncRoot: root, env, cliVersion, baseUrl });
    if (!parsed.apply) {
      return { handled: true, ok: true, dryRun: true, outputPath: null, bundle, summary: renderCliSummary(bundle, { dryRun: true }) };
    }
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    let outPath = parsed.output || path.join(cwd || process.cwd(), `nodecommand-diagnostics-${stamp}.tar.gz`);
    if (!outPath.endsWith('.tar.gz')) outPath += '.tar.gz';
    const files = {
      'manifest.json': JSON.stringify(bundle, null, 2) + '\n',
      'summary.txt': renderCliSummary(bundle, { dryRun: false, wrote: outPath }) + '\n',
      'config-redacted.json': JSON.stringify(bundle.config || {}, null, 2) + '\n',
      'platform.json': JSON.stringify(bundle.platform || {}, null, 2) + '\n'
    };
    for (const [label, tail] of Object.entries(bundle.logs || {})) {
      files[`logs/${label}.log`] = String(tail?.content || '');
    }
    const archive = packCliTarGz(files);
    const writer =
      writeFile ||
      ((f, d) => {
        fs.mkdirSync(path.dirname(f), { recursive: true });
        fs.writeFileSync(f, d, { mode: 0o600 });
      });
    try {
      writer(outPath, archive);
    } catch (err) {
      const hint =
        err?.code === 'EACCES'
          ? 'Suggested action: choose a writable --output path or re-run with permission to write there.'
          : err?.code === 'ENOSPC'
            ? 'Suggested action: free disk space and re-run.'
            : 'Suggested action: choose a different --output path and re-run.';
      return {
        handled: true,
        ok: false,
        outputPath: null,
        bundle,
        summary: `diagnostics bundle collected but the archive could not be written to ${outPath} (${err?.code || err?.message || err}). ${hint}`
      };
    }
    return {
      handled: true,
      ok: true,
      dryRun: false,
      outputPath: outPath,
      bundle,
      summary: renderCliSummary(bundle, { dryRun: false, wrote: outPath })
    };
  } catch (err) {
    return {
      handled: true,
      ok: false,
      outputPath: null,
      summary: `diagnostics collection failed (${err?.message || err}). Suggested action: re-run with --diagnostics to preview; if the failure repeats, report the error text (no secrets are included) via nc_feedback.`
    };
  }
}
