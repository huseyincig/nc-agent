import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { ncLayout } from './nc-paths.mjs';
import { normalizeTimingMs, restartInterruptionPayload } from './shell-runner.mjs';
import { browserAuditSummary } from '../browser/browser-manager.mjs';
import { redactDiagnosticsSecrets } from '../diagnostics/diagnostics-ops.mjs';
import {
  clearRetirementCandidate,
  normalizeRetirementCandidate,
  observeRetirementResponse
} from '../lifecycle/lifecycle.mjs';

const layout = ncLayout();

/**
 * @param {object} [options]
 * @param {string} [options.platform]
 * @param {(file: string) => boolean} [options.exists]
 * @param {(file: string) => string} [options.read]
 */
export function detectLegacyArtifacts({
  platform = process.platform,
  exists = fsSync.existsSync,
  read = /** @type {(file: string) => string} */ ((file) => fsSync.readFileSync(file, 'utf8'))
} = {}) {
  const found = [];
  if (platform === 'linux' || platform === 'darwin') {
    const retiredRoot = '/' + ['work', 'space'].join('');
    for (const [code, target] of [
      ['legacy_client_tree', retiredRoot + '/nc-client'],
      ['legacy_mcp_tree', retiredRoot + '/nc-mcp'],
      ['legacy_update_cache', retiredRoot + '/.nc-client-updates'],
      ['legacy_usr_local', '/usr/local/nc'],
      ['legacy_etc_config', '/etc/nc']
    ]) {
      try {
        if (exists(target)) found.push(code);
      } catch {}
    }
    if (platform === 'linux') {
      const unit = '/etc/systemd/system/nc-mcp.service',
        clientUnit = '/etc/systemd/system/nc-client.service';
      try {
        if (exists(unit) && String(read(unit)).includes(retiredRoot + '/nc-mcp'))
          found.push('obsolete_systemd_unit');
      } catch {}
      try {
        if (exists(clientUnit) && /^Environment=NC_ROOT=/m.test(String(read(clientUnit))))
          found.push('obsolete_root_env');
      } catch {}
    } else if (platform === 'darwin') {
      const plist = '/Library/LaunchDaemons/com.nc.client.plist';
      try {
        if (exists(plist) && /<key>NC_ROOT<\/key>/.test(String(read(plist))))
          found.push('obsolete_root_env');
      } catch {}
    }
  } else if (platform === 'win32') {
    const pf = String(process.env.ProgramFiles || 'C:\\Program Files'),
      pd = String(process.env.ProgramData || 'C:\\ProgramData');
    for (const [code, target] of [
      ['legacy_program_files', pf + '\\NC'],
      ['legacy_program_data', pd + '\\NC']
    ]) {
      try {
        if (exists(target)) found.push(code);
      } catch {}
    }
  }
  return [...new Set(found)].sort();
}

export function filesystemLayoutMetadata(customLayout = layout) {
  return {
    root: customLayout.root,
    app: customLayout.app,
    config: customLayout.config,
    data: customLayout.data,
    logs: customLayout.logs,
    legacy_artifacts: detectLegacyArtifacts()
  };
}

/**
 * Install mode advertised to central: 'user' when the stamped service env
 * says so, 'system' otherwise. Drives central's default roots seeding.
 */
export function agentInstallMode(env = process.env) {
  return env.NC_SERVICE_MODE === 'user' ? 'user' : 'system';
}

/**
 * Existing per-user work folders (Desktop, Documents) for central's default
 * roots seeding on user-mode hosts. Existing dirs only, nonexistent names
 * omitted so central never seeds dead paths. Sync readdir-free checks.
 * @param {string} [platform]
 * @param {string} [home]
 */
export function discoverUserFolders(platform = process.platform, home = null) {
  let base = home;
  if (!base) {
    try {
      base = os.homedir();
    } catch {
      return {};
    }
  }
  if (!base) return {};
  const out = {};
  for (const [key, parts] of [
    ['desktop', ['Desktop']],
    ['documents', ['Documents']]
  ]) {
    const p = path.join(base, ...parts);
    try {
      if (fsSync.existsSync(p) && fsSync.statSync(p).isDirectory()) out[key] = p;
    } catch {}
  }
  return out;
}

let auditWrites = 0;
/**
 * Bounded tail-compaction for append-only logs (P2-D6 pattern): unique tmp
 * per writer + wx so concurrent compactors never share one tmp path and a
 * pre-planted symlink/file fails closed instead of capturing the rewrite.
 * No-op unless the file exceeds maxRows; keeps the newest keepRows lines.
 * @param {string} file
 * @param {{keepRows?: number, maxRows?: number}} [options]
 */
export async function compactTailedFile(file, { keepRows = 5000, maxRows = 5500 } = {}) {
  const text = await fs.readFile(file, 'utf8');
  const rows = text.split('\n').filter(Boolean);
  if (rows.length <= maxRows) return false;
  const tmp = `${file}.tmp-${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  await fs.writeFile(tmp, rows.slice(-keepRows).join('\n') + '\n', {
    mode: 0o640,
    flag: 'wx'
  });
  try {
    await fs.rename(tmp, file);
  } catch (error) {
    await fs.unlink(tmp).catch(() => {});
    throw error;
  }
  return true;
}
/**
 * @param {string} op @param {unknown} [payload] @param {unknown} [result]
 * @param {string} [localAuditFile]
 */
export async function localAudit(op, payload, result, localAuditFile = process.env.NC_LOCAL_AUDIT_FILE || layout.auditLog) {
  const resultRec =
    result && typeof result === 'object' ? /** @type {Record<string, unknown>} */ (result) : null;
  try {
    const entry = {
      ts: new Date().toISOString(),
      op,
      payload,
      ok: resultRec?.status === 'completed',
      status: resultRec?.status || null,
      duration_ms: resultRec?.duration_ms ?? null,
      // A7 — timing analytics: numbers only, never output bodies (the
      // body ban above still holds). Missing/non-numeric resolves to null
      // (never undefined) via normalizeTimingMs.
      time_to_first_output_ms: normalizeTimingMs(resultRec?.time_to_first_output_ms),
      time_to_pattern_match_ms: normalizeTimingMs(resultRec?.time_to_pattern_match_ms),
      exit_code: resultRec?.exit_code ?? null,
      error: resultRec?.error || null
    };
    await fs.mkdir(path.dirname(localAuditFile), { recursive: true });
    await fs.appendFile(localAuditFile, JSON.stringify(entry) + '\n', { mode: 0o640 });
    auditWrites++;
    if (auditWrites % 100 === 0) {
      await compactTailedFile(localAuditFile);
    }
  } catch {}
}

/**
 * @param {string} op @param {Record<string, unknown>} [payload] @param {Record<string, unknown>} [result] @returns {Record<string, unknown>}
 */
export function localAuditPayload(op, payload = {}, result = {}) {
  if (op === 'file_write') {
    const rp =
      result?.result_payload && typeof result.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (result.result_payload)
        : {};
    return {
      path:
        typeof rp.path === 'string'
          ? rp.path
          : typeof payload.path === 'string'
            ? payload.path
            : null,
      mode: typeof payload.mode === 'string' ? payload.mode : null,
      encoding: typeof payload.encoding === 'string' ? payload.encoding : 'utf8',
      create_parents: payload.create_parents === true,
      content_bytes:
        typeof payload.content === 'string' ? Buffer.byteLength(payload.content, 'utf8') : null,
      expected_sha256: typeof payload.expected_sha256 === 'string' ? payload.expected_sha256 : null,
      previous_sha256: typeof rp.previous_sha256 === 'string' ? rp.previous_sha256 : null,
      result_sha256: typeof rp.sha256 === 'string' ? rp.sha256 : null
    };
  }
  if (op === 'directory_create') {
    const rp =
      result?.result_payload && typeof result.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (result.result_payload)
        : {};
    return {
      path:
        typeof rp.path === 'string'
          ? rp.path
          : typeof payload.path === 'string'
            ? payload.path
            : null,
      parents: payload.parents === true
    };
  }
  if (op === 'file_move') {
    const rp =
      result?.result_payload && typeof result.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (result.result_payload)
        : {};
    return {
      source:
        typeof rp.source === 'string'
          ? rp.source
          : typeof payload.source === 'string'
            ? payload.source
            : null,
      destination:
        typeof rp.destination === 'string'
          ? rp.destination
          : typeof payload.destination === 'string'
            ? payload.destination
            : null,
      overwrite: payload.overwrite === true
    };
  }
  if (op === 'file_delete') {
    const rp =
      result?.result_payload && typeof result.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (result.result_payload)
        : {};
    return {
      path:
        typeof rp.path === 'string'
          ? rp.path
          : typeof payload.path === 'string'
            ? payload.path
            : null,
      recursive: payload.recursive === true
    };
  }
  if (op === 'transfer_write') {
    // Chunk bytes never hit the audit log: only metadata. A transfer-heavy
    // workload would otherwise balloon audit.jsonl and stall every 100th
    // write on whole-file rotation reads.
    return {
      path: typeof payload.path === 'string' ? payload.path : null,
      offset: Number.isInteger(payload.offset) ? payload.offset : null,
      overwrite: payload.overwrite === true,
      finalize: payload.finalize === true,
      chunk_bytes:
        typeof payload.base64 === 'string' ? Buffer.byteLength(payload.base64, 'utf8') : null,
      expected_sha256: typeof payload.expected_sha256 === 'string' ? payload.expected_sha256 : null
    };
  }
  if (op === 'shell_exec' || op === 'privileged_shell_exec') {
    // V-32.4: the old fall-through returned the payload verbatim, logging
    // secrets embedded in the command line (tokens, passwords) in plaintext.
    // Keep the command for audit but pass it through the shared secret
    // sanitizer (same vocabulary as diagnostics bundles / feedback reports).
    const rawCommand = typeof payload.command === 'string' ? payload.command : null;
    const redactedCommand =
      typeof rawCommand === 'string' ? redactAuditFreeText(rawCommand).slice(0, 4096) : null;
    const out = {
      command: redactedCommand,
      command_bytes: typeof rawCommand === 'string' ? Buffer.byteLength(rawCommand, 'utf8') : null,
      cwd: typeof payload.cwd === 'string' ? payload.cwd : null,
      timeout_seconds: Number.isFinite(Number(payload.timeout_seconds)) ? Number(payload.timeout_seconds) : null
    };
    // Future-proof: never log an env record verbatim if one ever arrives.
    if (payload.env && typeof payload.env === 'object' && !Array.isArray(payload.env)) {
      out.env = maskAuditEnv(/** @type {Record<string, unknown>} */ (payload.env));
    }
    return out;
  }
  if (op === 'process_start' || op === 'process_manage') {
    // V-32.4: process_start carries a model-supplied env record whose VALUES
    // must never reach the audit log in plaintext. Keys are kept for
    // inventory; every value is masked. Args may embed secrets
    // (--token=..., password=...) so each is passed through the shared
    // free-text sanitizer.
    const rawArgs = Array.isArray(payload.args) ? payload.args : null;
    return {
      executable: typeof payload.executable === 'string' ? payload.executable : null,
      args: rawArgs ? rawArgs.map((a) => redactAuditFreeText(String(a)).slice(0, 512)).slice(0, 64) : null,
      cwd: typeof payload.cwd === 'string' ? payload.cwd : null,
      env:
        payload.env && typeof payload.env === 'object' && !Array.isArray(payload.env)
          ? maskAuditEnv(/** @type {Record<string, unknown>} */ (payload.env))
          : null,
      timeout_seconds: Number.isFinite(Number(payload.timeout_seconds)) ? Number(payload.timeout_seconds) : null,
      idle_timeout_seconds: Number.isFinite(Number(payload.idle_timeout_seconds))
        ? Number(payload.idle_timeout_seconds)
        : null,
      process_id: typeof payload.process_id === 'string' ? payload.process_id : null
    };
  }
  if (typeof op === 'string' && op.startsWith('browser_')) {
    return browserAuditSummary(op, payload, result);
  }
  // Generic backstop: any other payload carrying an env record gets its
  // values masked rather than logged verbatim.
  if (payload && typeof payload.env === 'object' && payload.env !== null && !Array.isArray(payload.env)) {
    return {
      ...payload,
      env: maskAuditEnv(/** @type {Record<string, unknown>} */ (payload.env))
    };
  }
  return payload;
}

/**
 * Shared sanitizer plus CLI flag-form backstop (`--password s3cr3t`,
 * `--token=xxx`): the shared vocabulary only covers `key[:=]value`, so a
 * space-separated flag value would otherwise survive. Strictly stricter
 * than the shared helper, never looser.
 * @param {unknown} text
 * @returns {string}
 */
function redactAuditFreeText(text) {
  const once = String(redactDiagnosticsSecrets(String(text ?? '')));
  return once.replace(
    /(--?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|auth|authorization)[=\s]+)([^\s;,}]+)/gi,
    '$1[REDACTED]'
  );
}

/**
 * Mask every value of an env-style record for audit logging. Keys are kept
 * (inventory) while values become '[REDACTED]'. Runs the shared free-text
 * sanitizer first so pasted token [REDACTED] in keys are also neutralized,
 * then masks values wholesale (a generic secret like HUNTER2 under an
 * innocuous key must not survive just because the key is not sensitive).
 * Bounded to 256 entries to keep the audit line small.
 * @param {Record<string, unknown>} record
 * @returns {Record<string, string>}
 */
function maskAuditEnv(record) {
  /** @type {Record<string, string>} */
  const out = {};
  let n = 0;
  for (const [rawKey, rawValue] of Object.entries(record || {})) {
    if (n >= 256) break;
    n += 1;
    const cleanKey = String(redactDiagnosticsSecrets(String(rawKey))).slice(0, 256);
    void rawValue;
    out[cleanKey] = '[REDACTED]';
  }
  return out;
}

const MAX_BOUNDED_BYTES = 128 * 1024;
// Shrinking converges to MAX-64 (not MAX) so the metadata written AFTER the
// loop (`delivered_bytes` digits, `structural_fallback` flag) can never push
// the final envelope over the hard 128 KiB ceiling.
const BOUND_TARGET = MAX_BOUNDED_BYTES - 64;
const TRUNCATION_MARKER = '\n…[nc: wire response truncated]…\n';
const TRUNCATION_MARKER_BUF = Buffer.from(TRUNCATION_MARKER, 'utf8');
// Structural-fallback policy (Finding 4, SentinelX bounding.py:161-166):
// string-leaf passes cannot absorb bloat made of thousands of small nodes
// (e.g. a 5000-object file_list). When the payload stays over budget, the
// largest non-signal subtrees are substituted with bounded descriptors.
// Failure signal is never substituted: status/error/exit_code/duration_ms
// and the (already string-bounded) stdout/stderr tails always survive.
const STRUCTURAL_PRESERVED_KEYS = new Set([
  'status',
  'error',
  'exit_code',
  'duration_ms',
  'time_to_first_output_ms',
  'time_to_pattern_match_ms',
  'stdout',
  'stderr',
  'stdout_truncated',
  'stderr_truncated'
]);
const STRUCTURAL_FALLBACK_NOTE = 'result omitted: too large to bound field-wise';
const MAX_BOUND_VISITS_PER_PASS = 20000;

/**
 * Finds the largest string leaf in the dictionary/array tree using iterative DFS.
 * Skips _truncation metadata inside result_payload.
 * @param {Record<string, unknown>} root
 */
// Top-level failure-signal keys are never shrink candidates: chewing `error`
// (or `status`) to fit the budget would destroy exactly what the
// "never truncate away the error" rule protects. stdout/stderr stay
// shrinkable — head+tail preserves their tails by construction.
const NO_SHRINK_TOP_KEYS = new Set(['error', 'status']);
// Leaves at or below this size are never shrink candidates: chewing a 16-byte
// stderr tail (or an error_code) to fit the budget destroys signal for zero
// meaningful savings. Large streams still shrink (head+tail keeps their tails)
// and sub-threshold structural bloat is handled by the fallback below.
const MIN_SHRINK_BYTES = 256;

function findLargestStringLeaf(root) {
  let largest = null;
  /** @type {Array<{node: unknown, parent: any, key: string | number | null}>} */
  const stack = [{ node: root, parent: null, key: null }];
  const seen = new Set();
  let visits = 0;

  while (stack.length > 0) {
    const item = stack.pop();
    if (!item) continue;
    // Node-count bound: one pass never walks the whole tree of a giant
    // structure (progress still happens via the best leaf found so far;
    // the structural fallback below is the backstop).
    visits += 1;
    if (visits > MAX_BOUND_VISITS_PER_PASS) return largest;
    const { node, parent, key } = item;
    if (node === null || node === undefined) continue;

    if (typeof node === 'string') {
      const byteLength = Buffer.byteLength(node, 'utf8');
      if (byteLength > MIN_SHRINK_BYTES && (largest === null || byteLength > largest.byteLength)) {
        largest = { parent, key, byteLength, value: node };
      }
    } else if (Array.isArray(node)) {
      if (seen.has(node)) continue;
      seen.add(node);
      for (let i = 0; i < node.length; i++) {
        stack.push({ node: node[i], parent: node, key: i });
      }
    } else if (typeof node === 'object') {
      if (seen.has(node)) continue;
      seen.add(node);
      for (const [k, v] of Object.entries(node)) {
        if (node === root?.result_payload && k === '_truncation') {
          continue;
        }
        if (node === root && NO_SHRINK_TOP_KEYS.has(k)) {
          continue;
        }
        stack.push({ node: v, parent: node, key: k });
      }
    }
  }

  return largest;
}

/**
 * @param {unknown} result @returns {Record<string, unknown>}
 */
export function boundSessionResult(result) {
  if (!result || typeof result !== 'object') {
    return /** @type {Record<string, unknown>} */ (result);
  }
  const resultRec = /** @type {Record<string, unknown>} */ (result);
  const out = /** @type {Record<string, unknown>} */ (structuredClone(result));
  const original = Buffer.byteLength(JSON.stringify(out));
  if (original <= MAX_BOUNDED_BYTES) return out;

  /** @type {Record<string, unknown>} */
  const truncation = {
    response_truncated: true,
    original_bytes: original,
    delivered_bytes: 0,
    continuation_available: false,
    execution_status: resultRec.status
  };

  out.result_payload = {
    .../** @type {Record<string, unknown>} */ (out.result_payload || {}),
    _truncation: truncation
  };

  for (let pass = 0; pass < 64; pass++) {
    const currentBytes = Buffer.byteLength(JSON.stringify(out));
    if (currentBytes <= BOUND_TARGET) break;

    const largest = findLargestStringLeaf(out);
    if (!largest || largest.byteLength === 0 || !largest.parent) {
      break;
    }

    const raw = Buffer.from(largest.value, 'utf8');
    const ratio = Math.min(0.9, BOUND_TARGET / currentBytes);
    const targetKeep = Math.floor(raw.length * ratio);
    const keep = Math.max(0, Math.min(raw.length - 1, targetKeep));

    if (keep <= TRUNCATION_MARKER_BUF.length) {
      let trimmed = raw.subarray(0, keep).toString('utf8');
      while (Buffer.byteLength(trimmed, 'utf8') > keep && trimmed.length > 0) {
        trimmed = trimmed.slice(0, -1);
      }
      largest.parent[largest.key] = trimmed;
    } else {
      const avail = keep - TRUNCATION_MARKER_BUF.length;
      const head = Math.floor(avail * 0.6);
      const tail = avail - head;

      let headStr = raw.subarray(0, head).toString('utf8');
      while (Buffer.byteLength(headStr, 'utf8') > head && headStr.length > 0) {
        headStr = headStr.slice(0, -1);
      }

      let tailStr = tail > 0 ? raw.subarray(raw.length - tail).toString('utf8') : '';
      while (Buffer.byteLength(tailStr, 'utf8') > tail && tailStr.length > 0) {
        tailStr = tailStr.slice(1);
      }

      largest.parent[largest.key] = headStr + TRUNCATION_MARKER + tailStr;
    }
  }

  let currentBytes = 0;
  try {
    currentBytes = Buffer.byteLength(JSON.stringify(out));
  } catch {
    currentBytes = MAX_BOUNDED_BYTES + 1;
  }
  if (currentBytes > MAX_BOUNDED_BYTES) {
    // Structural-bloat fallback: substitute the largest non-signal top-level
    // subtrees with bounded descriptors until the envelope fits. Bounded
    // iteration (one pass over top-level keys): worst case every non-signal
    // key is a descriptor and the payload is trivially small — convergence
    // is guaranteed and no new memory grows without a bound.
    /** @param {unknown} v */
    const subtreeBytes = (v) => {
      try {
        return Buffer.byteLength(JSON.stringify(v));
      } catch {
        return Number.MAX_SAFE_INTEGER;
      }
    };
    const candidates = Object.keys(out)
      .filter((k) => !STRUCTURAL_PRESERVED_KEYS.has(k))
      .map((k) => ({ key: k, bytes: subtreeBytes(out[k]) }))
      .sort((a, b) => b.bytes - a.bytes);
    for (const { key, bytes } of candidates) {
      try {
        if (Buffer.byteLength(JSON.stringify(out)) <= BOUND_TARGET - 448) break;
      } catch {
        // Unstringifiable mid-repair: keep substituting.
      }
      out[key] =
        key === 'result_payload'
          ? {
              _truncation: truncation,
              note: STRUCTURAL_FALLBACK_NOTE,
              omitted_bytes: bytes
            }
          : { note: STRUCTURAL_FALLBACK_NOTE, omitted_bytes: bytes };
    }
    truncation.structural_fallback = true;
  }

  try {
    truncation.delivered_bytes = Buffer.byteLength(JSON.stringify(out));
    // Measure twice: the byte count includes its own decimal width, so the
    // first pass settles the digit count and the second reads the true size.
    truncation.delivered_bytes = Buffer.byteLength(JSON.stringify(out));
  } catch {
    truncation.delivered_bytes = MAX_BOUNDED_BYTES;
  }

  return out;
}

export function freshState() {
  return {
    offsets: /** @type {Record<string, number>} */ ({}),
    registered: false,
    registered_client_id: null,
    jobs: /** @type {Record<string, any>} */ ({}),
    pendingResults: /** @type {Record<string, unknown>} */ ({}),
    retirement: normalizeRetirementCandidate()
  };
}

/**
 * @param {any} state @param {string} clientId
 */
export function registrationStateForClient(state, clientId) {
  const registeredClientId =
    typeof state?.registered_client_id === 'string' ? state.registered_client_id : null;
  const registered = Boolean(state?.registered) && registeredClientId === clientId;
  return { registered, registered_client_id: registered ? registeredClientId : null };
}

export async function readState(stateFile = process.env.NC_STATE_FILE || layout.stateFile, clientId = process.env.NC_CLIENT_ID || os.hostname()) {
  try {
    const state = JSON.parse(await fs.readFile(stateFile, 'utf8'));
    state.offsets ||= {};
    state.jobs ||= {};
    state.pendingResults ||= {};
    state.retirement = normalizeRetirementCandidate(state.retirement);
    Object.assign(state, registrationStateForClient(state, clientId));
    return state;
  } catch {
    return freshState();
  }
}

export let stateWriteChain = Promise.resolve();

/**
 * @param {any} state
 * @param {string} [stateFile]
 */
export async function writeState(state, stateFile = process.env.NC_STATE_FILE || layout.stateFile) {
  const persist = async () => {
    await fs.mkdir(path.dirname(stateFile), { recursive: true });
    // Remove the single-file state.pendingResults dictionary from persisted state:
    const { pendingResults, ...toPersist } = state || {};
    // Unique tmp name per write: concurrent processes (e.g. parallel test
    // runners) sharing one state file must never share one tmp path, or a
    // rename by one writer deletes the other's tmp -> ENOENT on rename.
    const tmp = `${stateFile}.${process.pid}.${Date.now()}.${Math.floor(Math.random() * 1000000)}.tmp`;
    // V-32.5: 'wx' (O_CREAT|O_EXCL) fails with EEXIST instead of following
    // a planted symlink at the tmp path (default 'w' truncates through it).
    await fs.writeFile(tmp, `${JSON.stringify(toPersist, null, 2)}\n`, { mode: 0o640, flag: 'wx' });
    try {
      await fs.rename(tmp, stateFile);
    } catch (error) {
      try {
        await fs.unlink(tmp);
      } catch {}
      throw error;
    }
  };
  stateWriteChain = stateWriteChain.then(persist, persist);
  return stateWriteChain;
}

/**
 * @param {any} state
 * @param {string} [stateFile]
 */
export async function resetRetirementEvidence(state, stateFile = process.env.NC_STATE_FILE || layout.stateFile) {
  const next = clearRetirementCandidate(state.retirement);
  if (!next.changed) return;
  state.retirement = next.state;
  await writeState(state, stateFile);
}

/**
 * @param {any} state @param {unknown} error @param {object} [options]
 * @param {string} [options.serverUrl]
 * @param {string} [options.clientId]
 * @param {string} [options.stateFile]
 * @param {string} [options.retiredMarker]
 * @param {(level: string, message: string, extra?: unknown) => unknown} [options.logFn]
 */
export async function observeRetirementFailure(state, error, {
  serverUrl = process.env.NC_SERVER_URL || 'https://mcp.nodecommand.app',
  clientId = process.env.NC_CLIENT_ID || os.hostname(),
  stateFile = process.env.NC_STATE_FILE || layout.stateFile,
  retiredMarker = layout.retiredMarker,
  logFn = async () => {}
} = {}) {
  const next = observeRetirementResponse(state.retirement, error, { serverUrl });
  if (next.changed) {
    state.retirement = next.state;
    await writeState(state, stateFile);
  }
  if (!next.retire) return false;
  const marker = {
    client_id: clientId,
    reason: 'CLIENT_NOT_FOUND',
    confirmed_at: new Date().toISOString(),
    confirmations: next.state.consecutive_not_found,
    server: serverUrl
  };
  await fs.writeFile(retiredMarker, `${JSON.stringify(marker, null, 2)}\n`, { mode: 0o640 });
  await logFn('error', 'client_retired', {
    client_id: clientId,
    reason: marker.reason,
    confirmations: marker.confirmations
  });
  return true;
}

/**
 * Boot confirmation for updates: when this process IS the version a
 * client_update job targeted, the update succeeded regardless of which
 * restart interleaving lost the result. Upgrades the pending/failed mark
 * to completed+activated (truthful: same binary that staged it now runs).
 * A version mismatch keeps the interrupted verdict. Runs after
 * markInterruptedJobs so it can override the restart mark.
 * @param {any} state
 * @param {string} runningVersion
 */
export function confirmCompletedUpdates(state, runningVersion) {
  let changed = false;
  for (const [jobId, record] of Object.entries(state.jobs || {})) {
    if (!record || record.tool !== 'client_update') continue;
    if (String(record.update_version || '') !== String(runningVersion || '')) continue;
    if (record.status !== 'running' && record.status !== 'result_pending') continue;
    state.pendingResults[jobId] = {
      status: 'completed',
      exit_code: 0,
      stdout: '',
      stderr: '',
      duration_ms: record.duration_ms || 0,
      error: null,
      stdout_truncated: false,
      stderr_truncated: false,
      result_payload: {
        version: runningVersion,
        activation_pending: false,
        activated: true,
        confirmed_at_boot: true
      }
    };
    record.status = 'result_pending';
    changed = true;
  }
  return changed;
}

/**
 * @param {any} state
 */
export function markInterruptedJobs(state) {
  let changed = false;
  for (const [jobId, record] of Object.entries(state.jobs || {})) {
    if (record?.status === 'running' && !state.pendingResults[jobId]) {
      // Restart-safety classification (shell-runner owns the taxonomy): the
      // marker embeds safe_to_retry/suggested_action so the control-plane
      // result-mapper can tell the model whether re-issuing is safe.
      let interruption = null;
      try {
        interruption = restartInterruptionPayload(record);
      } catch {
        interruption = null;
      }
      const fallbackPayload = {
        error_code: 'CLIENT_RESTART_DURING_EXECUTION',
        retryable: true
      };
      state.pendingResults[jobId] = {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        duration_ms: record.duration_ms || 0,
        error:
          (interruption && typeof interruption.error === 'string' && interruption.error) ||
          'CLIENT_RESTART_DURING_EXECUTION',
        stdout_truncated: false,
        stderr_truncated: false,
        result_payload:
          interruption && interruption.result_payload && typeof interruption.result_payload === 'object'
            ? interruption.result_payload
            : fallbackPayload
      };
      record.status = 'result_pending';
      changed = true;
    }
  }
  return changed;
}


export const MAX_PENDING_RESULTS = 500;
export const PENDING_RESULT_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Resolves the directory for pending results.
 * Defaults to `path.join(path.dirname(stateFile), 'pending-results')`.
 * @param {object|string} [options]
 * @returns {string}
 */
export function pendingResultsDir(options = {}) {
  if (typeof options === 'string') {
    if (path.extname(options) || options.endsWith('.json')) {
      return path.join(path.dirname(options), 'pending-results');
    }
    return options;
  }
  if (options && typeof options === 'object') {
    if (typeof options.dir === 'string') return options.dir;
    if (typeof options.stateFile === 'string') {
      return path.join(path.dirname(options.stateFile), 'pending-results');
    }
  }
  const defaultStateFile = process.env.NC_STATE_FILE || layout.stateFile;
  return path.join(path.dirname(defaultStateFile), 'pending-results');
}

/**
 * Atomically writes a job result to the pending-results directory.
 * Limits total files in the directory to 500 files by pruning oldest.
 *
 * @param {string} jobId
 * @param {unknown} result
 * @param {object|string} [options]
 * @returns {Promise<string>} Target file path
 */
export async function recordPendingResult(jobId, result, options = {}) {
  const dir = pendingResultsDir(options);
  await fs.mkdir(dir, { recursive: true });

  // Limit to 500 files: prune oldest if limit reached
  try {
    const entries = await fs.readdir(dir);
    const jsonFiles = entries.filter((f) => f.endsWith('.json') && !f.endsWith('.tmp'));
    if (jsonFiles.length >= MAX_PENDING_RESULTS) {
      const stats = await Promise.all(
        jsonFiles.map(async (file) => {
          try {
            const stat = await fs.stat(path.join(dir, file));
            return { file, mtimeMs: stat.mtimeMs };
          } catch {
            return { file, mtimeMs: 0 };
          }
        })
      );
      stats.sort((a, b) => a.mtimeMs - b.mtimeMs);
      const toDeleteCount = stats.length - (MAX_PENDING_RESULTS - 1);
      for (let i = 0; i < toDeleteCount; i++) {
        await fs.unlink(path.join(dir, stats[i].file)).catch(() => {});
      }
    }
  } catch {}

  const safeName = encodeURIComponent(jobId);
  const targetPath = path.join(dir, `${safeName}.json`);
  const tmpPath = path.join(
    dir,
    `${safeName}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}.tmp`
  );

  const payload = {
    jobId,
    result,
    recorded_at: Date.now()
  };

  // V-32.5: 'wx' (O_CREAT|O_EXCL) fails with EEXIST instead of following a
  // planted symlink at the tmp path (default 'w' truncates through it).
  await fs.writeFile(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o640, flag: 'wx' });
  try {
    await fs.rename(tmpPath, targetPath);
  } catch (error) {
    await fs.unlink(tmpPath).catch(() => {});
    throw error;
  }
  return targetPath;
}

/**
 * Reads pending results from the directory, enforces 24-hour TTL (deleting older files),
 * and enforces the 500-file cap.
 *
 * @param {object|string} [options]
 * @returns {Promise<Array<{jobId: string, result: unknown, filePath: string, remove: () => Promise<void>}>>}
 */
export async function drainPendingResults(options = {}) {
  const dir = pendingResultsDir(options);
  let entries;
  try {
    entries = await fs.readdir(dir);
  } catch {
    return [];
  }

  const jsonFiles = entries.filter((f) => f.endsWith('.json') && !f.endsWith('.tmp'));
  if (jsonFiles.length === 0) return [];

  const now = Date.now();
  const fileDetails = [];

  for (const file of jsonFiles) {
    const filePath = path.join(dir, file);
    try {
      const stat = await fs.stat(filePath);
      if (now - stat.mtimeMs > PENDING_RESULT_TTL_MS) {
        // Expired TTL: delete older file during drain
        await fs.unlink(filePath).catch(() => {});
        continue;
      }
      fileDetails.push({ file, filePath, mtimeMs: stat.mtimeMs });
    } catch {}
  }

  if (fileDetails.length > MAX_PENDING_RESULTS) {
    fileDetails.sort((a, b) => a.mtimeMs - b.mtimeMs);
    const excess = fileDetails.length - MAX_PENDING_RESULTS;
    const toDelete = fileDetails.splice(0, excess);
    for (const item of toDelete) {
      await fs.unlink(item.filePath).catch(() => {});
    }
  }

  fileDetails.sort((a, b) => a.mtimeMs - b.mtimeMs);

  const results = [];
  for (const item of fileDetails) {
    try {
      const content = await fs.readFile(item.filePath, 'utf8');
      const parsed = JSON.parse(content);
      if (typeof parsed?.recorded_at === 'number' && now - parsed.recorded_at > PENDING_RESULT_TTL_MS) {
        await fs.unlink(item.filePath).catch(() => {});
        continue;
      }
      const jobId = parsed?.jobId || parsed?.job_id || decodeURIComponent(path.basename(item.file, '.json'));
      const result = parsed?.result !== undefined ? parsed.result : parsed;
      results.push({
        jobId,
        result,
        filePath: item.filePath,
        async remove() {
          await fs.unlink(item.filePath).catch(() => {});
        }
      });
    } catch {}
  }

  return results;
}
