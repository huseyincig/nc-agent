import fs from 'node:fs/promises';
import { loadDeviceKey, deviceAuthHeaders } from './device-proof.mjs';
import {
  verifyPolicySignature,
  validatePolicy,
  policyBindingFromJob,
  policyBindingRecord,
  authorizeBoundJob
} from '../policy/host-policy.mjs';
import { boundSessionResult, writeState, localAudit, drainPendingResults } from './agent-state.mjs';
import { shellAbortByJob, isDangerousJobId } from './shell-runner.mjs';
import { cancelProjectTask } from '../structured-ops/project-ops.mjs';
import { maskedFrame } from './ws-client.mjs';

export const BINARY_HEADER_SIZE = 20;
export const TRANSFER_ID_SIZE = 16;
export const CHUNK_INDEX_SIZE = 4;

/**
 * Encodes a 16-byte transfer_id, 4-byte uint32 chunk_index, and payload into a binary frame.
 * @param {string | Buffer | Uint8Array} transferId
 * @param {number} chunkIndex
 * @param {Buffer | Uint8Array | string} [payload]
 * @returns {Buffer}
 */
export function encodeBinaryFrame(transferId, chunkIndex, payload = Buffer.alloc(0)) {
  const header = Buffer.alloc(BINARY_HEADER_SIZE);

  if (Buffer.isBuffer(transferId) || transferId instanceof Uint8Array) {
    const raw = Buffer.from(transferId);
    raw.copy(header, 0, 0, Math.min(TRANSFER_ID_SIZE, raw.length));
  } else if (typeof transferId === 'string') {
    const cleanHex = transferId.replace(/-/g, '');
    if (/^[0-9a-fA-F]{32}$/.test(cleanHex)) {
      Buffer.from(cleanHex, 'hex').copy(header, 0, 0, TRANSFER_ID_SIZE);
    } else {
      header.write(transferId, 0, TRANSFER_ID_SIZE, 'utf8');
    }
  }

  header.writeUInt32BE(Number(chunkIndex) >>> 0, TRANSFER_ID_SIZE);

  const p = Buffer.isBuffer(payload)
    ? payload
    : payload instanceof Uint8Array
      ? Buffer.from(payload)
      : Buffer.from(String(payload ?? ''));

  const frame = Buffer.concat([header, p]);
  /** @type {any} */ (frame).isFramed = true;
  return frame;
}

/**
 * Extracts and decodes the 20-byte header from a binary frame.
 * @param {Buffer | Uint8Array} frame
 * @returns {{
 *   transferId: string,
 *   transferIdRaw: Buffer,
 *   transferIdHex: string,
 *   chunkIndex: number,
 *   payload: Buffer
 * }}
 */
export function decodeBinaryFrame(frame) {
  const buf = Buffer.isBuffer(frame) ? frame : Buffer.from(frame);
  if (buf.length < BINARY_HEADER_SIZE) {
    throw new Error('INVALID_BINARY_FRAME_TOO_SHORT');
  }

  const transferIdRaw = Buffer.from(buf.subarray(0, TRANSFER_ID_SIZE));
  const chunkIndex = buf.readUInt32BE(TRANSFER_ID_SIZE);
  const payload = Buffer.from(buf.subarray(BINARY_HEADER_SIZE));

  const transferIdHex = transferIdRaw.toString('hex');
  const transferId = [
    transferIdHex.slice(0, 8),
    transferIdHex.slice(8, 12),
    transferIdHex.slice(12, 16),
    transferIdHex.slice(16, 20),
    transferIdHex.slice(20)
  ].join('-');

  return {
    transferId,
    transferIdRaw,
    transferIdHex,
    chunkIndex,
    payload
  };
}

/**
 * Extracts header metadata without slicing the full payload.
 * @param {Buffer | Uint8Array} frame
 * @returns {{
 *   transferId: string,
 *   transferIdRaw: Buffer,
 *   transferIdHex: string,
 *   chunkIndex: number,
 *   payloadLength: number
 * } | null}
 */
export function extractBinaryHeader(frame) {
  const buf = Buffer.isBuffer(frame) ? frame : Buffer.from(frame);
  if (buf.length < BINARY_HEADER_SIZE) return null;

  const transferIdRaw = Buffer.from(buf.subarray(0, TRANSFER_ID_SIZE));
  const chunkIndex = buf.readUInt32BE(TRANSFER_ID_SIZE);
  const transferIdHex = transferIdRaw.toString('hex');
  const transferId = [
    transferIdHex.slice(0, 8),
    transferIdHex.slice(8, 12),
    transferIdHex.slice(12, 16),
    transferIdHex.slice(16, 20),
    transferIdHex.slice(20)
  ].join('-');

  return {
    transferId,
    transferIdRaw,
    transferIdHex,
    chunkIndex,
    payloadLength: buf.length - BINARY_HEADER_SIZE
  };
}

export const PONG_TIMEOUT_MS = 10000;

/**
 * Liveness watchdog for one session (SYN-TRANS-001). Call `poke()` on every
 * inbound frame and `sentPing()` after each ping we emit. When `sentPing()`
 * is not followed by any inbound traffic within the window, `onTimeout`
 * fires once so the caller can destroy the (likely half-open) socket and
 * reconnect. All timing injectable for tests.
 * @param {{windowMs?: number, now?: () => number, setTimer?: typeof setTimeout, clearTimer?: typeof clearTimeout, onTimeout?: () => void}} [options]
 */
export function attachPongWatchdog({
  windowMs = PONG_TIMEOUT_MS,
  now = () => Date.now(),
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  onTimeout = () => {}
} = {}) {
  /** @type {ReturnType<typeof setTimeout> | null} */
  let timer = null;
  let fired = false;
  let lastActivityMs = now();
  const cancel = () => {
    if (timer) {
      clearTimer(timer);
      timer = null;
    }
  };
  return {
    poke() {
      if (fired) return;
      lastActivityMs = now();
      cancel();
    },
    sentPing() {
      if (fired) return;
      lastActivityMs = now();
      cancel();
      timer = setTimer(() => {
        timer = null;
        if (fired) return;
        fired = true;
        onTimeout();
      }, windowMs);
    },
    cancel,
    get armed() {
      return timer !== null;
    },
    get lastActivityMs() {
      return lastActivityMs;
    }
  };
}

/**
 * Reads a job-result payload without throwing on unexpected shapes.
 * Pending-results entries are always result objects in practice; anything
 * else yields undefined exactly where the old optional chains did.
 *
 * @param {unknown} result
 * @returns {Record<string, unknown>|undefined}
 */
export function resultPayloadOf(result) {
  if (!result || typeof result !== 'object') return undefined;
  const payload = /** @type {Record<string, unknown>} */ (result).result_payload;
  return payload && typeof payload === 'object'
    ? /** @type {Record<string, unknown>} */ (payload)
    : undefined;
}

/**
 * Sends a binary frame over websocket using sendBinary, send, or socket.write.
 * @param {any} ws
 * @param {Buffer} frame
 */
export function sendBinaryFrame(ws, frame) {
  if (typeof ws?.sendBinary === 'function') {
    ws.sendBinary(frame);
  } else if (typeof ws?.send === 'function') {
    ws.send(frame);
  } else if (ws?.socket && typeof ws.socket.write === 'function') {
    ws.socket.write(maskedFrame(2, frame));
  } else {
    throw new Error('WS_SEND_UNAVAILABLE');
  }
}

/**
 * Formats a binary frame from __binary_payload__, jobId, and result context.
 * @param {unknown} binaryPayload
 * @param {string} [jobId]
 * @param {unknown} [result]
 * @returns {Buffer}
 */
export function formatBinaryFrame(binaryPayload, jobId = '', result = null) {
  if (Buffer.isBuffer(binaryPayload) || binaryPayload instanceof Uint8Array) {
    const buf = Buffer.from(binaryPayload);
    const resObj = result && typeof result === 'object' ? /** @type {Record<string, unknown>} */ (result) : null;
    const explicitTransferId = resObj?.transfer_id ?? resObj?.transferId ?? (
      resObj?.result_payload && typeof resObj.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (resObj.result_payload).transfer_id
        : undefined
    );
    const explicitChunkIndex = resObj?.chunk_index ?? resObj?.chunkIndex ?? (
      resObj?.result_payload && typeof resObj.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (resObj.result_payload).chunk_index
        : undefined
    );
    if (explicitTransferId !== undefined) {
      return encodeBinaryFrame(String(explicitTransferId), Number(explicitChunkIndex ?? 0), buf);
    }
    if (/** @type {any} */ (binaryPayload).isFramed || /** @type {any} */ (binaryPayload)._isFramed) {
      return buf;
    }
    if (buf.length >= 20 && !jobId) {
      return buf;
    }
    return encodeBinaryFrame(jobId || '0000000000000000', Number(explicitChunkIndex ?? 0), buf);
  }
  if (typeof binaryPayload === 'object' && binaryPayload !== null) {
    const rec = /** @type {Record<string, unknown>} */ (binaryPayload);
    const resObj = result && typeof result === 'object' ? /** @type {Record<string, unknown>} */ (result) : null;
    const transferId = rec.transfer_id ?? rec.transferId ?? resObj?.transfer_id ?? resObj?.transferId ?? (
      resObj?.result_payload && typeof resObj.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (resObj.result_payload).transfer_id
        : undefined
    ) ?? jobId;
    const chunkIndex = rec.chunk_index ?? rec.chunkIndex ?? resObj?.chunk_index ?? resObj?.chunkIndex ?? (
      resObj?.result_payload && typeof resObj.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (resObj.result_payload).chunk_index
        : undefined
    ) ?? 0;
    const data = rec.data ?? rec.payload ?? rec.buffer ?? Buffer.alloc(0);
    return encodeBinaryFrame(
      typeof transferId === 'string' || Buffer.isBuffer(transferId) ? transferId : String(transferId || ''),
      Number(chunkIndex ?? 0),
      /** @type {Buffer | Uint8Array | string} */ (data)
    );
  }
  return encodeBinaryFrame(jobId || '0000000000000000', 0, Buffer.alloc(0));
}

/**
 * @param {any} ws @param {string} jobId @param {unknown} result
 */
export function sessionResponse(ws, jobId, result) {
  let binaryPayload = null;
  if (result && typeof result === 'object') {
    const resObj = /** @type {Record<string, unknown>} */ (result);
    if ('__binary_payload__' in resObj) {
      binaryPayload = resObj.__binary_payload__;
      delete resObj.__binary_payload__;
    } else if (
      resObj.result_payload &&
      typeof resObj.result_payload === 'object' &&
      '__binary_payload__' in /** @type {Record<string, unknown>} */ (resObj.result_payload)
    ) {
      const rp = /** @type {Record<string, unknown>} */ (resObj.result_payload);
      binaryPayload = rp.__binary_payload__;
      delete rp.__binary_payload__;
    }
  }

  if (binaryPayload !== null && binaryPayload !== undefined) {
    const frame = formatBinaryFrame(binaryPayload, jobId, result);
    sendBinaryFrame(ws, frame);
  }

  const bounded = boundSessionResult(result);
  const payload = {
    type: 'response',
    id: jobId,
    ok: bounded.status === 'completed',
    result: bounded,
    ...(bounded.status === 'completed'
      ? {}
      : {
          error: {
            code: bounded.error || 'REMOTE_OPERATION_FAILED',
            message: bounded.error || bounded.status
          }
        })
  };
  if (typeof ws?.sendJson === 'function') {
    ws.sendJson(payload);
  } else if (typeof ws?.send === 'function') {
    ws.send(JSON.stringify(payload));
  } else {
    throw new Error('WS_SEND_UNAVAILABLE');
  }
}

/**
 * Flushes pending results over the websocket using drainPendingResults().
 * If ws.send fails, files are preserved (fail-open).
 *
 * @param {any} [arg1]
 * @param {any} [arg2]
 * @param {any} [arg3]
 * @returns {Promise<boolean>}
 */
export async function flushSessionPending(arg1, arg2, arg3) {
  let state = null;
  let ws = null;
  let options = {};

  if (arg1 && (typeof arg1.sendJson === 'function' || typeof arg1.send === 'function')) {
    ws = arg1;
    options = arg2 || {};
  } else if (arg2 && (typeof arg2.sendJson === 'function' || typeof arg2.send === 'function')) {
    state = arg1;
    ws = arg2;
    options = arg3 || {};
  } else {
    state = arg1;
    ws = arg2;
    options = arg3 || {};
  }

  if (!ws || (typeof ws.sendJson !== 'function' && typeof ws.send !== 'function')) {
    return false;
  }

  const sentJobIds = new Set();
  const diskPending = await drainPendingResults(options);

  for (const item of diskPending) {
    if (state?.jobs?.[item.jobId]?.cancelRequested) continue;
    try {
      sessionResponse(ws, item.jobId, item.result);
      await item.remove();
      sentJobIds.add(item.jobId);
    } catch {
      // If ws.send fails, DO NOT delete the file (fail-open)
      return false;
    }
  }

  if (state?.pendingResults) {
    for (const [jobId, result] of Object.entries(state.pendingResults)) {
      if (sentJobIds.has(jobId)) continue;
      if (state?.jobs?.[jobId]?.cancelRequested) continue;
      try {
        sessionResponse(ws, jobId, result);
      } catch {
        return false;
      }
    }
  }

  return true;
}

/**
 * @param {string} serverUrl
 */
export function configuredTransportScheme(serverUrl) {
  try {
    return new URL(serverUrl).protocol === 'https:' ? 'https' : 'http';
  } catch {
    return 'http';
  }
}

export const transportProtected = (serverUrl) => configuredTransportScheme(serverUrl) === 'https';

let deviceKeyPromise = null;
export const getDeviceKey = (deviceKeyFile) => {
  if (!deviceKeyPromise) {
    // A failed load must not poison the cache: key rotation or a transient
    // disk error would otherwise fail all auth until process restart.
    const pending = loadDeviceKey(deviceKeyFile);
    deviceKeyPromise = pending;
    pending.catch(() => {
      if (deviceKeyPromise === pending) deviceKeyPromise = null;
    });
  }
  return deviceKeyPromise;
};

export async function authenticatedHeaders(method, absoluteUrl, {
  clientToken,
  clientId,
  deviceKeyFile,
  json = true
}) {
  if (!clientToken) throw new Error('CLIENT_TOKEN_REQUIRED');
  const privateKey = await getDeviceKey(deviceKeyFile);
  const baseHeaders = {
    ...(json ? { 'content-type': 'application/json' } : {}),
    ...deviceAuthHeaders({
      privateKey,
      clientId,
      method,
      url: absoluteUrl,
      token: clientToken
    })
  };
  return baseHeaders;
}

export async function requestJson(method, urlPath, body, timeoutMs = 7000, {
  serverUrl,
  clientToken,
  clientId,
  deviceKeyFile
}) {
  const absoluteUrl = `${serverUrl}${urlPath}`;
  const options = {
    method,
    headers: await authenticatedHeaders(method, absoluteUrl, { clientToken, clientId, deviceKeyFile }),
    signal: AbortSignal.timeout(timeoutMs)
  };
  if (body !== undefined) options.body = JSON.stringify(body);
  const response = await fetch(absoluteUrl, options);
  const text = await response.text();
  if (!response.ok) {
    const error = /** @type {Error & {status?: number, body?: string}} */ (
      new Error(`HTTP ${response.status}: ${text.slice(0, 500)}`)
    );
    error.status = response.status;
    error.body = text;
    throw error;
  }
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export const postJson = (urlPath, body, timeoutMs, opts) => requestJson('POST', urlPath, body, timeoutMs, opts);

export async function postJobStart(jobId, opts) {
  return postJson(
    `/api/clients/${encodeURIComponent(opts.clientId)}/jobs/${encodeURIComponent(jobId)}/start`,
    {},
    undefined,
    opts
  );
}

export async function postJobResult(jobId, result, opts) {
  return postJson(
    `/api/clients/${encodeURIComponent(opts.clientId)}/jobs/${encodeURIComponent(jobId)}/result`,
    result,
    15000,
    opts
  );
}

export function applyCurrentPolicy(policy, sig = null, { serverUrl, clientId }) {
  if (!transportProtected(serverUrl)) {
    const error = /** @type {Error & {code?: string}} */ (
      new Error('HOST_POLICY_TRANSPORT_UNPROTECTED')
    );
    error.code = 'HOST_POLICY_TRANSPORT_UNPROTECTED';
    throw error;
  }
  const verified = verifyPolicySignature(policy, sig, clientId);
  if (!verified.ok) {
    const error = /** @type {Error & {code?: string}} */ (
      new Error(/** @type {string} */ (verified.error))
    );
    error.code = /** @type {string} */ (verified.error);
    throw error;
  }
  const checked = validatePolicy(policy, clientId);
  if (!checked.ok) {
    const error = /** @type {Error & {code?: string}} */ (new Error(checked.error));
    error.code = checked.error;
    throw error;
  }
  return checked.policy;
}

export async function fetchCurrentPolicy({ serverUrl, clientId, clientToken, deviceKeyFile }) {
  try {
    const body = await requestJson(
      'GET',
      `/api/clients/${encodeURIComponent(clientId)}/policy`,
      undefined,
      7000,
      { serverUrl, clientId, clientToken, deviceKeyFile }
    );
    return applyCurrentPolicy(body?.policy, body?.policy_sig, { serverUrl, clientId });
  } catch (error) {
    const errRec = error && typeof error === 'object' ? error : null;
    if (errRec && 'code' in errRec && errRec.code) throw error;
    let code = 'HOST_POLICY_NOT_READY';
    try {
      const errBody = errRec && 'body' in errRec ? errRec.body : undefined;
      const body = JSON.parse(typeof errBody === 'string' && errBody ? errBody : '{}');
      const bodyRec = body && typeof body === 'object' ? body : null;
      if (bodyRec && 'error' in bodyRec && bodyRec.error) code = String(bodyRec.error);
    } catch {}
    const wrapped = /** @type {Error & {code?: string}} */ (new Error(code));
    wrapped.code = code;
    throw wrapped;
  }
}

export function policyFailureResult(check) {
  return {
    status: 'failed',
    exit_code: null,
    stdout: '',
    stderr: '',
    duration_ms: 0,
    error: check?.error || 'HOST_POLICY_NOT_READY',
    result_payload: {
      policy_error: check?.error || 'HOST_POLICY_NOT_READY',
      ...(Array.isArray(check?.denied_capabilities)
        ? { denied_capabilities: [...check.denied_capabilities] }
        : {})
    }
  };
}

export async function ensureJobPolicy(job, { serverUrl, clientId, clientToken, deviceKeyFile }) {
  const binding = policyBindingFromJob(job);
  if (!binding.ok) return binding;
  if (!binding.bound) {
    if (
      process.env.ALLOW_LEGACY_UNBOUND_JOBS === 'true' ||
      process.env.ALLOW_LEGACY_UNBOUND_JOBS === '1'
    ) {
      return { ok: true, bound: false };
    }
    return { ok: false, error: 'MISSING_POLICY_BINDING' };
  }
  try {
    const policy = await fetchCurrentPolicy({ serverUrl, clientId, clientToken, deviceKeyFile });
    return authorizeBoundJob(job, /** @type {any} */ (policy), { transportProtected: transportProtected(serverUrl) });
  } catch (error) {
    const policyErr = /** @type {Record<string, unknown>} */ (error);
    return { ok: false, error: policyErr?.code || 'HOST_POLICY_NOT_READY' };
  }
}

export async function auditPolicyFailure(job, result, localAuditFn = localAudit) {
  await localAuditFn(String(job?.tool || 'unknown'), { policy_enforced: true }, result);
}

export async function sendAuditLine(line, { serverUrl, clientId, clientToken, deviceKeyFile }) {
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    parsed = { raw: line };
  }
  const eventName = String(parsed.tool || parsed.event || parsed.action || 'audit');
  return postJson(`/api/clients/${encodeURIComponent(clientId)}/audit`, {
    event: eventName,
    payload: { source: 'nc-mcp', ingested_at: new Date().toISOString(), ...parsed }
  }, undefined, { serverUrl, clientId, clientToken, deviceKeyFile });
}

/** Single poll read cap for the audit/log forwarder (see readNewCompleteLines). Exported for tests. */
export const MAX_FORWARD_READ_BYTES = 1024 * 1024;
export async function readNewCompleteLines(file, offset, bootstrapBytes) {
  let stat = null;
  try {
    stat = await fs.stat(file);
  } catch {
    return { lines: [], nextOffset: typeof offset === 'number' ? offset : 0 };
  }
  let start = typeof offset === 'number' && Number.isFinite(offset) ? offset : null;
  if (start === null) start = Math.max(0, stat.size - bootstrapBytes);
  if (stat.size < start) start = 0;
  if (stat.size === start) return { lines: [], nextOffset: start };
  // One poll never buffers the whole backlog: a GB-scale log that grew
  // while offline is drained across polls instead of OOMing the agent.
  const length = Math.min(stat.size - start, MAX_FORWARD_READ_BYTES);
  const handle = await fs.open(file, 'r');
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, start);
    const text = buffer.subarray(0, bytesRead).toString('utf8');
    const lastNl = text.lastIndexOf('\n');
    if (lastNl < 0) return { lines: [], nextOffset: start };
    const complete = text.slice(0, lastNl);
    const lines = complete ? complete.split('\n').filter(Boolean) : [];
    return { lines, nextOffset: start + Buffer.byteLength(text.slice(0, lastNl + 1)) };
  } finally {
    await handle.close();
  }
}

/**
 * @param {any} state @param {string} key @param {string} file @param {(line: string) => Promise<void>} sender
 * @param {object} [options] @param {number} [options.bootstrapBytes] @param {string} [options.stateFile]
 */
export async function forwardFile(state, key, file, sender, { bootstrapBytes = 65536, stateFile } = {}) {
  const currentOffset = Object.prototype.hasOwnProperty.call(state.offsets, key)
    ? state.offsets[key]
    : null;
  const { lines, nextOffset } = await readNewCompleteLines(file, currentOffset, bootstrapBytes);
  let deliveredOffset = currentOffset;
  if (currentOffset === null && lines.length === 0) deliveredOffset = nextOffset;
  if (lines.length > 0) {
    const stat = await fs.stat(file);
    const base =
      currentOffset === null
        ? Math.max(0, stat.size - bootstrapBytes)
        : stat.size < currentOffset
          ? 0
          : currentOffset;
    let cursor = base;
    for (const line of lines) {
      await sender(line);
      cursor += Buffer.byteLength(`${line}\n`);
      deliveredOffset = cursor;
      state.offsets[key] = deliveredOffset;
      await writeState(state, stateFile);
    }
  } else {
    state.offsets[key] = deliveredOffset ?? nextOffset;
  }
  if (lines.length > 0 && deliveredOffset !== nextOffset) state.offsets[key] = nextOffset;
  await writeState(state, stateFile);
  return lines.length;
}

/**
 * P1-01: cooperative cancellation from the hub (`{type:'cancel', job_id}`).
 * Kills the tracked shell child (if any), marks the local record so the
 * late result is never sent (hub is already terminal), and drops the
 * registry entry. Unknown or already-settled jobs are silent no-ops.
 * @param {any} state @param {{job_id?: unknown}} msg
 * @param {{log?: (level: string, msg: string, extra?: Record<string, unknown>) => Promise<void>, stateFile?: string}} [options]
 */
export async function handleSessionCancel(state, msg, { log = async () => {}, stateFile } = {}) {
  const jobId = String(msg?.job_id || '');
  // P23 prototype-key guard: `state.jobs['__proto__']` reads Object.prototype
  // and `rec.cancelRequested = true` would pollute it process-wide.
  if (!jobId || isDangerousJobId(jobId)) return;
  try {
    const abort = shellAbortByJob.get(jobId);
    if (abort) {
      shellAbortByJob.delete(jobId);
      try {
        abort();
      } catch {}
    }
  } catch {}
  try {
    cancelProjectTask(jobId);
  } catch {}
  try {
    const rec = state?.jobs?.[jobId];
    if (rec && rec.status !== 'result_pending') {
      rec.cancelRequested = true;
      try {
        await writeState(state, stateFile);
      } catch {}
      try {
        await log('info', 'session_job_cancel_received', { job_id: jobId });
      } catch {}
    }
  } catch {}
}

/**
 * @param {any} state @param {any} ws @param {any} msg
 * @param {Record<string, any>} [options]
 */
export async function handleSessionJob(state, ws, msg, {
  ensurePolicy = async () => ({ ok: true }),
  policyFailure = () => ({ status: 'failed', error: 'HOST_POLICY_NOT_READY' }),
  auditPolicyFail = async () => {},
  executeTool = async () => ({ status: 'failed', error: 'NO_HANDLER' }),
  log = async () => {},
  stateFile
} = {}) {
  const jobId = String(msg?.id || ''),
    tool = String(msg?.op || '');
  // P23 prototype-key guard: `__proto__`/`constructor` ids read through to
  // Object.prototype (phantom pending/duplicate hits) and `state.jobs[id] =
  // record` would replace the container prototype. Fail closed like a
  // missing id.
  if (!jobId || isDangerousJobId(jobId)) return;
  if (state.pendingResults[jobId]) {
    sessionResponse(ws, jobId, state.pendingResults[jobId]);
    return;
  }
  if (state.jobs[jobId] && state.jobs[jobId].status !== 'result_pending') {
    await log('error', 'duplicate_session_job_blocked', {
      job_id: jobId,
      local_status: state.jobs[jobId].status
    });
    return;
  }
  const job = {
    id: jobId,
    tool,
    request_payload: msg.payload || {},
    policy_contract_version: msg.policy_contract_version ?? null,
    policy_revision: msg.policy_revision ?? null,
    policy_digest: msg.policy_digest ?? null,
    required_capabilities: msg.required_capabilities ?? null,
    admission_origin: msg.admission_origin ?? null
  };
  state.jobs[jobId] = {
    status: 'claimed',
    claimed_at: new Date().toISOString(),
    tool,
    policy_binding: policyBindingRecord(job)
  };
  await writeState(state, stateFile);
  const policyCheck = await ensurePolicy(job);
  let result;
  if (!policyCheck.ok) {
    result = policyFailure(policyCheck);
    await auditPolicyFail(job, result);
  } else {
    ws.sendJson({ type: 'event', kind: 'job_started', data: { job_id: jobId } });
    state.jobs[jobId].status = 'running';
    state.jobs[jobId].started_at = new Date().toISOString();
    await writeState(state, stateFile);
    const execStarted = Date.now();
    try {
      result = await executeTool(job);
    } catch (error) {
      result = {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: String(/** @type {Record<string, unknown>} */ (error)?.message || error),
        duration_ms: Date.now() - execStarted,
        result_payload: {}
      };
    }
  }
  state.pendingResults[jobId] = result;
  state.jobs[jobId].status = 'result_pending';
  state.jobs[jobId].finished_local_at = new Date().toISOString();
  await writeState(state, stateFile);
  try {
    if (state.jobs[jobId]?.cancelRequested) {
      try {
        await log('info', 'session_job_cancelled_locally', { job_id: jobId });
      } catch {}
    } else sessionResponse(ws, jobId, result);
  } catch {}
}
