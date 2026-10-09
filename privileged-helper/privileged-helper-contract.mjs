import crypto from 'node:crypto';

export const PRIVILEGED_HELPER_PROTOCOL_VERSION = '1.0.0';
export const PRIVILEGED_HELPER_MAX_TTL_MS = 300_000;
export const PRIVILEGED_HELPER_CLOCK_SKEW_MS = 10_000;
export const PRIVILEGED_HELPER_MAX_PAYLOAD_BYTES = 64 * 1024;
export const PRIVILEGED_HELPER_OPERATIONS = Object.freeze([
  'client_uninstall',
  'privileged_shell_exec',
  'service_control',
  'container_control',
  'compose_control',
  'package_control',
  'system_log_read',
  'file_permissions'
]);
export const PRIVILEGED_HELPER_ERRORS = Object.freeze([
  'PRIVILEGED_HELPER_NOT_AVAILABLE',
  'PRIVILEGED_HELPER_PROTOCOL_MISMATCH',
  'PRIVILEGED_HELPER_AUTH_REQUIRED',
  'PRIVILEGED_HELPER_AUTH_INVALID',
  'PRIVILEGED_HELPER_AUTH_EXPIRED',
  'PRIVILEGED_HELPER_REPLAY',
  'PRIVILEGED_HELPER_CLIENT_MISMATCH',
  'PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED',
  'PRIVILEGED_HELPER_POLICY_BINDING_MISMATCH',
  'PRIVILEGED_HELPER_PAYLOAD_MISMATCH'
]);

const CLIENT_ID_RE = /^nc_[0-9a-f]{64}$/;
const REQUEST_ID_RE = /^phreq_[0-9a-f]{32}$/;
const JOB_ID_RE = /^job_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KEY_ID_RE = /^phk_[0-9a-f]{16}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const ORIGINS = Object.freeze(['admin_api', 'mcp', 'system']);
/**
 * @param {unknown} v
 * @returns {v is Record<string, unknown>}
 */
const isObject = (v) => Boolean(v && typeof v === 'object' && !Array.isArray(v));
/**
 * @param {unknown} a
 * @param {unknown} b
 */
const sameArray = (a, b) =>
  Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => v === b[i]);

/**
 * @param {unknown} value
 * @param {number} [depth]
 * @returns {unknown}
 */
function canonicalValue(value, depth = 0) {
  if (depth > 8) throw new Error('PRIVILEGED_HELPER_PAYLOAD_MISMATCH');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map((v) => canonicalValue(v, depth + 1));
  if (isObject(value)) {
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const key of Object.keys(value).sort()) {
      const canonical = canonicalValue(value[key], depth + 1);
      // P23 prototype-key guard: `out['__proto__'] = v` invokes the
      // prototype setter, silently dropping the key from the integrity hash.
      // Preserve it as an own data property so the signed hash covers the
      // full input. (`constructor`/`prototype` assignments already create
      // own properties and serialize normally.)
      if (key === '__proto__')
        Object.defineProperty(out, key, {
          value: canonical,
          enumerable: true,
          writable: true,
          configurable: true
        });
      else out[key] = canonical;
    }
    return out;
  }
  throw new Error('PRIVILEGED_HELPER_PAYLOAD_MISMATCH');
}

/**
 * @param {unknown} payload
 */
export function canonicalPrivilegedPayload(payload) {
  if (!isObject(payload))
    throw Object.assign(new Error('PRIVILEGED_HELPER_PAYLOAD_MISMATCH'), {
      code: 'PRIVILEGED_HELPER_PAYLOAD_MISMATCH'
    });
  const encoded = JSON.stringify(canonicalValue(payload));
  if (Buffer.byteLength(encoded, 'utf8') > PRIVILEGED_HELPER_MAX_PAYLOAD_BYTES) {
    throw Object.assign(new Error('PRIVILEGED_HELPER_PAYLOAD_MISMATCH'), {
      code: 'PRIVILEGED_HELPER_PAYLOAD_MISMATCH'
    });
  }
  return encoded;
}

/**
 * @param {unknown} payload
 */
export function privilegedPayloadSha256(payload) {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(canonicalPrivilegedPayload(payload), 'utf8'))
    .digest('hex');
}

/**
 * @param {unknown} publicKey
 */
export function privilegedHelperPublicKeyId(publicKey) {
  const keyInput =
    publicKey && typeof publicKey === 'object'
      ? /** @type {Record<string, unknown>} */ (publicKey)
      : null;
  const key =
    keyInput?.type === 'public'
      ? /** @type {import('node:crypto').KeyObject} */ (publicKey)
      : crypto.createPublicKey(/** @type {import('node:crypto').KeyLike} */ (publicKey));
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('PRIVILEGED_HELPER_AUTH_INVALID');
  const der = key.export({ type: 'spki', format: 'der' });
  return 'phk_' + crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);
}

/**
 * @param {unknown} request
 */
function expectedPrivilegeBinding(request) {
  const req = /** @type {Record<string, unknown>} */ (request);
  const required = Array.isArray(req.required_capabilities)
    ? [...new Set(req.required_capabilities)].sort()
    : null;
  if (!required || !sameArray(required, req.required_capabilities)) return false;
  if (req.operation === 'privileged_shell_exec') {
    return (
      ORIGINS.includes(/** @type {string} */ (req.admission_origin)) &&
      sameArray(required, ['privileged_exec', 'shell_exec'])
    );
  }
  if (req.operation === 'client_uninstall') {
    return req.admission_origin === 'admin_api' && required.length === 0;
  }
  if (req.operation === 'service_control') {
    // Dedicated allowlisted service verbs only (never arbitrary shell):
    // MCP tool calls and dashboard host-ops, gated on the service_control
    // policy capability by central planning before signing.
    return (
      ['mcp', 'admin_api'].includes(/** @type {string} */ (req.admission_origin)) &&
      sameArray(required, ['service_control'])
    );
  }
  if (req.operation === 'container_control') {
    // Bounded container-runtime operations only (never arbitrary shell):
    // container_read carries process_inspect, container_logs carries
    // shell_exec. Central planning selects the binding per tool.
    return (
      ['mcp', 'admin_api'].includes(/** @type {string} */ (req.admission_origin)) &&
      (sameArray(required, ['process_inspect']) || sameArray(required, ['shell_exec']))
    );
  }
  if (req.operation === 'compose_control') {
    // Bounded compose operations only: compose_list carries file_read,
    // compose_op carries shell_exec.
    return (
      ['mcp', 'admin_api'].includes(/** @type {string} */ (req.admission_origin)) &&
      (sameArray(required, ['file_read']) || sameArray(required, ['shell_exec']))
    );
  }
  if (req.operation === 'package_control') {
    // Bounded system-scope package operations only, gated on
    // package_management by central planning before signing.
    return (
      ['mcp', 'admin_api'].includes(/** @type {string} */ (req.admission_origin)) &&
      sameArray(required, ['package_management'])
    );
  }
  if (req.operation === 'system_log_read') {
    // Bounded privileged system/service log reads only, gated on log_read.
    return (
      ['mcp', 'admin_api'].includes(/** @type {string} */ (req.admission_origin)) &&
      sameArray(required, ['log_read'])
    );
  }
  if (req.operation === 'file_permissions') {
    // Bounded file permission metadata changes (chmod/chown) via privileged helper.
    // Gated on privileged_exec + file_write capabilities, plus
    // directory_manage when recursive (mirrors requiredCapabilitiesForOperation).
    // Wording must stay semantically identical to the central/client copy.
    return (
      ['mcp', 'admin_api'].includes(/** @type {string} */ (req.admission_origin)) &&
      (sameArray(required, ['file_write', 'privileged_exec']) ||
        sameArray(required, ['directory_manage', 'file_write', 'privileged_exec']))
    );
  }
  return false;
}

/**
 * @param {unknown} request
 */
export function canonicalPrivilegedHelperClaims(request) {
  const req = /** @type {Record<string, unknown>} */ (request);
  const authorization =
    req.authorization && typeof req.authorization === 'object'
      ? /** @type {Record<string, unknown>} */ (req.authorization)
      : null;
  return JSON.stringify({
    protocol_version: req.protocol_version,
    request_id: req.request_id,
    job_id: req.job_id,
    client_id: req.client_id,
    operation: req.operation,
    admission_origin: req.admission_origin,
    policy_contract_version: req.policy_contract_version,
    policy_revision: req.policy_revision,
    policy_digest: req.policy_digest,
    required_capabilities: req.required_capabilities,
    issued_at_ms: req.issued_at_ms,
    expires_at_ms: req.expires_at_ms,
    payload_sha256: req.payload_sha256,
    key_id: authorization?.key_id
  });
}

/**
 * @param {unknown} request
 * @param {object} options
 * @param {import('node:crypto').KeyLike} options.privateKey
 * @param {string} options.keyId
 */
export function signPrivilegedHelperRequest(request, { privateKey, keyId }) {
  if (!KEY_ID_RE.test(String(keyId || ''))) throw new Error('PRIVILEGED_HELPER_AUTH_INVALID');
  const req = /** @type {Record<string, unknown>} */ (request);
  const unsigned = { ...req, authorization: { key_id: keyId } };
  const signature = crypto
    .sign(null, Buffer.from(canonicalPrivilegedHelperClaims(unsigned), 'utf8'), privateKey)
    .toString('base64url');
  return { ...req, authorization: { key_id: keyId, signature } };
}

/**
 * @param {unknown} request
 * @param {object} [options]
 * @param {unknown} [options.clientId]
 * @param {unknown} [options.publicKey]
 * @param {number} [options.nowMs]
 * @param {Set<string>} [options.replaySet]
 * @returns {{ok: false, error: string} | {ok: true, request: Record<string, unknown>}}
 */
export function verifyPrivilegedHelperRequest(
  request,
  { clientId, publicKey, nowMs = Date.now(), replaySet } = {}
) {
  if (!isObject(request)) return { ok: false, error: 'PRIVILEGED_HELPER_AUTH_INVALID' };
  const req = request;
  if (request.protocol_version !== PRIVILEGED_HELPER_PROTOCOL_VERSION)
    return { ok: false, error: 'PRIVILEGED_HELPER_PROTOCOL_MISMATCH' };
  if (
    !REQUEST_ID_RE.test(String(request.request_id || '')) ||
    !JOB_ID_RE.test(String(request.job_id || '')) ||
    !CLIENT_ID_RE.test(String(request.client_id || ''))
  )
    return { ok: false, error: 'PRIVILEGED_HELPER_AUTH_INVALID' };
  if (request.client_id !== clientId)
    return { ok: false, error: 'PRIVILEGED_HELPER_CLIENT_MISMATCH' };
  if (!PRIVILEGED_HELPER_OPERATIONS.includes(/** @type {string} */ (request.operation)))
    return { ok: false, error: 'PRIVILEGED_HELPER_OPERATION_NOT_ALLOWED' };
  if (
    req.policy_contract_version !== '1.0.0' ||
    !Number.isInteger(req.policy_revision) ||
    /** @type {number} */ (req.policy_revision) < 1 ||
    !SHA256_RE.test(String(req.policy_digest || '')) ||
    !expectedPrivilegeBinding(req)
  )
    return { ok: false, error: 'PRIVILEGED_HELPER_POLICY_BINDING_MISMATCH' };
  if (!Number.isSafeInteger(req.issued_at_ms) || !Number.isSafeInteger(req.expires_at_ms))
    return { ok: false, error: 'PRIVILEGED_HELPER_AUTH_INVALID' };
  const issuedAt = /** @type {number} */ (req.issued_at_ms);
  const expiresAt = /** @type {number} */ (req.expires_at_ms);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > PRIVILEGED_HELPER_MAX_TTL_MS)
    return { ok: false, error: 'PRIVILEGED_HELPER_AUTH_INVALID' };
  if (issuedAt > nowMs + PRIVILEGED_HELPER_CLOCK_SKEW_MS || expiresAt < nowMs)
    return { ok: false, error: 'PRIVILEGED_HELPER_AUTH_EXPIRED' };
  let payloadHash;
  try {
    payloadHash = privilegedPayloadSha256(request.payload);
  } catch {
    return { ok: false, error: 'PRIVILEGED_HELPER_PAYLOAD_MISMATCH' };
  }
  if (
    !SHA256_RE.test(String(request.payload_sha256 || '')) ||
    payloadHash !== request.payload_sha256
  )
    return { ok: false, error: 'PRIVILEGED_HELPER_PAYLOAD_MISMATCH' };
  const authorization = request.authorization;
  if (
    !isObject(authorization) ||
    !KEY_ID_RE.test(String(authorization.key_id || '')) ||
    !SIG_RE.test(String(authorization.signature || ''))
  )
    return { ok: false, error: 'PRIVILEGED_HELPER_AUTH_REQUIRED' };
  const signatureBytes = Buffer.from(/** @type {string} */ (authorization.signature), 'base64url');
  if (!publicKey) return { ok: false, error: 'PRIVILEGED_HELPER_AUTH_REQUIRED' };
  let expectedKeyId,
    verified = false;
  try {
    expectedKeyId = privilegedHelperPublicKeyId(publicKey);
    if (authorization.key_id !== expectedKeyId)
      return { ok: false, error: 'PRIVILEGED_HELPER_AUTH_INVALID' };
    verified = crypto.verify(
      null,
      Buffer.from(canonicalPrivilegedHelperClaims(request), 'utf8'),
      /** @type {import('node:crypto').KeyLike} */ (publicKey),
      signatureBytes
    );
  } catch {
    return { ok: false, error: 'PRIVILEGED_HELPER_AUTH_INVALID' };
  }
  if (!verified) return { ok: false, error: 'PRIVILEGED_HELPER_AUTH_INVALID' };
  const requestId = /** @type {string} */ (request.request_id);
  if (replaySet?.has(requestId)) return { ok: false, error: 'PRIVILEGED_HELPER_REPLAY' };
  replaySet?.add(requestId);
  return {
    ok: true,
    request: {
      ...request,
      payload: structuredClone(request.payload),
      authorization: { ...authorization }
    }
  };
}
