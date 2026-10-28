import { invokePrivilegedHelper } from './privileged-helper-ipc.mjs';
import { classifyShellFailure, stderrExcerpt } from '../src/client/shell-runner.mjs';

/**
 * Per-operation IPC timeouts (live telemetry: 92 PRIVILEGED_HELPER_TIMEOUT).
 *
 * Root cause: the client used the 5s transport default for EVERY operation
 * while the daemon legitimately runs up to 600s (package install/remove,
 * compose) and 120s (uninstall). The watchdog fired mid-operation, the job
 * failed as TIMEOUT, and the root operation kept running orphaned.
 * These budgets mirror each daemon watchdog plus a 15s call margin, so the
 * watchdog only fires when the daemon itself is wedged (true infra fault).
 */
export const PRIVILEGED_IPC_CALL_MARGIN_MS = 15000;
export const PRIVILEGED_IPC_DEFAULT_TIMEOUT_MS = 60000;
export const PRIVILEGED_IPC_QUICK_OP_TIMEOUT_MS = 45000;
export const PRIVILEGED_IPC_LONG_OP_TIMEOUT_MS = 615000;
export const PRIVILEGED_IPC_UNINSTALL_TIMEOUT_MS = 135000;

/**
 * @param {unknown} request signed privileged-helper request envelope
 */
export function timeoutMsForPrivilegedRequest(request) {
  try {
    const rec = request && typeof request === 'object' && !Array.isArray(request)
      ? /** @type {Record<string, unknown>} */ (request)
      : {};
    const op = String(rec.operation || '');
    const payload = rec.payload && typeof rec.payload === 'object' && !Array.isArray(rec.payload)
      ? /** @type {Record<string, unknown>} */ (rec.payload)
      : {};
    if (op === 'privileged_shell_exec') {
      const raw = Number(payload.timeout_seconds ?? 30);
      const secs = Number.isFinite(raw) ? Math.max(1, Math.min(3600, raw)) : 30;
      return secs * 1000 + PRIVILEGED_IPC_CALL_MARGIN_MS;
    }
    if (op === 'package_control' || op === 'compose_control') {
      const action = String(payload.action || '').toLowerCase();
      if (action && action !== 'list') return PRIVILEGED_IPC_LONG_OP_TIMEOUT_MS;
      return PRIVILEGED_IPC_QUICK_OP_TIMEOUT_MS;
    }
    if (op === 'client_uninstall') return PRIVILEGED_IPC_UNINSTALL_TIMEOUT_MS;
    return PRIVILEGED_IPC_QUICK_OP_TIMEOUT_MS;
  } catch {
    return PRIVILEGED_IPC_DEFAULT_TIMEOUT_MS;
  }
}

/**
 * Infra-vs-command recovery hint for privileged-helper error codes.
 * Transport/timeout faults are retryable (ours); validation/policy codes
 * need different input; everything else goes to the operator.
 * @param {unknown} code
 */
export function suggestedActionForHelperError(code) {
  const c = String(code || '');
  if (/TIMEOUT|NOT_AVAILABLE/.test(c)) return 'retry';
  if (/PEER_|POLICY/.test(c)) return 'contact_operator';
  if (/INVALID|DENIED|NOT_ALLOWED|UNSAFE|MISMATCH|REQUIRED/.test(c)) return 'change_input';
  return 'contact_operator';
}

/**
 * @param {object} [options]
 * @param {(request: unknown, options?: unknown) => Promise<unknown>} [options.invoke]
 * @param {() => boolean} [options.isAvailable]
 * @param {((request: unknown) => Promise<string|null>)|null} [options.transportProof] file-secret
 * proof provider for transports without kernel peer credentials (win32);
 * resolved per call so rotations take effect without restart.
 * @param {((request: unknown) => Promise<string|null>)|null} [options.replySecret] L01b-4:
 * transport-secret provider for reply-frame HMAC verification (same secret
 * as transportProof); resolved per call. Absent = no reply verification
 * (unix-socket transports keep kernel peer credentials).
 */
export function makePrivilegedHelperClientHandler({
  invoke = invokePrivilegedHelper,
  isAvailable,
  transportProof = null,
  replySecret = null
} = {}) {
  /**
   * @param {string} error
   */
  const unavailable = (error) => ({
    status: 'failed',
    exit_code: null,
    stdout: '',
    stderr: '',
    duration_ms: 0,
    error,
    result_payload: {}
  });
  return async (/** @type {unknown} */ job) => {
    if (isAvailable && !isAvailable()) return unavailable('PRIVILEGED_HELPER_NOT_AVAILABLE');
    const jobRecord = /** @type {{request_payload?: unknown}} */ (job || {});
    const payloadRecord =
      jobRecord.request_payload && typeof jobRecord.request_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (jobRecord.request_payload)
        : null;
    const request = payloadRecord?.privileged_authorization;
    if (!request || typeof request !== 'object' || Array.isArray(request))
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        duration_ms: 0,
        error: 'PRIVILEGED_HELPER_AUTH_REQUIRED',
        result_payload: {}
      };
    let reply;
    const started = Date.now();
    try {
      const proof = transportProof ? await transportProof(request).catch(() => null) : null;
      const secret = typeof replySecret === "function" ? await replySecret(request).catch(() => null) : null;
      reply = /** @type {Record<string, any>} */ (
        await invoke(request, {
          ...(proof ? { transportProof: proof } : {}),
          ...(secret ? { replySecret: secret } : {}),
          timeoutMs: timeoutMsForPrivilegedRequest(request)
        })
      );
    } catch (error) {
      const errorRecord = /** @type {{message?: unknown}} */ (error);
      const code = errorRecord?.message || 'PRIVILEGED_HELPER_NOT_AVAILABLE';
      // Infra fault (ours), never a command failure: keep the code, add the
      // class so telemetry stops mixing these with real nonzero exits.
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        duration_ms: Date.now() - started,
        error: code,
        result_payload: {
          privileged: true,
          failure_class: 'infra-transport',
          suggested_action: suggestedActionForHelperError(code)
        }
      };
    }
    if (!reply?.ok) {
      const code = reply?.error || 'PRIVILEGED_HELPER_EXECUTION_FAILED';
      // Infra fault (helper could not run it: validation/transport/daemon
      // fault), NOT an elevated-command nonzero — that arrives as ok:true
      // with status failed + exit_code below.
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        duration_ms: Date.now() - started,
        error: code,
        result_payload: {
          privileged: true,
          failure_class: 'infra-request',
          suggested_action: suggestedActionForHelperError(code)
        }
      };
    }
    const r = reply.result && typeof reply.result === 'object' ? reply.result : {};
    const status = ['completed', 'failed', 'timeout'].includes(r.status) ? r.status : 'completed';
    const enriched = { privileged: true };
    if (status === 'timeout') {
      enriched.failure_class = 'command-timeout';
      enriched.suggested_action = 'retry';
      enriched.stderr_excerpt = stderrExcerpt(r.stderr);
    } else if (status === 'failed') {
      // Legit elevated-command failure (stays failed): rich signal so the
      // model fixes the cause instead of retrying verbatim.
      const signal_ = classifyShellFailure({ exitCode: r.exit_code, stderr: r.stderr });
      enriched.failure_class = 'command-failed';
      enriched.suggested_action = signal_.suggested_action;
      enriched.stderr_excerpt = stderrExcerpt(r.stderr, 4000);
      enriched.cause = signal_.cause;
    }
    return {
      status,
      exit_code: r.exit_code ?? null,
      stdout: String(r.stdout || ''),
      stderr: String(r.stderr || ''),
      duration_ms: Number(r.duration_ms || 0),
      error: r.error ?? null,
      stdout_truncated: Boolean(r.stdout_truncated),
      stderr_truncated: Boolean(r.stderr_truncated),
      result_payload: enriched
    };
  };
}

/**
 * File-permissions client handler: same privileged-helper transport as
 * privileged_shell_exec, but the daemon returns metadata witnesses
 * ({action, target, success, previous/current mode/owner}) instead of a
 * shell-shaped result. Witnesses are preserved verbatim into
 * result_payload so the control-plane compact projection can echo them;
 * failures keep a stable taxonomy-backed code with the daemon reason in
 * stderr (never a raw leak), mirroring the generic handler's error shapes.
 *
 * @param {object} [options]
 * @param {(request: unknown, options?: unknown) => Promise<unknown>} [options.invoke]
 * @param {() => boolean} [options.isAvailable]
 * @param {((request: unknown) => Promise<string|null>)|null} [options.transportProof] file-secret
 * proof provider for transports without kernel peer credentials (win32);
 * resolved per call so rotations take effect without restart.
 * @param {((request: unknown) => Promise<string|null>)|null} [options.replySecret] L01b-4:
 * same-secret provider for reply-frame HMAC verification (see generic
 * handler); absent = no reply verification.
 */
export function makeFilePermissionsClientHandler({
  invoke = invokePrivilegedHelper,
  isAvailable,
  transportProof = null,
  replySecret = null
} = {}) {
  /**
   * @param {string} error
   * @param {Record<string, unknown>} [witnesses]
   */
  const failed = (error, witnesses = {}) => ({
    status: 'failed',
    exit_code: null,
    stdout: '',
    stderr: '',
    duration_ms: 0,
    error,
    result_payload: { ...witnesses }
  });
  /**
   * @param {unknown} value
   */
  const asCode = (value, fallback) =>
    typeof value === 'string' && value ? value : fallback;
  /**
   * @param {unknown} result
   */
  const witnessesOf = (result) => {
    const r =
      result && typeof result === 'object' && !Array.isArray(result)
        ? /** @type {Record<string, unknown>} */ (result)
        : {};
    const str = (/** @type {unknown} */ v) => (typeof v === 'string' ? v : null);
    return {
      action: str(r.action),
      target: str(r.target),
      previous_mode: str(r.previous_mode),
      current_mode: str(r.current_mode),
      previous_owner: str(r.previous_owner),
      current_owner: str(r.current_owner)
    };
  };
  return async (/** @type {unknown} */ job) => {
    if (isAvailable && !isAvailable()) return failed('PRIVILEGED_HELPER_NOT_AVAILABLE');
    const jobRecord = /** @type {{request_payload?: unknown}} */ (job || {});
    const payloadRecord =
      jobRecord.request_payload && typeof jobRecord.request_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (jobRecord.request_payload)
        : null;
    const request = payloadRecord?.privileged_authorization;
    if (!request || typeof request !== 'object' || Array.isArray(request))
      return failed('PRIVILEGED_HELPER_AUTH_REQUIRED');
    const started = Date.now();
    let reply;
    try {
      const proof = transportProof ? await transportProof(request).catch(() => null) : null;
      const secret = typeof replySecret === "function" ? await replySecret(request).catch(() => null) : null;
      reply = /** @type {Record<string, any>} */ (
        await invoke(request, {
          ...(proof ? { transportProof: proof } : {}),
          ...(secret ? { replySecret: secret } : {}),
          timeoutMs: timeoutMsForPrivilegedRequest(request)
        })
      );
    } catch (error) {
      const errorRecord = /** @type {{message?: unknown}} */ (error);
      const out = failed(
        asCode(errorRecord?.message, 'PRIVILEGED_HELPER_NOT_AVAILABLE')
      );
      out.duration_ms = Date.now() - started;
      return out;
    }
    const durationMs = Date.now() - started;
    if (!reply?.ok)
      return {
        ...failed(asCode(reply?.error, 'PRIVILEGED_HELPER_EXECUTION_FAILED')),
        duration_ms: durationMs
      };
    const witnesses = witnessesOf(reply.result);
    if (!reply.result || typeof reply.result !== 'object' || reply.result.success !== true) {
      const rec = /** @type {Record<string, unknown>} */ (
        reply.result && typeof reply.result === 'object' ? reply.result : {}
      );
      const detail = typeof rec.message === 'string' ? rec.message.slice(0, 2000) : '';
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: detail,
        duration_ms: durationMs,
        error: 'PRIVILEGED_HELPER_EXECUTION_FAILED',
        result_payload: witnesses
      };
    }
    return {
      status: 'completed',
      exit_code: null,
      stdout: '',
      stderr: '',
      duration_ms: durationMs,
      error: null,
      result_payload: witnesses
    };
  };
}
