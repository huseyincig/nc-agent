export const RETIRE_CONFIRMATIONS = 6;
export const RETIRE_MIN_WINDOW_MS = 45000;

/**
 * @param {unknown} error
 */
function parsedBody(error) {
  const errorRecord = /** @type {Record<string, unknown>} */ (error || {});
  try {
    return JSON.parse(String(errorRecord.body || ''));
  } catch {
    return null;
  }
}

/**
 * @param {unknown} error
 * @param {object} [options]
 * @param {unknown} [options.serverUrl]
 */
export function authoritativeClientNotFound(error, { serverUrl } = {}) {
  if (!String(serverUrl || '').startsWith('https://')) return false;
  const errorRecord = /** @type {Record<string, unknown>} */ (error || {});
  if (Number(errorRecord.status) !== 404) return false;
  return (
    /** @type {Record<string, unknown>} */ (parsedBody(error) || {}).error === 'CLIENT_NOT_FOUND'
  );
}

/**
 * @param {unknown} [value]
 * @returns {{consecutive_not_found: number, first_seen_at: string|null, last_seen_at: string|null}}
 */
export function normalizeRetirementCandidate(value = {}) {
  const record = /** @type {Record<string, unknown>} */ (value || {});
  return {
    consecutive_not_found: Math.max(
      0,
      Number.isInteger(record.consecutive_not_found)
        ? /** @type {number} */ (record.consecutive_not_found)
        : 0
    ),
    first_seen_at: typeof record.first_seen_at === 'string' ? record.first_seen_at : null,
    last_seen_at: typeof record.last_seen_at === 'string' ? record.last_seen_at : null
  };
}

/**
 * @param {unknown} [value]
 */
export function clearRetirementCandidate(value = {}) {
  const current = normalizeRetirementCandidate(value);
  const changed =
    current.consecutive_not_found !== 0 ||
    current.first_seen_at !== null ||
    current.last_seen_at !== null;
  return { state: { consecutive_not_found: 0, first_seen_at: null, last_seen_at: null }, changed };
}

/**
 * @param {unknown} candidate
 * @param {unknown} error
 * @param {object} [options]
 * @param {unknown} [options.serverUrl]
 * @param {number} [options.nowMs]
 * @param {number} [options.confirmations]
 * @param {number} [options.minWindowMs]
 */
export function observeRetirementResponse(
  candidate,
  error,
  {
    serverUrl,
    nowMs = Date.now(),
    confirmations = RETIRE_CONFIRMATIONS,
    minWindowMs = RETIRE_MIN_WINDOW_MS
  } = {}
) {
  const current = normalizeRetirementCandidate(candidate);
  if (!authoritativeClientNotFound(error, { serverUrl })) {
    const reset = clearRetirementCandidate(current);
    return { ...reset, retire: false, authoritative: false };
  }
  const firstMs = current.first_seen_at ? Date.parse(current.first_seen_at) : NaN;
  const firstSeen = Number.isFinite(firstMs) ? firstMs : nowMs;
  const next = {
    consecutive_not_found: current.consecutive_not_found + 1,
    first_seen_at: new Date(firstSeen).toISOString(),
    last_seen_at: new Date(nowMs).toISOString()
  };
  const retire = next.consecutive_not_found >= confirmations && nowMs - firstSeen >= minWindowMs;
  return { state: next, changed: true, retire, authoritative: true };
}
