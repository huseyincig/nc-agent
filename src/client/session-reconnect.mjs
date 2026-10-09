// Phase 5 refactor: reconnect math extracted from core/client.mjs.
// Self-contained (backoff table moves along). Behavior unchanged.
export const SESSION_BACKOFF = [0, 1, 5, 15, 30, 60];

/**
 * WebSocket close codes that mean "the server is going away, but it (or its
 * replacement) will be back — reconnect promptly instead of backing off".
 * 1012 is the gateway's own restart signal (`peer.close(1012, ...)`);
 * 1001 (endpoint going away) is its standards-track twin; 1006 (abnormal
 * closure, no close frame — hard kill / rolling-restart SIGKILL) is the same
 * situation minus the courtesy frame. Every other code (1008 policy
 * rejection, 1011 server error, 4000-4999 operator/reaper actions, connect
 * failures with no code at all) keeps the escalating backoff: retrying fast
 * against a refusing server only hammers it.
 */
export const SERVER_RESTART_CLOSE_CODES = new Set([1001, 1006, 1012]);

/**
 * @param {unknown} code
 */
export function isServerRestartCloseCode(code) {
  return SERVER_RESTART_CLOSE_CODES.has(Number(code));
}

/**
 * Full-jitter reconnect delay (SentinelX `apply_jitter`): uniform in
 * [0, baseMs] instead of the old additive [baseMs, baseMs + 1s], which
 * bunched every agent into the same 1-second spike at each backoff step.
 *
 * Floor reasoning: a floor of 0 lets a single healthy agent reconnect
 * immediately after one failure — that is the decorrelation working, not a
 * hammer risk, because (a) the per-attempt backoff table still grows the
 * window on every consecutive failure, so a persistently-down server still
 * sees an exponentially decaying aggregate retry rate; (b) the 1012-reset
 * path below only fires when the server was alive enough to send a close
 * frame, i.e. it is (or its replacement is) already accepting reconnects.
 * The maximum stays exactly baseMs: a slow reconnect is never slower than
 * the design allows, and on average reconnects land at baseMs / 2.
 * @param {number} baseSeconds
 * @param {() => number} [rand] injectable uniform [0,1) source (tests)
 */
export function reconnectDelayMs(baseSeconds, rand = Math.random) {
  const baseMs = Math.max(0, Math.floor(Number(baseSeconds) || 0)) * 1000;
  if (baseMs <= 0) return 0;
  const r = Number(rand());
  const clamped = Number.isFinite(r) ? Math.min(Math.max(r, 0), 0.999999999) : 0;
  return Math.floor(clamped * baseMs);
}

export /**
 * @param {number} attempt @param {{sessionEstablished?: unknown, closeCode?: unknown}|null|undefined} [error]
 */
function nextSessionAttempt(attempt, error) {
  // Server-going-away close (1012/1001/1006): the peer is healthy and the
  // server just restarted — reset the counter so the agent reconnects
  // promptly instead of serving a 30-60s penalty for a deploy it survived.
  if (error && isServerRestartCloseCode(error.closeCode)) return 0;
  const base = error?.sessionEstablished ? 0 : attempt;
  return Math.min(base + 1, SESSION_BACKOFF.length - 1);
}
