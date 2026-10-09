import { spawn } from 'node:child_process';

/**
 * Leak-free spawn capture for the privileged helper daemon (root/SYSTEM).
 *
 * Why this exists (live telemetry: 92 PRIVILEGED_HELPER_TIMEOUT +
 * 20 PRIVILEGED_HELPER_EXECUTION_FAILED): every previous capture helper
 * resolved ONLY on child `close`/`error`. A killed child whose grandchildren
 * still hold the stdio pipes never emits `close`, so the daemon promise
 * hung forever — the agent IPC watchdog fired first and the root operation
 * (apt, systemctl, compose) kept running orphaned underneath. This helper
 * inverts the discipline:
 *
 * - the watchdog resolves the promise ITSELF (timeout result, never a hang);
 * - escalation is TERM-then-KILL (graceful first: SIGKILLing dpkg/apt
 *   mid-transaction corrupts system state) with group kill for detached
 *   POSIX children so no orphan survives;
 * - stdio streams are destroyed on escalation so a late `close` can only
 *   no-op via the settled flag, never resolve twice;
 * - all timers are unref'd and always cleared (no timer leaks, no PID reuse
 *   window: group kill targets the pgid captured at spawn).
 *
 * @param {import('node:child_process').ChildProcess|undefined|null} child
 * @param {string} [platform]
 * @param {boolean} [force]
 * @param {boolean} [tree] group kill (only true for detached POSIX children;
 * never true for non-detached: kill(-pid) would signal the agent's own group)
 */
export function killSpawnTree(child, platform = process.platform, force = false, tree = false) {
  const pid = Math.floor(Number(child?.pid));
  if (!Number.isInteger(pid) || pid < 2) return;
  if (platform === 'win32') {
    try {
      const args = force ? ['/PID', String(pid), '/T', '/F'] : ['/PID', String(pid), '/T'];
      spawn('taskkill', args, { stdio: 'ignore', windowsHide: true }).unref();
    } catch {}
    return;
  }
  const signal = force ? 'SIGKILL' : 'SIGTERM';
  if (tree) {
    try {
      process.kill(-pid, signal);
      return;
    } catch {}
  }
  try {
    child.kill(signal);
  } catch {}
}

/**
 * P2-04: probe whether a detached POSIX process GROUP is still alive before
 * a deferred group SIGKILL. Signal 0 delivers nothing; ESRCH means the
 * group is gone (skip the kill — the PGID may already be recycled) while
 * any other outcome (alive, EPERM, ...) assumes alive so the escalation
 * still sweeps orphans. POSIX-only by construction: callers gate on
 * platform !== 'win32' (Windows never uses negative-pid signaling and the
 * win32 path uses taskkill /T instead).
 * @param {number|undefined|null} pid group-leader pid (pgid == pid when detached)
 * @returns {boolean} true unless the group is provably gone
 */
function groupAlive(pid) {
  const id = Math.floor(Number(pid));
  if (!Number.isInteger(id) || id < 2) return false;
  try {
    process.kill(-id, 0);
    return true;
  } catch (e) {
    return /** @type {NodeJS.ErrnoException} */ (e)?.code !== 'ESRCH';
  }
}
/**
 * @param {ReturnType<typeof setTimeout>|undefined} timer
 */
function unrefTimer(timer) {
  try {
    timer?.unref?.();
  } catch {}
}

export const PRIVILEGED_CAPTURE_DEFAULT_TIMEOUT_MS = 30000;
export const PRIVILEGED_CAPTURE_DEFAULT_GRACE_MS = 5000;
export const PRIVILEGED_CAPTURE_DEFAULT_MAX_CHARS = 65536;

/**
 * Spawn argv (never a shell) and capture bounded output. NEVER hangs: the
 * timeout watchdog resolves independently of child `close`.
 *
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {object} [options]
 * @param {number} [options.timeoutMs]
 * @param {number} [options.killGraceMs] TERM→KILL escalation delay
 * @param {boolean} [options.tree] detached group kill (POSIX only)
 * @param {boolean} [options.detached] spawn detached (POSIX process group)
 * @param {Record<string,string>|null} [options.env] extra env overlay
 * @param {boolean} [options.inheritEnv] inherit process.env (default true)
 * @param {boolean} [options.inheritEnv] true (default): inherit process.env
 * like the old inline spawns (PATH stubs, proxies, locale survive); false:
 * restricted PATH+LANG base for privileged SHELLS (never leak agent env —
 * tokens included — into a root shell)
 * @param {string|null} [options.cwd]
 * @param {number} [options.maxChars] per-stream cap
 * @param {number} [options.maxOutChars] arrival-order merged cap
 * @param {string} [options.platform]
 * @returns {Promise<{code: number|null, stdout: string, stderr: string, out: string, error: string|null, timedOut: boolean, stdoutTruncated: boolean, stderrTruncated: boolean}>}
 */
export function runPrivilegedCapture(cmd, args, {
  timeoutMs = PRIVILEGED_CAPTURE_DEFAULT_TIMEOUT_MS,
  killGraceMs = PRIVILEGED_CAPTURE_DEFAULT_GRACE_MS,
  tree = false,
  detached = false,
  env = null,
  inheritEnv = true,
  cwd = null,
  maxChars = PRIVILEGED_CAPTURE_DEFAULT_MAX_CHARS,
  maxOutChars = PRIVILEGED_CAPTURE_DEFAULT_MAX_CHARS,
  platform = process.platform
} = {}) {
  // P2-04: detached-tree captures kill by PROCESS GROUP (pgid == child pid).
  // A child's exit/close no longer implies the group is gone (grandchildren
  // may survive holding pipes), so post-timeout close/exit must NOT blindly
  // disarm the group escalation — the escalation itself re-verifies group
  // liveness before signaling (no orphan when alive, no blind kill when the
  // PGID is provably gone). Child-only captures (tree false / win32) keep
  // the PASS-1 V-32.10 discipline: child gone ⇒ nothing left ⇒ disarm.
  const groupKill = tree === true && platform !== 'win32';
  const timeout = Math.max(1000, Math.min(3600000, Math.floor(Number(timeoutMs) || 0) || PRIVILEGED_CAPTURE_DEFAULT_TIMEOUT_MS));
  const grace = Math.max(0, Math.min(30000, Math.floor(Number(killGraceMs) || 0)));
  const cap = Math.max(1024, Math.min(4 * 1024 * 1024, Math.floor(Number(maxChars) || 0) || PRIVILEGED_CAPTURE_DEFAULT_MAX_CHARS));
  const outCap = Math.max(1024, Math.min(4 * 1024 * 1024, Math.floor(Number(maxOutChars) || 0) || PRIVILEGED_CAPTURE_DEFAULT_MAX_CHARS));
  // Env discipline: capture helpers (systemctl/docker/journalctl/...) keep
  // the old inherit-everything behavior; privileged shells stay restricted.
  const spawnEnv = inheritEnv === false
    ? {
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        LANG: 'C.UTF-8',
        ...(env || {})
      }
    : { ...process.env, ...(env || {}) };
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, {
        cwd: cwd || '/',
        env: spawnEnv,
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: platform !== 'win32' && detached === true,
        windowsHide: true
      });
    } catch (e) {
      resolve({
        code: null,
        stdout: '',
        stderr: '',
        out: '',
        error: e instanceof Error ? e.message : String(e),
        timedOut: false,
        stdoutTruncated: false,
        stderrTruncated: false
      });
      return;
    }
    let settled = false;
    let stdout = '';
    let stderr = '';
    let out = '';
    let stdoutTruncated = false;
    let stderrTruncated = false;
    /** @type {ReturnType<typeof setTimeout>|undefined} */
    let escalate;
    /** @param {string} chunk @param {0|1} stream 0=stdout 1=stderr */
    const push = (chunk, stream) => {
      const text = String(chunk);
      if (!text) return;
      if (stream === 0) {
        const room = Math.max(0, cap - stdout.length);
        if (text.length > room) stdoutTruncated = true;
        if (room > 0) stdout += text.slice(0, room);
      } else {
        const room = Math.max(0, cap - stderr.length);
        if (text.length > room) stderrTruncated = true;
        if (room > 0) stderr += text.slice(0, room);
      }
      if (out.length < outCap) out += text.slice(0, outCap - out.length);
    };
    const clearEscalate = () => {
      if (escalate) {
        clearTimeout(escalate);
        escalate = undefined;
      }
    };
    const timer = setTimeout(() => {
      // Watchdog: resolve NOW (never wait for `close` — orphaned pipe
      // holders must not hang the daemon), escalate the kill in background.
      if (settled) return;
      settled = true;
      const note = `${cmd} timed out after ${Math.round(timeout / 1000)}s`;
      try {
        killSpawnTree(child, platform, false, tree);
      } catch {}
      escalate = setTimeout(() => {
        try {
          // P2-04 fail-safe: re-verify before the SIGKILL. Group provably
          // gone (ESRCH) ⇒ skip the signal (PGID-reuse safety, PASS-1);
          // otherwise the group kill proceeds (no orphan, P2-04).
          if (!(groupKill && !groupAlive(child?.pid))) killSpawnTree(child, platform, true, tree);
        } catch {}
        try {
          child.stdout?.destroy();
        } catch {}
        try {
          child.stderr?.destroy();
        } catch {}
      }, grace);
      unrefTimer(escalate);
      resolve({
        code: null,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        out: out.trim() || note,
        error: null,
        timedOut: true,
        stdoutTruncated,
        stderrTruncated
      });
    }, timeout);
    unrefTimer(timer);
    child.stdout?.on('data', (d) => push(d, 0));
    child.stderr?.on('data', (d) => push(d, 1));
    child.once('error', (e) => {
      // V-32.10: always disarm the SIGKILL escalation first. The old early
      // return on settled left the escalate timer armed after a timeout, so
      // it later signalled a possibly-reused PID/group.
      clearEscalate();
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code: null,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        out: out.trim(),
        error: e instanceof Error ? e.message : String(e),
        timedOut: false,
        stdoutTruncated,
        stderrTruncated
      });
    });
    child.once('close', (code) => {
      // V-32.10 + P2-04: disarm on close — EXCEPT a post-timeout close of
      // a detached-tree child, where pipe-holding grandchildren may still
      // be alive in the group. There the escalation stays armed and
      // re-verifies group liveness itself before signaling; every other
      // close disarms exactly as before (child gone ⇒ child-only kill
      // unwarranted, PID may be reused).
      if (!(groupKill && settled)) clearEscalate();
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        code,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        out: out.trim(),
        error: null,
        timedOut: false,
        stdoutTruncated,
        stderrTruncated
      });
    });
    child.once('exit', () => {
      // V-32.10 + P2-04: 'close' may never fire when grandchildren hold
      // the stdio pipes, but 'exit' fires when the child itself exits.
      // Child-only captures: the exit means the gentle kill worked —
      // cancel the pending SIGKILL (PID may be reused). Detached-tree
      // captures: the GROUP may survive the child, so the escalation stays
      // armed (it re-verifies liveness before signaling). Either way our
      // stream ends are destroyed so a pipe-holding grandchild cannot
      // leak them.
      if (!settled) return;
      if (!groupKill) clearEscalate();
      try {
        child.stdout?.destroy();
      } catch {}
      try {
        child.stderr?.destroy();
      } catch {}
    });
  });
}
