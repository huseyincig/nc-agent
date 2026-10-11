import { spawn } from 'node:child_process';
import fs from 'node:fs';

const SWEEP_VERIFY_TOLERANCE_MS = 120 * 1000;

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
 * a deferred group SIGKILL. Re-verifies PGID identity against the recorded
 * start time before authorizing the signal to prevent PID-reuse races.
 * If unverifiable, skips signal (fail-safe).
 * @param {number|undefined|null} pid group-leader pid (pgid == pid when detached)
 * @param {string|number} [startedAtIso] expected process/group start time ISO
 * @param {{platform?: string}} [options]
 * @returns {Promise<boolean>|boolean} true unless the group is provably gone or identity mismatch
 */
export async function verifyProcessStartTime(
  pid,
  startedAtIso,
  { platform = process.platform, execFile = null } = {}
) {
  const expected = Date.parse(String(startedAtIso || ''));
  if (!Number.isFinite(expected)) return null;
  try {
    if (platform === 'linux') {
      const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
      const afterComm = stat
        .slice(stat.lastIndexOf(')') + 1)
        .trim()
        .split(/\s+/);
      const ticks = Number(afterComm[19]);
      if (!Number.isFinite(ticks)) return null;
      const btime = Number(
        fs
          .readFileSync('/proc/stat', 'utf8')
          .split('\n')
          .find((l) => l.startsWith('btime'))
          ?.split(/\s+/)[1]
      );
      const ticksPerSec = 100;
      if (!Number.isFinite(btime)) return null;
      const actualMs = (btime + ticks / ticksPerSec) * 1000;
      return Math.abs(actualMs - expected) <= SWEEP_VERIFY_TOLERANCE_MS;
    }
    if (platform === 'win32') return null;
    const { execFile: ef } = execFile || (await import('node:child_process'));
    const { promisify } = await import('node:util');
    const run = promisify(ef);
    const { stdout } = await run('ps', ['-o', 'lstart=', '-p', String(pid)], {
      timeout: 10000
    });
    const actualMs = Date.parse(String(stdout || '').trim());
    if (!Number.isFinite(actualMs)) return null;
    return Math.abs(actualMs - expected) <= SWEEP_VERIFY_TOLERANCE_MS;
  } catch {
    return null;
  }
}

export async function verifyPgidIdentity(
  pid,
  startedAtIso,
  { platform = process.platform, execFile = null } = {}
) {
  const id = Math.floor(Number(pid));
  if (!Number.isInteger(id) || id < 2) return false;
  const leaderVerdict = await verifyProcessStartTime(id, startedAtIso, { platform, execFile });
  if (leaderVerdict === true) return true;
  if (leaderVerdict === false) return false;
  if (platform === 'linux') {
    try {
      const expected = Date.parse(String(startedAtIso || ''));
      if (!Number.isFinite(expected)) return false;
      const btime = Number(
        fs
          .readFileSync('/proc/stat', 'utf8')
          .split('\n')
          .find((l) => l.startsWith('btime'))
          ?.split(/\s+/)[1]
      );
      if (!Number.isFinite(btime)) return false;
      const ticksPerSec = 100;
      const pids = fs.readdirSync('/proc').filter((p) => /^\d+$/.test(p));
      for (const p of pids) {
        try {
          const s = fs.readFileSync(`/proc/${p}/stat`, 'utf8');
          const afterComm = s.slice(s.lastIndexOf(')') + 1).trim().split(/\s+/);
          const pgrp = Number(afterComm[2]);
          if (pgrp === id) {
            const ticks = Number(afterComm[19]);
            if (Number.isFinite(ticks)) {
              const actualMs = (btime + ticks / ticksPerSec) * 1000;
              if (Math.abs(actualMs - expected) <= SWEEP_VERIFY_TOLERANCE_MS) {
                return true;
              }
            }
          }
        } catch {}
      }
    } catch {
      return false;
    }
  }
  return false;
}

export async function groupAlive(pid, startedAtIso, { platform = process.platform } = {}) {
  const id = Math.floor(Number(pid));
  if (!Number.isInteger(id) || id < 2) return false;
  let alive = false;
  try {
    process.kill(-id, 0);
    alive = true;
  } catch (e) {
    alive = /** @type {NodeJS.ErrnoException} */ (e)?.code !== 'ESRCH';
  }
  if (!alive) return false;
  if (startedAtIso !== undefined) {
    return await verifyPgidIdentity(id, startedAtIso, { platform });
  }
  return true;
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
    const startedAtIso = new Date().toISOString();
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
      escalate = setTimeout(async () => {
        try {
          // Re-verify PGID identity before group SIGKILL (PID-reuse safety).
          // If group is gone (ESRCH) or identity is unverifiable, skip signal.
          if (groupKill) {
            const isAlive = await groupAlive(child?.pid, startedAtIso, { platform });
            if (isAlive) killSpawnTree(child, platform, true, tree);
          } else {
            killSpawnTree(child, platform, true, tree);
          }
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
