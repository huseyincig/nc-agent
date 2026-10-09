import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

/**
 * @param {unknown} pid
 */
export function defaultPidAlive(pid) {
  if (typeof pid !== 'number' || !Number.isInteger(pid) || pid < 2) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const errorCode =
      error && typeof error === 'object' && 'code' in error ? error.code : undefined;
    return errorCode === 'EPERM';
  }
}

/**
 * Owner process start time in ms since epoch, or null when indeterminable.
 * Defeats PID-reuse traps: after an unclean reboot the lock file may point
 * at a recycled PID owned by an unrelated process (live Mac case: lock said
 * 243, PID 243 was rpcsvchost). Best-effort on every platform; null means
 * "cannot tell", and the caller falls back to PID-liveness alone.
 * @param {number} pid
 * @param {string} [platform]
 */
export function defaultOwnerStartMs(pid, platform = process.platform) {
  try {
    if (!Number.isInteger(pid) || pid < 2) return null;
    if (platform === 'linux') {
      const stat = fsSync.readFileSync(`/proc/${pid}/stat`, 'utf8');
      const end = stat.lastIndexOf(')');
      const fields = stat.slice(end + 2).split(' ');
      const startTicks = Number(fields[19]);
      if (!Number.isFinite(startTicks)) return null;
      const btime = Number(
        (fsSync.readFileSync('/proc/stat', 'utf8').match(/^btime\s+(\d+)/m) || [])[1]
      );
      if (!Number.isFinite(btime)) return null;
      return btime * 1000 + Math.floor((startTicks * 1000) / 100);
    }
    if (platform === 'darwin' || platform === 'win32') {
      const out =
        platform === 'darwin'
          ? execFileSync('ps', ['-o', 'lstart=', '-p', String(pid)], {
              timeout: 5000,
              windowsHide: true
            }).toString()
          : execFileSync(
              'powershell.exe',
              [
                '-NoProfile',
                '-NonInteractive',
                '-Command',
                `(Get-Process -Id ${pid} -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o')`
              ],
              { timeout: 5000, windowsHide: true }
            ).toString();
      const ms = Date.parse(out.trim());
      return Number.isFinite(ms) ? ms : null;
    }
  } catch {}
  return null;
}

/**
 * Process-local registry of locks held by THIS process, so in-process
 * update supervision can hand the singleton lock to the staged child:
 * the old process must release before spawning, otherwise the child
 * dies with NC_CLIENT_ALREADY_RUNNING, no healthy marker ever lands,
 * and every OTA rolls back in a silent loop (posix fleet freeze).
 * @type {Map<string, () => Promise<void>>}
 */
const heldLocks = new Map();

/**
 * Release a lock previously acquired by this process (best-effort no-op
 * when absent). Used only by the update-supervision handoff.
 * @param {string} lockFile
 */
export async function releaseHeldLock(lockFile) {
  const release = lockFile ? heldLocks.get(String(lockFile)) : null;
  if (!release) return false;
  try {
    await release();
  } catch {}
  return true;
}

/**
 * @param {object} [options]
 * @param {string} [options.lockFile]
 * @param {number} [options.pid]
 * @param {(pid: number) => boolean} [options.pidAlive]
 * @param {(pid: number) => number|null} [options.ownerStartMs]
 */
export async function acquireClientLock({
  lockFile,
  pid = process.pid,
  pidAlive = defaultPidAlive,
  ownerStartMs = defaultOwnerStartMs
} = {}) {
  if (!lockFile) throw new Error('CLIENT_LOCK_PATH_REQUIRED');
  await fs.mkdir(path.dirname(lockFile), { recursive: true });
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const handle = await fs.open(lockFile, 'wx', 0o640);
      await handle.writeFile(JSON.stringify({ pid, started_at: new Date().toISOString() }) + '\n');
      await handle.close();
      let released = false;
      const release = async () => {
        if (released) return;
        released = true;
        heldLocks.delete(String(lockFile));
        try {
          const row = JSON.parse(await fs.readFile(lockFile, 'utf8'));
          if (Number(row.pid) === pid) await fs.rm(lockFile, { force: true });
        } catch {}
      };
      heldLocks.set(String(lockFile), release);
      return release;
    } catch (error) {
      const errorCode =
        error && typeof error === 'object' && 'code' in error ? error.code : undefined;
      if (errorCode !== 'EEXIST') throw error;
      let owner = 0,
        ownerClaimedAt = null;
      try {
        const row = JSON.parse(await fs.readFile(lockFile, 'utf8'));
        owner = Number(row.pid || 0);
        ownerClaimedAt = typeof row.started_at === 'string' ? Date.parse(row.started_at) : null;
      } catch {}
      if (owner && pidAlive(owner)) {
        // PID-reuse trap: the lock owner may be an unrelated recycled PID
        // (unclean reboot). The true owner started before writing the lock;
        // a process that started after the lock timestamp is an impostor.
        let recycled = false;
        if (Number.isFinite(ownerClaimedAt)) {
          try {
            const ownerStart = ownerStartMs(owner);
            recycled =
              ownerStart != null && ownerStart - /** @type {number} */ (ownerClaimedAt) > 5000;
          } catch {}
        }
        if (!recycled) {
          const e = /** @type {Error & {code?: string, owner_pid?: number}} */ (
            new Error('NC_CLIENT_ALREADY_RUNNING')
          );
          e.code = 'NC_CLIENT_ALREADY_RUNNING';
          e.owner_pid = owner;
          throw e;
        }
      }
      await fs.rm(lockFile, { force: true });
    }
  }
  throw new Error('CLIENT_LOCK_ACQUIRE_FAILED');
}
