import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

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
 * @type {Map<string, {pid: number, raw: string, release: () => Promise<void>}>}
 */
const heldLocks = new Map();

/**
 * Release a lock previously acquired by this process (best-effort no-op
 * when absent). Used only by the update-supervision handoff.
 * @param {string} lockFile
 */
export async function releaseHeldLock(lockFile) {
  const release = lockFile ? heldLocks.get(String(lockFile))?.release : null;
  if (!release) return false;
  try {
    await release();
  } catch {}
  return true;
}

function alreadyRunning(owner = 0) {
  return Object.assign(new Error('NC_CLIENT_ALREADY_RUNNING'), {
    code: 'NC_CLIENT_ALREADY_RUNNING', owner_pid: owner
  });
}

async function lockContent(lockFile) {
  try {
    return await fs.readFile(lockFile, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    // A partial write or read failure is not proof of a dead owner.
    throw alreadyRunning();
  }
}

function requireStaleOwner(raw, pidAlive, ownerStartMs) {
  let row;
  try { row = JSON.parse(raw); } catch { throw alreadyRunning(); }
  if (!row || !Number.isInteger(row.pid) || row.pid < 2 ||
      typeof row.started_at !== 'string' || !Number.isFinite(Date.parse(row.started_at))) {
    throw alreadyRunning();
  }
  if (!pidAlive(row.pid)) return;
  // Preserve the existing PID-reuse check, failing closed on unknown start time.
  let ownerStart = null;
  try { ownerStart = ownerStartMs(row.pid); } catch {}
  if (ownerStart != null && ownerStart - Date.parse(row.started_at) > 5000) return;
  throw alreadyRunning(row.pid);
}

async function acquireMutationGuard(lockFile) {
  const guard = `${lockFile}.guard`;
  try {
    await fs.mkdir(guard, { mode: 0o700 });
  } catch (error) {
    if (error?.code === 'EEXIST') throw alreadyRunning();
    throw error;
  }
  // Never reap this guard automatically: a crash must fail closed, not allow
  // another mutator into a paused rename/create or release transaction.
  return guard;
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
  const rawNow = await lockContent(lockFile);
  const held = heldLocks.get(String(lockFile));
  if (held?.pid === pid && held.raw === rawNow) throw alreadyRunning(pid);
  if (rawNow !== null) requireStaleOwner(rawNow, pidAlive, ownerStartMs);
  if (await lockContent(lockFile) !== rawNow) throw alreadyRunning();

  // Rename alone is not compare-and-swap: a delayed contender could rename a
  // fresh owner's file. Serialize ALL mutations (including create/release),
  // then validate the optimistic snapshot again before quarantining anything.
  const guard = await acquireMutationGuard(lockFile);
  try {
    if (await lockContent(lockFile) !== rawNow) throw alreadyRunning();
    if (rawNow !== null) {
      requireStaleOwner(rawNow, pidAlive, ownerStartMs);
      const quarantine = path.join(guard, `stale-${randomUUID()}`);
      await fs.rename(lockFile, quarantine);
      try {
        const renamed = await lockContent(quarantine);
        if (renamed !== rawNow) throw alreadyRunning();
        requireStaleOwner(renamed, pidAlive, ownerStartMs);
      } catch (error) {
        // Restore without overwriting an unexpected replacement. If restoration
        // fails, retain quarantine + guard and fail closed for manual recovery.
        await fs.link(quarantine, lockFile);
        await fs.unlink(quarantine);
        throw error;
      }
      await fs.unlink(quarantine);
    }

    const raw = JSON.stringify({
      pid, started_at: new Date().toISOString(), lock_id: randomUUID()
    }) + '\n';
    const handle = await fs.open(lockFile, 'wx', 0o640);
    try { await handle.writeFile(raw); } finally { await handle.close(); }
    if (await lockContent(lockFile) !== raw) throw alreadyRunning();
    let released = false;
    const release = async () => {
      if (released) return;
      const releaseGuard = await acquireMutationGuard(lockFile);
      try {
        // Exact claim identity, not just PID: old releases cannot remove a
        // later claim, even when the PID or timestamp has been reused.
        if (await lockContent(lockFile) === raw) await fs.unlink(lockFile);
        released = true;
        if (heldLocks.get(String(lockFile))?.release === release) {
          heldLocks.delete(String(lockFile));
        }
      } finally {
        await fs.rmdir(releaseGuard);
      }
    };
    heldLocks.set(String(lockFile), { pid, raw, release });
    return release;
  } finally {
    await fs.rmdir(guard);
  }
}
