import { spawn } from 'node:child_process';

/**
 * @param {NodeJS.ReadableStream} stream
 * @param {number} [max]
 */
function collectLimited(stream, max = 4096) {
  return new Promise((resolve) => {
    /** @type {Array<Buffer>} */
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks).toString('utf8'));
    };
    stream.on('data', (/** @type {Buffer} */ chunk) => {
      if (size >= max) return;
      const b = Buffer.from(chunk),
        take = b.subarray(0, max - size);
      chunks.push(take);
      size += take.length;
    });
    stream.on('end', finish);
    // V-32.2: a stream 'error' with no listener throws via EventEmitter and
    // leaves this promise pending forever. Resolve with the partial read so
    // the caller fails closed on the exit-code check below (never hangs).
    // Test doubles may expose only .on: prefer .once, fall back to .on
    // (the single-finish guard keeps the resolve-once contract either way).
    const onceOrOn =
      typeof stream.once === 'function' ? stream.once.bind(stream) : stream.on.bind(stream);
    onceOrOn('error', finish);
    // Destroyed streams (timeout path) emit 'close' without 'end': resolve
    // there too so a grandchild-held pipe cannot hang the daemon.
    onceOrOn('close', finish);
  });
}

/**
 * Parse darwin-peercred JSON output (pure, unit-tested directly).
 * @param {unknown} text
 */
export function parseDarwinPeercredOutput(text) {
  let o;
  try {
    o = JSON.parse(String(text || ''));
  } catch {
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  }
  const pid = Number(o?.pid);
  const uid = Number(o?.uid);
  const gid = Number(o?.gid);
  if (!Number.isSafeInteger(pid) || pid <= 0 || !Number.isSafeInteger(uid) || uid < 0 || !Number.isSafeInteger(gid) || gid < 0)
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  return { ok: true, credentials: { pid, uid, gid } };
}

/**
 * @param {unknown} socket
 * @param {object} [options]
 * @param {string} [options.binary]
 * @param {number} [options.timeoutMs]
 * @param {(cmd: string, args: Array<string>, options: unknown) => unknown} [options.spawnImpl]
 */
export async function readDarwinPeerCredentials(
  socket,
  { binary, timeoutMs = 1000, spawnImpl = null } = {}
) {
  if (process.platform !== 'darwin' && !spawnImpl)
    return { ok: false, error: 'PRIVILEGED_HELPER_PLATFORM_UNSUPPORTED' };
  const socketRecord = /** @type {Record<string, unknown>} */ (socket || {});
  if (
    !socket ||
    typeof socket !== 'object' ||
    typeof socketRecord.destroy !== 'function' ||
    !binary
  )
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  const spawnFn = spawnImpl || spawn;
  let child;
  try {
    child = /** @type {import('node:child_process').ChildProcess} */ (
      spawnFn(/** @type {string} */ (binary), [], {
        stdio: ['ignore', 'pipe', 'pipe', /** @type {any} */ (socket)],
        env: { PATH: '/usr/bin:/bin' }
      })
    );
  } catch {
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  }
  const stdoutP = collectLimited(/** @type {NodeJS.ReadableStream} */ (child.stdout)),
    stderrP = collectLimited(/** @type {NodeJS.ReadableStream} */ (child.stderr));
  const exitP = new Promise((resolve) => {
    child.once('error', () => resolve(null));
    child.once('exit', (code) => resolve(code));
  });
  const timer = setTimeout(() => {
    try {
      child.kill('SIGKILL');
    } catch {}
    // V-32.7 sibling (linux): destroy both streams so a grandchild-held
    // pipe cannot hang Promise.all below forever (collectLimited resolves
    // on 'close'/'error').
    try {
      child.stdout?.destroy();
    } catch {}
    try {
      child.stderr?.destroy();
    } catch {}
  }, timeoutMs);
  const [out, , code] = await Promise.all([stdoutP, stderrP, exitP]);
  clearTimeout(timer);
  if (code !== 0) return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  const parsed = parseDarwinPeercredOutput(out);
  return parsed;
}

/**
 * @param {unknown} socket
 * @param {object} [options]
 * @param {string} [options.binary]
 * @param {number} [options.expectedUid]
 * @param {number} [options.expectedGid]
 * @param {string} [options.identity]
 * @param {(cmd: string, args: Array<string>, options: unknown) => unknown} [options.spawnImpl]
 */
export async function verifyDarwinHelperPeer(
  socket,
  { binary, expectedUid, expectedGid, identity = '_nc', spawnImpl = null } = {}
) {
  if (
    typeof expectedUid !== 'number' ||
    !Number.isSafeInteger(expectedUid) ||
    expectedUid < 0 ||
    typeof expectedGid !== 'number' ||
    !Number.isSafeInteger(expectedGid) ||
    expectedGid < 0
  )
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  const result = await readDarwinPeerCredentials(socket, { binary, spawnImpl });
  if (!result.ok) return result;
  if (result.credentials.uid !== expectedUid || result.credentials.gid !== expectedGid)
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_DENIED' };
  return {
    ok: true,
    peer: {
      transport: 'unix_socket',
      identity,
      credential_verified: true,
      pid: result.credentials.pid,
      uid: result.credentials.uid,
      gid: result.credentials.gid
    }
  };
}
