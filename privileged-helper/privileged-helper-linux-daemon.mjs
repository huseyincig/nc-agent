import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { createPrivilegedHelperCore } from './privileged-helper-core.mjs';
import {
  decodePrivilegedHelperFrame,
  encodePrivilegedHelperFrame,
  PRIVILEGED_HELPER_MAX_FRAME_BYTES
} from './privileged-helper-ipc.mjs';
import { verifyLinuxHelperPeer } from '../src/client/linux-peer-credentials.mjs';
import { linuxPrivilegedHelperHandlers } from './privileged-helper-linux-operations.mjs';

export const LINUX_HELPER_CONFIG = '/opt/nc/config/privileged-helper.json';
export const LINUX_HELPER_PUBLIC_KEY = '/opt/nc/config/privileged-helper-public.pem';
export const LINUX_PEERCRED_BINARY = '/opt/nc/libexec/nc-linux-peercred';
const CLIENT_ID_RE = /^nc_[0-9a-f]{64}$/;

// Daemon source files whose replacement must trigger a self-restart.
// Agent OTA swaps these under the running root daemon; without this the new
// operations never take effect until a manual systemctl restart (2026-09-10:
// service_control sat deployed-but-dead until hand-restarted).
const HELPER_SOURCE_FILES = Object.freeze([
  'privileged-helper-linux-daemon.mjs',
  'privileged-helper-linux-operations.mjs',
  'privileged-helper-contract.mjs',
  'privileged-helper-core.mjs',
  'privileged-helper-ipc.mjs'
]);
/**
 * @param {ReadonlyArray<string>} [files]
 */
export function helperSourceSnapshot(files = HELPER_SOURCE_FILES) {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return files.map((f) => {
    try {
      const st = fs.statSync(path.join(dir, f));
      return { file: f, mtimeMs: st.mtimeMs, size: st.size };
    } catch {
      return { file: f, mtimeMs: null, size: null };
    }
  });
}
/**
 * @param {Array<{file: string, mtimeMs: number|null, size: number|null}>} snap
 * @param {ReadonlyArray<string>} [files]
 */
export function helperSourcesChanged(snap, files = HELPER_SOURCE_FILES) {
  const now = helperSourceSnapshot(files);
  if (now.length !== snap.length) return true;
  return now.some(
    (n, i) => n.file !== snap[i].file || n.mtimeMs !== snap[i].mtimeMs || n.size !== snap[i].size
  );
}
/**
 * Default code-change hook: log to the journal and exit(1) after the reply
 * flushes so systemd (Restart=on-failure) relaunches us from the new tree.
 */
function restartOnCodeChange() {
  try {
    console.error('[nc-privileged-helper] source changed under running daemon; restarting');
  } catch {}
  setTimeout(() => process.exit(1), 250).unref();
}
/**
 * After a served request, restart once when our own source files changed
 * under us (agent OTA). Exported for tests.
 */
export function maybeRestartOnCodeChange(bootSnapshot, onCodeChange) {
  if (!bootSnapshot || !helperSourcesChanged(bootSnapshot)) return false;
  try {
    (onCodeChange || restartOnCodeChange)();
  } catch {}
  return true;
}
/**
 * @param {unknown} value
 * @param {Array<string>} keys
 */
const exactKeys = (value, keys) =>
  value &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());

/**
 * @param {string} [file]
 */
export function loadLinuxPrivilegedHelperConfig(file = LINUX_HELPER_CONFIG) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!exactKeys(value, ['client_id', 'service_gid', 'service_uid']))
    throw new Error('PRIVILEGED_HELPER_CONFIG_INVALID');
  if (
    !CLIENT_ID_RE.test(String(value.client_id || '')) ||
    !Number.isSafeInteger(value.service_uid) ||
    value.service_uid < 0 ||
    !Number.isSafeInteger(value.service_gid) ||
    value.service_gid < 0
  )
    throw new Error('PRIVILEGED_HELPER_CONFIG_INVALID');
  return Object.freeze({ ...value });
}

/**
 * @param {string} [file]
 */
export function loadLinuxPrivilegedHelperPublicKey(file = LINUX_HELPER_PUBLIC_KEY) {
  const key = crypto.createPublicKey(fs.readFileSync(file));
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('PRIVILEGED_HELPER_AUTH_INVALID');
  return key;
}
/**
 * @param {import('node:net').Socket} socket
 * @param {Buffer} buffer
 * @param {object} options
 * @param {ReturnType<typeof import('./privileged-helper-core.mjs').createPrivilegedHelperCore>} options.core
 * @param {any} options.config
 * @param {string} [options.peercredBinary]
 * @param {ReturnType<typeof helperSourceSnapshot>|null} [options.bootSnapshot]
 * @param {(() => void)|null} [options.onCodeChange]
 */
async function dispatchFrame(socket, buffer, { core, config, peercredBinary, bootSnapshot, onCodeChange }) {
  const peer = await verifyLinuxHelperPeer(socket, {
    binary: peercredBinary,
    expectedUid: config.service_uid,
    expectedGid: config.service_gid
  });
  if (!peer.ok) {
    socket.end(encodePrivilegedHelperFrame(peer));
    return;
  }
  let request;
  try {
    request = decodePrivilegedHelperFrame(buffer);
  } catch {
    socket.end(
      encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_FRAME_INVALID' })
    );
    return;
  }
  const result = await core.handle(request, { peer: peer.peer });
  socket.end(encodePrivilegedHelperFrame(result));
  maybeRestartOnCodeChange(bootSnapshot, onCodeChange);
}

/**
 * @param {import('node:net').Socket} socket
 * @param {object} context
 * @param {ReturnType<typeof import('./privileged-helper-core.mjs').createPrivilegedHelperCore>} context.core
 * @param {any} context.config
 * @param {string} [context.peercredBinary]
 * @param {ReturnType<typeof helperSourceSnapshot>|null} [context.bootSnapshot]
 * @param {(() => void)|null} [context.onCodeChange]
 */
function serveConnection(socket, context) {
  let buffer = Buffer.alloc(0),
    handled = false;
  // Idle-connection guard: an unauthenticated peer that connects and sends
  // nothing must not hold a root-daemon fd forever. Disabled once the
  // single request frame arrives (long privileged ops may run minutes).
  socket.setTimeout(15000);
  socket.once('timeout', () => {
    try {
      socket.destroy();
    } catch {}
  });
  socket.on('data', (chunk) => {
    if (handled) return;
    buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
    if (buffer.length > PRIVILEGED_HELPER_MAX_FRAME_BYTES) {
      handled = true;
      socket.end(
        encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_FRAME_TOO_LARGE' })
      );
      return;
    }
    const nl = buffer.indexOf(10);
    if (nl < 0) return;
    handled = true;
    socket.pause();
    socket.setTimeout(0);
    if (nl !== buffer.length - 1) {
      socket.end(
        encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_FRAME_INVALID' })
      );
      return;
    }
    void dispatchFrame(socket, buffer, context).catch(() => {
      try {
        socket.end(
          encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_EXECUTION_FAILED' })
        );
      } catch {
        socket.destroy();
      }
    });
  });
}

/**
 * @param {object} [options]
 * @param {any} [options.config]
 * @param {unknown} [options.publicKey]
 * @param {string} [options.peercredBinary]
 * @param {Record<string, (payload: unknown, context: Record<string, unknown>) => unknown>} [options.handlers]
 * @param {() => void} [options.onCodeChange]
 */
export function createLinuxPrivilegedHelperServer({
  config,
  publicKey,
  peercredBinary = LINUX_PEERCRED_BINARY,
  handlers = {},
  onCodeChange
} = {}) {
  if (process.platform !== 'linux' || process.getuid?.() !== 0)
    throw new Error('PRIVILEGED_HELPER_ROOT_REQUIRED');
  const core = createPrivilegedHelperCore({
    clientId: config.client_id,
    publicKey,
    handlers,
    platform: 'linux',
    peerIdentity: '_nc'
  });
  const bootSnapshot = helperSourceSnapshot();
  return net.createServer({ allowHalfOpen: false }, (socket) =>
    serveConnection(socket, { core, config, peercredBinary, bootSnapshot, onCodeChange })
  );
}
export async function main() {
  const config = loadLinuxPrivilegedHelperConfig(),
    publicKey = loadLinuxPrivilegedHelperPublicKey();
  // Self-reconciliation (OTA without a root agent): the agent swaps this
  // very tree unprivileged and pokes us; on boot refresh the root-owned
  // artifacts (peercred binary, systemd units) from our own tree when
  // drifted. Best-effort and idempotent — never fatal to serving.
  try {
    const { reconcileLinuxHelperArtifacts } = await import(
      './privileged-helper-provision.mjs'
    );
    const appDir = path.dirname(fileURLToPath(import.meta.url));
    const reconciled = await reconcileLinuxHelperArtifacts({
      appDir,
      serviceGid: config.service_gid,
      nodeBin: process.execPath
    });
    if (reconciled?.steps?.length) {
      try {
        console.error(
          `[nc-privileged-helper] artifacts reconciled: ${reconciled.steps.join(',')}`
        );
      } catch {}
    }
  } catch (e) {
    try {
      console.error(
        `[nc-privileged-helper] artifact reconcile skipped: ${(e instanceof Error ? e.message : String(e)).slice(0, 200)}`
      );
    } catch {}
  }
  const server = createLinuxPrivilegedHelperServer({
    config,
    publicKey,
    handlers: linuxPrivilegedHelperHandlers()
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ fd: 3 }, () => resolve(server));
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error?.message || 'PRIVILEGED_HELPER_START_FAILED');
    process.exitCode = 1;
  });
}
