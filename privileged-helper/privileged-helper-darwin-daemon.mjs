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
import { verifyDarwinHelperPeer } from '../src/client/darwin-peer-credentials.mjs';
import { darwinPrivilegedHelperHandlers } from './privileged-helper-darwin-operations.mjs';

// Canonical macOS system-install paths (mirror the Linux layout; the
// LaunchDaemon runs as root, the agent as its service account).
export const DARWIN_HELPER_CONFIG = '/opt/nc/libexec/privileged-helper/privileged-helper.json';
export const DARWIN_HELPER_PUBLIC_KEY = '/opt/nc/libexec/privileged-helper/privileged-helper-public.pem';
export const DARWIN_PEERCRED_BINARY = '/opt/nc/libexec/nc-darwin-peercred';
const CLIENT_ID_RE = /^nc_[0-9a-f]{64}$/;

/**
 * @param {string} [file]
 */
export function loadDarwinPrivilegedHelperConfig(file = DARWIN_HELPER_CONFIG) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('PRIVILEGED_HELPER_CONFIG_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (value);
  if (!CLIENT_ID_RE.test(String(rec.client_id || '')))
    throw new Error('PRIVILEGED_HELPER_CONFIG_INVALID');
  if (!Number.isSafeInteger(rec.service_uid) || !Number.isSafeInteger(rec.service_gid))
    throw new Error('PRIVILEGED_HELPER_CONFIG_INVALID');
  return Object.freeze({ ...value });
}

/**
 * @param {string} [file]
 */
export function loadDarwinPrivilegedHelperPublicKey(file = DARWIN_HELPER_PUBLIC_KEY) {
  const key = crypto.createPublicKey(fs.readFileSync(file));
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('PRIVILEGED_HELPER_AUTH_INVALID');
  return key;
}

/**
 * @param {object} [options]
 * @param {any} [options.config]
 * @param {unknown} [options.publicKey]
 * @param {string} [options.peercredBinary]
 * @param {Record<string, (payload: unknown, context: Record<string, unknown>) => unknown>} [options.handlers]
 * @param {string} [options.socketPath]
 */
export function createDarwinPrivilegedHelperServer({
  config,
  publicKey,
  peercredBinary = DARWIN_PEERCRED_BINARY,
  handlers = {},
  socketPath = '/var/run/nc/privileged-helper-v1.sock'
} = {}) {
  if (process.platform !== 'darwin')
    throw new Error('PRIVILEGED_HELPER_PLATFORM_UNSUPPORTED');
  const core = createPrivilegedHelperCore({
    clientId: config.client_id,
    publicKey,
    handlers,
    platform: 'darwin',
    peerIdentity: '_nc'
  });
  /**
   * @param {import('node:net').Socket} socket
   * @param {Buffer} buffer
   */
  const dispatchFrame = async (socket, buffer) => {
    const peer = await verifyDarwinHelperPeer(socket, {
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
  };
  const server = net.createServer((socket) => {
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
      void dispatchFrame(socket, buffer).catch(() => {
        try {
          socket.end(
            encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_EXECUTION_FAILED' })
          );
        } catch {
          socket.destroy();
        }
      });
    });
  });
  void socketPath;
  return server;
}

export async function main() {
  const config = loadDarwinPrivilegedHelperConfig(),
    publicKey = loadDarwinPrivilegedHelperPublicKey();
  const server = createDarwinPrivilegedHelperServer({
    config,
    publicKey,
    handlers: darwinPrivilegedHelperHandlers()
  });
  const socketPath = '/var/run/nc/privileged-helper-v1.sock';
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => resolve(server));
  });
  try {
    fs.chmodSync(socketPath, 0o660);
  } catch {}
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error?.message || 'PRIVILEGED_HELPER_START_FAILED');
    process.exitCode = 1;
  });
}
