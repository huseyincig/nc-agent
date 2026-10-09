import net from 'node:net';
import { createPrivilegedHelperCore } from './privileged-helper-core.mjs';
import {
  decodePrivilegedHelperFrame,
  encodePrivilegedHelperFrame,
  PRIVILEGED_HELPER_MAX_FRAME_BYTES
} from './privileged-helper-ipc.mjs';
import { verifyTransportProof, loadTransportSecret } from './privileged-helper-transport-proof.mjs';

export const WINDOWS_HELPER_PIPE = '\\\\.\\pipe\\NCPrivilegedV1';
export const WINDOWS_HELPER_PEER_IDENTITY = 'S-1-5-19';

/**
 * Windows privileged-helper service (Faz 10): SYSTEM-owned named-pipe
 * server. Peer authentication is a file-secret HMAC proof (see
 * privileged-helper-transport-proof.mjs): only SYSTEM and the agent
 * service account can read the secret file (installer icacls), which is
 * the enforceable equivalent of a uid check in pure Node. Central
 * Ed25519 authorization is verified by the shared core afterwards.
 * @param {object} [options]
 * @param {any} [options.config]
 * @param {unknown} [options.publicKey]
 * @param {string} [options.secretHex]
 * @param {string} [options.endpoint]
 * @param {string} [options.peerIdentity]
 * @param {Record<string, (payload: unknown, context: Record<string, unknown>) => unknown>} [options.handlers]
 */
export function createWindowsPrivilegedHelperServer({
  config,
  publicKey = null,
  secretHex = '',
  endpoint = WINDOWS_HELPER_PIPE,
  peerIdentity = WINDOWS_HELPER_PEER_IDENTITY,
  handlers = {}
} = {}) {
  const secret = String(secretHex || '');
  const core = createPrivilegedHelperCore({
    clientId: config?.client_id,
    publicKey: publicKey || config?.publicKey || null,
    handlers,
    platform: 'win32',
    peerIdentity
  });
  /**
   * @param {unknown} request
   */
  const checkProof = (request) => {
    const rec = request && typeof request === 'object' && !Array.isArray(request)
      ? /** @type {Record<string, unknown>} */ (request)
      : null;
    if (!rec || typeof rec.payload_sha256 !== 'string') return false;
    return verifyTransportProof(rec.transport_proof, rec.payload_sha256, secret);
  };
  const server = net.createServer((socket) => {
    let buffer = Buffer.alloc(0),
      handled = false;
    // Idle-connection guard: an unauthenticated peer that connects and sends
    // nothing must not hold a SYSTEM-daemon fd forever. Disabled once the
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
        socket.end(encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_FRAME_TOO_LARGE' }));
        return;
      }
      const nl = buffer.indexOf(10);
      if (nl < 0) return;
      handled = true;
      socket.pause();
      socket.setTimeout(0);
      (async () => {
        try {
          if (nl !== buffer.length - 1) throw new Error('PRIVILEGED_HELPER_FRAME_INVALID');
          const request = decodePrivilegedHelperFrame(buffer);
          if (!checkProof(request))
            throw new Error('PRIVILEGED_HELPER_PEER_UNVERIFIED');
          const peer = { transport: 'named_pipe', credential_verified: true, identity: peerIdentity };
          const out = await core.handle(request, { peer });
          socket.end(encodePrivilegedHelperFrame(out));
        } catch (e) {
          try {
            socket.end(
              encodePrivilegedHelperFrame({
                ok: false,
                error: e instanceof Error ? e.message : 'PRIVILEGED_HELPER_EXECUTION_FAILED'
              })
            );
          } catch {
            socket.destroy();
          }
        }
      })().catch(() => {
        try {
          socket.destroy();
        } catch {}
      });
    });
  });
  return server;
}

/**
 * @param {string} [secretFile]
 */
export async function loadWindowsHelperSecret(secretFile) {
  return loadTransportSecret(secretFile);
}

export async function main() {
  const { loadWindowsHelperConfig, loadWindowsHelperPublicKey } = await import(
    './privileged-helper-windows-config.mjs'
  );
  const { windowsPrivilegedHelperHandlers } = await import(
    './privileged-helper-windows-operations.mjs'
  );
  const config = loadWindowsHelperConfig();
  const publicKey = loadWindowsHelperPublicKey();
  const secret = await loadWindowsHelperSecret(config.transport_secret_file);
  if (!secret) throw new Error('PRIVILEGED_HELPER_SECRET_INVALID');
  const server = createWindowsPrivilegedHelperServer({
    config,
    secretHex: secret,
    handlers: windowsPrivilegedHelperHandlers()
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(WINDOWS_HELPER_PIPE, () => resolve(server));
  });
  return server;
}

import { pathToFileURL } from 'node:url';

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error?.message || 'PRIVILEGED_HELPER_START_FAILED');
    process.exitCode = 1;
  });
}
