import net from 'node:net';
import { createPrivilegedHelperCore } from './privileged-helper-core.mjs';
import {
  decodePrivilegedHelperFrame,
  encodePrivilegedHelperFrame,
  PRIVILEGED_HELPER_MAX_FRAME_BYTES
} from './privileged-helper-ipc.mjs';
import {
  verifyTransportProof,
  loadTransportSecret,
  sealHelperReply
} from './privileged-helper-transport-proof.mjs';

export const WINDOWS_HELPER_PIPE = '\\\\.\\pipe\\NCPrivilegedV1';
export const WINDOWS_HELPER_PEER_IDENTITY = 'S-1-5-19';
// L01b-4: cap on concurrent connections. Requests are pre-auth (the proof
// arrives in the first frame), so an unbounded pipe lets any local user
// pin SYSTEM-daemon threads/fds. Small N: legitimate callers issue one
// request per connection and settle fast.
export const WINDOWS_HELPER_MAX_INFLIGHT = 8;
// No protected Windows helper deployment exists in the current single-user
// runtime. Stale configuration/pipe presence cannot make it executable.
export const WINDOWS_PRIVILEGED_HELPER_AVAILABLE = false;

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
 * @param {number} [options.maxInflight]
 */
export function createWindowsPrivilegedHelperServer({
  config,
  publicKey = null,
  secretHex = '',
  endpoint = WINDOWS_HELPER_PIPE,
  peerIdentity = WINDOWS_HELPER_PEER_IDENTITY,
  handlers = {},
  maxInflight = WINDOWS_HELPER_MAX_INFLIGHT
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
  // L01b-4: in-flight counter bounds concurrent UNAUTHENTICATED
  // connections. Increment on accept, decrement exactly once on close;
  // over-limit peers get a single error frame, never a handler thread.
  let inFlight = 0;
  const cap = Math.max(1, Math.min(64, Math.floor(Number(maxInflight) || 0) || WINDOWS_HELPER_MAX_INFLIGHT));
  const seal = (out) => {
    try {
      // L01b-4: HMAC-authenticate every reply frame with the same
      // transport secret (fail open only when no valid secret exists —
      // in which case no request can verify either).
      const sealed = secret ? sealHelperReply(out, secret) : null;
      return encodePrivilegedHelperFrame(sealed || out);
    } catch {
      return encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_FRAME_TOO_LARGE' });
    }
  };
  const server = net.createServer((socket) => {
    if (inFlight >= cap) {
      try {
        socket.end(seal({ ok: false, error: 'PRIVILEGED_HELPER_BUSY' }));
      } catch {
        try {
          socket.destroy();
        } catch {}
      }
      return;
    }
    inFlight++;
    socket.once('close', () => {
      inFlight = Math.max(0, inFlight - 1);
    });
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
        socket.end(seal({ ok: false, error: 'PRIVILEGED_HELPER_FRAME_TOO_LARGE' }));
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
          socket.end(seal(out));
        } catch (e) {
          try {
            socket.end(
              seal({
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
  throw new Error('PRIVILEGED_HELPER_NOT_AVAILABLE');
}

import { pathToFileURL } from 'node:url';

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error?.message || 'PRIVILEGED_HELPER_START_FAILED');
    process.exitCode = 1;
  });
}
