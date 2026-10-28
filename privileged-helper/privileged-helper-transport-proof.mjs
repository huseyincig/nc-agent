import crypto from 'node:crypto';
import fs from 'node:fs/promises';

/**
 * File-secret transport proof (Faz 10, non-Linux platforms without a
 * peer-credential syscall path in pure Node).
 *
 * Threat model: the daemon cannot inspect the connecting process, so it
 * trusts the OS file ACLs instead — the secret file is readable only by
 * SYSTEM (daemon) and the agent service account. Possession proves
 * same-account origin, equivalent to a uid check. The proof binds to the
 * request's payload_sha256, so a captured proof cannot be replayed onto a
 * different request (envelope TTL + replay set cover same-payload replay).
 * Central Ed25519 authorization is always verified first; this is the
 * transport layer beneath it, mirroring SO_PEERCRED semantics.
 */
const SECRET_RE = /^[0-9a-f]{64}$/;

/**
 * @param {unknown} secretHex
 */
export function normalizeTransportSecret(secretHex) {
  const s = String(secretHex || '').trim().toLowerCase();
  return SECRET_RE.test(s) ? s : null;
}

/**
 * @param {string} payloadSha256
 * @param {string} secretHex
 * @returns {string|null}
 */
export function computeTransportProof(payloadSha256, secretHex) {
  if (!/^[0-9a-f]{64}$/.test(String(payloadSha256 || ''))) return null;
  const secret = normalizeTransportSecret(secretHex);
  if (!secret) return null;
  return crypto
    .createHmac('sha256', Buffer.from(secret, 'hex'))
    .update(String(payloadSha256), 'utf8')
    .digest('hex');
}

/**
 * @param {unknown} proof
 * @param {string} payloadSha256
 * @param {string} secretHex
 */
export function verifyTransportProof(proof, payloadSha256, secretHex) {
  const expected = computeTransportProof(payloadSha256, secretHex);
  if (!expected || typeof proof !== 'string') return false;
  const a = Buffer.from(proof.toLowerCase(), 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/**
 * L01b-4: reply authentication. The daemon HMACs every reply frame with
 * the same file-secret used for request proofs, so a local impostor on
 * the pipe cannot forge privileged-helper replies (request auth alone
 * leaves the response leg spoofable). The digest covers the canonical
 * reply body (JSON without the proof field itself).
 * @param {unknown} reply
 * @returns {string|null} sha256 hex of the canonical reply body
 */
export function replyDigest(reply) {
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) return null;
  const { reply_proof: _dropped, ...body } = /** @type {Record<string, unknown>} */ (reply);
  try {
    return crypto.createHash('sha256').update(JSON.stringify(body), 'utf8').digest('hex');
  } catch {
    return null;
  }
}

/**
 * @param {unknown} reply
 * @param {string} secretHex
 * @returns {Record<string, unknown>|null} reply with reply_proof attached, or null
 */
export function sealHelperReply(reply, secretHex) {
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) return null;
  const digest = replyDigest(reply);
  const proof = digest ? computeTransportProof(digest, secretHex) : null;
  if (!proof) return null;
  return { .../** @type {Record<string, unknown>} */ (reply), reply_proof: proof };
}

/**
 * @param {unknown} reply
 * @param {string} secretHex
 * @returns {boolean}
 */
export function verifyHelperReply(reply, secretHex) {
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) return false;
  const rec = /** @type {Record<string, unknown>} */ (reply);
  if (typeof rec.reply_proof !== 'string') return false;
  const digest = replyDigest(rec);
  if (!digest) return false;
  return verifyTransportProof(rec.reply_proof, digest, secretHex);
}

/**
 * @param {string} [secretFile]
 * @returns {Promise<string|null>}
 */
export async function loadTransportSecret(secretFile) {
  if (!secretFile) return null;
  try {
    return normalizeTransportSecret(await fs.readFile(secretFile, 'utf8'));
  } catch {
    return null;
  }
}
