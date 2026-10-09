import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { readCappedResponseBody } from '../updater/updater.mjs';
import {
  createDeviceProof,
  deviceAuthHeaders,
  deviceKeyThumbprint,
  devicePublicKey,
  ensureDeviceKey
} from './device-proof.mjs';

const readStdin = async () => {
  let out = '';
  for await (const chunk of process.stdin) out += chunk;
  return out.trim();
};

/**
 * @param {object} [options]
 * @param {string} [options.serverUrl]
 * @param {string} [options.hostId]
 * @param {string} [options.keyFile]
 * @param {string} [options.archiveFile]
 * @param {string} [options.enrollmentToken]
 */
export async function enrollBootstrap({
  serverUrl,
  hostId,
  keyFile,
  archiveFile,
  enrollmentToken
} = {}) {
  const server = String(serverUrl || '').replace(/\/$/, '');
  if (!/^https:\/\//i.test(server) && !/^http:\/\/127\.0\.0\.1(?::\d+)?$/i.test(server))
    throw new Error('ENROLLMENT_HTTPS_REQUIRED');
  if (!/^nc_[0-9a-f]{64}$/.test(String(hostId || ''))) throw new Error('INVALID_CLIENT_ID');
  if (typeof keyFile !== 'string' || !keyFile || typeof archiveFile !== 'string' || !archiveFile)
    throw new Error('ENROLLMENT_PATH_REQUIRED');
  if (!/^nc_enr_[0-9a-f]{64}$/.test(String(enrollmentToken || '')))
    throw new Error('INVALID_ENROLLMENT_TOKEN');

  const privateKey = await ensureDeviceKey(keyFile);
  const publicKey = devicePublicKey(privateKey);
  const thumbprint = deviceKeyThumbprint(publicKey);

  const redeemUrl = server + '/api/enroll/redeem';
  const proof = createDeviceProof({
    privateKey,
    clientId: hostId,
    method: 'POST',
    url: redeemUrl,
    credential: enrollmentToken
  });
  const redeemResponse = await fetch(redeemUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'NC-Device-Proof': proof },
    body: JSON.stringify({ host_id: hostId, token: enrollmentToken, device_public_key: publicKey }),
    signal: AbortSignal.timeout(15000)
  });
  const redeemText = await redeemResponse.text();
  /** @type {any} */
  let redeemed = {};
  try {
    redeemed = redeemText ? JSON.parse(redeemText) : {};
  } catch {}
  if (!redeemResponse.ok)
    throw new Error(String(redeemed.error || 'ENROLL_REDEEM_HTTP_' + redeemResponse.status));
  if (
    redeemed.client_id !== hostId ||
    redeemed.token_type !== 'NC-Device' ||
    redeemed.device_key_thumbprint !== thumbprint
  )
    throw new Error('ENROLLMENT_BINDING_MISMATCH');
  if (!/^nc_tok_[0-9a-f]{64}$/.test(String(redeemed.client_token || '')))
    throw new Error('INVALID_CLIENT_TOKEN');
  const release = redeemed.release;
  if (
    !release ||
    typeof release.bootstrap_url !== 'string' ||
    !release.bootstrap_url.startsWith('/') ||
    !/^[0-9a-f]{64}$/.test(String(release.bootstrap_sha256 || ''))
  )
    throw new Error('CLIENT_BOOTSTRAP_MANIFEST_INVALID');

  const bootstrapUrl = server + release.bootstrap_url;
  const headers = deviceAuthHeaders({
    privateKey,
    clientId: hostId,
    method: 'GET',
    url: bootstrapUrl,
    token: redeemed.client_token
  });
  const bootstrapResponse = await fetch(bootstrapUrl, {
    headers,
    signal: AbortSignal.timeout(30000)
  });
  if (!bootstrapResponse.ok) throw new Error('CLIENT_BOOTSTRAP_HTTP_' + bootstrapResponse.status);
  const body = await readCappedResponseBody(bootstrapResponse);
  const actual = crypto.createHash('sha256').update(body).digest('hex');
  if (actual !== release.bootstrap_sha256) throw new Error('NC_BOOTSTRAP_SHA256_MISMATCH');
  await fs.writeFile(archiveFile, body, { mode: 0o600 });
  return {
    client_id: hostId,
    client_token: redeemed.client_token,
    token_type: 'NC-Device',
    device_key_thumbprint: thumbprint,
    release
  };
}

if (process.argv[1] && process.argv[1].endsWith('enroll-bootstrap.mjs')) {
  const [serverUrl, hostId, keyFile, archiveFile] = process.argv.slice(2);
  try {
    const enrollmentToken = await readStdin();
    const out = await enrollBootstrap({ serverUrl, hostId, keyFile, archiveFile, enrollmentToken });
    process.stdout.write(JSON.stringify(out));
  } catch (error) {
    const message =
      error && typeof error === 'object' && 'message' in error && error.message
        ? error.message
        : error;
    process.stderr.write(String(message) + '\n');
    process.exitCode = 1;
  }
}
