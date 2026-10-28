import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

export const DEVICE_PROOF_VERSION = 'v1';
const PUBLIC_KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;

/**
 * @param {import('node:crypto').KeyLike} privateKey
 */
const publicRawFromPrivate = (privateKey) => {
  const jwk = crypto.createPublicKey(privateKey).export({ format: 'jwk' });
  const x = String(jwk?.x || '');
  if (
    jwk?.kty !== 'OKP' ||
    jwk?.crv !== 'Ed25519' ||
    !PUBLIC_KEY_RE.test(x) ||
    Buffer.from(x, 'base64url').length !== 32
  )
    throw new Error('DEVICE_PUBLIC_KEY_INVALID');
  return x;
};

/**
 * @param {unknown} value
 */
export function normalizeRequestTarget(value) {
  const u = /^https?:\/\//i.test(String(value))
    ? new URL(String(value))
    : new URL(String(value), 'http://nc.invalid');
  if (u.hash) throw new Error('DEVICE_PROOF_TARGET_INVALID');
  return (u.pathname || '/') + (u.search || '');
}

/**
 * @param {unknown} credential
 */
export function credentialHash(credential) {
  if (typeof credential !== 'string' || !credential) throw new Error('DEVICE_CREDENTIAL_REQUIRED');
  // utf8 (not ascii): ascii silently folds code points >127, collapsing
  // distinct non-ASCII passphrases onto the same hash (keep parity with
  // the live copy at apps/control-plane/lib/device-proof.mjs).
  return crypto.createHash('sha256').update(credential, 'utf8').digest('hex');
}

/**
 * @param {unknown} publicKey
 */
export function deviceKeyThumbprint(publicKey) {
  if (!PUBLIC_KEY_RE.test(String(publicKey || ''))) throw new Error('DEVICE_PUBLIC_KEY_INVALID');
  return crypto
    .createHash('sha256')
    .update(Buffer.from(/** @type {string} */ (publicKey), 'base64url'))
    .digest('base64url');
}

export function generateDevicePrivateKeyPem() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

/**
 * @param {string} file
 */
export async function loadDeviceKey(file) {
  const pem = await fs.readFile(file, 'utf8');
  let key;
  try {
    key = crypto.createPrivateKey(pem);
  } catch {
    throw new Error('DEVICE_KEY_INVALID');
  }
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('DEVICE_KEY_INVALID');
  return key;
}

/**
 * @param {string} file
 */
export async function ensureDeviceKey(file) {
  try {
    return await loadDeviceKey(file);
  } catch (error) {
    const errorCode =
      error && typeof error === 'object' && 'code' in error ? error.code : undefined;
    if (errorCode !== 'ENOENT') throw error;
  }
  await fs.mkdir(path.dirname(file), { recursive: true });
  const pem = generateDevicePrivateKeyPem();
  const tmp = file + '.tmp-' + process.pid + '-' + crypto.randomBytes(6).toString('hex');
  await fs.writeFile(tmp, pem, { mode: 0o600, flag: 'wx' });
  await fs.chmod(tmp, 0o600);
  try {
    await fs.rename(tmp, file);
  } catch (error) {
    await fs.rm(tmp, { force: true });
    const errorCode =
      error && typeof error === 'object' && 'code' in error ? error.code : undefined;
    if (errorCode !== 'EEXIST' && errorCode !== 'EPERM') throw error;
  }
  const key = await loadDeviceKey(file);
  try {
    await fs.chmod(file, 0o600);
  } catch {}
  return key;
}

/**
 * @param {unknown} privateKey
 */
export function devicePublicKey(privateKey) {
  const key =
    typeof privateKey === 'string'
      ? crypto.createPrivateKey(privateKey)
      : /** @type {import('node:crypto').KeyObject} */ (privateKey);
  if (!key || key.asymmetricKeyType !== 'ed25519') throw new Error('DEVICE_KEY_INVALID');
  return publicRawFromPrivate(key);
}

/**
 * @param {object} [options]
 * @param {unknown} [options.clientId]
 * @param {unknown} [options.method]
 * @param {unknown} [options.target]
 * @param {unknown} [options.credential]
 * @param {unknown} [options.iat]
 * @param {unknown} [options.nonce]
 */
export function deviceProofCanonical({ clientId, method, target, credential, iat, nonce } = {}) {
  const id = String(clientId || ''),
    m = String(method || '').toUpperCase(),
    t = normalizeRequestTarget(target),
    h = credentialHash(credential),
    n = String(nonce || '');
  if (!/^nc_[0-9a-f]{64}$/.test(id)) throw new Error('INVALID_CLIENT_ID');
  if (!/^[A-Z]+$/.test(m)) throw new Error('DEVICE_PROOF_METHOD_INVALID');
  if (!Number.isInteger(iat)) throw new Error('DEVICE_PROOF_TIME_INVALID');
  if (!NONCE_RE.test(n)) throw new Error('DEVICE_PROOF_NONCE_INVALID');
  return [
    'NC-DEVICE-PROOF-V1',
    'client_id:' + id,
    'method:' + m,
    'target:' + t,
    'credential_sha256:' + h,
    'iat:' + String(iat),
    'nonce:' + n,
    ''
  ].join('\n');
}

/**
 * @param {object} [options]
 * @param {string|object} [options.privateKey]
 * @param {string} [options.clientId]
 * @param {string} [options.method]
 * @param {string} [options.url]
 * @param {string} [options.credential]
 * @param {number} [options.iat]
 * @param {string} [options.nonce]
 */
export function createDeviceProof({
  privateKey,
  clientId,
  method,
  url,
  credential,
  iat = Math.floor(Date.now() / 1000),
  nonce = crypto.randomBytes(16).toString('hex')
} = {}) {
  const key =
    typeof privateKey === 'string'
      ? crypto.createPrivateKey(privateKey)
      : /** @type {import('node:crypto').KeyObject} */ (privateKey);
  if (!key || key.asymmetricKeyType !== 'ed25519') throw new Error('DEVICE_KEY_INVALID');
  const canonical = deviceProofCanonical({ clientId, method, target: url, credential, iat, nonce });
  const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), key).toString('base64url');
  return `v1.${iat}.${nonce}.${signature}`;
}

/**
 * @param {object} [options]
 * @param {unknown} [options.privateKey]
 * @param {unknown} [options.clientId]
 * @param {unknown} [options.method]
 * @param {unknown} [options.url]
 * @param {unknown} [options.token]
 */
export function deviceAuthHeaders({ privateKey, clientId, method, url, token } = {}) {
  if (typeof token !== 'string' || !token) throw new Error('CLIENT_TOKEN_REQUIRED');
  return {
    authorization: 'NC-Device ' + token,
    'nc-device-proof': createDeviceProof({
      privateKey: /** @type {string | object} */ (privateKey),
      clientId: /** @type {string} */ (clientId),
      method: /** @type {string} */ (method),
      url: /** @type {string} */ (url),
      credential: token
    })
  };
}
