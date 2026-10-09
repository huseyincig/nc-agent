import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import { deviceAuthHeaders, loadDeviceKey } from '../src/client/device-proof.mjs';
import { privilegedHelperPublicKeyId } from './privileged-helper-contract.mjs';

const CLIENT_ID_RE = /^nc_[0-9a-f]{64}$/;
/**
 * @param {unknown} text
 */
function parseEnv(text) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const line of String(text).split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1);
  }
  return out;
}
/**
 * @param {object} [options]
 * @param {string} [options.configFile]
 * @param {string} [options.keyFile]
 * @param {string} [options.publicKeyFile]
 */
export async function fetchPrivilegedHelperBootstrap({
  configFile = '/opt/nc/config/nc-client.env',
  keyFile = '/opt/nc/config/nc-device-key.pem',
  publicKeyFile = '/opt/nc/config/privileged-helper-public.pem'
} = {}) {
  const env = parseEnv(await fs.readFile(configFile, 'utf8')),
    server = String(env.NC_SERVER_URL || '').replace(/\/$/, ''),
    clientId = String(env.NC_CLIENT_ID || ''),
    token = String(env.NC_CLIENT_TOKEN || '');
  if (!server.startsWith('https://')) throw new Error('PRIVILEGED_HELPER_HTTPS_REQUIRED');
  if (!CLIENT_ID_RE.test(clientId) || !token)
    throw new Error('PRIVILEGED_HELPER_CLIENT_CONFIG_INVALID');
  const privateKey = await loadDeviceKey(keyFile),
    target = `/api/clients/${encodeURIComponent(clientId)}/privileged-helper/bootstrap`,
    url = server + target;
  const headers = deviceAuthHeaders({ privateKey, clientId, method: 'GET', url, token });
  const response = await fetch(url, { headers, signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error('PRIVILEGED_HELPER_BOOTSTRAP_HTTP_' + response.status);
  const body = await response.json();
  if (
    body?.protocol_version !== '1.0.0' ||
    typeof body.public_key_pem !== 'string' ||
    typeof body.key_id !== 'string'
  )
    throw new Error('PRIVILEGED_HELPER_BOOTSTRAP_INVALID');
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(body.public_key_pem);
  } catch {
    throw new Error('PRIVILEGED_HELPER_BOOTSTRAP_INVALID');
  }
  if (
    publicKey.asymmetricKeyType !== 'ed25519' ||
    privilegedHelperPublicKeyId(publicKey) !== body.key_id
  )
    throw new Error('PRIVILEGED_HELPER_BOOTSTRAP_INVALID');
  // Unique tmp per writer: concurrent bootstraps must never share one tmp
  // path ('wx' would fail the loser with EEXIST). Mirrors ensureDeviceKey.
  const tmp = `${publicKeyFile}.tmp-${process.pid}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  await fs.writeFile(tmp, body.public_key_pem, { mode: 0o600, flag: 'wx' });
  try {
    await fs.rename(tmp, publicKeyFile);
  } catch (error) {
    await fs.rm(tmp, { force: true });
    throw error;
  }
  // V-32.9: no post-rename chmod. rename(2) preserves the tmp mode (0600
  // above); a chmod after rename re-opens the path and is vulnerable to a
  // symlink swap between rename and chmod (TOCTOU).
  return {
    protocol_version: body.protocol_version,
    key_id: body.key_id,
    public_key_file: publicKeyFile
  };
}
if (process.argv[1] && process.argv[1].endsWith('privileged-helper-bootstrap.mjs'))
  fetchPrivilegedHelperBootstrap({
    configFile: process.argv[2],
    keyFile: process.argv[3],
    publicKeyFile: process.argv[4]
  })
    .then((x) => process.stdout.write(JSON.stringify(x) + '\n'))
    .catch((e) => {
      process.stderr.write((e?.message || 'PRIVILEGED_HELPER_BOOTSTRAP_FAILED') + '\n');
      process.exitCode = 1;
    });
