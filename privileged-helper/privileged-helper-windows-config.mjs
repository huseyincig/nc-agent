import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const CLIENT_ID_RE = /^nc_[0-9a-f]{64}$/;

/**
 * @param {string} [root]
 */
export function windowsHelperPaths(root = process.env.NC_WINDOWS_ROOT || 'C:\\ProgramData\\NC') {
  return {
    root,
    configFile: path.join(root, 'config', 'privileged-helper.json'),
    publicKeyFile: path.join(root, 'config', 'privileged-helper-public.pem'),
    secretFile: path.join(root, 'config', 'transport-secret.bin'),
    serviceScript: path.join(root, 'app', 'privileged-helper-windows-service.mjs')
  };
}

/**
 * @param {string} [file]
 */
export function loadWindowsHelperConfig(file) {
  const paths = windowsHelperPaths();
  const value = JSON.parse(fs.readFileSync(file || paths.configFile, 'utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('PRIVILEGED_HELPER_CONFIG_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (value);
  if (!CLIENT_ID_RE.test(String(rec.client_id || '')))
    throw new Error('PRIVILEGED_HELPER_CONFIG_INVALID');
  return Object.freeze({
    ...value,
    transport_secret_file: String(rec.transport_secret_file || paths.secretFile)
  });
}

/**
 * @param {string} [file]
 */
export function loadWindowsHelperPublicKey(file) {
  const key = crypto.createPublicKey(
    fs.readFileSync(file || windowsHelperPaths().publicKeyFile)
  );
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('PRIVILEGED_HELPER_AUTH_INVALID');
  return key;
}
