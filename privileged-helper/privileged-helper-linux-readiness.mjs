import fs from 'node:fs';
import crypto from 'node:crypto';
import {
  loadLinuxPrivilegedHelperConfig,
  LINUX_HELPER_CONFIG,
  LINUX_HELPER_PUBLIC_KEY,
  LINUX_PEERCRED_BINARY
} from './privileged-helper-linux-daemon.mjs';
import { privilegedHelperPublicKeyId } from './privileged-helper-contract.mjs';
import { privilegedHelperEndpoint } from './privileged-helper-ipc.mjs';

/** @param {import('node:fs').Stats} s */
const mode = (s) => s.mode & 0o777;
/**
 * @param {object} [options]
 * @param {string} [options.clientId]
 * @param {number} [options.serviceUid]
 * @param {number} [options.serviceGid]
 * @param {string|null} [options.expectedKeyId]
 * @param {string} [options.configFile]
 * @param {string} [options.publicKeyFile]
 * @param {string} [options.peercredBinary]
 * @param {string} [options.socketPath]
 * @param {string} [options.runtimeDir]
 */
export function linuxPrivilegedHelperReadiness({
  clientId,
  serviceUid,
  serviceGid,
  expectedKeyId = null,
  configFile = LINUX_HELPER_CONFIG,
  publicKeyFile = LINUX_HELPER_PUBLIC_KEY,
  peercredBinary = LINUX_PEERCRED_BINARY,
  socketPath = privilegedHelperEndpoint('linux'),
  runtimeDir = '/run/nc'
} = {}) {
  const reasons = [];
  let keyId = null;
  try {
    const st = fs.statSync(configFile);
    if (st.uid !== 0 || st.gid !== 0 || mode(st) !== 0o600)
      reasons.push('PRIVILEGED_HELPER_CONFIG_PERMISSIONS');
    if (process.getuid?.() === 0) {
      const config = loadLinuxPrivilegedHelperConfig(configFile);
      if (
        config.client_id !== clientId ||
        config.service_uid !== serviceUid ||
        config.service_gid !== serviceGid
      )
        reasons.push('PRIVILEGED_HELPER_CONFIG_MISMATCH');
    }
  } catch (error) {
    const errorCode =
      error && typeof error === 'object' && 'code' in error ? error.code : undefined;
    if (errorCode !== 'EACCES' || process.getuid?.() === 0)
      reasons.push('PRIVILEGED_HELPER_CONFIG_INVALID');
  }
  try {
    const st = fs.statSync(publicKeyFile),
      key = crypto.createPublicKey(fs.readFileSync(publicKeyFile));
    if (key.asymmetricKeyType !== 'ed25519') throw new Error();
    if (st.uid !== 0 || st.gid !== 0 || mode(st) !== 0o644)
      reasons.push('PRIVILEGED_HELPER_PUBLIC_KEY_PERMISSIONS');
    keyId = privilegedHelperPublicKeyId(key);
    if (expectedKeyId && keyId !== expectedKeyId)
      reasons.push('PRIVILEGED_HELPER_PUBLIC_KEY_MISMATCH');
  } catch {
    reasons.push('PRIVILEGED_HELPER_PUBLIC_KEY_INVALID');
  }
  try {
    const st = fs.statSync(peercredBinary);
    if (!st.isFile() || st.uid !== 0 || st.gid !== 0 || mode(st) !== 0o755)
      reasons.push('PRIVILEGED_HELPER_PEERCRED_INVALID');
  } catch {
    reasons.push('PRIVILEGED_HELPER_PEERCRED_INVALID');
  }
  try {
    const st = fs.statSync(runtimeDir);
    if (!st.isDirectory() || st.uid !== 0 || st.gid !== serviceGid || mode(st) !== 0o750)
      reasons.push('PRIVILEGED_HELPER_RUNTIME_DIR_INVALID');
  } catch {
    reasons.push('PRIVILEGED_HELPER_RUNTIME_DIR_INVALID');
  }
  try {
    const st = fs.statSync(socketPath);
    if (!st.isSocket() || st.uid !== 0 || st.gid !== serviceGid || mode(st) !== 0o660)
      reasons.push('PRIVILEGED_HELPER_SOCKET_INVALID');
  } catch {
    reasons.push('PRIVILEGED_HELPER_SOCKET_INVALID');
  }
  return { ok: reasons.length === 0, reasons: [...new Set(reasons)], key_id: keyId };
}
