import fs from 'node:fs';
import net from 'node:net';
import { normalizeTransportSecret } from './privileged-helper-transport-proof.mjs';

/**
 * Windows readiness (Faz 10): pipe reachable + transport secret present +
 * config identity matches. No elevation needed to evaluate (connect probe
 * + file reads), so the advertise gate reflects reality on every boot.
 * @param {object} [options]
 * @param {string} [options.clientId]
 * @param {string} [options.pipePath]
 * @param {string} [options.secretFile]
 * @param {string} [options.configFile]
 * @param {(path: string) => Promise<{ok: boolean}>} [options.probePipe]
 */
export function windowsPrivilegedHelperReadiness({
  clientId = '',
  pipePath = '\\\\.\\pipe\\NCPrivilegedV1',
  secretFile = '',
  configFile = '',
  probePipe = null
} = {}) {
  const reasons = [];
  const probe =
    probePipe ||
    (async (p) => {
      try {
        await new Promise((resolve, reject) => {
          const s = net.createConnection(p);
          const t = setTimeout(() => {
            try {
              s.destroy();
            } catch {}
            reject(new Error('timeout'));
          }, 2000);
          s.once('connect', () => {
            clearTimeout(t);
            try {
              s.destroy();
            } catch {}
            resolve(true);
          });
          s.once('error', (e) => {
            clearTimeout(t);
            reject(e);
          });
        });
        return { ok: true };
      } catch {
        return { ok: false };
      }
    });
  return (async () => {
    if (!/^nc_[0-9a-f]{64}$/.test(String(clientId || '')))
      reasons.push('PRIVILEGED_HELPER_CLIENT_ID_INVALID');
    try {
      const secret = secretFile ? normalizeTransportSecret(fs.readFileSync(secretFile, 'utf8')) : null;
      if (!secret) reasons.push('PRIVILEGED_HELPER_SECRET_INVALID');
    } catch {
      reasons.push('PRIVILEGED_HELPER_SECRET_INVALID');
    }
    if (configFile) {
      try {
        const cfg = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        if (cfg?.client_id !== clientId) reasons.push('PRIVILEGED_HELPER_CONFIG_MISMATCH');
      } catch {
        reasons.push('PRIVILEGED_HELPER_CONFIG_INVALID');
      }
    }
    const p = await probe(pipePath);
    if (!p.ok) reasons.push('PRIVILEGED_HELPER_PIPE_UNREACHABLE');
    return reasons.length ? { ok: false, reasons } : { ok: true, reasons: [] };
  })();
}
