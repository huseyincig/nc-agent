import fs from 'node:fs';
import net from 'node:net';
import { spawnSync } from 'node:child_process';
import { normalizeTransportSecret } from './privileged-helper-transport-proof.mjs';

// L01b-5: identities allowed an ACE on the transport-secret file. Anything
// else (Users, Everyone, Authenticated Users, ...) fails the check.
const SECRET_ACL_ALLOWED = new Set(['NT AUTHORITY\\SYSTEM', 'BUILTIN\\ADMINISTRATORS']);

/**
 * Parse `icacls <file>` stdout into ACE identities (upper-cased).
 * Skips blanks and the `Successfully processed...` trailer. Exported for tests.
 * The filename prefix is stripped with the exact queried path (both carry
 * spaces — `C:\nc dir\secret.bin NT AUTHORITY\SYSTEM:(I)(F)` — so no
 * whitespace split can separate them; continuation ACE lines omit the
 * filename and parse whole). An unstrippable line fails closed downstream
 * (unknown identity, never in the allowed set).
 * @param {unknown} output
 * @param {string|null} [file] exact queried path whose prefix is stripped
 * @returns {Array<string>}
 */
export function parseIcaclsIdentities(output, file = null) {
  const out = [];
  const prefix = typeof file === 'string' && file ? file : null;
  for (const line of String(output || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || /^successfully processed/i.test(t)) continue;
    const aceAt = t.indexOf(':(');
    if (aceAt < 1) continue;
    let head = t.slice(0, aceAt);
    if (prefix && head.startsWith(prefix)) head = head.slice(prefix.length);
    const identity = head.trim().toUpperCase();
    if (!identity) continue;
    out.push(identity);
  }
  return out;
}

/**
 * L01b-5: verify the transport-secret file is owned by SYSTEM and grants
 * access to SYSTEM/Administrators only. Fail-closed: ok:true only when
 * both checks positively pass. `run` is injectable for deterministic tests.
 * @param {string} secretFile
 * @param {{run?: ((cmd: string, args: Array<string>) => {status: number|null, stdout: string})|null}} [options]
 */
export function verifyWindowsSecretAcl(secretFile, { run = null } = {}) {
  const runner =
    run ||
    ((cmd, args) => {
      try {
        const r = spawnSync(cmd, args, { timeout: 10000, windowsHide: true, encoding: 'utf8' });
        return { status: r.status, stdout: String(r.stdout || '') };
      } catch {
        return { status: null, stdout: '' };
      }
    });
  try {
    const ic = runner('icacls', [String(secretFile)]);
    if (!ic || ic.status !== 0) return { ok: false };
    const identities = parseIcaclsIdentities(ic.stdout, String(secretFile));
    if (identities.length === 0 || !identities.every((id) => SECRET_ACL_ALLOWED.has(id)))
      return { ok: false };
    const quoted = String(secretFile).replace(/'/g, "''");
    const ow = runner('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-Command',
      `(Get-Acl -LiteralPath '${quoted}').Owner`
    ]);
    if (!ow || ow.status !== 0) return { ok: false };
    if (String(ow.stdout || '').trim().toUpperCase() !== 'NT AUTHORITY\\SYSTEM')
      return { ok: false };
    return { ok: true };
  } catch {
    return { ok: false };
  }
}

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
 * @param {((file: string) => Promise<{ok: boolean}>|{ok: boolean})|null} [options.checkSecretAcl]
 * @param {string} [options.platform]
 */
export function windowsPrivilegedHelperReadiness({
  clientId = '',
  pipePath = '\\\\.\\pipe\\NCPrivilegedV1',
  secretFile = '',
  configFile = '',
  probePipe = null,
  checkSecretAcl = null,
  platform = process.platform
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
    let secretValid = false;
    try {
      const secret = secretFile ? normalizeTransportSecret(fs.readFileSync(secretFile, 'utf8')) : null;
      if (!secret) reasons.push('PRIVILEGED_HELPER_SECRET_INVALID');
      else secretValid = true;
    } catch {
      reasons.push('PRIVILEGED_HELPER_SECRET_INVALID');
    }
    // L01b-5: a readable secret with a loose ACL/owner is a leaked
    // credential — verify ownership/ACL and report distinctly. Injected
    // hook in tests; real icacls/Get-Acl check on Windows; skipped
    // elsewhere (this module evaluates Windows readiness).
    if (secretValid && secretFile) {
      if (checkSecretAcl) {
        let r = null;
        try {
          r = await checkSecretAcl(secretFile);
        } catch {
          r = null;
        }
        if (!r || r.ok !== true) reasons.push('PRIVILEGED_HELPER_SECRET_PERMISSIONS');
      } else if (platform === 'win32') {
        if (!verifyWindowsSecretAcl(secretFile).ok)
          reasons.push('PRIVILEGED_HELPER_SECRET_PERMISSIONS');
      }
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
