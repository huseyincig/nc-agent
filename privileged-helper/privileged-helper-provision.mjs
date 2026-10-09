import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { normalizeServiceMode } from '../src/client/shell-runner.mjs';
import { invokePrivilegedHelper as defaultInvokePrivilegedHelper } from './privileged-helper-ipc.mjs';

const runRaw = promisify(execFile);

/**
 * Faz 10 OTA provisioning for the Linux privileged helper (system installs
 * running as root). Mirrors install-linux.sh helper section, but consumes
 * the prebuilt binary from the release tree instead of a toolchain.
 *
 * Privilege reality: an unprivileged agent (user mode, or a system install
 * running as its service account) can NEVER write root-owned helper paths.
 * Those cases skip with a drift reason (surfaced in logs; the advertise
 * gate keeps the tool hidden) instead of failing the activation.
 * @param {string} cmd
 * @param {Array<string>} args
 */
async function defaultExec(cmd, args) {
  try {
    const r = await runRaw(cmd, args, { timeout: 60000, windowsHide: true });
    return { code: 0, stdout: String(r.stdout || ''), stderr: String(r.stderr || '') };
  } catch (e) {
    const rec = e && typeof e === 'object' ? e : {};
    return {
      code: Number.isInteger(rec.code) ? rec.code : 1,
      stdout: String(rec.stdout || ''),
      stderr: String(rec.stderr || '')
    };
  }
}

/**
 * @param {string} gidFileContents
 * @param {unknown} gid
 */
async function groupNameForGid(gidFileContents, gid) {
  for (const line of String(gidFileContents || '').split('\n')) {
    const parts = line.split(':');
    if (parts.length >= 3 && Number(parts[2]) === Number(gid) && parts[0]) return parts[0];
  }
  return Number(gid) === 0 ? 'root' : null;
}

// Exported for the release-sync test: these templates must ride the OTA
// client payload (REQUIRED_UPDATE_FILES) or step 4 can never succeed.
export const HELPER_UNIT_FILES = Object.freeze([
  {
    template: 'install/nc-privileged-helper-linux.socket.in',
    dest: '/etc/systemd/system/nc-privileged-helper.socket',
    mode: 0o644,
    vars: { '@NC_SERVICE_GROUP@': 'group' }
  },
  {
    template: 'install/nc-privileged-helper-linux.service.in',
    dest: '/etc/systemd/system/nc-privileged-helper.service',
    mode: 0o644,
    vars: { '@NODE_BIN@': 'nodeBin' }
  },
  {
    template: 'install/nc-privileged-helper-tmpfiles.in',
    dest: '/etc/tmpfiles.d/nc-privileged-helper.conf',
    mode: 0o644,
    vars: { '@NC_SERVICE_GROUP@': 'group' }
  }
]);

/**
 * @param {object} [options]
 * @param {string} [options.platform]
 * @param {string} [options.arch]
 * @param {number|null} [options.euid]
 * @param {string} [options.serviceMode]
 * @param {{app?: string, root?: string, config?: string}} [options.layout]
 * @param {string} [options.clientId]
 * @param {number} [options.serviceUid]
 * @param {number} [options.serviceGid]
 * @param {string} [options.nodeBin]
 * @param {string} [options.envFile]
 * @param {string} [options.deviceKeyFile]
 * @param {string} [options.configFile]
 * @param {string} [options.publicKeyFile]
 * @param {string} [options.peercredDest]
 * @param {string} [options.socketPath]
 * @param {string} [options.runtimeDir]
 * @param {(cmd: string, args: Array<string>) => Promise<{code: number, stdout: string, stderr: string}>} [options.exec]
 * @param {typeof fs} [options.fsp]
 * @returns {Promise<{provisioned: boolean, reason: string, steps: Array<string>}>}
 */
export async function provisionLinuxHelperPostSwap({
  platform = process.platform,
  arch = process.arch,
  euid = typeof process.geteuid === 'function' ? process.geteuid() : null,
  serviceMode = process.env.NC_SERVICE_MODE || '',
  layout = null,
  clientId = '',
  serviceUid = 0,
  serviceGid = 0,
  nodeBin = process.execPath,
  envFile = '/opt/nc/config/nc-client.env',
  deviceKeyFile = '/opt/nc/config/nc-device-key.pem',
  configFile = '/opt/nc/config/privileged-helper.json',
  publicKeyFile = '/opt/nc/config/privileged-helper-public.pem',
  peercredDest = '/opt/nc/libexec/nc-linux-peercred',
  socketPath = '/run/nc/privileged-helper-v1.sock',
  runtimeDir = '/run/nc',
  exec = defaultExec,
  fsp = fs
} = {}) {
  const steps = [];
  const skip = (reason) => ({ provisioned: false, reason, steps });
  if (platform !== 'linux') return skip('NON_LINUX_PLATFORM');
  if (normalizeServiceMode(serviceMode, 'NC_SERVICE_MODE') === 'user') return skip('USER_MODE_BY_DESIGN');
  if (euid !== 0) return skip('NOT_RUNNING_AS_ROOT');
  if (arch !== 'x64') return skip(`UNSUPPORTED_ARCH:${arch}`);
  const appDir = layout?.app || '/opt/nc/app';
  const staged = path.join(appDir, 'native/linux-peercred-linux-x64');
  try {
    const st = await fsp.stat(staged);
    if (!st.isFile()) return skip('STAGED_BINARY_MISSING');
  } catch {
    return skip('STAGED_BINARY_MISSING');
  }
  if (!/^nc_[0-9a-f]{64}$/.test(String(clientId || ''))) return skip('CLIENT_ID_REQUIRED');
  // 1. Install the peercred binary root-owned.
  try {
    await fsp.mkdir(path.dirname(peercredDest), { recursive: true });
    await fsp.copyFile(staged, peercredDest);
    await fsp.chmod(peercredDest, 0o755);
    await fsp.chown(peercredDest, 0, 0);
    steps.push('peercred-binary');
  } catch (e) {
    return skip(`PEERCRED_INSTALL_FAILED:${e instanceof Error ? e.message : e}`);
  }
  // 2. Bootstrap the public key (needs central reachability; fail closed).
  let haveKey = false;
  try {
    const st = await fsp.stat(publicKeyFile);
    haveKey = st.isFile();
  } catch {}
  if (!haveKey) {
    try {
      const { fetchPrivilegedHelperBootstrap } = await import('./privileged-helper-bootstrap.mjs');
      await fetchPrivilegedHelperBootstrap({
        configFile: envFile,
        keyFile: deviceKeyFile,
        publicKeyFile
      });
      await fsp.chown(publicKeyFile, 0, 0).catch(() => {});
      await fsp.chmod(publicKeyFile, 0o644).catch(() => {});
      steps.push('bootstrap-key');
    } catch (e) {
      return skip(`BOOTSTRAP_FAILED:${e instanceof Error ? e.message : e}`);
    }
  }
  // 3. Helper config (preserve an existing one).
  try {
    await fsp.stat(configFile);
    steps.push('config-kept');
  } catch {
    try {
      const body =
        JSON.stringify({ client_id: clientId, service_gid: serviceGid, service_uid: serviceUid }) +
        '\n';
      await fsp.mkdir(path.dirname(configFile), { recursive: true });
      await fsp.writeFile(configFile, body, { mode: 0o600 });
      await fsp.chown(configFile, 0, 0);
      steps.push('config-written');
    } catch (e) {
      return skip(`CONFIG_WRITE_FAILED:${e instanceof Error ? e.message : e}`);
    }
  }
  // 4. systemd units from staged templates (rewrite only on drift).
  const group = await resolveHelperServiceGroup({ serviceGid, fsp });
  let unitsChanged = false;
  for (const unit of HELPER_UNIT_FILES) {
    try {
      const text = await renderHelperUnitText({
        template: unit.template,
        appDir,
        group,
        nodeBin,
        fsp
      });
      let current = null;
      try {
        current = await fsp.readFile(unit.dest, 'utf8');
      } catch {}
      if (current !== text) {
        await fsp.mkdir(path.dirname(unit.dest), { recursive: true });
        await fsp.writeFile(unit.dest, text, { mode: unit.mode });
        await fsp.chown(unit.dest, 0, 0);
        unitsChanged = true;
        steps.push(`unit-${path.basename(unit.dest)}`);
      }
    } catch (e) {
      return skip(`UNIT_WRITE_FAILED:${e instanceof Error ? e.message : e}`);
    }
  }
  void socketPath;
  void runtimeDir;
  // 5. Activate: tmpfiles, reload on drift, enable socket, restart daemon
  // so a refreshed config/identity takes effect. A failed enable means
  // the helper will not start: report not-provisioned (readiness stays
  // red and the tool stays hidden) instead of claiming success.
  try {
    const tmpfiles = HELPER_UNIT_FILES.find((u) => u.dest.includes('tmpfiles'));
    if (tmpfiles) await exec('systemd-tmpfiles', ['--create', tmpfiles.dest]);
    if (unitsChanged) await exec('systemctl', ['daemon-reload']);
    const enabled = await exec('systemctl', ['enable', '--now', 'nc-privileged-helper.socket']);
    if (enabled.code !== 0) {
      return skip(
        `SERVICE_ENABLE_FAILED:${(enabled.stderr || enabled.stdout || '').slice(0, 160)}`
      );
    }
    await exec('systemctl', ['stop', 'nc-privileged-helper.service']);
    steps.push('service-activated');
  } catch (e) {
    return skip(`SERVICE_ACTIVATE_FAILED:${e instanceof Error ? e.message : e}`);
  }
  return { provisioned: true, reason: 'OK', steps };
}

/** Name of the agent-visible helper-upgrade state file under layout.data. */
export const HELPER_UPGRADE_STATE_FILE = 'helper-upgrade-state.json';
/** Staged prebuilt peercred binary inside an activated release tree. */
export const STAGED_PEERCRED_RELATIVE = 'native/linux-peercred-linux-x64';

/**
 * Resolve the service group name for unit rendering (best-effort read of
 * /etc/group; falls back to 'root'). Unprivileged-safe (read-only).
 * @param {object} [options]
 * @param {number} [options.serviceGid]
 * @param {typeof fs} [options.fsp]
 */
export async function resolveHelperServiceGroup({ serviceGid = 0, fsp = fs } = {}) {
  try {
    const etcGroup = await fsp.readFile('/etc/group', 'utf8');
    return (await groupNameForGid(etcGroup, serviceGid)) || 'root';
  } catch {
    return 'root';
  }
}

/**
 * Render one helper unit template exactly as the root provisioner writes it.
 * Shared by the provisioner, drift detection and the daemon boot
 * reconciler so all three agree byte-for-byte on the desired content.
 * @param {object} [options]
 * @param {string} [options.template]
 * @param {string} [options.appDir]
 * @param {string} [options.group]
 * @param {string} [options.nodeBin]
 * @param {typeof fs} [options.fsp]
 */
export async function renderHelperUnitText({
  template = '',
  appDir = '/opt/nc/app',
  group = 'root',
  nodeBin = process.execPath,
  fsp = fs
} = {}) {
  let text = await fsp.readFile(path.join(appDir, template), 'utf8');
  text = text.replace(/@NC_SERVICE_GROUP@/g, group).replace(/@NODE_BIN@/g, nodeBin);
  // The template pins /opt/nc/app; honor relocated canonical trees.
  text = text.split('/opt/nc/app').join(appDir);
  return text;
}

/**
 * @param {unknown} a
 * @param {unknown} b
 */
function bytesEqual(a, b) {
  try {
    const ba = Buffer.isBuffer(a) ? a : Buffer.from(/** @type {any} */ (a));
    const bb = Buffer.isBuffer(b) ? b : Buffer.from(/** @type {any} */ (b));
    return ba.equals(bb);
  } catch {
    return false;
  }
}

/**
 * Read-only drift detection between the activated release tree and the
 * installed root-owned helper artifacts. Unprivileged-safe: every check is
 * a read, so an unprivileged agent can prove skew without elevation.
 * @param {object} [options]
 * @param {string} [options.appDir]
 * @param {number} [options.serviceGid]
 * @param {string} [options.nodeBin]
 * @param {string} [options.peercredDest]
 * @param {typeof fs} [options.fsp]
 * @returns {Promise<{assessable: boolean, drift: boolean|null, reason: string, details: {peercred: string, units: Record<string, string>}}>}
 */
export async function detectLinuxHelperDrift({
  appDir = '/opt/nc/app',
  serviceGid = 0,
  nodeBin = process.execPath,
  peercredDest = '/opt/nc/libexec/nc-linux-peercred',
  fsp = fs
} = {}) {
  const details = { peercred: 'unknown', units: {} };
  let staged = null;
  try {
    staged = await fsp.readFile(path.join(appDir, STAGED_PEERCRED_RELATIVE));
  } catch {
    return { assessable: false, drift: null, reason: 'STAGED_BINARY_MISSING', details };
  }
  let installed = null;
  try {
    installed = await fsp.readFile(peercredDest);
  } catch {
    installed = null;
  }
  details.peercred =
    installed === null ? 'missing' : bytesEqual(staged, installed) ? 'current' : 'drift';
  const group = await resolveHelperServiceGroup({ serviceGid, fsp });
  for (const unit of HELPER_UNIT_FILES) {
    let wanted = null;
    try {
      wanted = await renderHelperUnitText({ template: unit.template, appDir, group, nodeBin, fsp });
    } catch {
      details.units[unit.dest] = 'template-unreadable';
      continue;
    }
    let current = null;
    try {
      current = await fsp.readFile(unit.dest, 'utf8');
    } catch {
      current = null;
    }
    details.units[unit.dest] =
      current === null ? 'missing' : current === wanted ? 'current' : 'drift';
  }
  const drifted =
    details.peercred !== 'current' ||
    Object.values(details.units).some((s) => s !== 'current');
  return {
    assessable: true,
    drift: drifted,
    reason: drifted ? 'HELPER_DRIFT_DETECTED' : 'HELPER_CURRENT',
    details
  };
}

/**
 * Poke the running helper daemon so a swapped release tree takes effect.
 * The poke is a deliberately unsigned minimal frame: the daemon answers
 * with a protocol error AND (post-swap) notices its own sources changed
 * and restarts from the new tree, where the boot reconciler (root)
 * refreshes binaries/units. Any decoded reply — ok or error — proves the
 * daemon is reachable; only a transport failure means it is not.
 * One-shot by design: never looped, so an old daemon that cannot
 * self-upgrade degrades to explicit DEFERRED state instead of a restart
 * storm.
 * @param {object} [options]
 * @param {(request: unknown, options?: unknown) => Promise<unknown>} [options.invoke]
 */
export async function requestHelperCodeReload({ invoke = defaultInvokePrivilegedHelper } = {}) {
  try {
    await invoke({ probe: 'helper_code_reload', protocol_version: '0.0.0' });
    return { reachable: true };
  } catch {
    return { reachable: false };
  }
}

/**
 * Write `dest` atomically (unique tmp sibling + mode/owner fixup + rename)
 * so a crash can never leave a half-written root-owned artifact.
 * Idempotent: byte-identical content skips the write entirely.
 * @param {object} options
 * @param {string} options.dest
 * @param {string|Buffer} options.content
 * @param {number} options.mode
 * @param {typeof fs} [options.fsp]
 */
export async function atomicRootWrite({ dest, content, mode, fsp = fs }) {
  let current = null;
  try {
    current = await fsp.readFile(dest);
  } catch {
    current = null;
  }
  const wanted = typeof content === 'string' ? Buffer.from(content, 'utf8') : Buffer.from(content);
  if (current !== null && bytesEqual(current, wanted)) return 'unchanged';
  const tmp = `${dest}.tmp-${process.pid}-${Date.now()}`;
  await fsp.writeFile(tmp, wanted, { mode });
  try {
    await fsp.chmod(tmp, mode);
    await fsp.chown(tmp, 0, 0);
    await fsp.rename(tmp, dest);
  } catch (e) {
    try {
      await fsp.rm(tmp, { force: true });
    } catch {}
    throw e;
  }
  return 'written';
}

/**
 * Root-side boot reconciler: refresh the installed peercred binary and
 * systemd units from the daemon's own (OTA-swapped) tree when drifted.
 * Runs inside the root daemon at boot, so an unprivileged agent never
 * needs elevation: it only pokes the daemon, the daemon heals itself.
 * Best-effort and idempotent; throws only on unexpected failure (the
 * daemon catches and keeps serving).
 * @param {object} [options]
 * @param {string} [options.appDir]
 * @param {number} [options.serviceGid]
 * @param {string} [options.nodeBin]
 * @param {string} [options.peercredDest]
 * @param {(cmd: string, args: Array<string>) => Promise<{code: number, stdout: string, stderr: string}>} [options.exec]
 * @param {typeof fs} [options.fsp]
 */
export async function reconcileLinuxHelperArtifacts({
  appDir = '/opt/nc/app',
  serviceGid = 0,
  nodeBin = process.execPath,
  peercredDest = '/opt/nc/libexec/nc-linux-peercred',
  exec = defaultExec,
  fsp = fs
} = {}) {
  const steps = [];
  const drift = await detectLinuxHelperDrift({ appDir, serviceGid, nodeBin, peercredDest, fsp });
  if (!drift.assessable) return { reconciled: false, reason: drift.reason, steps };
  if (!drift.drift) return { reconciled: true, reason: 'HELPER_CURRENT', steps: ['already-current'] };
  if (drift.details.peercred !== 'current') {
    const staged = await fsp.readFile(path.join(appDir, STAGED_PEERCRED_RELATIVE));
    await fsp.mkdir(path.dirname(peercredDest), { recursive: true });
    const res = await atomicRootWrite({ dest: peercredDest, content: staged, mode: 0o755, fsp });
    if (res === 'written') steps.push('peercred-binary');
  }
  const group = await resolveHelperServiceGroup({ serviceGid, fsp });
  let unitsChanged = false;
  for (const unit of HELPER_UNIT_FILES) {
    const wanted = await renderHelperUnitText({ template: unit.template, appDir, group, nodeBin, fsp });
    await fsp.mkdir(path.dirname(unit.dest), { recursive: true });
    const res = await atomicRootWrite({ dest: unit.dest, content: wanted, mode: unit.mode, fsp });
    if (res === 'written') {
      unitsChanged = true;
      steps.push(`unit-${path.basename(unit.dest)}`);
    }
  }
  try {
    const tmpfiles = HELPER_UNIT_FILES.find((u) => u.dest.includes('tmpfiles'));
    if (tmpfiles) await exec('systemd-tmpfiles', ['--create', tmpfiles.dest]);
    if (unitsChanged) await exec('systemctl', ['daemon-reload']);
    const enabled = await exec('systemctl', ['enable', '--now', 'nc-privileged-helper.socket']);
    if (enabled.code !== 0) {
      return {
        reconciled: false,
        reason: `SERVICE_ENABLE_FAILED:${(enabled.stderr || enabled.stdout || '').slice(0, 160)}`,
        steps
      };
    }
    await exec('systemctl', ['stop', 'nc-privileged-helper.service']);
    steps.push('service-activated');
  } catch (e) {
    return { reconciled: false, reason: `SERVICE_ACTIVATE_FAILED:${e instanceof Error ? e.message : e}`, steps };
  }
  return { reconciled: true, reason: 'OK', steps };
}

/**
 * @param {string} reason
 */
function actionForProvisionReason(reason) {
  const r = String(reason || 'unknown');
  if (r.startsWith('SERVICE_ENABLE_FAILED') || r.startsWith('SERVICE_ACTIVATE_FAILED'))
    return 'as root: systemctl daemon-reload && systemctl enable --now nc-privileged-helper.socket; else re-run the installer as root';
  if (r.startsWith('BOOTSTRAP_FAILED'))
    return 'check central reachability and device-key validity, then re-run the installer as root';
  if (r.startsWith('PEERCRED_INSTALL_FAILED') || r.startsWith('CONFIG_WRITE_FAILED') || r.startsWith('UNIT_WRITE_FAILED'))
    return 'root-owned paths unwritable — re-run the installer as root';
  if (r === 'STAGED_BINARY_MISSING')
    return 'release lacks the staged helper binary — next OTA or a manual root installer run refreshes the helper';
  if (r.startsWith('UNSUPPORTED_ARCH')) return 'helper unsupported on this arch — privileged ops stay unavailable by design';
  return 're-run the installer as root to refresh the helper';
}

const sleepMs = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Post-swap helper reconciliation for every privilege reality. Root system
 * installs provision directly (existing path). Unprivileged agents detect
 * drift read-only and route the upgrade through the already-running root
 * daemon (poke → daemon restarts into the new tree → boot reconciler
 * refreshes binaries/units as root). Every outcome — including user-mode
 * and unreachable-helper — returns an explicit status with an actionable
 * message; there is no silent skip.
 * @param {object} [options]
 * @param {string} [options.platform]
 * @param {string} [options.arch]
 * @param {number|null} [options.euid]
 * @param {string} [options.serviceMode]
 * @param {{app?: string, root?: string, config?: string, data?: string}|null} [options.layout]
 * @param {string} [options.clientId]
 * @param {number} [options.serviceUid]
 * @param {number} [options.serviceGid]
 * @param {string} [options.nodeBin]
 * @param {(request: unknown, options?: unknown) => Promise<unknown>} [options.invoke]
 * @param {number} [options.recheckWaitMs] budget for the post-poke reconcile poll
 * @param {(cmd: string, args: Array<string>) => Promise<{code: number, stdout: string, stderr: string}>} [options.exec]
 * @param {typeof fs} [options.fsp]
 * @param {string} [options.version] agent version just activated (recorded in state)
 * @returns {Promise<{status: string, reason: string, action: string|null, steps: Array<string>, drift: unknown, state: Record<string, unknown>|undefined}>}
 */
export async function ensureLinuxHelperPostSwap({
  platform = process.platform,
  arch = process.arch,
  euid = typeof process.geteuid === 'function' ? process.geteuid() : null,
  serviceMode = process.env.NC_SERVICE_MODE || '',
  layout = null,
  clientId = '',
  serviceUid = 0,
  serviceGid = 0,
  nodeBin = process.execPath,
  invoke = defaultInvokePrivilegedHelper,
  recheckWaitMs = 10000,
  exec = defaultExec,
  fsp = fs,
  version = ''
} = {}) {
  const steps = [];
  /**
   * @param {string} status
   * @param {string} reason
   * @param {string|null} action
   * @param {unknown} drift
   */
  const finish = (status, reason, action, drift = null) => ({
    status,
    reason,
    action,
    steps,
    drift,
    state:
      platform === 'linux'
        ? {
            status,
            reason,
            action,
            version: String(version || ''),
            at: new Date().toISOString(),
            drift: drift && typeof drift === 'object' ? drift : null
          }
        : undefined
  });
  if (platform !== 'linux') return finish('skipped', 'NON_LINUX_PLATFORM', null);
  if (normalizeServiceMode(serviceMode, 'NC_SERVICE_MODE') === 'user')
    return finish(
      'skipped',
      'USER_MODE_BY_DESIGN',
      'none — user installs run without the privileged helper by design'
    );
  if (arch !== 'x64')
    return finish('skipped', `UNSUPPORTED_ARCH:${arch}`, actionForProvisionReason('UNSUPPORTED_ARCH'));
  const appDir = layout?.app || '/opt/nc/app';
  if (euid === 0) {
    const prov = await provisionLinuxHelperPostSwap({
      platform,
      arch,
      euid,
      serviceMode,
      layout,
      clientId,
      serviceUid,
      serviceGid,
      nodeBin,
      exec,
      fsp
    });
    steps.push(...prov.steps);
    if (prov.provisioned === true) return finish('provisioned', 'OK', null);
    return finish('deferred', prov.reason, actionForProvisionReason(prov.reason));
  }
  // Unprivileged: detect drift read-only, then route the upgrade through
  // the already-running root daemon instead of requiring root ourselves.
  const drift = await detectLinuxHelperDrift({ appDir, serviceGid, nodeBin, fsp });
  if (!drift.assessable)
    return finish('deferred', drift.reason, actionForProvisionReason(drift.reason), drift.details);
  if (!drift.drift) return finish('current', 'HELPER_CURRENT', null, drift.details);
  const poke = await requestHelperCodeReload({ invoke });
  steps.push(poke.reachable ? 'helper-poked' : 'helper-unreachable');
  if (!poke.reachable)
    return finish(
      'deferred',
      'HELPER_UNREACHABLE',
      'as root: systemctl restart nc-privileged-helper (or re-run the installer as root); privileged ops stay unavailable until the helper runs the new tree',
      drift.details
    );
  const deadline = Date.now() + Math.max(0, recheckWaitMs);
  for (;;) {
    const recheck = await detectLinuxHelperDrift({ appDir, serviceGid, nodeBin, fsp });
    if (recheck.assessable && !recheck.drift) {
      steps.push('helper-reconciled');
      return finish('upgraded_via_helper', 'OK', null, recheck.details);
    }
    if (Date.now() >= deadline)
      return finish(
        'deferred',
        'HELPER_RECONCILE_TIMEOUT',
        'the helper restarted but drift persists (older daemon without the boot reconciler?) — re-run the installer as root to refresh binaries/units',
        recheck.assessable ? recheck.details : drift.details
      );
    await sleepMs(500);
  }
}
