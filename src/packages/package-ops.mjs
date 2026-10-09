/**
 * Native package-manager operations for the NC agent (contract 5.14.0).
 * Pure parsers are exported for unit tests; handlers exec argv-form
 * commands (no shell) with bounded output, mirroring diagnostics-ops.mjs.
 * Install/remove are convergent (pre-check first) and fail closed with
 * PACKAGE_PRIVILEGE_REQUIRED when system scope needs elevation the agent
 * identity does not have.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { constants as fsConstants } from 'node:fs';
import { access } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { invokePrivilegedHelper as defaultInvokePrivilegedHelper } from '../../privileged-helper/privileged-helper-ipc.mjs';

const run = promisify(execFile);
const MAX_ROWS = 1000;
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9+_.:~-]{0,127}$/;
const PRIV_RE =
  /permission denied|are you root|access is denied|requires elevation|eacces|operation not permitted/i;

/**
 * @param {string} name
 */
export function checkPackageName(name) {
  if (typeof name !== 'string' || !NAME_RE.test(name)) throw new Error('INVALID_PACKAGE_NAME');
}

/**
 * Parse `dpkg-query -W -f='${Package}\t${Version}\n'` or equivalent
 * tab-separated name/version rows.
 * @param {string} text
 */
export function parseTabNameVersion(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const tab = t.indexOf('\t');
    if (tab <= 0) continue;
    const name = t.slice(0, tab).trim();
    const version = t.slice(tab + 1).trim() || null;
    if (name) out.push({ name, version });
  }
  return out;
}

/**
 * Parse `apk info -v` rows (`musl-1.2.4-r2`): split version at the dash
 * that starts a digit run, keeping Alpine -rN revisions with the version.
 * @param {string} text
 */
export function parseApkInfo(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const m = t.match(/^(.*)-(\d[^-]*(?:-r\d+)?)$/);
    if (!m) {
      out.push({ name: t, version: null });
      continue;
    }
    out.push({ name: m[1], version: m[2] });
  }
  return out;
}

/**
 * Parse `pacman -Q` rows (`name version`).
 * @param {string} text
 */
export function parsePacmanQ(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const sp = t.indexOf(' ');
    if (sp <= 0) {
      out.push({ name: t, version: null });
      continue;
    }
    out.push({ name: t.slice(0, sp), version: t.slice(sp + 1).trim() || null });
  }
  return out;
}

/**
 * Parse `brew list --versions` rows (`name 1.2.3 1.2.4`): keep the first
 * reported version.
 * @param {string} text
 */
export function parseBrewVersions(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const parts = t.split(/\s+/);
    if (parts.length < 1) continue;
    out.push({ name: parts[0], version: parts.length > 1 ? parts[1] : null });
  }
  return out;
}

/**
 * Parse Windows registry Uninstall JSON rows ({DisplayName, DisplayVersion}).
 * @param {unknown} rows
 */
export function parseRegistryUninstall(rows) {
  const out = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    const rec = /** @type {Record<string, unknown>} */ (r && typeof r === 'object' ? r : {});
    const name = typeof rec.DisplayName === 'string' ? rec.DisplayName.trim() : '';
    if (!name) continue;
    out.push({
      name,
      version:
        typeof rec.DisplayVersion === 'string' && rec.DisplayVersion.trim()
          ? rec.DisplayVersion.trim()
          : null
    });
  }
  return out;
}

/**
 * @param {unknown} e
 */
function privilegeOrThrow(e, manager) {
  const errRec = /** @type {{message?: unknown}} */ (e && typeof e === 'object' ? e : {});
  const message = String(errRec.message || (typeof e === 'string' ? e : '') || '');
  const out = [message];
  try {
    const rec = /** @type {{stdout?: unknown, stderr?: unknown}} */ (
      e && typeof e === 'object' ? e : {}
    );
    if (rec.stdout) out.push(String(rec.stdout));
    if (rec.stderr) out.push(String(rec.stderr));
  } catch {}
  const full = out.join('\n');
  if (PRIV_RE.test(full)) {
    throw new Error(
      `PACKAGE_PRIVILEGE_REQUIRED: ${manager} system scope needs an elevated agent identity (root/Administrator or the privileged helper); user-domain managers work unprivileged`,
      { cause: e }
    );
  }
  throw new Error(full.slice(0, 2000) || 'PACKAGE_OP_FAILED', { cause: e });
}

/**
 * PATH scan without a shell (execFile has no shell: `command -v` and
 * `which` are not binaries). Mirrors login-shell lookup closely enough
 * for manager detection.
 * @param {string} cmd
 */
async function have(cmd) {
  const dirs = String(process.env.PATH || '')
    .split(path.delimiter)
    .filter(Boolean);
  const names =
    process.platform === 'win32' && !/\.[^.\\/]+$/.test(cmd)
      ? [cmd + '.exe', cmd + '.cmd', cmd + '.bat']
      : [cmd];
  for (const dir of dirs) {
    for (const n of names) {
      try {
        await access(path.join(dir, n), fsConstants.X_OK);
        return true;
      } catch {}
    }
  }
  return false;
}

const LINUX_MANAGERS = ['apt', 'dnf', 'apk', 'pacman', 'zypper'];

/**
 * Real winget presence for the Windows mutating-tools advertise gate.
 * package_list works without winget (registry scan); package_install and
 * package_remove genuinely need the binary, so advertisement must know.
 * @returns {Promise<boolean>}
 */
export async function wingetAvailable() {
  try {
    return (await have('winget')) === true;
  } catch {
    return false;
  }
}

/**
 * Resolve the effective manager: explicit must exist, auto picks the
 * first available for the platform.
 * @param {string} platform @param {string} [wanted]
 */
export async function detectPackageManager(platform, wanted = 'auto') {
  const want = String(wanted || 'auto').toLowerCase();
  if (want !== 'auto') {
    if (platform === 'linux' && !LINUX_MANAGERS.includes(want))
      throw new Error('PACKAGE_MANAGER_UNAVAILABLE');
    if (platform === 'win32' && want !== 'winget') throw new Error('PACKAGE_MANAGER_UNAVAILABLE');
    if (platform === 'darwin' && want !== 'brew') throw new Error('PACKAGE_MANAGER_UNAVAILABLE');
    if (platform !== 'linux' && platform !== 'win32' && platform !== 'darwin')
      throw new Error('PACKAGE_MANAGER_UNAVAILABLE');
    return want;
  }
  if (platform === 'linux') {
    for (const m of LINUX_MANAGERS) {
      const bin = m === 'apt' ? 'apt-get' : m === 'dnf' ? 'dnf' : m;
      if (await have(bin)) return m;
    }
    throw new Error('PACKAGE_MANAGER_UNAVAILABLE');
  }
  if (platform === 'win32') {
    if (await have('winget')) return 'winget';
    return 'registry';
  }
  if (platform === 'darwin') {
    if (await have('brew')) return 'brew';
    throw new Error('PACKAGE_MANAGER_UNAVAILABLE');
  }
  throw new Error('PACKAGE_MANAGER_UNAVAILABLE');
}

/**
 * @param {string} manager
 */
async function listByManager(platform, manager) {
  if (manager === 'apt') {
    const { stdout } = await run('dpkg-query', ['-W', '-f=${Package}\t${Version}\n'], {
      timeout: 30000
    });
    return parseTabNameVersion(stdout);
  }
  if (manager === 'dnf' || manager === 'zypper') {
    const { stdout } = await run(
      'rpm',
      ['-qa', '--queryformat', '%{NAME}\t%{VERSION}-%{RELEASE}\n'],
      { timeout: 30000 }
    );
    return parseTabNameVersion(stdout);
  }
  if (manager === 'apk') {
    const { stdout } = await run('apk', ['info', '-v'], { timeout: 30000 });
    return parseApkInfo(stdout);
  }
  if (manager === 'pacman') {
    const { stdout } = await run('pacman', ['-Q'], { timeout: 30000 });
    return parsePacmanQ(stdout);
  }
  if (manager === 'brew') {
    const { stdout } = await run('brew', ['list', '--versions'], { timeout: 30000 });
    let rows = parseBrewVersions(stdout);
    try {
      const casks = await run('brew', ['list', '--cask', '--versions'], { timeout: 30000 });
      rows = rows.concat(parseBrewVersions(casks.stdout));
    } catch {}
    return rows;
  }
  if (manager === 'winget' || manager === 'registry') {
    const ps =
      'try { chcp 65001 | Out-Null } catch {}; ' +
      '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; ' +
      '$OutputEncoding = [System.Text.Encoding]::UTF8; ' +
      "$paths = @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); " +
      '$rows = foreach ($p in $paths) { Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion }; ' +
      '$rows | ConvertTo-Json -Compress';
    const { stdout } = await run(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', ps],
      { timeout: 30000, windowsHide: true, maxBuffer: 8 * 1024 * 1024, encoding: 'utf8' }
    );
    let parsed = [];
    try {
      const text =
        (Buffer.isBuffer(stdout) ? stdout.toString('utf8') : String(stdout || ''))
          .replace(/^\uFEFF/, '')
          .trim() || '[]';
      const v = JSON.parse(text);
      parsed = Array.isArray(v) ? v : [v];
    } catch {
      throw new Error('PACKAGE_PARSE_FAILED');
    }
    return parseRegistryUninstall(parsed);
  }
  throw new Error('PACKAGE_MANAGER_UNAVAILABLE');
}

/**
 * @param {string} platform @param {string} manager @param {string} name
 */
async function isInstalled(platform, manager, name) {
  try {
    if (manager === 'apt') {
      const { stdout } = await run('dpkg-query', ['-W', '-f=${Status}', name], { timeout: 15000 });
      return String(stdout || '').includes('install ok installed');
    }
    if (manager === 'dnf' || manager === 'zypper') {
      await run('rpm', ['-q', name], { timeout: 15000 });
      return true;
    }
    if (manager === 'apk') {
      await run('apk', ['info', '-e', name], { timeout: 15000 });
      return true;
    }
    if (manager === 'pacman') {
      await run('pacman', ['-Q', name], { timeout: 15000 });
      return true;
    }
    if (manager === 'brew') {
      await run('brew', ['list', '--versions', name], { timeout: 15000 });
      return true;
    }
    if (manager === 'winget' || manager === 'registry') {
      const rows = await listByManager(platform, manager);
      return rows.some((r) => r.name.toLowerCase() === name.toLowerCase());
    }
  } catch {
    return false;
  }
  return false;
}

/**
 * @param {string} platform @param {string} manager @param {string} name
 */
async function installedVersion(platform, manager, name) {
  try {
    const rows = await listByManager(platform, manager);
    const hit = rows.find((r) => r.name.toLowerCase() === name.toLowerCase());
    return hit ? hit.version : null;
  } catch {
    return null;
  }
}

const ok = (/** @type {unknown} */ result_payload) => ({
  status: 'completed',
  exit_code: 0,
  stdout: '',
  stderr: '',
  error: null,
  duration_ms: 0,
  result_payload
});
const fail = (/** @type {unknown} */ error) => ({
  status: 'failed',
  exit_code: null,
  stdout: '',
  stderr: '',
  error: String(error),
  duration_ms: 0,
  result_payload: {}
});

/**
 * @param {unknown} job
 */
function payloadOf(job) {
  const r = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  return /** @type {Record<string, unknown>} */ (r.request_payload || r.payload || {});
}

/**
 * Extract the centrally-signed privileged-helper envelope. Accepts both the
 * canonical `privileged_authorization` key and the `privileged_envelope` alias.
 * @param {unknown} job
 */
function extractPrivilegedAuthorization(job) {
  if (!job || typeof job !== 'object' || Array.isArray(job)) return null;
  const rec = /** @type {Record<string, unknown>} */ (job);
  for (const key of ['privileged_authorization', 'privileged_envelope']) {
    const v = rec[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) return v;
  }
  const payload = payloadOf(job);
  for (const key of ['privileged_authorization', 'privileged_envelope']) {
    const v = payload[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) return v;
  }
  return null;
}

/**
 * @param {unknown} e
 */
function isPrivilegeError(e) {
  const rec =
    /** @type {{code?: unknown, stdout?: unknown, stderr?: unknown, message?: unknown}} */ (
      e && typeof e === 'object' ? e : {}
    );
  if (rec.code === 'EACCES' || rec.code === 'EPERM') return true;
  const parts = [rec.message, rec.stdout, rec.stderr, typeof e === 'string' ? e : '']
    .map((x) => String(x || ''))
    .filter(Boolean);
  return PRIV_RE.test(parts.join('\n')) || /PACKAGE_PRIVILEGE_REQUIRED/.test(parts.join('\n'));
}

/**
 * Dispatch the signed envelope to the helper socket/pipe. Returns the helper
 * `result` on success, throws the ORIGINAL direct error when the helper is
 * unavailable, has no envelope, or reports failure.
 * @param {unknown} job
 * @param {unknown} directError
 * @param {(request: unknown) => Promise<unknown>} invoke
 * @param {(() => boolean)|null} isAvailable
 */
async function dispatchHelperResult(job, directError, invoke, isAvailable) {
  let available = typeof invoke === 'function';
  if (available && typeof isAvailable === 'function') {
    try {
      available = isAvailable();
    } catch {
      available = false;
    }
  }
  const authorization = extractPrivilegedAuthorization(job);
  if (!available || !authorization) throw directError;
  let reply;
  try {
    reply = await invoke(authorization);
  } catch {
    throw directError;
  }
  const rec =
    reply && typeof reply === 'object' ? /** @type {Record<string, any>} */ (reply) : null;
  if (!rec || rec.ok !== true) throw directError;
  const result = rec.result && typeof rec.result === 'object' ? rec.result : null;
  if (!result || result.success !== true) throw directError;
  return result;
}

/**
 * Parse a helper `output_tail` package listing with the manager-appropriate
 * parser, mirroring listByManager shapes.
 * @param {string} manager
 * @param {unknown} outputTail
 */
function parseHelperPackageList(manager, outputTail) {
  const text = String(outputTail || '');
  if (manager === 'apk') return parseApkInfo(text);
  if (manager === 'pacman') return parsePacmanQ(text);
  if (manager === 'brew') return parseBrewVersions(text);
  if (manager === 'winget' || manager === 'registry') {
    try {
      const v = JSON.parse(text.trim() || '[]');
      return parseRegistryUninstall(Array.isArray(v) ? v : [v]);
    } catch {
      return [];
    }
  }
  return parseTabNameVersion(text);
}

/**
 * @param {string} [platform]
 * @param {object} [options]
 * @param {(request: unknown) => Promise<unknown>} [options.invokePrivilegedHelper]
 * @param {() => boolean} [options.isPrivilegedHelperAvailable]
 */
export function makePackageHandlers(
  platform = process.platform,
  { invokePrivilegedHelper = null, isPrivilegedHelperAvailable = null } = {}
) {
  const invoke = invokePrivilegedHelper ?? defaultInvokePrivilegedHelper;
  return {
    package_list: async (job) => {
      const p = (job && (job.request_payload || job.payload)) || {};
      try {
        const manager = await detectPackageManager(platform, p.manager);
        const contains = typeof p.contains === 'string' ? p.contains.toLowerCase() : '';
        const lim = p.limit == null ? 200 : Math.max(1, Math.min(MAX_ROWS, Number(p.limit) || 200));
        let rows;
        try {
          rows = await listByManager(platform, manager);
        } catch (directError) {
          if (!isPrivilegeError(directError)) throw directError;
          const helperResult = await dispatchHelperResult(
            job,
            directError,
            invoke,
            isPrivilegedHelperAvailable
          );
          const helperManager = String(helperResult.manager || manager);
          let helperRows = parseHelperPackageList(helperManager, helperResult.output_tail);
          const helperContains =
            helperResult.contains != null ? String(helperResult.contains).toLowerCase() : contains;
          if (helperContains)
            helperRows = helperRows.filter((r) => r.name.toLowerCase().includes(helperContains));
          const helperLim =
            helperResult.limit != null
              ? Math.max(1, Math.min(MAX_ROWS, Number(helperResult.limit) || lim))
              : lim;
          // Sibling service_* convention: total_count rides with truncated
          // (post-filter, pre-truncation inventory size) so consumers can
          // detect the cut from the payload alone.
          const total_count = helperRows.length;
          const truncated = total_count > helperLim;
          return ok({
            platform,
            manager: helperManager,
            total_count,
            truncated,
            packages: helperRows.slice(0, helperLim),
            privileged: true
          });
        }
        if (contains) rows = rows.filter((r) => r.name.toLowerCase().includes(contains));
        const total_count = rows.length;
        const truncated = total_count > lim;
        return ok({
          platform,
          manager,
          total_count,
          truncated,
          packages: rows.slice(0, lim)
        });
      } catch (e) {
        try {
          privilegeOrThrow(e, 'package');
        } catch (mapped) {
          const mappedMessage = mapped && mapped.message ? mapped.message : 'PACKAGE_OP_FAILED';
          if (/PACKAGE_PRIVILEGE_REQUIRED/.test(String(mappedMessage))) {
            try {
              const helperResult = await dispatchHelperResult(
                job,
                e,
                invoke,
                isPrivilegedHelperAvailable
              );
              const helperManager = String(helperResult.manager || 'auto');
              const helperRows = parseHelperPackageList(helperManager, helperResult.output_tail);
              const total_count = helperRows.length;
              return ok({
                platform,
                manager: helperManager,
                total_count,
                truncated: total_count > MAX_ROWS,
                packages: helperRows.slice(0, MAX_ROWS),
                privileged: true
              });
            } catch {
              return fail(mappedMessage);
            }
          }
          return fail(mappedMessage);
        }
      }
    },
    package_install: async (job) => {
      const p = (job && (job.request_payload || job.payload)) || {};
      try {
        const name = String(p.name || '');
        checkPackageName(name);
        const manager = await detectPackageManager(platform, p.manager);
        if (await isInstalled(platform, manager, name)) {
          return ok({
            platform,
            manager,
            name,
            installed: true,
            version: await installedVersion(platform, manager, name)
          });
        }
        try {
          if (manager === 'apt') await run('apt-get', ['install', '-y', name], { timeout: 600000 });
          else if (manager === 'dnf')
            await run('dnf', ['install', '-y', name], { timeout: 600000 });
          else if (manager === 'zypper')
            await run('zypper', ['--non-interactive', 'install', name], { timeout: 600000 });
          else if (manager === 'apk') await run('apk', ['add', name], { timeout: 600000 });
          else if (manager === 'pacman')
            await run('pacman', ['-S', '--noconfirm', '--needed', name], { timeout: 600000 });
          else if (manager === 'winget')
            await run(
              'winget',
              [
                'install',
                name,
                '--exact',
                '--silent',
                '--accept-package-agreements',
                '--accept-source-agreements'
              ],
              { timeout: 600000, windowsHide: true }
            );
          else if (manager === 'brew') await run('brew', ['install', name], { timeout: 600000 });
          else throw new Error('PACKAGE_MANAGER_UNAVAILABLE');
        } catch (e) {
          try {
            privilegeOrThrow(e, manager);
          } catch (privilegeError) {
            if (!/PACKAGE_PRIVILEGE_REQUIRED/.test(String(privilegeError?.message || '')))
              throw privilegeError;
            const helperResult = await dispatchHelperResult(
              job,
              privilegeError,
              invoke,
              isPrivilegedHelperAvailable
            );
            const helperManager = String(helperResult.manager || manager);
            const helperName = String(helperResult.name || name);
            return ok({
              platform,
              manager: helperManager,
              name: helperName,
              installed: true,
              version: await installedVersion(platform, helperManager, helperName).catch(
                () => null
              ),
              privileged: true
            });
          }
        }
        return ok({
          platform,
          manager,
          name,
          installed: true,
          version: await installedVersion(platform, manager, name)
        });
      } catch (e) {
        const msg = String((e && e.message) || e || 'PACKAGE_OP_FAILED');
        if (/PACKAGE_PRIVILEGE_REQUIRED/.test(msg)) {
          try {
            const helperResult = await dispatchHelperResult(
              job,
              e,
              invoke,
              isPrivilegedHelperAvailable
            );
            const p = payloadOf(job);
            const helperManager = String(helperResult.manager || p.manager || 'auto');
            const helperName = String(helperResult.name || p.name || '');
            return ok({
              platform,
              manager: helperManager,
              name: helperName,
              installed: true,
              version: await installedVersion(platform, helperManager, helperName).catch(
                () => null
              ),
              privileged: true
            });
          } catch {
            return fail(msg);
          }
        }
        return fail(msg);
      }
    },
    package_remove: async (job) => {
      const p = (job && (job.request_payload || job.payload)) || {};
      try {
        const name = String(p.name || '');
        checkPackageName(name);
        const manager = await detectPackageManager(platform, p.manager);
        if (!(await isInstalled(platform, manager, name))) {
          return ok({ platform, manager, name, removed: false });
        }
        try {
          if (manager === 'apt') await run('apt-get', ['remove', '-y', name], { timeout: 600000 });
          else if (manager === 'dnf') await run('dnf', ['remove', '-y', name], { timeout: 600000 });
          else if (manager === 'zypper')
            await run('zypper', ['--non-interactive', 'remove', name], { timeout: 600000 });
          else if (manager === 'apk') await run('apk', ['del', name], { timeout: 600000 });
          else if (manager === 'pacman')
            await run('pacman', ['-R', '--noconfirm', name], { timeout: 600000 });
          else if (manager === 'winget')
            await run(
              'winget',
              [
                'uninstall',
                name,
                '--exact',
                '--silent',
                '--accept-package-agreements',
                '--accept-source-agreements'
              ],
              { timeout: 600000, windowsHide: true }
            );
          else if (manager === 'brew') await run('brew', ['uninstall', name], { timeout: 600000 });
          else throw new Error('PACKAGE_MANAGER_UNAVAILABLE');
        } catch (e) {
          try {
            privilegeOrThrow(e, manager);
          } catch (privilegeError) {
            if (!/PACKAGE_PRIVILEGE_REQUIRED/.test(String(privilegeError?.message || '')))
              throw privilegeError;
            const helperResult = await dispatchHelperResult(
              job,
              privilegeError,
              invoke,
              isPrivilegedHelperAvailable
            );
            const helperManager = String(helperResult.manager || manager);
            const helperName = String(helperResult.name || name);
            return ok({
              platform,
              manager: helperManager,
              name: helperName,
              removed: true,
              privileged: true
            });
          }
        }
        return ok({ platform, manager, name, removed: true });
      } catch (e) {
        const msg = String((e && e.message) || e || 'PACKAGE_OP_FAILED');
        if (/PACKAGE_PRIVILEGE_REQUIRED/.test(msg)) {
          try {
            const helperResult = await dispatchHelperResult(
              job,
              e,
              invoke,
              isPrivilegedHelperAvailable
            );
            const pp = payloadOf(job);
            const helperManager = String(helperResult.manager || pp.manager || 'auto');
            const helperName = String(helperResult.name || pp.name || '');
            return ok({
              platform,
              manager: helperManager,
              name: helperName,
              removed: true,
              privileged: true
            });
          } catch {
            return fail(msg);
          }
        }
        return fail(msg);
      }
    }
  };
}
