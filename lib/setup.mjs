// nodecommand setup/remove shared logic.
//
// Pure, dependency-free helpers behind the `setup` / `remove` subcommands so
// the mode decision table and install-root detection stay unit-testable with
// injected platform/privilege probes (no process mocking needed).

import child_process from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** Single-line notice printed when setup falls back to user mode. */
export const LIMITED_CAPS_WARNING =
  'limited: privileged_shell_exec and container tools are off (re-run as administrator for full capabilities)';

/**
 * Detects Windows administrator rights via `net session` (exit 0 ⇔ admin).
 * Never throws: any failure means "not admin".
 * @param {(cmd: string, args: string[]) => { status: number|null }} [run]
 */
export function detectWindowsAdmin(run = null) {
  try {
    const runner =
      run ||
      ((cmd, args) => {
        try {
          const r = child_process.spawnSync(cmd, args, { stdio: 'ignore' });
          return { status: typeof r.status === 'number' ? r.status : 1 };
        } catch {
          return { status: 1 };
        }
      });
    return runner('net', ['session']).status === 0;
  } catch {
    return false;
  }
}

/**
 * True when the current process can perform a machine-wide (system) install.
 * Privilege probes are injectable for deterministic tests.
 * @param {{ platform?: string, getuid?: (() => number)|null, isAdmin?: boolean|null, runAdminCheck?: (() => boolean)|null }} [options]
 */
export function isElevated({ platform = os.platform(), getuid = null, isAdmin = null, runAdminCheck = null } = {}) {
  if (platform === 'win32') {
    if (typeof isAdmin === 'boolean') return isAdmin;
    if (typeof runAdminCheck === 'function') {
      try {
        return !!runAdminCheck();
      } catch {
        return false;
      }
    }
    return detectWindowsAdmin();
  }
  const getter = typeof getuid === 'function' ? getuid : typeof process.getuid === 'function' ? process.getuid : null;
  if (typeof getter !== 'function') return false;
  try {
    return getter() === 0;
  } catch {
    return false;
  }
}

/**
 * Automatic install-mode decision. The user is never asked: elevated
 * processes install machine-wide, everything else installs per-user.
 * @param {{ platform?: string, getuid?: (() => number)|null, isAdmin?: boolean|null, runAdminCheck?: (() => boolean)|null }} [options]
 * @returns {'system'|'user'}
 */
export function decideInstallMode(options = {}) {
  return isElevated(options) ? 'system' : 'user';
}

/**
 * Warning text for the given mode: a single line for user mode, null for
 * system mode (callers assert presence/absence on this, not on stdout).
 * @param {'system'|'user'} mode
 */
export function modeWarningFor(mode) {
  return mode === 'user' ? LIMITED_CAPS_WARNING : null;
}

/**
 * Environment additions forwarded to the OS installer scripts so the
 * privileged/unprivileged layout matches the CLI mode decision. All three
 * installers (linux/macos/windows) honor NC_MODE; the *_INSTALL flags force
 * the matching branch even when auto-detection would disagree (e.g. a
 * root-owned NC_ROOT reused by a test harness).
 * @param {'system'|'user'} mode
 */
export function installerEnvForMode(mode) {
  if (mode === 'user') return { NC_MODE: 'user', NC_USER_INSTALL: '1' };
  return { NC_MODE: 'system', NC_SYSTEM_INSTALL: '1' };
}

/**
 * Explicit NC_ROOT overrides the whole candidate list: when the caller names
 * a target tree, only that tree is considered (deterministic for tests and
 * for "remove exactly what I pointed at"). Otherwise both the machine-wide
 * and the per-user tree are listed so `remove` finds installs made under a
 * different privilege level than the current process.
 * @param {{ platform?: string, env?: NodeJS.ProcessEnv, homedir?: string }} [options]
 */
export function candidateInstallRoots({ platform = os.platform(), env = process.env, homedir = os.homedir() } = {}) {
  if (env.NC_ROOT) return [env.NC_ROOT];
  const roots = [];
  if (platform === 'win32') {
    const programData = env.ProgramData || 'C:\\ProgramData';
    const localAppData = env.LOCALAPPDATA || path.join(homedir, 'AppData', 'Local');
    roots.push(path.join(programData, 'NC'), path.join(localAppData, 'nc'));
  } else if (platform === 'darwin') {
    roots.push('/opt/nc', path.join(homedir, 'Library', 'Application Support', 'nc'));
  } else {
    const dataHome = env.XDG_DATA_HOME || path.join(homedir, '.local', 'share');
    roots.push('/opt/nc', path.join(dataHome, 'nc'));
  }
  return [...new Set(roots)];
}

/**
 * True when the directory looks like a real agent tree. Mirrors the safety
 * guard inside the uninstall scripts (config/nc-client.env or app/).
 * @param {string} root
 * @param {(p: string) => boolean} [existsSync]
 */
export function isInstallRoot(root, existsSync = fs.existsSync) {
  try {
    return (
      existsSync(path.join(root, 'config', 'nc-client.env')) || existsSync(path.join(root, 'app'))
    );
  } catch {
    return false;
  }
}

/**
 * Tri-state install-tree probe. A root-owned system tree (0750/0700) is
 * unreadable to a non-root caller: a plain boolean would report "nothing to
 * remove" for a machine-wide install that clearly exists, and the sudo path
 * would never be reached. Distinguishes:
 *   - 'install'    markers readable → normal removal path
 *   - 'absent'     root directory does not exist
 *   - 'foreign'    root exists and is traversable but carries no markers
 *   - 'unreadable' root exists but markers cannot be stat'ed (EACCES/EPERM)
 *                  → needs elevation; the uninstaller's own safety guard
 *                    still refuses non-NC trees when run under sudo.
 * @param {string} root
 * @param {{ statSync?: (p: string) => { isDirectory(): boolean }, accessSync?: (p: string, mode?: number) => void }} [io]
 * @returns {'install'|'absent'|'foreign'|'unreadable'}
 */
export function probeInstallRoot(root, io = {}) {
  const statSync = io.statSync || fs.statSync;
  const accessSync = io.accessSync || fs.accessSync;
  try {
    const st = statSync(root);
    if (!st.isDirectory()) return 'foreign';
  } catch (err) {
    return err && err.code === 'ENOENT' ? 'absent' : 'unreadable';
  }
  for (const marker of [path.join(root, 'config', 'nc-client.env'), path.join(root, 'app')]) {
    try {
      accessSync(marker);
      return 'install';
    } catch (err) {
      if (err && (err.code === 'EACCES' || err.code === 'EPERM')) return 'unreadable';
    }
  }
  return 'foreign';
}

/**
 * Removal targets split by accessibility. `install` roots are removed by the
 * local flow; `unreadable` roots (system installs seen from a non-root shell)
 * are routed to the elevated runUninstallerScript path instead of being
 * silently reported as "nothing to remove".
 * @param {{ platform?: string, env?: NodeJS.ProcessEnv, homedir?: string, io?: object }} [options]
 * @returns {{ install: string[], unreadable: string[] }}
 */
export function findRemovalTargets({ io = {}, ...rest } = {}) {
  const install = [];
  const unreadable = [];
  for (const root of candidateInstallRoots(rest)) {
    const status = probeInstallRoot(root, io);
    if (status === 'install') install.push(root);
    else if (status === 'unreadable') unreadable.push(root);
  }
  return { install, unreadable };
}

/**
 * Installed roots only, in candidate order.
 * @param {{ platform?: string, env?: NodeJS.ProcessEnv, homedir?: string, existsSync?: (p: string) => boolean }} [options]
 */
export function findInstallations({ existsSync = fs.existsSync, ...rest } = {}) {
  return candidateInstallRoots(rest).filter((r) => isInstallRoot(r, existsSync));
}

/**
 * Mode-aware install root. NC_ROOT still wins when set; otherwise the root
 * mirrors the tree the OS installer builds for that mode — critically on
 * win32, where system installs target %ProgramData%\NC while user installs
 * target %LOCALAPPDATA%\nc (getNcRoot() has no notion of mode and would put
 * an admin setup's credentials in the user tree the agent never reads).
 * @param {'system'|'user'} mode
 * @param {{ platform?: string, env?: NodeJS.ProcessEnv, homedir?: string }} [options]
 */
export function getNcRootForMode(mode, { platform = os.platform(), env = process.env, homedir = os.homedir() } = {}) {
  if (env.NC_ROOT) return env.NC_ROOT;
  if (platform === 'win32') {
    if (mode === 'system') return path.join(env.ProgramData || 'C:\\ProgramData', 'NC');
    const localAppData = env.LOCALAPPDATA || path.join(homedir, 'AppData', 'Local');
    return path.join(localAppData, 'nc');
  }
  if (mode === 'system') return '/opt/nc';
  if (platform === 'darwin') return path.join(homedir, 'Library', 'Application Support', 'nc');
  const dataHome = env.XDG_DATA_HOME || path.join(homedir, '.local', 'share');
  return path.join(dataHome, 'nc');
}

/**
 * Uninstaller script living inside an installed tree. The scripts are
 * self-locating ($ROOT derived from their own path), so no root argument is
 * passed — presence of the tree itself is the authorization.
 * @param {string} root
 * @param {string} [platform]
 */
export function uninstallerForRoot(root, platform = os.platform()) {
  if (platform === 'win32') return path.join(root, 'uninstall.ps1');
  return path.join(root, 'uninstall.sh');
}

/**
 * Suggested-action line printed when an uninstaller fails. The unix text
 * names the direct recovery command; win32 keeps the generic wording because
 * the .ps1 uninstaller already runs with the caller's own rights (no sudo
 * equivalent is attempted there).
 * @param {string} [platform]
 */
export function uninstallFailureSuggestion(platform = os.platform()) {
  const base = 'Re-run with administrator/root rights, then retry.';
  if (platform === 'win32') return `suggested_action: ${base}`;
  return `suggested_action: ${base} (or run: sudo nodecommand remove --yes)`;
}

/**
 * Runs one uninstaller script, forwarding the inherited environment.
 *
 * Unix elevation: a system-wide tree is installed by root, so its
 * uninstaller is root-owned (mode 0700) and a non-root caller cannot even
 * read it — plain `bash <script>` always fails there with status 126. When
 * the caller is not root the script is therefore run via `sudo -E bash`,
 * keeping `stdio: 'inherit'` so the sudo password prompt stays visible.
 * When sudo itself is missing (ENOENT) the direct call is retried once so
 * user-owned trees stay removable without sudo; any other sudo failure
 * propagates unchanged and the caller reports the usual [UNINSTALL_FAILED]
 * guidance — behavior never gets worse, it only starts working when sudo
 * exists. Already-root callers run the script directly (no sudo).
 *
 * Security boundary: the caller (runRemove) only ever passes the
 * uninstallerForRoot() path of a tree that already passed the
 * isInstallRoot() check inside findInstallations() — elevation is never
 * applied to an arbitrary path. Windows is untouched: the .ps1 uninstaller
 * runs with the caller's own rights, so no elevation is attempted there.
 * @param {string} scriptPath
 * @param {string|{ platform?: string, execFile?: (cmd: string, args: string[], opts?: object) => unknown, getuid?: (() => number)|null }} [platform]
 * @param {{ execFile?: (cmd: string, args: string[], opts?: object) => unknown, getuid?: (() => number)|null }} [options]
 */
export function runUninstallerScript(scriptPath, platform = os.platform(), options = {}) {
  let opts = options || {};
  if (typeof platform !== 'string') {
    opts = platform || {};
    platform = opts.platform || os.platform();
  }
  const execFile = opts.execFile || child_process.execFileSync;
  if (platform === 'win32') {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath],
      { stdio: 'inherit' }
    );
    return;
  }
  const getuid =
    typeof opts.getuid === 'function'
      ? opts.getuid
      : typeof process.getuid === 'function'
        ? () => process.getuid()
        : null;
  let uid = null;
  try {
    uid = typeof getuid === 'function' ? getuid() : null;
  } catch {
    uid = null;
  }
  if (uid === 0) {
    execFile('bash', [scriptPath], { stdio: 'inherit' });
    return;
  }
  try {
    execFile('sudo', ['-E', 'bash', scriptPath], { stdio: 'inherit' });
  } catch (err) {
    // Without a sudo binary there is nothing to elevate with: retry the
    // historical direct call so user-owned trees stay removable. Any other
    // sudo failure (denied, wrong password, script error) propagates.
    if (!err || err.code !== 'ENOENT') throw err;
    execFile('bash', [scriptPath], { stdio: 'inherit' });
  }
}
