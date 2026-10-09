import path from 'node:path';
import { homedir } from 'node:os';
import { isSea } from 'node:sea';

/**
 * True inside a Single Executable Application bundle (nc-agent.exe).
 * In SEA there is no script argv[1] and import.meta has no file URL;
 * process.execPath is the bundle itself.
 */
export function isSeaRuntime() {
  try {
    return isSea();
  } catch {
    return false;
  }
}
/** Absolute path of the running entry (script file, or exe bundle in SEA). */
export function mainScriptPath() {
  if (process.argv[1]) return process.argv[1];
  if (isSeaRuntime()) return process.execPath;
  return '';
}
/** Directory of the running entry (used for runtime metadata only). */
export function mainScriptDir() {
  const p = mainScriptPath();
  return p ? path.dirname(p) : '';
}

/**
 * @param {string} platform
 */
function pathApi(platform) {
  return platform === 'win32' ? path.win32 : path.posix;
}

/**
 * @param {string} [platform]
 */
export function defaultNcRoot(platform = process.platform) {
  // Machine-wide mutable app tree: ProgramData on Windows (Program Files is
  // immutable and would break OTA self-update; C:\NC is legacy), /opt/nc
  // on Unix.
  if (platform === 'win32') {
    const base =
      (typeof process === 'object' && process.env && process.env.ProgramData) || 'C:\\ProgramData';
    return `${base}\\NC`;
  }
  return '/opt/nc';
}

/**
 * Per-user install root (zero-privilege default). The agent owns this tree,
 * so install/update/uninstall never need elevation. System-wide installs
 * keep using defaultNcRoot() via the explicit system flag.
 * @param {string} [platform]
 * @param {Record<string, string | undefined>} [env]
 */
export function defaultUserNcRoot(platform = process.platform, env = process.env) {
  const api = pathApi(platform);
  const e = env || {};
  let home = e.HOME || e.USERPROFILE || '';
  if (!home) {
    try {
      home = homedir();
    } catch {
      home = '';
    }
  }
  if (platform === 'win32') {
    const local =
      e.LOCALAPPDATA ||
      (home ? api.join(home, 'AppData', 'Local') : 'C:\\Users\\Default\\AppData\\Local');
    return api.join(local, 'NC');
  }
  if (platform === 'darwin') {
    return api.join(home || '/var/empty', 'Library', 'Application Support', 'nc');
  }
  const dataHome = e.XDG_DATA_HOME || (home ? api.join(home, '.local', 'share') : '/tmp');
  return api.join(dataHome, 'nc');
}

/**
 * Resolve the runtime root from the running entry point, so the agent works
 * from any install location (machine-wide or per-user) without configuration.
 * Production launches run `<root>/app/launcher.mjs` (or the SEA bundle beside
 * it); the root is the parent of that `app` directory. Anything else falls
 * back to the machine-wide default. NC_ROOT stays non-configurable on
 * purpose: self-location cannot be hijacked via environment.
 * @param {object} [options]
 * @param {unknown} [options.argv1]
 * @param {unknown} [options.execPath]
 * @param {boolean} [options.sea]
 * @param {string} [options.platform]
 */
export function resolveRuntimeRoot({
  argv1 = typeof process === 'object' && process.argv ? process.argv[1] : '',
  execPath = typeof process === 'object' ? process.execPath : '',
  sea = isSeaRuntime(),
  platform = process.platform
} = {}) {
  const api = pathApi(platform);
  let entry = '';
  if (/[/\\]launcher\.mjs$/.test(String(argv1 || ''))) entry = String(argv1);
  else if (sea && execPath) entry = String(execPath);
  if (entry) {
    const dir = api.dirname(entry);
    if (api.basename(dir) === 'app') return api.dirname(dir);
  }
  return defaultNcRoot(platform);
}

/**
 * @param {string} [platform]
 */
export function runtimeRoot(platform = process.platform) {
  return resolveRuntimeRoot({ platform });
}

/**
 * @param {string} [root] explicit root wins; omitted resolves from the running entry
 * @param {string} [platform]
 */
export function ncLayout(root = undefined, platform = process.platform) {
  const api = pathApi(platform),
    r = api.resolve(root ?? runtimeRoot(platform));
  /** @param {Array<string>} parts */
  const join = (...parts) => api.join(...parts);
  return Object.freeze({
    root: r,
    app: join(r, 'app'),
    config: join(r, 'config'),
    data: join(r, 'data'),
    logs: join(r, 'logs'),
    releases: join(r, 'releases'),
    backups: join(r, 'backups'),
    tmp: join(r, 'tmp'),
    envFile: join(r, 'config', 'nc-client.env'),
    deviceKey: join(r, 'config', 'nc-device-key.pem'),
    stateFile: join(r, 'data', 'client-state.json'),
    pidFile: join(r, 'data', 'client.pid'),
    lockFile: join(r, 'data', 'client.lock'),
    // Canonical writable workspace for file mutation tools. The policy root
    // (layout root) is OS-owned on Unix; this service-owned subtree is the
    // guaranteed-writable area for directory_create/file_write/file_edit.
    workspace: join(r, 'data', 'workspace'),
    retiredMarker: join(r, 'data', 'retired.json'),
    updateState: join(r, 'data', 'update-activation.json'),
    clientLog: join(r, 'logs', 'client.log'),
    auditLog: join(r, 'logs', 'audit.jsonl'),
    serverLog: join(r, 'logs', 'mcp-server.log'),
    tunnelLog: join(r, 'logs', 'mcp-tunnel.log'),
    clientReleases: join(r, 'releases', 'client'),
    clientBackups: join(r, 'backups', 'client')
  });
}

export function canonicalLayoutContract() {
  return Object.freeze({
    unixRoot: '/opt/nc',
    windowsRoot: 'C:\\ProgramData\\NC',
    subdirs: ['app', 'config', 'data', 'logs', 'releases', 'backups', 'tmp']
  });
}
