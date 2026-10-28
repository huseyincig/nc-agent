import fs from 'node:fs/promises';
import { ncLayout, isSeaRuntime, runtimeRoot } from './nc-paths.mjs';
import { acquireClientLock } from './singleton.mjs';
import { shouldHandleDiagnosticsCli, runDiagnosticsCommand } from '../diagnostics/diagnostics-ops.mjs';

/**
 * @param {unknown} text
 */
export function parseEnvFile(text) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i < 1) throw new Error('INVALID_ENV_LINE');
    const key = line.slice(0, i).trim();
    let value = line.slice(i + 1).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new Error('INVALID_ENV_KEY');
    if (key === 'NC_ROOT') throw new Error('NC_ROOT_NOT_CONFIGURABLE');
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    )
      value = value.slice(1, -1);
    out[key] = value;
  }
  return out;
}

/**
 * @param {object} [options]
 * @param {Record<string, string | undefined>} [options.env]
 * @param {string} [options.platform]
 * @param {string} [options.root]
 */
export async function loadCanonicalEnv({
  env = process.env,
  platform = process.platform,
  root = runtimeRoot(platform)
} = {}) {
  const layout = ncLayout(root, platform);
  /** @type {Record<string, string>} */
  let parsed = {};
  try {
    parsed = parseEnvFile(await fs.readFile(layout.envFile, 'utf8'));
  } catch (error) {
    const errorCode =
      error && typeof error === 'object' && 'code' in error ? error.code : undefined;
    if (errorCode !== 'ENOENT') throw error;
  }
  for (const [key, value] of Object.entries(parsed)) if (env[key] == null) env[key] = value;
  return { root, layout, loaded: Object.keys(parsed).length > 0 };
}

/**
 * A8-a — libuv file-I/O threadpool default for the agent process.
 *
 * Node defaults to 4 threads; concurrent file-heavy work (log scans,
 * transfers, diagnostics bundles) stalls on that pool. 16 matches the
 * rival-proven sizing. Applied at boot ONLY when the operator did not
 * already provide a value: an existing `UV_THREADPOOL_SIZE` (even `0`)
 * is kept verbatim — operator config always wins over this default.
 * Blank (empty/whitespace) counts as unset. Must run before the first
 * threadpool use to take full effect; runLauncher calls it first.
 */
export const UV_THREADPOOL_SIZE_DEFAULT = '16';
/**
 * @param {Record<string, string|undefined>} [env]
 * @returns {'set'|'kept'}
 */
export function ensureThreadpoolSize(env = process.env) {
  const current = env?.UV_THREADPOOL_SIZE;
  if (current === undefined || current === null || String(current).trim() === '') {
    env.UV_THREADPOOL_SIZE = UV_THREADPOOL_SIZE_DEFAULT;
    return 'set';
  }
  return 'kept';
}

export const LINUX_RETIRED_EXIT_CODE = 75;
/**
 * @param {unknown} platform
 * @param {unknown} outcome
 */
export function launcherExitCode(platform, outcome) {
  return platform === 'linux' && outcome === 'retired' ? LINUX_RETIRED_EXIT_CODE : null;
}

/**
 * @param {object} [options]
 * @param {Record<string, string | undefined>} [options.env]
 * @param {string} [options.platform]
 * @param {string} [options.root]
 * @param {() => Promise<any>} [options.loadClient]
 * @param {Array<string>} [options.argv]
 * @param {string} [options.diagnosticsVersion]
 */
export async function runLauncher({
  env = process.env,
  platform = process.platform,
  root = runtimeRoot(platform),
  loadClient = () => import('./client.mjs'),
  argv = process.argv.slice(2),
  diagnosticsVersion = 'unknown'
} = {}) {
  ensureThreadpoolSize(env);
  if (shouldHandleDiagnosticsCli(argv)) {
    let version = diagnosticsVersion;
    if (!version || version === 'unknown') {
      try {
        const pkg = JSON.parse(
          await fs.readFile(new URL('../package.json', import.meta.url), 'utf8')
        );
        if (pkg && typeof pkg.version === 'string') version = pkg.version;
      } catch {
        version = 'unknown';
      }
    }
    const result = await runDiagnosticsCommand({ argv, platform, root, env, version });
    if (result.summary) console.log(result.summary);
    if (!result.ok) process.exitCode = 1;
    return 'diagnostics';
  }
  const { layout } = await loadCanonicalEnv({ env, platform, root });
  const release = await acquireClientLock({ lockFile: layout.lockFile });
  let outcome;
  try {
    const { main } = await loadClient();
    if (typeof main !== 'function') throw new Error('CLIENT_MAIN_NOT_EXPORTED');
    outcome = await main();
  } finally {
    await release();
  }
  const exitCode = launcherExitCode(platform, outcome);
  if (exitCode != null) process.exitCode = exitCode;
  return outcome;
}

// NC_SEA_BUNDLE is defined true by the esbuild SEA pipeline (never in
// source): the bundle is always the program entry, regardless of filename.
const seaGlobals = /** @type {Record<string, unknown>} */ (globalThis);
const bundledEntry = Boolean(seaGlobals.NC_SEA_BUNDLE);
const invoked =
  bundledEntry ||
  isSeaRuntime() ||
  (process.argv[1] &&
    (process.argv[1].endsWith('/launcher.mjs') || process.argv[1].endsWith('\\launcher.mjs')));
// No top-level await: the bundle must compile to CJS for Single Executable
// Applications (Node SEA rejects ESM entry). Floating the promise is
// equivalent — client loops keep the loop alive; rejection exits nonzero.
if (invoked) {
  process.on('unhandledRejection', (reason) => {
    try {
      console.error(
        `[nc-launcher] unhandled rejection: ${reason instanceof Error ? (reason.stack || reason.message) : String(reason)}`
      );
    } catch {}
  });
  // V-32.6: log startup failures instead of exiting silently with code 1.
  runLauncher().catch((e) => {
    try {
      console.error(`[nc-launcher] startup failed: ${e instanceof Error ? (e.stack || e.message) : String(e)}`);
    } catch {}
    process.exitCode = 1;
  });
}
