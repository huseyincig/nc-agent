import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import dns from 'node:dns/promises';

export {
  browserCreateJob,
  browserCloseJob,
  browserNavigateJob,
  browserInteractJob,
  browserSnapshotJob,
  browserFindJob,
  browserTabsJob,
  browserScreenshotJob,
  browserConsoleJob,
  browserNetworkJob,
  browserUploadJob,
  browserHealthJob
} from './browser-jobs.mjs';
export {
  getBrowserManager,
  resetBrowserManager,
  installContextEgressFilter
} from './browser-manager.mjs';
export {
  validateEgressUrl,
  auditProjectionUrl,
  matchHostList
} from '../policy/egress-policy.mjs';
export {
  BROWSER_RUNTIME_PIN,
  BROWSER_DEFAULTS,
  resolveBrowserRuntime,
  browserHealth,
  stageBrowserInstall,
  validateBrowserLaunch,
  ensureManagedBrowsers,
  activateStagedBrowserRuntime,
  activateBundledBrowserRuntime
} from './browser-runtime.mjs';

/**
 * @param {string} hostname
 * @returns {Promise<Array<string>>}
 */
export async function resolveAgentAddresses(hostname) {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

// --- Managed Chromium Discovery ---
// Preferred engine is the NC-managed Chromium under the browser data dir
// (Playwright registry layout). System Edge/Chrome locations are retained
// for diagnostics and for operator-guided `existing` mode setup.
/**
 * @param {string} dataDir
 */
export function findManagedChromium(dataDir) {
  if (!dataDir) return null;
  const browsersDir = path.join(dataDir, 'browser', 'playwright-browsers');
  /** @type {Array<string>} */
  const candidates = [];
  try {
    for (const entry of fs.readdirSync(browsersDir, { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^chromium-/.test(entry.name)) continue;
      const base = path.join(browsersDir, entry.name);
      if (process.platform === 'win32')
        candidates.push(path.join(base, 'chrome-win', 'chrome.exe'));
      else if (process.platform === 'darwin')
        candidates.push(
          path.join(base, 'chrome-mac', 'Chromium.app', 'Contents', 'MacOS', 'Chromium')
        );
      else candidates.push(path.join(base, 'chrome-linux', 'chrome'));
    }
  } catch {
    return null;
  }
  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) return { path: c, type: 'chromium' };
    } catch {}
  }
  return null;
}

// Known installed executables only; never a registry command or daily profile.
/**
 * @param {string} [preferred]
 * @param {{platform?: string, env?: NodeJS.ProcessEnv}} [options]
 */
export function findSystemBrowser(preferred = 'auto', { platform = process.platform, env = process.env } = {}) {
  const plat = platform;
  /** @type {Array<{path: string, type: string}>} */
  const candidates = [];

  if (plat === 'win32') {
    if (preferred !== 'edge' && preferred !== 'chrome') return null;
    const progFiles86 = env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
    const progFiles = env.ProgramFiles || 'C:\\Program Files';
    const localAppData = env.LOCALAPPDATA || path.win32.join(os.homedir(), 'AppData', 'Local');

    const edgePaths = [
      path.win32.join(progFiles86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.win32.join(progFiles, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.win32.join(localAppData, 'Microsoft', 'Edge', 'Application', 'msedge.exe')
    ];
    const chromePaths = [
      path.win32.join(progFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.win32.join(progFiles86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.win32.join(localAppData, 'Google', 'Chrome', 'Application', 'chrome.exe')
    ];

    if (preferred === 'edge') {
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
    } else if (preferred === 'chrome') {
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
    }
  } else if (plat === 'darwin') {
    candidates.push({ path: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', type: 'chrome' });
  } else {
    // Linux
    const chromePaths = [
      '/usr/bin/google-chrome',
      '/usr/bin/google-chrome-stable',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser'
    ];
    const edgePaths = ['/usr/bin/microsoft-edge', '/usr/bin/microsoft-edge-stable'];

    if (preferred === 'edge') {
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
    } else {
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
    }
  }

  for (const c of candidates) {
    try {
      if (!fs.statSync(c.path).isFile()) continue;
      fs.accessSync(c.path, fs.constants.R_OK | (plat === 'win32' ? 0 : fs.constants.X_OK));
      return c;
    } catch {}
  }
  return null;
}
