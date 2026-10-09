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

// --- System Browser Discovery (diagnostics / existing-mode guidance) ---
/**
 * @param {string} [preferred]
 */
export function findSystemBrowser(preferred = 'auto') {
  const plat = os.platform();
  /** @type {Array<{path: string, type: string}>} */
  const candidates = [];

  if (plat === 'win32') {
    const progFiles86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
    const progFiles = process.env.ProgramFiles || 'C:\\Program Files';
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');

    const edgePaths = [
      path.join(progFiles86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(progFiles, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(localAppData, 'Microsoft', 'Edge', 'Application', 'msedge.exe')
    ];
    const chromePaths = [
      path.join(progFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(progFiles86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(localAppData, 'Google', 'Chrome', 'Application', 'chrome.exe')
    ];

    if (preferred === 'edge') {
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
    } else if (preferred === 'chrome') {
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
    } else {
      // Default on Windows: Prefer Edge then Chrome
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
    }
  } else if (plat === 'darwin') {
    const edgePaths = ['/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'];
    const chromePaths = [
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
      '/Applications/Chromium.app/Contents/MacOS/Chromium'
    ];

    if (preferred === 'edge') {
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
    } else if (preferred === 'chrome') {
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
    } else {
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
    }
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
      if (fs.existsSync(c.path)) {
        return c;
      }
    } catch {}
  }
  return null;
}
