import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import path from 'node:path';
import {
  BROWSER_DEFAULTS,
  BROWSER_RUNTIME_PIN,
  resolveBrowserRuntime,
  resolveChromiumExecutable,
  loadPlaywrightCore,
  applyBrowsersPathEnv,
  browserLaunchEnv,
  ensureDir,
  expectedChromiumRevision
} from './browser-runtime.mjs';
import { validateEgressUrl, auditProjectionUrl, matchHostList } from '../policy/egress-policy.mjs';
import { runtimeRoot, ncLayout } from '../client/nc-paths.mjs';
import { isSensitivePath } from '../filesystem/sensitive-paths.mjs';

// Interactive ARIA roles that always deserve a stable ref.
const WIDGET_ROLES = new Set([
  'button',
  'link',
  'textbox',
  'searchbox',
  'combobox',
  'listbox',
  'checkbox',
  'radio',
  'switch',
  'slider',
  'spinbutton',
  'menuitem',
  'menuitemcheckbox',
  'menuitemradio',
  'tab',
  'treeitem',
  'option',
  'gridcell',
  'rowheader',
  'columnheader',
  'heading',
  'img'
]);
const SKIP_ROLES = new Set(['none', 'presentation', 'generic']);
/** @type {Record<string, number>} */
export const CONSOLE_SEVERITY = Object.freeze({ error: 0, warning: 1, info: 2, debug: 3 });
// AX roles that getByRole cannot query (Chromium-internal text roles and
// roleless containers). Refs on these resolve through visible text instead.
const TEXT_FALLBACK_ROLES = new Set([
  'StaticText',
  'InlineTextBox',
  'text',
  'generic',
  'none',
  'presentation',
  'node'
]);
const STATIC_RESOURCE_TYPES = new Set(['image', 'font', 'stylesheet', 'media']);

/**
 * Playwright API surfaces (structural, intentionally loose: the vendored
 * playwright-core is loaded by explicit path at runtime, never bundled, so
 * static binding to its .d.ts would lie about availability).
 * @typedef {Record<string, any>} PWBrowser
 * @typedef {Record<string, any>} PWBContext
 * @typedef {Record<string, any>} PWPage
 * @typedef {Record<string, any>} PWLocator
 * @typedef {Record<string, any>} PWDialog
 * @typedef {Record<string, any>} PWDownload
 * @typedef {{page: PWPage, url: string, title: string}} PageRecord
 * @typedef {{role: string, name: string, index: number, nameIndex: number, pageId: string, revision: number}} RefEntry
 */

/**
 * @param {unknown} text
 */
export function redactSecretText(text) {
  let out = String(text || '');
  out = out.replace(/nc_[0-9a-f]{64}/g, 'nc_[REDACTED]');
  out = out.replace(/brw_[0-9a-f]{32}/g, 'brw_[REDACTED]');
  out = out.replace(/prc_[0-9a-f]{32}/g, 'prc_[REDACTED]');
  out = out.replace(/log_[0-9a-f]{32}/g, 'log_[REDACTED]');
  out = out.replace(/Bearer\s+[A-Za-z0-9\-._~+/=]{8,}/gi, 'Bearer [REDACTED]');
  out = out.replace(
    /(password|passwd|secret|api[_-]?key|access[_-]?token|session[_-]?token)\s*[:=]\s*\S+/gi,
    '$1=[REDACTED]'
  );
  out = out.replace(
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    '[PRIVATE KEY REDACTED]'
  );
  return out;
}

/**
 * @param {unknown} job
 */
export function policyFromJob(job) {
  const record = /** @type {Record<string, unknown>} */ (job || {});
  const payload = /** @type {Record<string, unknown>} */ (
    record.request_payload || record.payload || {}
  );
  const rawCaps = record.agent_policy_capabilities;
  const caps = /** @type {Record<string, unknown>} */ (
    rawCaps && typeof rawCaps === 'object' ? rawCaps : {}
  );
  const roots =
    /** @type {{read?: Array<string>, write?: Array<string>}|Record<string, unknown>|null} */ (
      record.agent_policy_roots || null
    );
  const net = /** @type {Record<string, unknown>} */ (
    payload.browser_network_policy && typeof payload.browser_network_policy === 'object'
      ? payload.browser_network_policy
      : {}
  );
  // Upload sources follow the same filesystem policy as file_read: when the
  // host policy carries no read roots (operator never set any), fall back to
  // the NC tree instead of denying everything. Mirrors the
  // makeStructuredHandlers readRoots default.
  const policyReadRoots = Array.isArray(roots?.read)
    ? roots.read.filter((x) => typeof x === 'string')
    : Array.isArray(/** @type {Record<string, unknown>} */ (roots)?.allowed_read_roots)
      ? /** @type {Array<string>} */ (
          /** @type {Record<string, unknown>} */ (roots).allowed_read_roots
        ).filter((x) => typeof x === 'string')
      : [];
  const readRoots = policyReadRoots.length > 0 ? policyReadRoots : [runtimeRoot()];
  // Operator-granted full access (same predicate as policyExtraRoots in
  // host-policy.mjs): skips the allowlist membership test ONLY. The
  // credential denylist below still applies (SEC-001 parity with file_read).
  const allowAll = /** @type {Record<string, unknown>} */ (roots)?.allow_all_filesystem === true;
  return {
    payload,
    present: rawCaps !== null && typeof rawCaps === 'object',
    scriptExec: caps.browser_script_exec === true,
    privateNetwork: caps.browser_private_network === true,
    uploads: caps.browser_uploads === true,
    downloads: caps.browser_downloads === true,
    headed: caps.browser_headed === true,
    existingAttach: caps.browser_existing_attach === true,
    readRoots,
    allowAll,
    network: {
      allowPrivateNetwork:
        net.allow_private_networks === true || caps.browser_private_network === true,
      allowLoopback:
        net.allow_loopback === true
          ? true
          : net.allow_loopback === false
            ? false
            : caps.browser_private_network === true,
      allowedHosts: Array.isArray(net.allowed_hosts)
        ? net.allowed_hosts.filter((x) => typeof x === 'string')
        : [],
      blockedHosts: Array.isArray(net.blocked_hosts)
        ? net.blocked_hosts.filter((x) => typeof x === 'string')
        : []
    }
  };
}

/**
 * Egress gate for operator/model-supplied CDP endpoints (existing mode).
 * Navigation URLs pass through validateEgressUrl; a CDP endpoint must too,
 * or the model can aim the agent at internal HTTP (cloud metadata, LAN
 * services) via browser_create. Loopback stays allowed by default — the
 * documented existing-mode use is a local endpoint (http://127.0.0.1:9222)
 * — while an explicit allow_loopback:false still closes it. Failures map
 * to the generic attach error so probe results never leak cross-origin.
 * @param {unknown} endpoint
 * @param {{allowPrivateNetwork?: boolean, allowLoopback?: boolean, allowedHosts?: Array<string>, blockedHosts?: Array<string>}|null|undefined} [network]
 */
export async function validateCdpEndpoint(endpoint, network = {}) {
  const raw = String(endpoint || '').trim();
  if (!raw) return { ok: false, error: 'BROWSER_EXISTING_ATTACH_FAILED' };
  try {
    const net = network && typeof network === 'object' ? network : {};
    const verdict = await validateEgressUrl(raw, {
      allowPrivateNetwork: net.allowPrivateNetwork === true,
      allowLoopback: net.allowLoopback !== false,
      allowedHosts: Array.isArray(net.allowedHosts) ? net.allowedHosts : [],
      blockedHosts: Array.isArray(net.blockedHosts) ? net.blockedHosts : [],
      resolve: async (hostname) => {
        const records = await dns.lookup(hostname, { all: true, verbatim: true });
        return records.map((r) => r.address);
      }
    });
    if (!verdict.ok) return { ok: false, error: 'BROWSER_EXISTING_ATTACH_FAILED' };
    return { ok: true, url: raw };
  } catch {
    return { ok: false, error: 'BROWSER_EXISTING_ATTACH_FAILED' };
  }
}
/** Max page.evaluate expression length: unbounded input pins CDP framing. */
export const MAX_EVALUATE_EXPRESSION_CHARS = 65536;

/**
 * Intercept and validate all network requests at BrowserContext or Page level
 * to prevent SSRF and redirect-based SSRF (NC-02).
 *
 * Intercepts top-level navigation, HTTP 30x redirects, subresources (iframes,
 * scripts, styles, images) and XHR/fetch before any network traffic occurs.
 *
 * @param {PWBContext|PWPage|Record<string, any>} context
 * @param {BrowserSession|Record<string, any>} [sessionOrPolicy]
 */
export async function installContextEgressFilter(context, sessionOrPolicy) {
  if (!context || typeof context.route !== 'function') return;
  if (context._egressFilterInstalled) return;
  context._egressFilterInstalled = true;

  try {
    await context.route('**/*', async (route, request) => {
      try {
        const rawUrl =
          typeof request.url === 'function' ? request.url() : String(request.url || '');
        if (rawUrl.startsWith('about:')) {
          return await route.continue().catch(() => {});
        }
        const policyHolder = sessionOrPolicy?.policy || sessionOrPolicy || {};
        const net = policyHolder.network || policyHolder;
        const allowPrivateNetwork =
          net.allowPrivateNetwork === true || net.allow_private_networks === true;
        const allowLoopback =
          net.allowLoopback === true || net.allow_loopback === true;
        const allowedHosts = Array.isArray(net.allowedHosts)
          ? net.allowedHosts
          : Array.isArray(net.allowed_hosts)
            ? net.allowed_hosts
            : Array.isArray(net.allowlist)
              ? net.allowlist
              : [];
        const blockedHosts = Array.isArray(net.blockedHosts)
          ? net.blockedHosts
          : Array.isArray(net.blocked_hosts)
            ? net.blocked_hosts
            : Array.isArray(net.denylist)
              ? net.denylist
              : [];
        const resolve =
          typeof net.resolve === 'function'
            ? net.resolve
            : async (hostname) => {
                const records = await dns.lookup(hostname, { all: true, verbatim: true });
                return records.map((r) => r.address);
              };

        const validation = await validateEgressUrl(rawUrl, {
          allowPrivateNetwork,
          allowLoopback,
          allowedHosts,
          blockedHosts,
          resolve
        });
        if (!validation.ok) {
          return await route.abort('accessdenied').catch(() => {});
        }
        return await route.continue().catch(() => {});
      } catch {
        return await route.abort('accessdenied').catch(() => {});
      }
    });
  } catch {}
}
/**
 * @param {unknown} expr
 */
export function assertEvaluateExpression(expr) {
  const text = String(expr || '');
  if (!text) throw new Error('EXPRESSION_REQUIRED_FOR_EVALUATE');
  if (text.length > MAX_EVALUATE_EXPRESSION_CHARS)
    throw new Error('BROWSER_EXPRESSION_TOO_LARGE');
  return text;
}
/** Max model-supplied regex length for find/filter: bounds pattern-side work. */
export const MAX_FIND_REGEX_CHARS = 500;
/** Max text length a model regex is tested against per attempt (find lines). */
export const MAX_REGEX_TEST_CHARS = 4000;
/**
 * Reject model-supplied regexes that can wedge the agent's single-threaded
 * event loop (P3-D3): sync RegExp.test has no timeout, and nested
 * quantifiers (`(a+)+$`) backtrack exponentially — a 7-char pattern held a
 * probe for 20+ minutes against a 100KB input. Fail closed on quantified
 * groups containing quantifiers or alternation; literals, classes and
 * single-level quantifiers (including `(?:…)` non-capturing groups) stay
 * allowed. Callers map the throw onto their existing invalid-query code.
 * @param {unknown} pattern
 * @returns {string} the validated pattern
 */
export function assertSafeRegexPattern(pattern) {
  const s = String(pattern || '');
  if (!s || s.length > MAX_FIND_REGEX_CHARS) throw new Error('BROWSER_REGEX_REJECTED');
  const stack = [{ quant: false, alt: false }];
  let escaped = false;
  let inClass = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (c === '\\') {
      escaped = true;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      continue;
    }
    if (c === '[') {
      inClass = true;
      continue;
    }
    if (c === '(') {
      stack.push({ quant: false, alt: false });
      continue;
    }
    if (c === ')') {
      const g =
        stack.length > 1
          ? /** @type {{quant: boolean, alt: boolean}} */ (stack.pop())
          : { quant: false, alt: false };
      const next = s[i + 1];
      if (
        (next === '*' || next === '+' || next === '?' || next === '{') &&
        (g.quant || g.alt)
      )
        throw new Error('BROWSER_REGEX_REJECTED');
      const top = stack[stack.length - 1];
      if (top) top.quant = true;
      continue;
    }
    if (c === '|') {
      const top = stack[stack.length - 1];
      if (top) top.alt = true;
      continue;
    }
    // A '?' right after '(' opens a (?:…)/(?=…)/(?i:…) modifier, not a
    // quantifier: without this exemption every non-capturing group would
    // read as "quantified" and break common linear patterns.
    if (c === '?' && s[i - 1] === '(') continue;
    if (c === '*' || c === '+' || c === '?' || c === '{') {
      const top = stack[stack.length - 1];
      if (top) top.quant = true;
    }
  }
  return s;
}
/**
 * @param {string} sessionId
 * @param {string} filename
 */
function sanitizeDownloadName(sessionId, filename) {
  const base = path.basename(String(filename || 'download')).replace(/[\0\\/]/g, '_');
  // Collapse dot-runs (no '..' traversal lookalikes, no hidden files) and
  // strip anything outside a conservative portable set.
  const clean =
    base
      .replace(/\.\.+/g, '_')
      .replace(/^\.+/, '')
      .replace(/[^A-Za-z0-9._-]/g, '_')
      .slice(0, 128) || 'download';
  return `${sessionId}_${Date.now().toString(36)}_${clean}`;
}

/**
 * @param {unknown} p
 * @param {Array<string>} readRoots
 * @param {string} downloadsDir
 * @param {boolean} [allowAll]
 * @returns {{ok: true, path: string, size: number}|{ok: false, error: string}}
 */
export function resolveUploadPath(p, readRoots, downloadsDir, allowAll = false) {
  const denied = /** @type {{ok: false, error: string}} */ ({
    ok: false,
    error: 'BROWSER_UPLOAD_DENIED'
  });
  const raw = String(p || '');
  if (!raw) return denied;
  if (!path.isAbsolute(raw)) return denied;
  if (raw.includes('\0')) return denied;
  // SEC-001 parity with file_read (realAllowed): credential denylist precedes
  // the allowlist AND the allow_all bypass.
  try {
    if (isSensitivePath(raw, process.platform)) return denied;
  } catch {}
  let real = null;
  try {
    real = fs.realpathSync(raw);
  } catch {
    return denied;
  }
  try {
    if (isSensitivePath(real, process.platform)) return denied;
  } catch {}
  let st = null;
  try {
    st = fs.statSync(real);
  } catch {
    return denied;
  }
  if (!st.isFile()) return denied;
  if (st.size > BROWSER_DEFAULTS.maxDownloadBytes) return denied;
  if (allowAll === true) return { ok: true, path: real, size: st.size };
  const inside = (/** @type {string} */ root) => {
    const rel = path.relative(path.resolve(root), real);
    return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
  };
  if (inside(path.resolve(downloadsDir))) return { ok: true, path: real, size: st.size };
  for (const root of readRoots || []) {
    try {
      if (inside(root)) return { ok: true, path: real, size: st.size };
    } catch {}
  }
  return denied;
}

class BrowserSession {
  /**
   * @param {string} id
   * @param {Record<string, any>} [options]
   */
  constructor(id, options = {}) {
    this.id = id;
    this.mode = options.mode || 'managed';
    this.state = 'creating';
    /** @type {PWBrowser|null} */
    this.browser = options.browser || null;
    this.ownsBrowser = options.ownsBrowser !== false;
    /** @type {PWBContext|null} */
    this.context = null;
    /** @type {Map<string, PageRecord>} */
    this.pages = new Map();
    /** @type {string|null} */
    this.currentPageId = null;
    this.pageSeq = 0;
    /** @type {Map<string, RefEntry>} */
    this.refs = new Map();
    /** @type {string|null} */
    this.snapshotId = null;
    this.pageRevision = 0;
    /** @type {Map<string, Record<string, any>>} */
    this.cdpSessions = new Map();
    /** @type {Array<{seq: number, type: string, text: string, url: string|null, ts: string}>} */
    this.console = [];
    this.consoleSeq = 0;
    /** @type {Array<{seq: number, method: string, url: string, status: number|null, resource_type: string, duration_ms: number|null, failed: boolean}>} */
    this.network = [];
    this.networkSeq = 0;
    /** @type {Array<{filename: string, path: string, size_bytes: number, status: string}>} */
    this.downloads = [];
    /** @type {Record<string, any>|null} */
    this.pendingDialog = null;
    this.includeStatic = false;
    this.createdAt = Date.now();
    this.lastUsed = Date.now();
    this.headless = options.headless !== false;
    this.viewport = options.viewport || { ...BROWSER_DEFAULTS.viewport };
    this.locale = options.locale || null;
    this.timezone = options.timezone || null;
    this.userAgent = options.userAgent || null;
    this.profileId = options.profileId || null;
    this.downloadsDir = options.downloadsDir || null;
    this.playwrightVersion = options.playwrightVersion || null;
    this.browserRevision = options.browserRevision || null;
    /** @type {Promise<unknown>} */
    this.queue = Promise.resolve();
    this.policy = options.policy || null;
  }

  touch() {
    this.lastUsed = Date.now();
  }

  /**
   * Serialize ops per session; sessions stay independent.
   * @param {() => Promise<unknown>} fn
   */
  enqueue(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  currentPage() {
    const known =
      this.currentPageId && this.pages.has(this.currentPageId) ? this.currentPageId : null;
    const id = known || [...this.pages.keys()][0] || null;
    if (!id) return null;
    const rec = this.pages.get(id);
    if (!rec) return null;
    this.currentPageId = id;
    return { pageId: id, page: rec.page, url: rec.url, title: rec.title };
  }
}

export class BrowserManager {
  /**
   * @param {{dataDir?: string|null, root?: string|null, env?: NodeJS.ProcessEnv}} [options]
   */
  constructor(options = {}) {
    this.rt = resolveBrowserRuntime(options);
    /** @type {Record<string, any>|null} */
    this.core = null;
    /** @type {Map<string, BrowserSession>} */
    this.sessions = new Map();
    /** @type {Map<string, PWBrowser>} */
    this.managedBrowsers = new Map();
    /** @type {Map<string, string>} */
    this.profileLocks = new Map();
    this.sweeper = null;
    this.shuttingDown = false;
  }

  paths() {
    return this.rt;
  }

  startSweeper() {
    if (this.sweeper) return;
    this.sweeper = setInterval(() => {
      this.sweep().catch(() => {});
    }, BROWSER_DEFAULTS.sweepIntervalMs);
    if (this.sweeper.unref) this.sweeper.unref();
  }

  async coreApi() {
    if (this.core) return this.core;
    applyBrowsersPathEnv(this.rt.browsersDir);
    const loaded = await loadPlaywrightCore(this.rt.coreDir);
    if (!loaded) throw new Error('BROWSER_RUNTIME_MISSING');
    this.core = loaded;
    return loaded;
  }

  versions() {
    return {
      playwright: BROWSER_RUNTIME_PIN.playwright,
      revision: expectedChromiumRevision(this.rt.coreDir)
    };
  }

  /**
   * @param {string} id
   */
  sessionState(id) {
    let s = this.sessions.get(id);
    if (!s && (id === 'default' || !id)) {
      const candidates = [...this.sessions.values()]
        .filter((sess) => sess && sess.state !== 'closing' && sess.state !== 'closed')
        .sort((a, b) => (b.lastUsed || 0) - (a.lastUsed || 0));
      if (candidates.length > 0) s = candidates[0];
    }
    return s ? s.state : 'closed';
  }

  async sweep() {
    const now = Date.now();
    const ids = [...this.sessions.keys()];
    // Evict over-limit sessions first (oldest idle), then expired ones.
    const byIdle = ids
      .map((id) => /** @type {[string, BrowserSession]} */ ([id, this.sessions.get(id)]))
      .filter(([, s]) => s && s.id !== 'default')
      .sort((a, b) => (a[1]?.lastUsed || 0) - (b[1]?.lastUsed || 0));
    let excess = Math.max(0, byIdle.length - BROWSER_DEFAULTS.maxSessionsPerClient);
    for (const [id, s] of byIdle) {
      if (excess <= 0) break;
      if (s && s.state !== 'closing' && s.state !== 'closed') {
        await this.closeSession(id, 'evicted').catch(() => {});
        excess--;
      }
    }
    for (const [id, s] of this.sessions) {
      if (!s || s.state === 'closing' || s.state === 'closed') continue;
      if (
        now - s.lastUsed > BROWSER_DEFAULTS.idleTimeoutMs ||
        now - s.createdAt > BROWSER_DEFAULTS.maxLifetimeMs
      ) {
        await this.closeSession(id, 'expired').catch(() => {});
      }
    }
    // Shut down orphan managed browsers with no live sessions.
    for (const [key, browser] of this.managedBrowsers) {
      const inUse = [...this.sessions.values()].some(
        (s) => s.mode === 'managed' && s.browser === browser && s.state !== 'closed'
      );
      if (!inUse) {
        this.managedBrowsers.delete(key);
        try {
          await browser.close();
        } catch {}
      }
    }
  }

  /**
   * @param {{headless?: boolean, policy?: object}} [options]
   */
  async managedBrowser(options = {}) {
    const key = options.headless === false ? 'headed' : 'headless';
    const live = this.managedBrowsers.get(key);
    if (live) {
      try {
        if (live.isConnected && live.isConnected()) return live;
      } catch {}
      this.managedBrowsers.delete(key);
    }
    const core = await this.coreApi();
    const launchArgs = [
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-background-networking',
      '--disable-client-side-phishing-detection',
      '--disable-default-apps',
      '--disable-dev-shm-usage',
      '--disable-extensions',
      '--disable-sync',
      '--disable-translate',
      '--metrics-recording-only',
      '--safebrowsing-disable-auto-update'
    ];
    // NOTE: no --no-sandbox by policy. Sandbox stays enabled; deployments
    // that truly need otherwise must document and gate it explicitly.
    // SYN-BRW-002: resolve the executable ourselves (deterministic fs check)
    // instead of trusting Playwright's process-global registry memoization.
    const resolved = resolveChromiumExecutable({
      browsersDir: this.rt.browsersDir,
      headless: key === 'headless'
    });
    if (!resolved.ok || !resolved.executablePath) {
      throw Object.assign(new Error('BROWSER_INSTALLATION_MISSING'), {
        detail: { tried: resolved.tried, browsersDir: this.rt.browsersDir }
      });
    }
    let browser = null;
    try {
      browser = await core.chromium.launch({
        headless: key === 'headless',
        executablePath: resolved.executablePath,
        timeout: 60000,
        env: browserLaunchEnv({ browsersDir: this.rt.browsersDir }),
        args: launchArgs
      });
    } catch (e) {
      const msg = e && typeof e === 'object' && 'message' in e ? String(e.message) : '';
      if (/executable doesn't exist|Executable doesn't exist/i.test(msg))
        throw Object.assign(new Error('BROWSER_INSTALLATION_MISSING'), {
          cause: e,
          detail: { tried: resolved.tried, browsersDir: this.rt.browsersDir }
        });
      throw Object.assign(new Error('BROWSER_LAUNCH_FAILED'), { cause: e });
    }
    try {
      browser.on('disconnected', () => {
        this.managedBrowsers.delete(key);
        for (const s of this.sessions.values()) {
          if (s.browser === browser && s.state !== 'closed') s.state = 'lost';
        }
      });
    } catch {}
    this.managedBrowsers.set(key, browser);
    return browser;
  }

  /**
   * @param {string} id
   * @param {Record<string, any>} [options]
   */
  async createSession(id, options = {}) {
    const existing = this.sessions.get(id);
    if (existing && existing.state !== 'closed' && existing.state !== 'lost') return existing;
    if (existing) this.sessions.delete(id);
    const mode = String(options.mode || 'managed').toLowerCase();
    if (mode !== 'managed' && mode !== 'existing') throw new Error('BROWSER_UNSUPPORTED_MODE');
    if (mode === 'existing' && options.policy?.existingAttach !== true)
      throw new Error('BROWSER_POLICY_DENIED');
    if (options.headless === false && options.policy?.headed !== true)
      throw new Error('BROWSER_POLICY_DENIED');
    const session = new BrowserSession(id, {
      mode,
      headless: options.headless !== false,
      viewport: options.viewport || { ...BROWSER_DEFAULTS.viewport },
      locale: options.locale || null,
      timezone: options.timezone || null,
      userAgent: options.userAgent || null,
      profileId: options.profileId || null,
      policy: options.policy || null,
      downloadsDir: options.downloadsDir || null,
      playwrightVersion: BROWSER_RUNTIME_PIN.playwright,
      browserRevision: expectedChromiumRevision(this.rt.coreDir)
    });
    this.sessions.set(id, session);
    this.startSweeper();
    try {
      if (mode === 'existing') await this.attachExisting(session, options);
      else await this.launchManaged(session, options);
      session.state = 'ready';
    } catch (e) {
      session.state = 'error';
      // A post-launch failure (owned context/browser created, first page
      // rejected) must not strand resources with no live session entry:
      // route through closeSession so an owned context/browser dies and a
      // held profile lock releases, then rethrow the original error.
      try {
        await this.closeSession(id, 'create-failed');
      } catch {}
      throw e;
    }
    return session;
  }

  /**
   * @param {BrowserSession} session
   * @param {Record<string, any>} [options]
   */
  async launchManaged(session, options = {}) {
    const core = await this.coreApi();
    const profileId = options.profileId || null;
    if (profileId) {
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(profileId)) throw new Error('BROWSER_POLICY_DENIED');
      if (this.profileLocks.has(profileId)) throw new Error('BROWSER_PROFILE_IN_USE');
      this.profileLocks.set(profileId, session.id);
      const userDataDir = path.join(this.rt.profilesDir, profileId);
      ensureDir(this.rt.profilesDir);
      let context = null;
      try {
        const resolvedProfile = resolveChromiumExecutable({
          browsersDir: this.rt.browsersDir,
          headless: session.headless
        });
        if (!resolvedProfile.ok || !resolvedProfile.executablePath) {
          throw Object.assign(new Error('BROWSER_INSTALLATION_MISSING'), {
            detail: { tried: resolvedProfile.tried, browsersDir: this.rt.browsersDir }
          });
        }
        context = await core.chromium.launchPersistentContext(userDataDir, {
          headless: session.headless,
          executablePath: resolvedProfile.executablePath,
          env: browserLaunchEnv({ browsersDir: this.rt.browsersDir }),
          viewport: session.viewport,
          ...(session.locale ? { locale: session.locale } : {}),
          ...(session.timezone ? { timezoneId: session.timezone } : {}),
          ...(session.userAgent ? { userAgent: session.userAgent } : {}),
          acceptDownloads: true,
          downloadsPath: session.downloadsDir || path.join(this.rt.downloadsDir, session.id),
          timeout: 60000,
          args: ['--no-first-run', '--no-default-browser-check', '--disable-dev-shm-usage']
        });
      } catch (e) {
        this.profileLocks.delete(profileId);
        const msg = e && typeof e === 'object' && 'message' in e ? String(e.message) : '';
        if (/^BROWSER_[A-Z_]+/.test(msg)) throw e;
        if (/executable doesn't exist|Executable doesn't exist/i.test(msg))
          throw Object.assign(new Error('BROWSER_INSTALLATION_MISSING'), { cause: e });
        throw Object.assign(new Error('BROWSER_LAUNCH_FAILED'), { cause: e });
      }
      session.browser = context.browser() || null;
      session.ownsBrowser = true;
      if (session.browser) {
        try {
          session.browser.on('disconnected', () => {
            if (session.state !== 'closed') session.state = 'lost';
          });
        } catch {}
      }
      session.context = context;
    } else {
      const browser = await this.managedBrowser({ headless: session.headless });
      session.browser = browser;
      session.ownsBrowser = false;
      let context = null;
      try {
        context = await browser.newContext({
          viewport: session.viewport,
          ...(session.locale ? { locale: session.locale } : {}),
          ...(session.timezone ? { timezoneId: session.timezone } : {}),
          ...(session.userAgent ? { userAgent: session.userAgent } : {}),
          acceptDownloads: true,
          downloadsPath: session.downloadsDir || path.join(this.rt.downloadsDir, session.id)
        });
      } catch {
        throw new Error('BROWSER_LAUNCH_FAILED');
      }
      session.context = context;
    }
    ensureDir(session.downloadsDir || path.join(this.rt.downloadsDir, session.id));
    session.downloadsDir = session.downloadsDir || path.join(this.rt.downloadsDir, session.id);
    if (!session.context) throw new Error('BROWSER_LAUNCH_FAILED');
    await this.wireContext(session, session.context);
    await this.newPage(session, null);
  }

  /**
   * @param {BrowserSession} session
   * @param {Record<string, any>} [options]
   */
  async attachExisting(session, options = {}) {
    const endpoint = String(options.cdpEndpoint || '').trim();
    if (!endpoint) throw new Error('BROWSER_EXISTING_ATTACH_FAILED');
    const proved = await validateCdpEndpoint(
      endpoint,
      options.policy?.network || session.policy?.network || {}
    );
    if (!proved.ok) throw new Error('BROWSER_EXISTING_ATTACH_FAILED');
    const core = await this.coreApi();
    let browser = null;
    try {
      browser = await core.chromium.connectOverCDP(endpoint, { timeout: 30000 });
    } catch {
      throw new Error('BROWSER_EXISTING_ATTACH_FAILED');
    }
    session.browser = browser;
    session.ownsBrowser = false;
    const contexts = typeof browser.contexts === 'function' ? browser.contexts() : [];
    // Existing mode reuses the operator's default context: no storage
    // isolation is promised here. Managed mode is the isolated default.
    session.context = contexts[0] || null;
    if (!session.context) {
      try {
        if (browser.close) await browser.close();
      } catch {}
      throw new Error('BROWSER_EXISTING_ATTACH_FAILED');
    }
    try {
      browser.on('disconnected', () => {
        if (session.state !== 'closed') session.state = 'lost';
      });
    } catch {}
    session.downloadsDir = session.downloadsDir || path.join(this.rt.downloadsDir, session.id);
    ensureDir(session.downloadsDir);
    if (!session.context) throw new Error('BROWSER_EXISTING_ATTACH_FAILED');
    await this.wireContext(session, session.context);
    const pages = typeof session.context.pages === 'function' ? session.context.pages() : [];
    if (pages.length === 0) await this.newPage(session, null);
    else {
      for (const page of pages) this.trackPage(session, page);
    }
  }

  /**
   * @param {BrowserSession} session
   * @param {PWBContext} context
   */
  async wireContext(session, context) {
    if (!context) return;
    await installContextEgressFilter(context, session);
    try {
      context.setDefaultTimeout(BROWSER_DEFAULTS.actionTimeoutMs);
    } catch {}
    try {
      context.setDefaultNavigationTimeout(BROWSER_DEFAULTS.navigationTimeoutMs);
    } catch {}
    try {
      context.on('console', (/** @type {Record<string, any>} */ msg) => {
        try {
          const type = String((msg && msg.type && msg.type()) || 'log');
          const rank = CONSOLE_SEVERITY[type] !== undefined ? type : 'debug';
          let locUrl = null;
          try {
            locUrl = (msg.location && msg.location() && msg.location().url) || null;
          } catch {}
          session.console.push({
            seq: ++session.consoleSeq,
            type: rank,
            text: redactSecretText(String((msg && msg.text && msg.text()) || '')).slice(0, 2000),
            url: typeof locUrl === 'string' ? auditProjectionUrl(locUrl) : null,
            ts: new Date().toISOString()
          });
          if (session.console.length > BROWSER_DEFAULTS.maxConsoleEntries)
            session.console.splice(0, session.console.length - BROWSER_DEFAULTS.maxConsoleEntries);
        } catch {}
      });
    } catch {}
    const pending = new Map();
    try {
      context.on('request', (/** @type {Record<string, any>} */ req) => {
        try {
          pending.set(req, Date.now());
        } catch {}
      });
      const finish = (
        /** @type {Record<string, any>} */ req,
        /** @type {number|null} */ status,
        /** @type {boolean} */ failed
      ) => {
        try {
          const startedAt = pending.get(req) || Date.now();
          pending.delete(req);
          let rawUrl = '';
          try {
            rawUrl = req.url();
          } catch {}
          const type = (() => {
            try {
              return String(req.resourceType());
            } catch {
              return 'other';
            }
          })();
          if (
            !failed &&
            (status === null || status < 400) &&
            STATIC_RESOURCE_TYPES.has(type) &&
            session.includeStatic !== true
          )
            return;
          session.network.push({
            seq: ++session.networkSeq,
            method: (() => {
              try {
                return String(req.method());
              } catch {
                return '';
              }
            })(),
            url: auditProjectionUrl(rawUrl),
            status,
            resource_type: type,
            duration_ms: Date.now() - startedAt,
            failed: Boolean(failed)
          });
          if (session.network.length > BROWSER_DEFAULTS.maxNetworkEntries)
            session.network.splice(0, session.network.length - BROWSER_DEFAULTS.maxNetworkEntries);
        } catch {}
      };
      context.on('response', (/** @type {Record<string, any>} */ res) => {
        try {
          finish(res.request(), res.status(), false);
        } catch {}
      });
      context.on('requestfailed', (/** @type {Record<string, any>} */ req) =>
        finish(req, null, true)
      );
    } catch {}
    try {
      context.on('page', (/** @type {PWPage} */ page) => {
        try {
          this.trackPage(session, page);
        } catch {}
      });
    } catch {}
    try {
      context.on('dialog', (/** @type {PWDialog} */ dialog) => {
        try {
          const record = {
            type: (() => {
              try {
                return String(dialog.type());
              } catch {
                return '';
              }
            })(),
            message: redactSecretText(
              (() => {
                try {
                  return String(dialog.message());
                } catch {
                  return '';
                }
              })()
            ).slice(0, 2000),
            url: session.currentPage()?.url || null,
            ts: new Date().toISOString(),
            handled: false
          };
          if (session.pendingDialog?.timer) clearTimeout(session.pendingDialog.timer);
          const timer = setTimeout(() => {
            try {
              if (session.pendingDialog?.dialog === dialog) {
                session.pendingDialog = { ...record, handled: true, accept: false };
                dialog.dismiss().catch(() => {});
              }
            } catch {}
          }, 3000);
          if (timer.unref) timer.unref();
          session.pendingDialog = { dialog, timer, ...record };
        } catch {
          try {
            dialog.dismiss().catch(() => {});
          } catch {}
        }
      });
    } catch {}
  }

  /**
   * @param {BrowserSession} session
   * @param {PWPage} page
   */
  trackPage(session, page) {
    for (const [id, rec] of session.pages) {
      if (rec.page === page) {
        session.currentPageId = session.currentPageId || id;
        return id;
      }
    }
    const pageId = 'pg_' + crypto.randomBytes(6).toString('hex');
    session.pages.set(pageId, { page, url: 'about:blank', title: '' });
    if (!session.currentPageId) session.currentPageId = pageId;
    try {
      page.on('close', () => {
        try {
          session.pages.delete(pageId);
          session.cdpSessions.delete(pageId);
          if (session.currentPageId === pageId) session.currentPageId = null;
        } catch {}
      });
    } catch {}
    try {
      page.on('download', (/** @type {PWDownload} */ dl) => {
        this.handleDownload(session, dl).catch(() => {});
      });
    } catch {}
    return pageId;
  }

  /**
   * @param {BrowserSession} session
   * @param {string|null} url
   */
  async newPage(session, url) {
    if (!session.context) throw new Error('BROWSER_SESSION_LOST');
    const page = await session.context.newPage();
    const pageId = this.trackPage(session, page);
    session.currentPageId = pageId;
    if (url) {
      try {
        await page.goto(url, { timeout: BROWSER_DEFAULTS.navigationTimeoutMs });
      } catch {}
    }
    return { pageId, page };
  }

  /**
   * @param {BrowserSession} session
   * @param {PWDownload} dl
   */
  async handleDownload(session, dl) {
    const allowed = session.policy?.downloads === true;
    let suggested = 'download';
    try {
      suggested = (await dl.suggestedFilename()) || suggested;
    } catch {}
    if (!allowed) {
      try {
        await dl.cancel();
      } catch {}
      session.downloads.push({
        filename: String(suggested).slice(0, 128),
        path: '',
        size_bytes: 0,
        status: 'blocked_policy'
      });
      return;
    }
    const filename = sanitizeDownloadName(session.id, suggested);
    const dest = path.join(session.downloadsDir, filename);
    try {
      await dl.saveAs(dest);
      let size = 0;
      try {
        size = fs.statSync(dest).size;
      } catch {}
      if (size > BROWSER_DEFAULTS.maxDownloadBytes) {
        try {
          fs.rmSync(dest, { force: true });
        } catch {}
        session.downloads.push({ filename, path: '', size_bytes: size, status: 'too_large' });
        return;
      }
      session.downloads.push({ filename, path: dest, size_bytes: size, status: 'completed' });
    } catch {
      session.downloads.push({ filename, path: '', size_bytes: 0, status: 'failed' });
    }
  }

  /**
   * @param {string} id
   * @param {string} [reason]
   */
  async closeSession(id, reason = 'close') {
    let session = this.sessions.get(id);
    if (!session && (id === 'default' || !id)) {
      const candidates = [...this.sessions.values()]
        .filter((s) => s && s.state !== 'closing' && s.state !== 'closed')
        .sort((a, b) => (b.lastUsed || 0) - (a.lastUsed || 0));
      if (candidates.length > 0) session = candidates[0];
    }
    if (!session) return { closed: false, existed: false };
    if (session.state === 'closed') return { closed: true, existed: true, sessionId: session.id };
    const sessionId = session.id || id;
    session.state = 'closing';
    if (session.pendingDialog?.timer) {
      try {
        clearTimeout(session.pendingDialog.timer);
      } catch {}
      session.pendingDialog = null;
    }
    for (const cdp of session.cdpSessions.values()) {
      try {
        await cdp.detach();
      } catch {}
    }
    session.cdpSessions.clear();
    try {
      if (session.context) {
        if (session.mode === 'existing' || session.profileId) {
          // Existing: never close the operator's browser; close only pages
          // we created. Persistent profiles keep their browser alive.
          if (session.mode === 'existing') {
            for (const [, rec] of session.pages) {
              try {
                await rec.page.close();
              } catch {}
            }
            try {
              if (session.browser && session.browser.close) {
                // Detach-only: Playwright closes CDP sessions it owns.
              }
            } catch {}
          } else {
            await session.context.close();
          }
        } else {
          await session.context.close();
        }
      }
    } catch {}
    if (session.profileId) this.profileLocks.delete(session.profileId);
    if (session.ownsBrowser && session.browser) {
      try {
        await session.browser.close();
      } catch {}
    }
    session.pages.clear();
    session.refs.clear();
    session.state = 'closed';
    this.sessions.delete(id);
    if (sessionId !== id) this.sessions.delete(sessionId);
    // Downloads metadata dies with the session; files are TTL-swept.
    try {
      fs.rmSync(path.join(this.rt.downloadsDir, sessionId), { recursive: true, force: true });
    } catch {}
    void reason;
    return { closed: true, existed: true, sessionId };
  }

  async closeAll() {
    this.shuttingDown = true;
    if (this.sweeper) {
      clearInterval(this.sweeper);
      this.sweeper = null;
    }
    for (const id of [...this.sessions.keys()]) {
      await this.closeSession(id, 'shutdown').catch(() => {});
    }
    for (const [, browser] of this.managedBrowsers) {
      try {
        await browser.close();
      } catch {}
    }
    this.managedBrowsers.clear();
  }

  /**
   * Resolve a live session or throw a terminal, actionable stale-handle
   * error (Lesson 7: never a bare failure). Dead entries are purged from
   * the map so they stop being listed/resolved; the thrown error keeps
   * the exact taxonomy code in `message` (existing equality assertions
   * depend on it) and carries the model guidance in `detail`
   * (see staleSessionHint, surfaced by the job layer in result_payload).
   * @param {string} id
   */
  requireSession(id) {
    let session = this.sessions.get(id);
    if (!session && (id === 'default' || !id)) {
      const candidates = [...this.sessions.values()]
        .filter(
          (s) =>
            s &&
            s.state !== 'closing' &&
            s.state !== 'closed' &&
            s.state !== 'lost' &&
            s.state !== 'error'
        )
        .sort((a, b) => (b.lastUsed || 0) - (a.lastUsed || 0));
      if (candidates.length > 0) session = candidates[0];
    }
    if (!session) {
      throw staleSessionError(id, 'missing');
    }
    if (session.state === 'lost' || session.state === 'error') {
      this.dropSessionEntry(session.id, id);
      throw staleSessionError(id, session.state);
    }
    if (session.state === 'closing' || session.state === 'closed') {
      this.dropSessionEntry(session.id, id);
      throw staleSessionError(id, session.state);
    }
    session.touch();
    return session;
  }

  /**
   * Forget one map entry by every key that can address it. Bounded: only
   * shrinks the sessions map, never grows it.
   * @param {string} sessionId canonical id on the session record
   * @param {string} lookupId id the caller resolved through
   */
  dropSessionEntry(sessionId, lookupId) {
    try {
      if (sessionId) this.sessions.delete(sessionId);
    } catch {}
    try {
      if (lookupId && lookupId !== sessionId) this.sessions.delete(lookupId);
    } catch {}
  }

  /**
   * Eagerly purge every dead handle (lost/error/closed) from the map.
   * Transient `creating`/`busy`/`ready` sessions are untouched, and
   * `closing` is left to its owner (closeSession deletes on completion).
   * @returns {number} purged entry count
   */
  purgeDeadSessions() {
    let purged = 0;
    for (const [key, s] of [...this.sessions]) {
      if (!s || s.state === 'lost' || s.state === 'error' || s.state === 'closed') {
        try {
          this.sessions.delete(key);
        } catch {}
        purged++;
      }
    }
    return purged;
  }

  /**
   * Resolve a live session, reviving a stale/missing handle when possible
   * (Lesson 7 auto-revival). A same-id managed session is created on
   * demand — managedBrowser() reuses a still-connected browser instead of
   * launching a new one — and returned with revived:true. When no browser
   * can be (re)launched the terminal stale-handle error (with guidance)
   * is rethrown. Callers must pass a validated session key (jobs validate
   * the brw_ shape before dispatch).
   * @param {string} id
   * @param {Record<string, any>} [options] createSession options for the revival
   * @returns {Promise<{session: any, revived: boolean}>}
   */
  async ensureSession(id, options = {}) {
    try {
      const live = this.requireSession(id);
      return { session: live, revived: false };
    } catch (stale) {
      // requireSession already purged the dead entry; only stale-handle
      // codes qualify for revival, anything else propagates untouched.
      const code =
        stale && typeof stale === 'object' && 'message' in stale
          ? String(stale.message || '').split(':')[0]
          : '';
      if (code !== 'BROWSER_SESSION_NOT_FOUND' && code !== 'BROWSER_SESSION_LOST') throw stale;
      const key = String(id || 'default');
      try {
        const session = await this.createSession(key, {
          mode: 'managed',
          headless: true,
          policy: null,
          ...options
        });
        return { session, revived: true };
      } catch (cause) {
        const staleDetail =
          stale && typeof stale === 'object'
            ? /** @type {{detail?: {state?: unknown}}} */ (stale).detail
            : null;
        const priorState =
          staleDetail && typeof staleDetail.state === 'string' ? staleDetail.state : 'missing';
        const err = staleSessionError(id, priorState);
        try {
          err.cause = cause;
        } catch {}
        throw err;
      }
    }
  }

  /**
   * @param {BrowserSession} session
   * @param {unknown} pageId
   */
  requirePage(session, pageId) {
    const wanted = typeof pageId === 'string' && pageId ? pageId : null;
    const id = wanted || session.currentPageId || session.currentPage()?.pageId || null;
    if (!id) throw new Error('BROWSER_PAGE_NOT_FOUND');
    const rec = session.pages.get(id);
    if (!rec) throw new Error('BROWSER_PAGE_NOT_FOUND');
    try {
      if (rec.page.isClosed && rec.page.isClosed()) {
        session.pages.delete(id);
        session.cdpSessions.delete(id);
        throw new Error('BROWSER_PAGE_NOT_FOUND');
      }
    } catch (e) {
      if (e && typeof e === 'object' && 'message' in e && String(e.message).startsWith('BROWSER_'))
        throw e;
    }
    return { pageId: /** @type {string} */ (id), ...rec };
  }

  /**
   * @param {BrowserSession} session
   * @param {unknown} pageId
   */
  async cdpForPage(session, pageId) {
    const ctx = session.context;
    if (!ctx) throw new Error('BROWSER_SESSION_LOST');
    const want = typeof pageId === 'string' && pageId ? pageId : session.currentPageId || '';
    const hit = session.cdpSessions.get(want);
    if (hit) return hit;
    const { page } = this.requirePage(session, want);
    const cdp = await ctx.newCDPSession(page);
    try {
      await cdp.send('Accessibility.enable');
    } catch {}
    session.cdpSessions.set(want, cdp);
    return cdp;
  }

  /**
   * @param {BrowserSession} session
   * @param {{pageId?: string|null, target?: string|null, depth?: number|null, maxChars?: number|null}} [options]
   */
  async snapshot(session, options = {}) {
    session.touch();
    const { page } = this.requirePage(session, options.pageId || '');
    const cdp = await this.cdpForPage(session, options.pageId || session.currentPageId || '');
    let rootId = null;
    if (options.target) {
      const resolved = await this.resolveTarget(session, options.target, {
        pageId: options.pageId || ''
      });
      rootId = resolved.backendNodeId || null;
      if (!rootId) throw new Error('BROWSER_TARGET_NOT_FOUND');
    }
    /** @type {{nodes?: Array<Record<string, unknown>>}} */
    let ax = { nodes: [] };
    try {
      ax = await cdp.send('Accessibility.getFullAXTree', {});
    } catch {
      throw new Error('BROWSER_SNAPSHOT_FAILED');
    }
    const nodes = Array.isArray(ax.nodes) ? ax.nodes : [];
    const rendered = this.renderAxTree(session, nodes, {
      rootId,
      depth: options.depth || null,
      maxChars: options.maxChars || BROWSER_DEFAULTS.maxSnapshotChars
    });
    let url = '';
    let title = '';
    try {
      url = page.url();
    } catch {}
    try {
      title = await page.title();
    } catch {}
    const rec = session.pages.get(options.pageId || session.currentPageId || '');
    if (rec) {
      rec.url = url;
      rec.title = title;
    }
    session.snapshotId = 'snap_' + crypto.randomBytes(8).toString('hex');
    return {
      snapshot_id: session.snapshotId,
      page_revision: session.pageRevision,
      url,
      title,
      tree: rendered.text,
      truncated: rendered.truncated,
      ref_count: rendered.refCount
    };
  }

  /**
   * @param {BrowserSession} session
   * @param {Array<Record<string, unknown>>} nodes
   * @param {{rootId?: string|number|null, depth?: number|null, maxChars?: number|null}} options
   */
  renderAxTree(session, nodes, options = {}) {
    const nodeMap = new Map();
    for (const n of nodes) nodeMap.set(n.nodeId, n);
    const childSet = new Set();
    for (const n of nodes) {
      if (Array.isArray(n.childIds)) for (const cid of n.childIds) childSet.add(cid);
    }
    // Subtree root: match CDP backendDOMNodeId when a target was given.
    let roots = nodes.filter((n) => !childSet.has(n.nodeId));
    if (options.rootId !== null && options.rootId !== undefined) {
      const match = nodes.find(
        (n) =>
          String(n.backendDOMNodeId || '') === String(options.rootId) ||
          String(n.nodeId || '') === String(options.rootId)
      );
      if (match) roots = [match];
    }
    /** @type {Array<{line: string, path: string, ref: string|null, depth: number}>} */
    const rows = [];
    session.refs.clear();
    let refSeq = 0;
    /** @type {Map<string, number>} */
    const roleCounts = new Map();
    /** @type {Map<string, number>} */
    const namedCounts = new Map();
    const maxDepth = options.depth || 0;
    /**
     * @param {Record<string, unknown>} node
     * @param {number} depth
     * @param {Array<string>} trail
     */
    const renderNode = (node, depth, trail) => {
      const role = String(/** @type {Record<string, any>} */ (node.role || {}).value || 'node');
      const name = String(/** @type {Record<string, any>} */ (node.name || {}).value || '').trim();
      const value = String(
        /** @type {Record<string, any>} */ (node.value || {}).value || ''
      ).trim();
      const description = String(
        /** @type {Record<string, any>} */ (node.description || {}).value || ''
      ).trim();
      const props = /** @type {Record<string, any>} */ (node.properties || {});
      const states = [];
      for (const [k, label] of [
        ['checked', 'checked'],
        ['disabled', 'disabled'],
        ['expanded', 'expanded'],
        ['selected', 'selected'],
        ['required', 'required'],
        ['invalid', 'invalid']
      ]) {
        if (props[k]?.value === true) states.push(label);
      }
      const ignored = node.ignored === true || SKIP_ROLES.has(role);
      const hasContent = Boolean(name || value || description);
      const refable = WIDGET_ROLES.has(role) || (!ignored && hasContent && name.length > 0);
      let ref = null;
      if (refable) {
        ref = 'e' + ++refSeq;
        const index = roleCounts.get(role) || 0;
        roleCounts.set(role, index + 1);
        const namedKey = role + '\u0000' + name;
        const nameIndex = namedCounts.get(namedKey) || 0;
        namedCounts.set(namedKey, nameIndex + 1);
        const cur = session.currentPage();
        session.refs.set(ref, {
          role,
          name,
          index,
          nameIndex,
          pageId: cur?.pageId || '',
          revision: session.pageRevision
        });
      }
      const crumb = name ? `${role} "${name.slice(0, 60)}"` : role;
      const nextTrail = [...trail, crumb];
      if (!ignored || hasContent) {
        const indent = '  '.repeat(depth);
        let line = `${indent}- ${role}`;
        if (name) line += ` "${name.slice(0, 200)}"`;
        if (value && value !== name) line += ` val="${value.slice(0, 120)}"`;
        if (description) line += ` (${description.slice(0, 120)})`;
        if (states.length) line += ` [${states.join(',')}]`;
        if (ref) line += ` [ref=${ref}]`;
        rows.push({ line, path: nextTrail.join(' > '), ref, depth });
      }
      if (maxDepth > 0 && depth >= maxDepth) return;
      if (Array.isArray(node.childIds)) {
        for (const cid of node.childIds) {
          const child = nodeMap.get(cid);
          if (child) renderNode(child, !ignored || hasContent ? depth + 1 : depth, nextTrail);
        }
      }
    };
    for (const r of roots) renderNode(r, 0, []);
    const budget = Math.max(
      1024,
      Math.min(100000, Number(options.maxChars) || BROWSER_DEFAULTS.maxSnapshotChars)
    );
    let text = rows.map((r) => r.line).join('\n') || '(empty accessibility tree)';
    let truncated = false;
    if (text.length > budget) {
      text = text.slice(0, budget);
      truncated = true;
    }
    return { text, truncated, refCount: session.refs.size, rows };
  }

  /**
   * @param {BrowserSession} session
   * @param {{text?: string|null, query?: string|null, target?: string|null, regex?: string|null, maxResults?: number|null}} options
   */
  async find(session, options = {}) {
    session.touch();
    const text =
      typeof options.text === 'string'
        ? options.text
        : typeof options.query === 'string'
          ? options.query
          : typeof options.target === 'string'
            ? options.target
            : '';
    const regex = typeof options.regex === 'string' ? options.regex : '';
    if ((text && regex) || (!text && !regex)) throw new Error('BROWSER_FIND_QUERY_REQUIRED');
    let matcher = null;
    if (text) {
      const needle = text.toLowerCase();
      matcher = (/** @type {string} */ line) => line.toLowerCase().includes(needle);
    } else {
      let pattern = regex;
      let flags = '';
      const m = /^\/(.+)\/([a-z]*)$/.exec(regex);
      if (m) {
        pattern = m[1] || '';
        flags = m[2] || '';
      }
      let re = null;
      try {
        // P3-D3: sync test() has no timeout; nested quantifiers backtrack
        // exponentially and wedge the agent event loop. Reject structurally
        // dangerous patterns before compiling (same fail-closed code).
        re = new RegExp(assertSafeRegexPattern(pattern), flags);
      } catch {
        throw new Error('BROWSER_FIND_QUERY_REQUIRED');
      }
      matcher = (/** @type {string} */ line) => {
        const text = String(line || '');
        // Bound per-attempt work for polynomial shapes: only the regex
        // branch is sliced (literal includes() stays full-recall).
        return re.test(
          text.length > MAX_REGEX_TEST_CHARS ? text.slice(0, MAX_REGEX_TEST_CHARS) : text
        );
      };
    }
    const full = await this.snapshot(session, { maxChars: 100000 });
    const lines = String(full.tree).split('\n');
    const maxResults = Math.max(1, Math.min(50, Number(options.maxResults) || 10));
    const matches = [];
    for (let i = 0; i < lines.length && matches.length < maxResults + 1; i++) {
      if (matcher(lines[i] || '')) {
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        const ref = /\[ref=(e\d+)\]/.exec(lines[i] || '')?.[1] || null;
        matches.push({
          ref,
          line: i + 1,
          snippet: lines.slice(start, end).join('\n').slice(0, 1200)
        });
      }
    }
    const truncated = matches.length > maxResults;
    return {
      matches: matches.slice(0, maxResults),
      truncated,
      snapshot_id: full.snapshot_id,
      page_revision: full.page_revision,
      url: full.url,
      title: full.title
    };
  }

  /**
   * Resolve a target (ref like e17, or CSS selector) to a Playwright locator
   * plus CDP backend node id when cheap. Stale refs fail closed.
   * @param {BrowserSession} session
   * @param {string} target
   * @param {{pageId?: string|null}} [options]
   */
  async resolveTarget(session, target, options = {}) {
    const raw = String(target || '').trim();
    if (!raw) throw new Error('BROWSER_TARGET_NOT_FOUND');
    const { page } = this.requirePage(session, options.pageId || '');
    const refMatch = /^e(\d+)$/.exec(raw);
    if (refMatch) {
      const entry = session.refs.get(raw);
      if (!entry) throw new Error('BROWSER_STALE_TARGET');
      if (entry.revision !== session.pageRevision) throw new Error('BROWSER_STALE_TARGET');
      if (options.pageId && entry.pageId && entry.pageId !== options.pageId)
        throw new Error('BROWSER_STALE_TARGET');
      // Deterministic re-resolution: nth widget of its role, narrowed by
      // name when the snapshot had one. Unnamed widgets (bare inputs)
      // resolve by role order instead of failing. Text-only roles fall back
      // to visible-text matching.
      let locator = null;
      if (TEXT_FALLBACK_ROLES.has(entry.role)) {
        if (!entry.name) throw new Error('BROWSER_TARGET_NOT_FOUND');
        locator = page.getByText(entry.name).nth(entry.nameIndex);
      } else {
        locator = entry.name
          ? page.getByRole(entry.role, { name: entry.name }).nth(entry.nameIndex)
          : page.getByRole(entry.role).nth(entry.index);
      }
      try {
        await locator.waitFor({ state: 'attached', timeout: 2000 });
      } catch {
        throw new Error('BROWSER_STALE_TARGET');
      }
      return { locator, pageId: entry.pageId, backendNodeId: null };
    }
    // CSS selector path (backward compatibility).
    let locator = null;
    try {
      locator = page.locator(raw).first();
      const count = await page.locator(raw).count();
      if (count < 1) throw new Error('BROWSER_TARGET_NOT_FOUND');
    } catch (e) {
      if (e && typeof e === 'object' && 'message' in e && String(e.message).startsWith('BROWSER_'))
        throw e;
      throw Object.assign(new Error('BROWSER_TARGET_NOT_FOUND'), { cause: e });
    }
    let backendNodeId = null;
    try {
      const cdp = await this.cdpForPage(session, options.pageId || session.currentPageId || '');
      const doc = await cdp.send('DOM.getDocument', { depth: 1 });
      const found = await cdp.send('DOM.querySelector', {
        nodeId: doc.root.nodeId,
        selector: raw
      });
      backendNodeId = found?.nodeId || null;
    } catch {}
    return { locator, pageId: options.pageId || session.currentPageId, backendNodeId };
  }
}

/** @type {BrowserManager|null} */
let sharedManager = null;

/**
 * @param {{dataDir?: string|null, root?: string|null, env?: NodeJS.ProcessEnv}} [options]
 */
export function getBrowserManager(options = {}) {
  if (sharedManager) return sharedManager;
  sharedManager = new BrowserManager(options);
  return sharedManager;
}

/** For tests: drop the shared instance. */
export function resetBrowserManager() {
  const m = sharedManager;
  sharedManager = null;
  return m;
}

/**
 * Terminal guidance for a stale browser handle. The control plane keeps
 * handles across agent restarts, browser crashes and TTL eviction, so a
 * missing/dead id is routine — the model must open a fresh session
 * instead of retrying the dead id. Error codes stay bare (taxonomy +
 * existing equality assertions); the guidance travels in result_payload.
 * @param {unknown} id requested session key
 * @param {unknown} err the stale-handle error (or its state string)
 * @returns {{browser_id: string|null, session_state: string, retryable: boolean, suggested_action: string, hint: string}}
 */
export function staleSessionHint(id, err = null) {
  const key = typeof id === 'string' && id ? id : 'default';
  let state = 'missing';
  if (typeof err === 'string' && err) state = err;
  else if (err && typeof err === 'object') {
    const detailState =
      /** @type {{detail?: {state?: unknown}}} */ (err).detail?.state;
    if (typeof detailState === 'string' && detailState) state = detailState;
    else {
      const m = /^BROWSER_SESSION_(NOT_FOUND|LOST)/.exec(String(/** @type {{message?: unknown}} */ (err).message || ''));
      if (m) state = m[1] === 'LOST' ? 'lost' : 'missing';
    }
  }
  const reason =
    state === 'lost' || state === 'error'
      ? 'its browser disconnected or crashed'
      : state === 'closing' || state === 'closed'
        ? 'it was closed or expired'
        : 'it never existed on this agent, or the agent restarted and forgot it';
  return {
    browser_id: key === 'default' ? null : key,
    session_state: String(state),
    retryable: false,
    suggested_action: 'browser_create',
    hint:
      `Browser session '${key}' is no longer available (${reason}). ` +
      'Call browser_create to open a new session, then retry the operation with the new browser_id. ' +
      'Do not retry with the old browser_id — it will keep failing.'
  };
}

/**
 * Build the stale-handle error: exact taxonomy code in `message`, terminal
 * model guidance in `detail` (surfaced by the job layer; see
 * staleSessionHint). missing/closing/closed map to
 * BROWSER_SESSION_NOT_FOUND, lost/error to BROWSER_SESSION_LOST.
 * @param {unknown} id
 * @param {unknown} state
 * @returns {Error & {code: string, detail: Record<string, unknown>}}
 */
export function staleSessionError(id, state = 'missing') {
  const s = String(state || 'missing');
  const code = s === 'lost' || s === 'error' ? 'BROWSER_SESSION_LOST' : 'BROWSER_SESSION_NOT_FOUND';
  const hint = staleSessionHint(id, s);
  const err = /** @type {Error & {code: string, detail: Record<string, unknown>}} */ (
    Object.assign(new Error(code), {
      code,
      detail: {
        session_id: typeof id === 'string' && id ? id : 'default',
        state: s,
        retryable: false,
        suggested_action: hint.suggested_action,
        hint: hint.hint
      }
    })
  );
  return err;
}

/**
 * @param {unknown} err
 * @param {'navigate'|'action'} kind
 */
export function mapBrowserError(err, kind = 'action') {
  const msg = err && typeof err === 'object' && 'message' in err ? String(err.message) : '';
  const base = /^BROWSER_[A-Z_]+/.exec(msg);
  if (base) return base[0];
  if (/Timeout/i.test(msg))
    return kind === 'navigate' ? 'BROWSER_NAVIGATION_TIMEOUT' : 'BROWSER_ACTION_TIMEOUT';
  if (/closed|destroyed|disconnected|crash|crashed/i.test(msg)) return 'BROWSER_SESSION_LOST';
  if (/net::|ERR_/i.test(msg)) return 'BROWSER_NAVIGATION_FAILED';
  return 'BROWSER_INTERNAL_ERROR';
}

/**
 * Standard job envelope helpers.
 * @param {number} started
 * @param {Record<string, unknown>} payload
 * @param {string|null} [stdout]
 */
export function okJob(started, payload, stdout = '') {
  return {
    status: 'completed',
    exit_code: 0,
    stdout: stdout || '',
    stderr: '',
    error: null,
    duration_ms: Date.now() - started,
    result_payload: payload
  };
}

/**
 * @param {number} started
 * @param {string} error
 * @param {Record<string, unknown>} [payload]
 */
export function failJob(started, error, payload = {}) {
  return {
    status: 'failed',
    exit_code: null,
    stdout: '',
    stderr: '',
    error,
    duration_ms: Date.now() - started,
    result_payload: payload
  };
}

/**
 * Client-audit summary for browser ops. Values, cookies, tokens and bodies
 * are NEVER included: action + target identity + sanitized URL only.
 * @param {string} op
 * @param {Record<string, unknown>} payload
 * @param {Record<string, unknown>} result
 */
export function browserAuditSummary(op, payload = {}, result = {}) {
  const rp =
    result?.result_payload && typeof result.result_payload === 'object'
      ? /** @type {Record<string, unknown>} */ (result.result_payload)
      : {};
  const redactTarget = (/** @type {unknown} */ t) => {
    const s = String(t || '');
    if (/^e\d+$/.test(s)) return s;
    return s ? '[selector]' : null;
  };
  return {
    browser_id:
      typeof rp.browser_id === 'string'
        ? rp.browser_id
        : typeof payload.browser_id === 'string'
          ? payload.browser_id
          : null,
    action:
      typeof rp.action === 'string'
        ? rp.action
        : typeof payload.action === 'string'
          ? payload.action
          : op,
    target: redactTarget(rp.target_ref || payload.target || payload.selector),
    url: typeof rp.url === 'string' ? auditProjectionUrl(rp.url) : null,
    page_id: typeof rp.page_id === 'string' ? rp.page_id : null,
    value: '[REDACTED]',
    duration_ms: typeof result.duration_ms === 'number' ? result.duration_ms : null,
    error: typeof result.error === 'string' ? result.error : null
  };
}

export { BROWSER_DEFAULTS };
