import {
  getBrowserManager,
  policyFromJob,
  resolveUploadPath,
  redactSecretText,
  mapBrowserError,
  staleSessionHint,
  okJob,
  failJob,
  assertEvaluateExpression,
  assertSafeRegexPattern,
  installContextEgressFilter,
  BROWSER_DEFAULTS,
  CONSOLE_SEVERITY
} from './browser-manager.mjs';
import { validateEgressUrl, auditProjectionUrl } from '../policy/egress-policy.mjs';
import { expectedChromiumRevision, installedChromiumRevisions } from './browser-runtime.mjs';
import { validateBrowserLaunch } from './browser-runtime.mjs';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/** Max retained over-budget captures per browser session (session-close wipes the dir). */
export const SCREENSHOT_ARTIFACT_KEEP = 5;

/**
 * @typedef {import('./browser-manager.mjs').PWPage} PWPage
 * @typedef {import('./browser-manager.mjs').PWLocator} PWLocator
 */

const BID_RE = /^brw_[0-9a-f]{32}$/;
const DEFAULT_SESSION = 'default';
// Model-visible target strings (refs/selectors/paths) are bounded so an
// unbounded input cannot pin selector matching or snapshot search.
export const MAX_BROWSER_TARGET_CHARS = 1024;
/**
 * @param {unknown} target
 */
export function assertBrowserTarget(target) {
  const text = String(target || '').trim();
  if (text.length > MAX_BROWSER_TARGET_CHARS) throw new Error('BROWSER_TARGET_INVALID');
  return text;
}

/**
 * Persist an over-budget capture instead of destroying it (SYN-BRW-001).
 * Stored under the session downloads dir so session close sweeps it, capped
 * to SCREENSHOT_ARTIFACT_KEEP newest files. The model fetches the bytes via
 * file_read (agent allowlist covers the downloads tree).
 * @param {{downloadsRoot?: string|null, sessionKey?: string, bytes?: unknown, ext?: string}} [options]
 */
export function storeScreenshotArtifact({
  downloadsRoot = null,
  sessionKey = DEFAULT_SESSION,
  bytes = null,
  ext = 'png'
} = {}) {
  if (!downloadsRoot || !Buffer.isBuffer(bytes) || bytes.length === 0)
    return { ok: false, error: 'BROWSER_ARTIFACT_STORE_FAILED' };
  const safeExt = ext === 'jpeg' || ext === 'jpg' ? 'jpg' : 'png';
  const safeKey = /^[A-Za-z0-9_-]{1,64}$/.test(String(sessionKey || ''))
    ? String(sessionKey)
    : 'default';
  try {
    const dir = path.join(String(downloadsRoot), safeKey);
    fs.mkdirSync(dir, { recursive: true });
    const name = `screenshot-${Date.now()}-${crypto.randomBytes(4).toString('hex')}.${safeExt}`;
    const full = path.join(dir, name);
    fs.writeFileSync(full, bytes, { mode: 0o600 });
    try {
      const kept = fs
        .readdirSync(dir)
        .filter((f) => f.startsWith('screenshot-') && (f.endsWith('.png') || f.endsWith('.jpg')))
        .map((f) => ({ f, t: fs.statSync(path.join(dir, f)).mtimeMs }))
        .sort((a, b) => b.t - a.t);
      for (const stale of kept.slice(SCREENSHOT_ARTIFACT_KEEP)) {
        try {
          fs.rmSync(path.join(dir, stale.f), { force: true });
        } catch {}
      }
    } catch {}
    return { ok: true, artifact_path: full, bytes: bytes.length };
  } catch {
    return { ok: false, error: 'BROWSER_ARTIFACT_STORE_FAILED' };
  }
}

/**
 * @param {unknown} job
 */
function jobPayload(job) {
  const record = /** @type {Record<string, unknown>} */ (job || {});
  const nested =
    record.request_payload && typeof record.request_payload === 'object'
      ? /** @type {Record<string, unknown>} */ (record.request_payload)
      : record.payload && typeof record.payload === 'object'
        ? /** @type {Record<string, unknown>} */ (record.payload)
        : {};
  return { ...record, ...nested };
}

/**
 * @param {unknown} v
 * @param {number} def
 * @param {number} min
 * @param {number} max
 */
function clampTimeout(v, def, min = 1000, max = BROWSER_DEFAULTS.maxTimeoutMs) {
  const n = Number(v);
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

/**
 * @param {unknown} v
 */
function parseViewport(v) {
  const m = /^([0-9]{2,5})x([0-9]{2,5})$/.exec(String(v || ''));
  if (!m) return { ...BROWSER_DEFAULTS.viewport };
  const width = Math.max(100, Math.min(4096, Number(m[1])));
  const height = Math.max(100, Math.min(4096, Number(m[2])));
  return { width, height };
}

/**
 * Failure payload for stale-handle rejections: the exact taxonomy code
 * stays in `error`, while the terminal next-step guidance (call
 * browser_create, never retry the dead id) rides in result_payload where
 * the model can act on it. Non-stale errors keep the legacy shape.
 * @param {string} key resolved session key
 * @param {unknown} err rejection from requireSession
 * @returns {Record<string, unknown>}
 */
function staleJobPayload(key, err) {
  const base = mapBrowserError(err);
  const extra = key !== DEFAULT_SESSION ? { browser_id: key } : {};
  if (base !== 'BROWSER_SESSION_NOT_FOUND' && base !== 'BROWSER_SESSION_LOST') return extra;
  return { ...extra, ...staleSessionHint(key, err) };
}

/**
 * @param {unknown} job
 */
function sessionKey(job) {
  const p = jobPayload(job);
  const bid = p.browser_id ?? p.session_id;
  if (bid === undefined || bid === null || bid === '') return DEFAULT_SESSION;
  if (typeof bid !== 'string' || !BID_RE.test(bid)) throw new Error('INVALID_BROWSER_ID');
  return bid;
}

/**
 * @param {unknown} url
 * @param {ReturnType<typeof policyFromJob>} policy
 * @returns {Promise<{ok: true, url: string}|{ok: false, error: string, url: string|null}>}
 */
async function checkUrl(url, policy) {
  const raw = String(url || '').trim();
  if (!raw) return { ok: false, error: 'URL_REQUIRED', url: null };
  try {
    const verdict = await validateEgressUrl(raw, {
      allowPrivateNetwork: policy.network.allowPrivateNetwork,
      allowLoopback: policy.network.allowLoopback,
      allowedHosts: policy.network.allowedHosts,
      blockedHosts: policy.network.blockedHosts,
      resolve: async (hostname) => {
        const dns = await import('node:dns/promises');
        const records = await dns.lookup(hostname, { all: true, verbatim: true });
        return records.map((r) => r.address);
      }
    });
    if (!verdict.ok)
      return {
        ok: false,
        error: verdict.error || 'URL_EGRESS_DENIED',
        url: auditProjectionUrl(raw)
      };
    return { ok: true, url: raw };
  } catch {
    return { ok: false, error: 'URL_VALIDATION_FAILED', url: auditProjectionUrl(raw) };
  }
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserCreateJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const policy = policyFromJob(job);
  const manager = getBrowserManager();
  let key;
  try {
    if (p.browser_id !== undefined && p.browser_id !== null && p.browser_id !== '') {
      key = sessionKey(job);
    } else {
      key = 'brw_' + crypto.randomBytes(16).toString('hex');
    }
  } catch (e) {
    return failJob(started, 'INVALID_BROWSER_ID');
  }
  const mode = String(p.mode || BROWSER_DEFAULTS.mode).toLowerCase();
  const headless = p.headless !== false;
  // Policy first (cheap, specific verdicts), runtime second: an existing-attach
  // without capability is DENIED even when no runtime is installed, and
  // headed mode needs its capability before any launch is attempted.
  if (mode === 'existing' && policy.existingAttach !== true)
    return failJob(started, 'BROWSER_POLICY_DENIED');
  if (headless === false && policy.headed !== true)
    return failJob(started, 'BROWSER_POLICY_DENIED');
  // Fail closed BEFORE allocating session state: without a usable runtime
  // create would mint a phantom handle (every later op denied). Managed
  // mode needs core + installed Chromium; existing-attach needs the core
  // library only (the browser lives elsewhere).
  try {
    await manager.coreApi();
  } catch {
    return failJob(started, 'BROWSER_RUNTIME_MISSING');
  }
  if (mode !== 'existing') {
    const rt = manager.paths();
    const rev = expectedChromiumRevision(rt.coreDir);
    if (!installedChromiumRevisions(rt.browsersDir).includes(rev))
      return failJob(started, 'BROWSER_INSTALLATION_MISSING');
  }
  try {
    const session = await manager.createSession(key, {
      mode,
      headless,
      viewport: parseViewport(p.viewport),
      locale: typeof p.locale === 'string' ? p.locale.slice(0, 32) : null,
      timezone: typeof p.timezone === 'string' ? p.timezone.slice(0, 64) : null,
      userAgent: typeof p.user_agent === 'string' ? p.user_agent.slice(0, 512) : null,
      profileId: typeof p.profile_id === 'string' ? p.profile_id : null,
      cdpEndpoint: typeof p.cdp_endpoint === 'string' ? p.cdp_endpoint : null,
      policy: {
        existingAttach: policy.existingAttach,
        headed: policy.headed,
        downloads: policy.downloads,
        network: policy.network
      },
      downloadsDir: null
    });
    if (session?.context) {
      await installContextEgressFilter(session.context, session);
    }
    const v = manager.versions();
    return okJob(
      started,
      {
        browser_id: key,
        default_context: key === DEFAULT_SESSION,
        mode: session.mode,
        headless: session.headless,
        playwright_version: v.playwright,
        browser_revision: v.revision,
        created: true
      },
      `Browser session ready (mode=${session.mode}, headless=${session.headless})`
    );
  } catch (e) {
    return failJob(
      started,
      mapBrowserError(e, 'navigate'),
      key !== DEFAULT_SESSION ? { browser_id: key } : {}
    );
  }
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserCloseJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const manager = getBrowserManager();
  const raw = p.browser_id ?? p.session_id;
  if (raw === undefined || raw === null || raw === '') {
    // Legacy close without a handle: release the default context.
    // F21: `closed` echoes the manager verdict (false when nothing existed),
    // so re-close reports closed:false exactly like existed:false.
    const r = await manager.closeSession(DEFAULT_SESSION, 'close');
    return okJob(started, { browser_id: r.sessionId || null, existed: r.existed, closed: r.closed });
  }
  if (typeof raw !== 'string' || !BID_RE.test(raw)) return failJob(started, 'INVALID_BROWSER_ID');
  const r = await manager.closeSession(raw, 'close');
  return okJob(started, { browser_id: raw, existed: r.existed, closed: r.closed });
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserNavigateJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const policy = policyFromJob(job);
  const manager = getBrowserManager();
  const timeoutMs = clampTimeout(p.timeout_ms, BROWSER_DEFAULTS.navigationTimeoutMs);
  let key = DEFAULT_SESSION;
  try {
    key = sessionKey(job);
  } catch {
    return failJob(started, 'INVALID_BROWSER_ID');
  }
  const gate = await checkUrl(p.url, policy);
  if (gate.ok === false)
    return failJob(started, gate.error, {
      ...(key !== DEFAULT_SESSION ? { browser_id: key } : {}),
      url: gate.url || null
    });
  try {
    let session = null;
    try {
      session = manager.requireSession(key);
    } catch {
      session = null;
    }
    if (!session) {
      session = await manager.createSession(key, {
        mode: 'managed',
        headless: p.headless !== false,
        viewport: parseViewport(p.viewport),
        policy: {
          existingAttach: policy.existingAttach,
          headed: policy.headed,
          downloads: policy.downloads,
          network: policy.network
        }
      });
    } else if (policy?.network) {
      session.policy = session.policy || {};
      session.policy.network = policy.network;
    }
    if (session?.context) {
      await installContextEgressFilter(session.context, session);
    }
    const s = session;
    return /** @type {Record<string, unknown>} */ (
      await s.enqueue(async () => {
        s.state = 'busy';
        try {
          const cur = s.currentPage();
          if (!cur) throw new Error('BROWSER_PAGE_NOT_FOUND');
          const { page } = manager.requirePage(s, cur.pageId);
          // A navigation that triggers a download aborts the document
          // commit: Playwright rejects goto even though the download was
          // captured. Treat captured-download as success, not failure.
          const dlBefore = s.downloads.length;
          let response = null;
          try {
            response = await page.goto(gate.url, {
              timeout: timeoutMs,
              waitUntil: 'domcontentloaded'
            });
          } catch (e) {
            if (s.downloads.length > dlBefore) {
              response = null;
            } else {
              throw Object.assign(new Error(mapBrowserError(e, 'navigate')), { cause: e });
            }
          }
          try {
            await page
              .waitForLoadState('load', { timeout: Math.min(5000, timeoutMs) })
              .catch(() => {});
            if (BROWSER_DEFAULTS.settleMs > 0)
              await page
                .waitForTimeout(Math.min(BROWSER_DEFAULTS.settleMs, timeoutMs))
                .catch(() => {});
          } catch {}
          let finalUrl = gate.url;
          let title = '';
          try {
            finalUrl = page.url();
          } catch {}
          try {
            title = await page.title();
          } catch {}
          const recheck = await checkUrl(finalUrl, policy);
          if (!recheck.ok) {
            try {
              await page.goto('about:blank').catch(() => {});
            } catch {}
            throw new Error('BROWSER_REDIRECT_DENIED');
          }
          s.pageRevision++;
          const rec = s.pages.get(cur.pageId);
          if (rec) {
            rec.url = finalUrl;
            rec.title = title;
          }
          s.state = 'ready';
          s.touch();
          const v = manager.versions();
          return okJob(
            started,
            {
              browser_id: key === DEFAULT_SESSION ? null : key,
              page_id: cur.pageId,
              page_revision: s.pageRevision,
              mode: s.mode,
              url: finalUrl,
              title,
              http_status: (() => {
                try {
                  return response ? response.status() : null;
                } catch {
                  return null;
                }
              })(),
              playwright_version: v.playwright,
              browser_revision: v.revision,
              downloads: s.downloads.length ? [...s.downloads] : []
            },
            `Navigated to ${finalUrl} ("${title}")`
          );
        } catch (e) {
          s.state = 'ready';
          const code = mapBrowserError(e, 'navigate');
          const errRec = /** @type {Record<string, unknown>|null} */ (
            e && typeof e === 'object' ? e : null
          );
          const detail =
            errRec && typeof errRec.detail === 'object' && errRec.detail !== null
              ? /** @type {Record<string, unknown>} */ (errRec.detail)
              : null;
          return failJob(started, code, {
            ...(key !== DEFAULT_SESSION ? { browser_id: key } : {}),
            url: auditProjectionUrl(String(p.url || '')),
            ...(detail ? { launch_detail: detail } : {})
          });
        }
      })
    );
  } catch (e) {
    const errRec = /** @type {Record<string, unknown>|null} */ (
      e && typeof e === 'object' ? e : null
    );
    const detail =
      errRec && typeof errRec.detail === 'object' && errRec.detail !== null
        ? /** @type {Record<string, unknown>} */ (errRec.detail)
        : null;
    return failJob(
      started,
      mapBrowserError(e, 'navigate'),
      key !== DEFAULT_SESSION
        ? { browser_id: key, ...(detail ? { launch_detail: detail } : {}) }
        : { ...(detail ? { launch_detail: detail } : {}) }
    );
  }
}

/**
 * @param {PWPage} page
 * @param {string} action
 * @param {PWLocator} locator
 * @param {string} value
 * @param {number} timeoutMs
 * @param {{dialogAccept?: boolean, promptText?: string}} [extra]
 */
async function runAction(page, action, locator, value, timeoutMs, extra = {}) {
  switch (action) {
    case 'click':
      await locator.click({ timeout: timeoutMs });
      return { clicked: true };
    case 'double_click':
      await locator.dblclick({ timeout: timeoutMs });
      return { clicked: true, double: true };
    case 'type':
      await locator.pressSequentially(value, { timeout: timeoutMs });
      return { typed_chars: value.length };
    case 'fill':
      await locator.fill(value, { timeout: timeoutMs });
      return { filled: true };
    case 'select': {
      const values = String(value)
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      await locator.selectOption(values.length > 1 ? values : values[0] || '', {
        timeout: timeoutMs
      });
      return { selected: values };
    }
    case 'check':
      await locator.check({ timeout: timeoutMs });
      return { checked: true };
    case 'uncheck':
      await locator.uncheck({ timeout: timeoutMs });
      return { checked: false };
    case 'press':
      await page.keyboard.press(value || 'Enter');
      return { key: value || 'Enter' };
    case 'hover':
      await locator.hover({ timeout: timeoutMs });
      return { hovered: true };
    case 'drag':
      throw new Error('BROWSER_DRAG_NEEDS_TARGET');
    case 'scroll_into_view':
      await locator.scrollIntoViewIfNeeded({ timeout: timeoutMs });
      return { scrolled: true };
    case 'wait_for':
      await locator.waitFor({ state: 'visible', timeout: timeoutMs });
      return { visible: true };
    case 'handle_dialog':
      throw new Error('BROWSER_DIALOG_DELEGATED');
    case 'evaluate':
      throw new Error('BROWSER_EVALUATE_DELEGATED');
    default:
      throw new Error(`UNSUPPORTED_INTERACT_ACTION: ${action}`);
  }
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserInteractJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const policy = policyFromJob(job);
  const manager = getBrowserManager();
  const action = String(p.action || 'click').toLowerCase();
  const timeoutMs = clampTimeout(
    p.timeout_ms,
    action === 'wait_for' ? 30000 : BROWSER_DEFAULTS.actionTimeoutMs
  );
  // Secret-bearing inputs are accepted for execution but never echoed: the
  // value stays out of results, stdout and audit (see browserAuditSummary).
  const value = String(p.value || '');
  let key = DEFAULT_SESSION;
  try {
    key = sessionKey(job);
  } catch {
    return failJob(started, 'INVALID_BROWSER_ID');
  }
  if (action === 'evaluate' && policy.scriptExec !== true) {
    return failJob(started, 'BROWSER_SCRIPT_EXEC_DENIED', {
      ...(key !== DEFAULT_SESSION ? { browser_id: key } : {})
    });
  }
  let session = null;
  try {
    session = manager.requireSession(key);
  } catch (e) {
    return failJob(started, mapBrowserError(e), key !== DEFAULT_SESSION ? { browser_id: key } : {});
  }
  const s = session;
  return /** @type {Record<string, unknown>} */ (
    await s.enqueue(async () => {
      s.state = 'busy';
      try {
        const targetRaw = assertBrowserTarget(p.target || p.selector);
        // handle_dialog and evaluate resolve their own targets.
        if (action === 'handle_dialog') {
          const pending = s.pendingDialog;
          if (!pending || !pending.dialog) {
            s.state = 'ready';
            return failJob(started, 'BROWSER_DIALOG_BLOCKED', {
              ...(key !== DEFAULT_SESSION ? { browser_id: key } : {})
            });
          }
          if (pending.timer) {
            try {
              clearTimeout(pending.timer);
            } catch {}
          }
          const accept = p.dialog_accept !== false;
          try {
            if (accept) await pending.dialog.accept(String(p.prompt_text || ''));
            else await pending.dialog.dismiss();
          } catch {
            throw new Error('BROWSER_DIALOG_BLOCKED');
          }
          s.pendingDialog = null;
          s.pageRevision++;
          s.state = 'ready';
          s.touch();
          return okJob(
            started,
            {
              browser_id: key === DEFAULT_SESSION ? null : key,
              page_revision: s.pageRevision,
              action,
              ok: true,
              target_ref: null
            },
            `Dialog ${accept ? 'accepted' : 'dismissed'}`
          );
        }
        if (action === 'evaluate') {
          const expr = assertEvaluateExpression(value || String(p.selector || ''));
          const cur = s.currentPage();
          if (!cur) throw new Error('BROWSER_PAGE_NOT_FOUND');
          let out = null;
          try {
            // Expression semantics: page.evaluate awaits a returned promise.
            out = await cur.page.evaluate(expr);
          } catch {
            throw new Error('BROWSER_EVALUATE_FAILED');
          }
          let text = '';
          try {
            text = JSON.stringify(out);
          } catch {
            text = String(out);
          }
          if (text === undefined) text = 'undefined';
          text = redactSecretText(text).slice(0, 8192);
          s.pageRevision++;
          s.state = 'ready';
          s.touch();
          return okJob(
            started,
            {
              browser_id: key === DEFAULT_SESSION ? null : key,
              page_id: cur.pageId,
              page_revision: s.pageRevision,
              action,
              ok: true,
              target_ref: null,
              value_preview: text.slice(0, 256)
            },
            'Expression evaluated (policy-gated)'
          );
        }
        if (!targetRaw) throw new Error('BROWSER_TARGET_NOT_FOUND');
        const resolved = await manager.resolveTarget(s, targetRaw, {});
        const { page } = manager.requirePage(s, resolved.pageId || '');
        if (action === 'drag') {
          const destRaw = value;
          if (!destRaw) throw new Error('BROWSER_DRAG_NEEDS_TARGET');
          const dest = await manager.resolveTarget(s, destRaw, {});
          try {
            await resolved.locator.dragTo(dest.locator, { timeout: timeoutMs });
          } catch (e) {
            throw Object.assign(new Error(mapBrowserError(e)), { cause: e });
          }
          s.pageRevision++;
          s.state = 'ready';
          s.touch();
          return okJob(
            started,
            {
              browser_id: key === DEFAULT_SESSION ? null : key,
              page_id: resolved.pageId,
              page_revision: s.pageRevision,
              action,
              ok: true,
              target_ref: /^e\d+$/.test(targetRaw) ? targetRaw : '[selector]'
            },
            `Action '${action}' executed`
          );
        }
        try {
          await runAction(page, action, resolved.locator, value, timeoutMs);
        } catch (e) {
          throw Object.assign(new Error(mapBrowserError(e)), { cause: e });
        }
        s.pageRevision++;
        s.state = 'ready';
        s.touch();
        const v = manager.versions();
        return okJob(
          started,
          {
            browser_id: key === DEFAULT_SESSION ? null : key,
            page_id: resolved.pageId,
            page_revision: s.pageRevision,
            action,
            ok: true,
            target_ref: /^e\d+$/.test(targetRaw) ? targetRaw : '[selector]',
            playwright_version: v.playwright,
            browser_revision: v.revision
          },
          `Action '${action}' executed`
        );
      } catch (e) {
        s.state = 'ready';
        return failJob(started, mapBrowserError(e), {
          ...(key !== DEFAULT_SESSION ? { browser_id: key } : {})
        });
      }
    })
  );
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserSnapshotJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const manager = getBrowserManager();
  let key = DEFAULT_SESSION;
  try {
    key = sessionKey(job);
  } catch {
    return failJob(started, 'INVALID_BROWSER_ID');
  }
  const type = String(p.type || 'accessibility').toLowerCase();
  let session = null;
  try {
    session = manager.requireSession(key);
  } catch (e) {
    return failJob(started, mapBrowserError(e), staleJobPayload(key, e));
  }
  const s = session;
  return /** @type {Record<string, unknown>} */ (
    await s.enqueue(async () => {
      s.state = 'busy';
      try {
        const cur = s.currentPage();
        if (!cur) throw new Error('BROWSER_PAGE_NOT_FOUND');
        if (type === 'html') {
          // Compatibility path: retained although the contract advertises
          // accessibility/text (see browser_snapshot description).
          let html = '';
          try {
            html = await cur.page.content();
          } catch {
            throw new Error('BROWSER_SNAPSHOT_FAILED');
          }
          const cap = Math.max(1024, Math.min(262144, Number(p.max_bytes || 65536)));
          const truncated = html.length > cap;
          s.state = 'ready';
          s.touch();
          return okJob(
            started,
            {
              browser_id: key === DEFAULT_SESSION ? null : key,
              page_id: cur.pageId,
              type: 'html',
              bytes: Math.min(html.length, cap),
              truncated,
              content: html.slice(0, cap)
            },
            'HTML snapshot captured'
          );
        }
        if (type === 'text') {
          let text = '';
          try {
            text = await cur.page.evaluate('document.body ? document.body.innerText : ""');
          } catch {
            throw new Error('BROWSER_SNAPSHOT_FAILED');
          }
          const cap = Math.max(1024, Math.min(262144, Number(p.max_bytes || 65536)));
          const content = redactSecretText(text).slice(0, cap);
          s.state = 'ready';
          s.touch();
          return okJob(
            started,
            {
              browser_id: key === DEFAULT_SESSION ? null : key,
              page_id: cur.pageId,
              type: 'text',
              bytes: content.length,
              truncated: text.length > cap,
              content
            },
            'Text snapshot captured'
          );
        }
        if (type !== 'accessibility') throw new Error('BROWSER_SNAPSHOT_FAILED');
        const maxChars = p.max_chars
          ? Math.max(1024, Math.min(100000, Number(p.max_chars)))
          : p.max_bytes
            ? Math.max(1024, Math.min(262144, Number(p.max_bytes)))
            : BROWSER_DEFAULTS.maxSnapshotChars;
        const snap = await manager.snapshot(s, {
          pageId: null,
          target: typeof p.target === 'string' ? p.target : null,
          depth: p.depth ? Math.max(1, Math.min(20, Number(p.depth))) : null,
          maxChars
        });
        s.state = 'ready';
        s.touch();
        const v = manager.versions();
        return okJob(
          started,
          {
            browser_id: key === DEFAULT_SESSION ? null : key,
            page_id: cur.pageId,
            url: snap.url,
            title: snap.title,
            snapshot_id: snap.snapshot_id,
            page_revision: snap.page_revision,
            truncated: snap.truncated,
            tree: snap.tree,
            playwright_version: v.playwright,
            browser_revision: v.revision
          },
          `Page: "${snap.title}" (${snap.url})`
        );
      } catch (e) {
        s.state = 'ready';
        return failJob(started, mapBrowserError(e), {
          ...(key !== DEFAULT_SESSION ? { browser_id: key } : {})
        });
      }
    })
  );
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserFindJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const manager = getBrowserManager();
  let key = DEFAULT_SESSION;
  try {
    key = sessionKey(job);
  } catch {
    return failJob(started, 'INVALID_BROWSER_ID');
  }
  let session = null;
  try {
    session = manager.requireSession(key);
  } catch (e) {
    return failJob(started, mapBrowserError(e), key !== DEFAULT_SESSION ? { browser_id: key } : {});
  }
  const s = session;
  return /** @type {Record<string, unknown>} */ (
    await s.enqueue(async () => {
      s.state = 'busy';
      try {
        const found = await manager.find(s, {
          text:
            typeof p.text === 'string'
              ? p.text
              : typeof p.query === 'string'
                ? p.query
                : typeof p.target === 'string'
                  ? p.target
                  : null,
          regex: typeof p.regex === 'string' ? p.regex : null,
          maxResults: p.max_results ? Number(p.max_results) : 10
        });
        const cur = s.currentPage();
        s.state = 'ready';
        s.touch();
        return okJob(
          started,
          {
            browser_id: key === DEFAULT_SESSION ? null : key,
            page_id: cur?.pageId || null,
            page_revision: found.page_revision,
            snapshot_id: found.snapshot_id,
            url: found.url,
            title: found.title,
            matches: found.matches,
            truncated: found.truncated
          },
          `${found.matches.length} match(es)${found.truncated ? ' (truncated)' : ''}`
        );
      } catch (e) {
        s.state = 'ready';
        return failJob(started, mapBrowserError(e), {
          ...(key !== DEFAULT_SESSION ? { browser_id: key } : {})
        });
      }
    })
  );
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserTabsJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const policy = policyFromJob(job);
  const manager = getBrowserManager();
  const action = String(p.action || 'list').toLowerCase();
  let key = DEFAULT_SESSION;
  try {
    key = sessionKey(job);
  } catch {
    return failJob(started, 'INVALID_BROWSER_ID');
  }
  if (!['list', 'new', 'select', 'close'].includes(action))
    return failJob(started, 'BROWSER_UNSUPPORTED_MODE');
  let session = null;
  try {
    session = manager.requireSession(key);
  } catch (e) {
    return failJob(started, mapBrowserError(e), staleJobPayload(key, e));
  }
  const s = session;
  return /** @type {Record<string, unknown>} */ (
    await s.enqueue(async () => {
      s.state = 'busy';
      try {
        if (action === 'new') {
          const url = typeof p.url === 'string' && p.url ? p.url : null;
          if (url) {
            const gate = await checkUrl(url, policy);
            if (gate.ok === false) throw new Error(gate.error || 'URL_EGRESS_DENIED');
          }
          const made = await manager.newPage(s, url);
          try {
            const rec = s.pages.get(made.pageId);
            if (rec) {
              try {
                rec.url = made.page.url();
              } catch {}
              try {
                rec.title = await made.page.title();
              } catch {}
            }
          } catch {}
          s.pageRevision++;
        } else if (action === 'select') {
          const pid = String(p.page_id || '');
          if (!s.pages.has(pid)) throw new Error('BROWSER_PAGE_NOT_FOUND');
          s.currentPageId = pid;
          s.pageRevision++;
        } else if (action === 'close') {
          const pid = String(p.page_id || '');
          const rec = pid ? s.pages.get(pid) : null;
          if (!rec) throw new Error('BROWSER_PAGE_NOT_FOUND');
          if (s.pages.size <= 1) throw new Error('BROWSER_PAGE_NOT_FOUND');
          try {
            await rec.page.close();
          } catch {}
          s.pages.delete(pid);
          s.cdpSessions.delete(pid);
          if (s.currentPageId === pid) s.currentPageId = null;
          s.pageRevision++;
        }
        const pages = [];
        for (const [pid, rec] of s.pages) {
          let url = rec.url;
          let title = rec.title;
          try {
            url = rec.page.url();
          } catch {}
          try {
            title = await rec.page.title();
          } catch {}
          pages.push({ page_id: pid, url, title });
        }
        const cur = s.currentPage();
        s.state = 'ready';
        s.touch();
        return okJob(
          started,
          {
            browser_id: key === DEFAULT_SESSION ? null : key,
            current_page_id: cur?.pageId || null,
            page_revision: s.pageRevision,
            pages
          },
          `${pages.length} tab(s)`
        );
      } catch (e) {
        s.state = 'ready';
        return failJob(started, mapBrowserError(e), {
          ...(key !== DEFAULT_SESSION ? { browser_id: key } : {})
        });
      }
    })
  );
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserScreenshotJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const manager = getBrowserManager();
  let key = DEFAULT_SESSION;
  try {
    key = sessionKey(job);
  } catch {
    return failJob(started, 'INVALID_BROWSER_ID');
  }
  const format = String(p.format || 'png').toLowerCase() === 'jpeg' ? 'jpeg' : 'png';
  const fullPage = p.full_page === true;
  const budget = Math.max(
    1024,
    Math.min(262144, Number(p.max_bytes || BROWSER_DEFAULTS.maxScreenshotBytes))
  );
  let session = null;
  try {
    session = manager.requireSession(key);
  } catch (e) {
    return failJob(started, mapBrowserError(e), key !== DEFAULT_SESSION ? { browser_id: key } : {});
  }
  const s = session;
  return /** @type {Record<string, unknown>} */ (
    await s.enqueue(async () => {
      s.state = 'busy';
      try {
        const targetRaw = assertBrowserTarget(p.target);
        if (targetRaw && fullPage) throw new Error('BROWSER_SCREENSHOT_CONFLICT');
        const { page } = manager.requirePage(s, '');
        /**
         * @param {'png'|'jpeg'} fmt
         * @param {number} [quality]
         */
        const shot = async (fmt, quality) => {
          /** @type {Record<string, any>} */
          const opts = { type: fmt, fullPage };
          if (fmt === 'jpeg' && quality) opts.quality = quality;
          if (targetRaw) {
            const resolved = await manager.resolveTarget(s, targetRaw, {});
            return resolved.locator.screenshot(opts);
          }
          return page.screenshot(opts);
        };
        let buf = null;
        let usedFormat = format;
        try {
          buf = await shot(format);
        } catch {
          throw new Error('BROWSER_SCREENSHOT_FAILED');
        }
        let b64 = Buffer.from(buf).toString('base64');
        let truncated = false;
        if (b64.length > budget && format === 'png') {
          try {
            const retry = await shot('jpeg', 60);
            const r64 = Buffer.from(retry).toString('base64');
            if (r64.length < b64.length) {
              buf = retry;
              b64 = r64;
              usedFormat = 'jpeg';
            }
          } catch {}
        }
        // SYN-BRW-001: persist over-budget captures as retrievable artifacts
        // instead of destroying the evidence. The model fetches bytes via
        // file_read; session close sweeps the directory.
        let artifactPath = null;
        let originalBytes = b64.length;
        if (b64.length > budget) {
          truncated = true;
          originalBytes = b64.length;
          const stored = storeScreenshotArtifact({
            downloadsRoot: manager.paths().downloadsDir,
            sessionKey: key,
            bytes: Buffer.from(buf),
            ext: usedFormat === 'jpeg' ? 'jpg' : 'png'
          });
          if (stored.ok) artifactPath = stored.artifact_path;
          b64 = '';
        }
        const cur = s.currentPage();
        s.state = 'ready';
        s.touch();
        return okJob(
          started,
          {
            browser_id: key === DEFAULT_SESSION ? null : key,
            page_id: cur?.pageId || null,
            format: usedFormat,
            bytes: originalBytes,
            truncated,
            base64: b64 || null,
            artifact_path: artifactPath
          },
          truncated
            ? artifactPath
              ? 'Screenshot exceeded budget (stored as artifact)'
              : 'Screenshot exceeded budget (truncated)'
            : 'Screenshot captured'
        );
      } catch (e) {
        s.state = 'ready';
        return failJob(started, mapBrowserError(e), {
          ...(key !== DEFAULT_SESSION ? { browser_id: key } : {})
        });
      }
    })
  );
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserConsoleJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const manager = getBrowserManager();
  let key = DEFAULT_SESSION;
  try {
    key = sessionKey(job);
  } catch {
    return failJob(started, 'INVALID_BROWSER_ID');
  }
  const level = String(p.level || 'info').toLowerCase();
  const rank = CONSOLE_SEVERITY[level] !== undefined ? CONSOLE_SEVERITY[level] : 2;
  const limit = Math.max(1, Math.min(500, Number(p.limit || 100)));
  const cursor = Math.max(0, Number(p.cursor || 0));
  let session = null;
  try {
    session = manager.requireSession(key);
  } catch (e) {
    return failJob(started, mapBrowserError(e), key !== DEFAULT_SESSION ? { browser_id: key } : {});
  }
  const messages = session.console
    .filter((m) => (CONSOLE_SEVERITY[m.type] ?? 3) <= rank && m.seq > cursor)
    .slice(-limit);
  session.touch();
  return okJob(started, {
    browser_id: key === DEFAULT_SESSION ? null : key,
    cursor: session.consoleSeq,
    messages
  });
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserNetworkJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const manager = getBrowserManager();
  let key = DEFAULT_SESSION;
  try {
    key = sessionKey(job);
  } catch {
    return failJob(started, 'INVALID_BROWSER_ID');
  }
  if (typeof p.filter === 'string' && p.filter) {
    try {
      // P3-D3: sync test() has no timeout; reject nested-quantifier
      // patterns that backtrack exponentially (fail closed, same code).
      void new RegExp(assertSafeRegexPattern(p.filter));
    } catch {
      return failJob(started, 'BROWSER_FILTER_INVALID');
    }
  }
  let session = null;
  try {
    session = manager.requireSession(key);
  } catch (e) {
    return failJob(started, mapBrowserError(e), key !== DEFAULT_SESSION ? { browser_id: key } : {});
  }
  if (p.include_static === true) session.includeStatic = true;
  const limit = Math.max(1, Math.min(500, Number(p.limit || 100)));
  const cursor = Math.max(0, Number(p.cursor || 0));
  const re = typeof p.filter === 'string' && p.filter ? new RegExp(p.filter) : null;
  const requests = session.network
    .filter((r) => r.seq > cursor && (!re || re.test(r.url)))
    .slice(-limit);
  session.touch();
  return okJob(started, {
    browser_id: key === DEFAULT_SESSION ? null : key,
    cursor: session.networkSeq,
    requests
  });
}

/**
 * @param {unknown} job
 * @returns {Promise<Record<string, any>>}
 */
export async function browserUploadJob(job) {
  const started = Date.now();
  const p = jobPayload(job);
  const policy = policyFromJob(job);
  const manager = getBrowserManager();
  let key = DEFAULT_SESSION;
  try {
    key = sessionKey(job);
  } catch {
    return failJob(started, 'INVALID_BROWSER_ID');
  }
  if (policy.uploads !== true) {
    return failJob(started, 'BROWSER_UPLOAD_DENIED', {
      ...(key !== DEFAULT_SESSION ? { browser_id: key } : {}),
      deny_reason: 'policy-uploads-off',
      policy_present: policy.present === true
    });
  }
  const paths = Array.isArray(p.paths) ? p.paths : [];
  if (paths.length < 1 || paths.length > 10)
    return failJob(started, 'BROWSER_UPLOAD_DENIED', {
      ...(key !== DEFAULT_SESSION ? { browser_id: key } : {}),
      deny_reason: 'paths-empty-or-too-many',
      paths_count: paths.length
    });
  let session = null;
  try {
    session = manager.requireSession(key);
  } catch (e) {
    return failJob(started, mapBrowserError(e), key !== DEFAULT_SESSION ? { browser_id: key } : {});
  }
  const s = session;
  return /** @type {Record<string, unknown>} */ (
    await s.enqueue(async () => {
      s.state = 'busy';
      try {
        const resolvedFiles = [];
        for (const candidate of paths) {
          const r = resolveUploadPath(
            candidate,
            policy.readRoots,
            s.downloadsDir || manager.paths().downloadsDir,
            policy.allowAll === true
          );
          if (!r.ok) throw new Error('BROWSER_UPLOAD_DENIED');
          resolvedFiles.push(r);
        }
        const targetRaw = assertBrowserTarget(p.target);
        const { page } = manager.requirePage(s, '');
        if (targetRaw) {
          const resolved = await manager.resolveTarget(s, targetRaw, {});
          try {
            await resolved.locator.setInputFiles(resolvedFiles.map((f) => f.path));
          } catch {
            throw new Error('BROWSER_UPLOAD_FAILED');
          }
        } else {
          let count = 0;
          try {
            count = await page.locator('input[type=file]').count();
          } catch {}
          if (count !== 1) throw new Error('BROWSER_TARGET_NOT_FOUND');
          try {
            await page
              .locator('input[type=file]')
              .first()
              .setInputFiles(resolvedFiles.map((f) => f.path));
          } catch {
            throw new Error('BROWSER_UPLOAD_FAILED');
          }
        }
        s.pageRevision++;
        s.state = 'ready';
        s.touch();
        return okJob(
          started,
          {
            browser_id: key === DEFAULT_SESSION ? null : key,
            uploaded: resolvedFiles.map((f) => ({
              path: f.path,
              filename: f.path.split(/[\\/]/).pop(),
              size_bytes: f.size
            }))
          },
          `${resolvedFiles.length} file(s) uploaded`
        );
      } catch (e) {
        s.state = 'ready';
        return failJob(started, mapBrowserError(e), {
          ...(key !== DEFAULT_SESSION ? { browser_id: key } : {})
        });
      }
    })
  );
}

/**
 * Full launch validation used by the client health gate and installer/OTA.
 * @param {{coreDir?: string, browsersDir?: string}} [options]
 */
export async function browserHealthJob(options = {}) {
  const started = Date.now();
  const manager = getBrowserManager();
  const coreDir = options.coreDir || manager.paths().coreDir;
  const browsersDir = options.browsersDir || manager.paths().browsersDir;
  const probe = await validateBrowserLaunch({ coreDir, browsersDir, headless: true });
  if (!probe.ok) return failJob(started, probe.error || 'BROWSER_NOT_AVAILABLE');
  return okJob(started, {
    available: true,
    playwright: probe.playwright,
    revision: probe.revision,
    duration_ms: probe.duration_ms
  });
}
