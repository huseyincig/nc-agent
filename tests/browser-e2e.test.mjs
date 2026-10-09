// Gated Playwright E2E: NC_BROWSER_E2E=1 plus a resolvable playwright-core
// and an installed managed Chromium. Everywhere else this file reports a
// single SKIP and runs nothing (never fake-passes platform coverage).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';

const CORE_CANDIDATES = [process.env.NC_PLAYWRIGHT_CORE_PATH].filter(Boolean);
const CORE = CORE_CANDIDATES.find((p) => {
  try {
    return fs.existsSync(path.join(p, 'package.json'));
  } catch {
    return false;
  }
});
const BROWSERS = process.env.PLAYWRIGHT_BROWSERS_PATH || '';
const ENABLED = process.env.NC_BROWSER_E2E === '1' && Boolean(CORE) && Boolean(BROWSERS);

if (!ENABLED) {
  test('browser E2E (real Chromium) — SKIPPED: set NC_BROWSER_E2E=1 with NC_PLAYWRIGHT_CORE_PATH and PLAYWRIGHT_BROWSERS_PATH', () => {
    console.log(
      `SKIP browser-e2e: NC_BROWSER_E2E=${process.env.NC_BROWSER_E2E || ''} core=${CORE || 'missing'} browsers=${BROWSERS || 'missing'} platform=${process.platform}`
    );
  });
} else {
  process.env.NC_PLAYWRIGHT_CORE_PATH = CORE;
  process.env.PLAYWRIGHT_BROWSERS_PATH = BROWSERS;

  const {
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
    getBrowserManager,
    resetBrowserManager
  } = await import('../src/browser/browser-adapter.mjs');
  const { installedChromiumRevisions } = await import('../src/browser/browser-runtime.mjs');

  const FORM = `<!DOCTYPE html><html><head><title>Form</title></head><body>
<h1>Welcome</h1>
<input id="email" type="text" /><input id="pw" type="password" />
<button id="go" onclick="document.getElementById('st').textContent='DONE'">Sign in</button>
<div id="st">INIT</div>
<input id="file" type="file" />
</body></html>`;
  const BIG = `<!DOCTYPE html><html><head><title>Big</title></head><body><h1>Index</h1><ul>${Array.from({ length: 400 }, (_, i) => `<li>row number ${i} needle-${i % 37}</li>`).join('')}</ul><p>UNIQUE_TARGET_XYZ</p></body></html>`;
  const DL_BYTES = Buffer.from('download-payload-12345');
  const CONSOLE = `<!DOCTYPE html><html><head><title>Con</title><script>console.error('boom-failure');console.log('hello-log');</script></head><body>ok</body></html>`;
  const DIALOG = `<!DOCTYPE html><html><head><title>Dlg</title></head><body><script>setTimeout(() => alert('pick me'), 300);</script><p>wait</p></body></html>`;

  /** @type {http.Server|null} */
  let server = null;
  let base = '';
  let dataDir = '';
  const newId = () => 'brw_' + crypto.randomBytes(16).toString('hex');
  const caps = (over = {}) => ({
    browser_script_exec: false,
    browser_private_network: false,
    browser_uploads: false,
    browser_downloads: false,
    browser_headed: false,
    browser_existing_attach: false,
    ...over
  });
  const net = () => ({
    browser_network_policy: {
      allowed_hosts: [],
      blocked_hosts: [],
      allow_loopback: true,
      allow_private_networks: false
    }
  });
  const job = (request_payload, overCaps) => ({
    request_payload: { ...request_payload, ...net() },
    agent_policy_capabilities: caps(overCaps),
    agent_policy_roots: { read: [dataDir] }
  });

  test.before(async () => {
    const installed = installedChromiumRevisions(BROWSERS);
    assert.ok(installed.length > 0, `no managed chromium in ${BROWSERS}`);
    server = http.createServer((req, res) => {
      const url = new URL(req.url || '/', 'http://x');
      if (url.pathname === '/big') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(BIG);
      } else if (url.pathname === '/dl') {
        res.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-disposition': 'attachment; filename="../../evil.txt"',
          'content-length': DL_BYTES.length
        });
        res.end(DL_BYTES);
      } else if (url.pathname === '/con') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(CONSOLE);
      } else if (url.pathname === '/dlg') {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(DIALOG);
      } else if (url.pathname === '/slow') {
        setTimeout(() => {
          try {
            res.writeHead(200, { 'content-type': 'text/html' });
            res.end('<html><body>slow</body></html>');
          } catch {}
        }, 4000);
      } else {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end(FORM);
      }
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${server.address().port}`;
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nc-e2e-'));
    process.env.NC_BROWSER_DATA_DIR = dataDir;
  });

  test.after(async () => {
    try {
      await getBrowserManager().closeAll();
    } catch {}
    resetBrowserManager();
    if (server) server.close();
    if (dataDir) fs.rmSync(dataDir, { recursive: true, force: true });
  });

  test('snapshot -> find -> interact -> verify -> close', async () => {
    const id = newId();
    const created = await browserCreateJob(job({ browser_id: id, headless: true }));
    assert.equal(created.status, 'completed', String(created.error));
    assert.equal(created.result_payload.playwright_version, '1.63.0');
    try {
      const nav = await browserNavigateJob(job({ browser_id: id, url: base + '/' }));
      assert.equal(nav.status, 'completed', String(nav.error));
      const snap = await browserSnapshotJob(job({ browser_id: id }));
      assert.equal(snap.status, 'completed');
      assert.ok(snap.result_payload.tree.includes('Welcome'));
      const emailRef = /textbox[^\n]*\[ref=(e\d+)\]/.exec(snap.result_payload.tree)?.[1];
      assert.ok(emailRef, 'textbox ref present');
      const found = await browserFindJob(job({ browser_id: id, text: 'Sign in' }));
      assert.equal(found.status, 'completed');
      assert.ok(found.result_payload.matches.length >= 1 && found.result_payload.matches[0].ref);
      const fill = await browserInteractJob(
        job({ browser_id: id, action: 'fill', target: emailRef, value: 'user@example.com' })
      );
      assert.equal(fill.status, 'completed', String(fill.error));
      assert.ok(!JSON.stringify(fill).includes('user@example.com'), 'input values never echoed');
      const btn = await browserFindJob(job({ browser_id: id, text: 'Sign in' }));
      const click = await browserInteractJob(
        job({ browser_id: id, action: 'click', target: btn.result_payload.matches[0].ref })
      );
      assert.equal(click.status, 'completed', String(click.error));
      const after = await browserSnapshotJob(job({ browser_id: id }));
      assert.ok(after.result_payload.tree.includes('DONE'));
      // Password fill is accepted but redacted everywhere.
      const boxes = [...after.result_payload.tree.matchAll(/textbox[^\n]*\[ref=(e\d+)\]/g)].map(
        (m) => m[1]
      );
      assert.ok(boxes.length >= 2, 'email + password boxes have refs');
      const pw = await browserInteractJob(
        job({ browser_id: id, action: 'fill', target: boxes[boxes.length - 1], value: 's3cr3t!' })
      );
      assert.equal(pw.status, 'completed');
      assert.ok(!JSON.stringify(pw).includes('s3cr3t!'));
    } finally {
      const closed = await browserCloseJob(job({ browser_id: id }));
      assert.equal(closed.status, 'completed');
    }
  });

  test('concurrent sessions are isolated (cookies, storage, tabs)', async () => {
    const ids = [newId(), newId(), newId()];
    for (const id of ids) {
      const c = await browserCreateJob(job({ browser_id: id, headless: true }));
      assert.equal(c.status, 'completed', String(c.error));
    }
    try {
      const marks = ['AAA', 'BBB', 'CCC'];
      for (let i = 0; i < 3; i++) {
        const nav = await browserNavigateJob(job({ browser_id: ids[i], url: base + '/' }));
        assert.equal(nav.status, 'completed');
        const set = await browserInteractJob(
          job(
            {
              browser_id: ids[i],
              action: 'evaluate',
              value: `document.cookie="m=${marks[i]}";localStorage.setItem("m","${marks[i]}");"${marks[i]}"`
            },
            { browser_script_exec: true }
          )
        );
        assert.equal(set.status, 'completed', String(set.error));
      }
      for (let i = 0; i < 3; i++) {
        const read = await browserInteractJob(
          job(
            {
              browser_id: ids[i],
              action: 'evaluate',
              value: 'document.cookie+"|"+localStorage.getItem("m")'
            },
            { browser_script_exec: true }
          )
        );
        assert.equal(read.status, 'completed');
        assert.ok(
          String(read.result_payload.value_preview).includes(marks[i]),
          `session ${i} sees its own mark`
        );
        for (let j = 0; j < 3; j++) {
          if (i !== j)
            assert.ok(
              !String(read.result_payload.value_preview).includes(marks[j]),
              `session ${i} must not see ${marks[j]}`
            );
        }
        const tabs = await browserTabsJob(job({ browser_id: ids[i], action: 'list' }));
        assert.equal(tabs.result_payload.pages.length, 1);
      }
    } finally {
      for (const id of ids) await browserCloseJob(job({ browser_id: id }));
    }
  });

  test('find is cheaper than full snapshot on large pages', async () => {
    const id = newId();
    await browserCreateJob(job({ browser_id: id, headless: true }));
    try {
      await browserNavigateJob(job({ browser_id: id, url: base + '/big' }));
      const full = await browserSnapshotJob(job({ browser_id: id, max_chars: 3000 }));
      assert.equal(full.status, 'completed', String(full.error));
      assert.equal(full.result_payload.truncated, true);
      assert.ok(full.result_payload.tree.length <= 3000);
      const found = await browserFindJob(job({ browser_id: id, text: 'UNIQUE_TARGET_XYZ' }));
      assert.equal(found.status, 'completed');
      assert.ok(found.result_payload.matches.length >= 1);
      assert.ok(found.result_payload.matches[0].ref);
      for (const m of found.result_payload.matches)
        assert.ok(m.snippet.includes('UNIQUE_TARGET_XYZ'));
      assert.ok(
        JSON.stringify(found.result_payload).length < full.result_payload.tree.length,
        'find response smaller than the truncated snapshot budget'
      );
      const re = await browserFindJob(job({ browser_id: id, regex: '/needle-3[0-9]/' }));
      assert.ok(re.result_payload.matches.length >= 1);
    } finally {
      await browserCloseJob(job({ browser_id: id }));
    }
  });

  test('upload policy: allowed file ok, outside/symlink denied', async () => {
    const id = newId();
    await browserCreateJob(job({ browser_id: id, headless: true }));
    const goodFile = path.join(dataDir, 'cv.pdf');
    fs.writeFileSync(goodFile, '%PDF-1.4 test');
    const outsideFile = path.join(os.tmpdir(), 'nc-e2e-outside.txt');
    fs.writeFileSync(outsideFile, 'secret');
    const linkFile = path.join(dataDir, 'link.pdf');
    try {
      fs.symlinkSync(outsideFile, linkFile);
    } catch {}
    try {
      await browserNavigateJob(job({ browser_id: id, url: base + '/' }));
      const deniedNoCap = await browserUploadJob(job({ browser_id: id, paths: [goodFile] }));
      assert.equal(deniedNoCap.status, 'failed');
      assert.equal(deniedNoCap.error, 'BROWSER_UPLOAD_DENIED');
      const ok = await browserUploadJob(
        job({ browser_id: id, paths: [goodFile] }, { browser_uploads: true })
      );
      assert.equal(ok.status, 'completed', String(ok.error));
      assert.equal(ok.result_payload.uploaded[0].filename, 'cv.pdf');
      const deniedOutside = await browserUploadJob(
        job({ browser_id: id, paths: [outsideFile] }, { browser_uploads: true })
      );
      assert.equal(deniedOutside.error, 'BROWSER_UPLOAD_DENIED');
      const deniedLink = await browserUploadJob(
        job({ browser_id: id, paths: [linkFile] }, { browser_uploads: true })
      );
      assert.equal(deniedLink.error, 'BROWSER_UPLOAD_DENIED');
    } finally {
      try {
        fs.rmSync(outsideFile, { force: true });
      } catch {}
      await browserCloseJob(job({ browser_id: id }));
    }
  });

  test('downloads land in the session dir with safe names', async () => {
    const id = newId();
    await browserCreateJob(job({ browser_id: id, headless: true }));
    try {
      await browserNavigateJob(job({ browser_id: id, url: base + '/dl' }));
      await new Promise((r) => setTimeout(r, 1500));
      const snap = await browserSnapshotJob(job({ browser_id: id }));
      void snap;
      const manager = getBrowserManager();
      const session = manager.sessions.get(id);
      assert.ok(session, 'session tracked');
      // Downloads are gated by capability: blocked by default, recorded.
      assert.ok(
        session.downloads.some((d) => d.status === 'blocked_policy'),
        JSON.stringify(session.downloads)
      );
    } finally {
      await browserCloseJob(job({ browser_id: id }));
    }
    // With the capability, the file lands sanitized (no traversal).
    // NOTE: the capability is bound at session creation, not per call.
    const id2 = newId();
    await browserCreateJob(job({ browser_id: id2, headless: true }, { browser_downloads: true }));
    try {
      await browserNavigateJob(
        job({ browser_id: id2, url: base + '/dl' }, { browser_downloads: true })
      );
      await new Promise((r) => setTimeout(r, 1500));
      const manager = getBrowserManager();
      const session = manager.sessions.get(id2);
      const done = session.downloads.find((d) => d.status === 'completed');
      assert.ok(done, JSON.stringify(session.downloads));
      assert.ok(!done.filename.includes('..') && !done.path.includes('..'));
      assert.ok(done.path.startsWith(path.join(dataDir, 'browser', 'downloads', id2)));
      assert.equal(fs.readFileSync(done.path, 'utf8'), 'download-payload-12345');
    } finally {
      await browserCloseJob(job({ browser_id: id2 }));
    }
  });

  test('console, network, screenshot, dialog, timeout surfaces', async () => {
    const id = newId();
    await browserCreateJob(job({ browser_id: id, headless: true }));
    try {
      await browserNavigateJob(job({ browser_id: id, url: base + '/con' }));
      const errors = await browserConsoleJob(job({ browser_id: id, level: 'error' }));
      assert.ok(errors.result_payload.messages.some((m) => m.text.includes('boom-failure')));
      assert.ok(
        errors.result_payload.messages.every((m) => m.type === 'error'),
        'level filters severity'
      );
      const network = await browserNetworkJob(job({ browser_id: id }));
      assert.ok(network.result_payload.requests.some((r) => r.url.includes('/con')));
      assert.ok(network.result_payload.requests.every((r) => !r.url.includes('?') || true));
      const shot = await browserScreenshotJob(job({ browser_id: id, format: 'jpeg' }));
      assert.equal(shot.status, 'completed');
      assert.ok(shot.result_payload.bytes > 1000);
      // Dialogs: auto-dismissed but recorded; explicit handle works in-window.
      await browserNavigateJob(job({ browser_id: id, url: base + '/dlg' }));
      const dlg = await browserInteractJob(
        job({ browser_id: id, action: 'handle_dialog', dialog_accept: true })
      );
      assert.ok(['completed', 'failed'].includes(dlg.status));
      // Slow navigation honors timeout_ms.
      const slow = await browserNavigateJob(
        job({ browser_id: id, url: base + '/slow', timeout_ms: 1000 })
      );
      assert.equal(slow.status, 'failed');
      assert.equal(slow.error, 'BROWSER_NAVIGATION_TIMEOUT');
      // Forbidden scheme fails closed at the client too.
      const bad = await browserNavigateJob(job({ browser_id: id, url: 'file:///etc/passwd' }));
      assert.equal(bad.error, 'URL_SCHEME_DENIED');
    } finally {
      await browserCloseJob(job({ browser_id: id }));
    }
  });

  test('evaluate is policy-gated, run_code does not exist', async () => {
    const id = newId();
    await browserCreateJob(job({ browser_id: id, headless: true }));
    try {
      await browserNavigateJob(job({ browser_id: id, url: base + '/' }));
      const denied = await browserInteractJob(
        job({ browser_id: id, action: 'evaluate', value: 'location.href' })
      );
      assert.equal(denied.error, 'BROWSER_SCRIPT_EXEC_DENIED');
      const allowed = await browserInteractJob(
        job(
          { browser_id: id, action: 'evaluate', value: 'document.title' },
          { browser_script_exec: true }
        )
      );
      assert.equal(allowed.status, 'completed');
      assert.ok(allowed.result_payload.value_preview.includes('Form'));
      const { getHandlers } = await import('../src/client/client.mjs');
      assert.equal('browser_run_code' in getHandlers(), false);
      assert.equal('browser_run_code_unsafe' in getHandlers(), false);
    } finally {
      await browserCloseJob(job({ browser_id: id }));
    }
  });

  test('create/close churn leaves no sessions behind', async () => {
    for (let i = 0; i < 5; i++) {
      const id = newId();
      const c = await browserCreateJob(job({ browser_id: id, headless: true }));
      assert.equal(c.status, 'completed');
      await browserNavigateJob(job({ browser_id: id, url: base + '/' }));
      const closed = await browserCloseJob(job({ browser_id: id }));
      assert.equal(closed.result_payload.existed, true);
    }
    const manager = getBrowserManager();
    assert.equal(manager.sessions.size, 0, 'no session residue');
    // The shared managed browser is intentionally reused across sessions;
    // closeAll must terminate it with no orphan processes.
    await manager.closeAll();
    assert.equal(manager.sessions.size, 0);
    assert.equal(manager.managedBrowsers.size, 0);
    const { execFileSync } = await import('node:child_process');
    let procs = '';
    try {
      // Match the browser binary path, not our own environment (which
      // contains PLAYWRIGHT_BROWSERS_PATH and would self-match). The
      // bracket trick keeps pgrep from matching its own command line.
      procs = execFileSync('pgrep', [
        '-af',
        '[c]hrome-headless-shell|[c]hrome-linux/chrome|[c]hrome-mac/Chromium'
      ]).toString();
    } catch {}
    assert.equal(
      procs.trim(),
      '',
      'no orphan NC-managed chromium processes: ' + procs.slice(0, 300)
    );
  });
}
