import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  redactSecretText,
  resolveUploadPath,
  policyFromJob,
  browserAuditSummary,
  getBrowserManager,
  resetBrowserManager,
  CONSOLE_SEVERITY
} from '../src/browser/browser-manager.mjs';
import { validateEgressUrl, matchHostList } from '../src/policy/egress-policy.mjs';
import {
  HOST_POLICY_CAPABILITIES,
  BROWSER_POLICY_V2_FEATURE,
  requiredCapabilitiesForOperation
} from '../src/policy/host-policy.mjs';
import {
  browserNavigateJob,
  browserInteractJob,
  browserSnapshotJob,
  browserCreateJob,
  browserCloseJob,
  browserFindJob,
  browserTabsJob,
  findSystemBrowser
} from '../src/browser/browser-adapter.mjs';

test('secret redaction covers tokens, handles, credentials and keys', () => {
  const token = 'nc_' + 'a'.repeat(64);
  const brw = 'brw_' + 'b'.repeat(32);
  const out = redactSecretText(`login ${token} handle ${brw} Bearer abcDEF123456 password=hunter2`);
  assert.ok(!out.includes(token));
  assert.ok(!out.includes(brw));
  assert.ok(!out.includes('hunter2'));
  assert.ok(out.includes('[REDACTED]'));
});

test('upload paths enforce allowlist, symlinks and traversal', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nc-upload-'));
  const allowed = path.join(dir, 'allowed.txt');
  const outside = path.join(os.tmpdir(), 'nc-upload-outside.txt');
  fs.writeFileSync(allowed, 'ok');
  fs.writeFileSync(outside, 'nope');
  const link = path.join(dir, 'link.txt');
  try {
    fs.symlinkSync(outside, link);
  } catch {}
  const dl = path.join(dir, 'downloads');
  fs.mkdirSync(dl);
  try {
    assert.equal(resolveUploadPath(allowed, [dir], dl).ok, true);
    assert.equal(resolveUploadPath('relative.txt', [dir], dl).ok, false);
    assert.equal(resolveUploadPath(path.join(dir, '..', 'nc-upload-outside.txt'), [dir], dl).ok, false);
    assert.equal(resolveUploadPath(outside, [dir], dl).ok, false);
    assert.equal(resolveUploadPath(link, [dir], dl).ok, false);
    const dlFile = path.join(dl, 'report.pdf');
    fs.writeFileSync(dlFile, 'x');
    assert.equal(resolveUploadPath(dlFile, [], dl).ok, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
    try {
      fs.rmSync(outside, { force: true });
    } catch {}
  }
});

test('host lists and loopback flags gate egress', async () => {
  const resolvePublic = async () => ['93.184.216.34'];
  const resolveLoop = async () => ['127.0.0.1'];
  assert.equal(
    (await validateEgressUrl('https://example.com/', { blockedHosts: ['example.com'], resolve: resolvePublic })).error,
    'URL_HOST_DENIED'
  );
  assert.equal(
    (await validateEgressUrl('https://other.com/', { allowedHosts: ['example.com'], resolve: resolvePublic })).error,
    'URL_HOST_DENIED'
  );
  assert.equal(
    (await validateEgressUrl('http://127.0.0.1/', { resolve: resolveLoop })).error,
    'URL_ADDRESS_DENIED'
  );
  assert.equal(
    (await validateEgressUrl('http://127.0.0.1/', { allowLoopback: true, resolve: resolveLoop })).ok,
    true
  );
  assert.equal(matchHostList('sub.example.com', ['example.com']), true);
  assert.equal(matchHostList('example.com.evil.com', ['example.com']), false);
});

test('capability map carries the 5.4.0 browser keys and v2 feature', () => {
  assert.equal(HOST_POLICY_CAPABILITIES.length, 22);
  assert.equal(BROWSER_POLICY_V2_FEATURE, 'browser_policy_v2');
  const cases = [
    ['browser_create', {}, ['gui_launch']],
    ['browser_create', { mode: 'existing' }, ['browser_existing_attach', 'gui_launch']],
    ['browser_create', { headless: false }, ['browser_headed', 'gui_launch']],
    ['browser_interact', { action: 'evaluate' }, ['browser_script_exec', 'gui_launch']],
    ['browser_file_upload', {}, ['browser_uploads', 'gui_launch']],
    ['browser_find', {}, ['gui_launch']]
  ];
  for (const [tool, payload, caps] of cases)
    assert.deepEqual(requiredCapabilitiesForOperation(tool, payload, 'mcp'), caps, tool);
});

test('browser audit summaries never carry values', () => {
  const out = browserAuditSummary(
    'browser_interact',
    { browser_id: 'brw_' + 'c'.repeat(32), action: 'fill', target: 'e3', value: 's3cr3t' },
    {
      duration_ms: 12,
      error: null,
      result_payload: { browser_id: 'brw_' + 'c'.repeat(32), action: 'fill', url: 'https://x.test/l?q=1', target_ref: 'e3' }
    }
  );
  assert.equal(out.value, '[REDACTED]');
  assert.equal(out.target, 'e3');
  assert.equal(out.url, 'https://x.test/l');
});

test('fail-closed behavior without a browser', async () => {
  const navFail = await browserNavigateJob({ request_payload: {} });
  assert.equal(navFail.error, 'URL_REQUIRED');
  const fresh = `brw_${'c'.repeat(32)}`;
  assert.equal((await browserInteractJob({ request_payload: { browser_id: fresh, action: 'click', target: 'e1' } })).error, 'BROWSER_SESSION_NOT_FOUND');
  assert.equal((await browserSnapshotJob({ request_payload: { browser_id: fresh } })).error, 'BROWSER_SESSION_NOT_FOUND');
  assert.equal((await browserFindJob({ request_payload: { browser_id: fresh } })).error, 'BROWSER_SESSION_NOT_FOUND');
  assert.equal((await browserTabsJob({ request_payload: { browser_id: fresh, action: 'list' } })).error, 'BROWSER_SESSION_NOT_FOUND');
  assert.equal((await browserInteractJob({ request_payload: { browser_id: fresh, action: 'evaluate', value: '1' } })).error, 'BROWSER_SCRIPT_EXEC_DENIED');
  assert.equal((await browserCloseJob({ request_payload: { browser_id: 'nope' } })).error, 'INVALID_BROWSER_ID');
  const existingDeny = await browserCreateJob({ request_payload: { mode: 'existing', cdp_endpoint: 'http://127.0.0.1:9222' } });
  assert.ok(['BROWSER_POLICY_DENIED', 'BROWSER_EXISTING_ATTACH_FAILED'].includes(existingDeny.error));
});

test('manager lifecycle is fail-closed and versioned', async () => {
  resetBrowserManager();
  const manager = getBrowserManager();
  try {
    assert.equal(manager.sessionState('brw_' + 'e'.repeat(32)), 'closed');
    assert.throws(() => manager.requireSession('brw_' + 'e'.repeat(32)), /BROWSER_SESSION_NOT_FOUND/);
    assert.equal((await manager.closeSession('brw_' + 'e'.repeat(32))).existed, false);
    assert.equal(manager.versions().playwright, '1.63.0');
    assert.equal(CONSOLE_SEVERITY.error < CONSOLE_SEVERITY.debug, true);
    assert.equal(typeof findSystemBrowser(), 'object');
  } finally {
    resetBrowserManager();
  }
});

test('policyFromJob maps capabilities and network policy', () => {
  const p = policyFromJob({
    request_payload: {
      browser_network_policy: { allowed_hosts: ['a.com'], blocked_hosts: [], allow_loopback: true, allow_private_networks: false }
    },
    agent_policy_capabilities: { browser_script_exec: true },
    agent_policy_roots: { allowed_read_roots: ['/opt/nc/data'] }
  });
  assert.equal(p.scriptExec, true);
  assert.deepEqual(p.network.allowedHosts, ['a.com']);
  assert.equal(p.network.allowLoopback, true);
  assert.deepEqual(p.readRoots, ['/opt/nc/data']);
});
