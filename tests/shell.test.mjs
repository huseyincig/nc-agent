import test from 'node:test';
import assert from 'node:assert/strict';
import { executeShellJob, normalizedJobPayload, shellChildDetached } from '../src/shell/shell.mjs';

const RT = { root: '/', maxTimeoutSeconds: 30, maxStdoutBytes: 65536, maxStderrBytes: 65536 };

test('echo completes with stdout', async () => {
  const r = await executeShellJob({ command: 'echo hello-shell' }, {}, RT);
  assert.equal(r.status, 'completed');
  assert.equal(r.exit_code, 0);
  assert.match(String(r.stdout), /hello-shell/);
  assert.equal(r.error, null);
});

test('missing command fails closed', async () => {
  await assert.rejects(executeShellJob({ command: '' }, {}, RT), /COMMAND_REQUIRED/);
  await assert.rejects(executeShellJob({}, {}, RT), /COMMAND_REQUIRED/);
});

test('failing command reports exit code', async () => {
  const r = await executeShellJob({ command: 'exit 41' }, {}, RT);
  assert.equal(r.status, 'failed');
  assert.equal(r.exit_code, 41);
  assert.match(String(r.error), /41/);
});

test('timeout kills and reports', async () => {
  const r = await executeShellJob({ command: 'sleep 30', timeout_seconds: 1 }, {}, RT);
  assert.equal(r.status, 'timeout');
  assert.match(String(r.error), /timeout/);
});

test('stdout truncates at the cap', async () => {
  const r = await executeShellJob({ command: 'yes | head -c 100000' }, {}, { ...RT, maxStdoutBytes: 1024 });
  assert.equal(r.stdout_truncated, true);
  assert.ok(String(r.stdout).length <= 1024);
});

test('payload normalization prefers request_payload', () => {
  assert.deepEqual(normalizedJobPayload({ request_payload: { a: 1 } }), { a: 1 });
  assert.deepEqual(normalizedJobPayload({ payload: { b: 2 } }), { b: 2 });
  assert.deepEqual(normalizedJobPayload(null), {});
});

test('detached differs by platform', () => {
  assert.equal(shellChildDetached('win32'), false);
  assert.equal(shellChildDetached('linux'), true);
});
