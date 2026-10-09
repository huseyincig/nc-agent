import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

test('package version matches client VERSION', async () => {
  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url)));
  const { compareAgentVersions } = await import('../src/updater/updater.mjs');
  assert.equal(typeof compareAgentVersions('0.4.61', '0.4.60'), 'number');
  assert.ok(compareAgentVersions('0.4.61', '0.4.60') > 0);
  assert.equal(pkg.version, '0.17.24');
});

test('policy and contract modules load', async () => {
  const policy = await import('../src/policy/host-policy.mjs');
  assert.equal(typeof policy.validatePolicy, 'function');
  const contract = await import('../privileged-helper/privileged-helper-contract.mjs');
  assert.ok(Array.isArray(contract.PRIVILEGED_HELPER_OPERATIONS));
});

test('runtime closure files exist', async () => {
  const { RUNTIME_FILES, SOURCE_PATHS } = await import('../scripts/package-release.mjs');
  assert.ok(RUNTIME_FILES.includes('client.mjs'));
  assert.ok(RUNTIME_FILES.includes('updater.mjs'));
  for (const name of RUNTIME_FILES) {
    if (name === 'package.json') continue;
    const rel = SOURCE_PATHS[name];
    assert.ok(rel, `no source path for ${name}`);
    assert.ok(fs.existsSync(new URL(`../${rel}`, import.meta.url)), `missing ${rel}`);
  }
});
