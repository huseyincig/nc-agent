import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const AGENT_ROOT = path.resolve(HERE, '..');
export const DEFAULT_OUTPUT_ROOT =
  process.env.NC_AGENT_RELEASE_ROOT ||
  path.resolve(AGENT_ROOT, '../../..', 'artifacts/client-candidates');

export const RUNTIME_FILES = Object.freeze([
  'launcher.mjs',
  'singleton.mjs',
  'gui-launch.mjs',
  'browser-adapter.mjs',
  'browser-manager.mjs',
  'browser-jobs.mjs',
  'browser-runtime.mjs',
  'process-sessions.mjs',
  'service-ops.mjs',
  'log-ops.mjs',
  'shell.mjs',
  'egress-policy.mjs',
  'client.mjs',
  'ws-client.mjs',
  'structured-ops.mjs',
  'mutation-ops.mjs',
  'host-policy.mjs',
  'device-proof.mjs',
  'lifecycle.mjs',
  'updater.mjs',
  'privileged-helper-contract.mjs',
  'privileged-helper-core.mjs',
  'privileged-helper-ipc.mjs',
  'linux-peer-credentials.mjs',
  'privileged-helper-linux-daemon.mjs',
  'privileged-helper-linux-operations.mjs',
  'privileged-helper-bootstrap.mjs',
  'privileged-helper-client.mjs',
  'privileged-helper-linux-readiness.mjs',
  'tar-extract.mjs',
  'uninstall-ops.mjs',
  'ws-transport.mjs',
  'agent-state.mjs',
  'shell-runner.mjs',
  'shell-ops.mjs',
  'session-reconnect.mjs',
  'doc-extract.mjs',
  'path-auth.mjs',
  'sensitive-paths.mjs',
  'diagnostics-ops.mjs',
  'system-log-ops.mjs',
  'package-ops.mjs',
  'git-ops.mjs',
  'project-ops.mjs',
  'container-ops.mjs',
  'consolidated-tools.mjs',
  'nc-paths.mjs',
  'privileged-helper-spawn.mjs',
  'privileged-helper-provision.mjs',
  'privileged-helper-transport-proof.mjs',
  'privileged-helper-windows-service.mjs',
  'privileged-helper-windows-operations.mjs',
  'privileged-helper-windows-config.mjs',
  'privileged-helper-windows-readiness.mjs',
  'privileged-helper-darwin-daemon.mjs',
  'privileged-helper-darwin-operations.mjs',
  'privileged-helper-darwin-readiness.mjs',
  'darwin-peer-credentials.mjs',
  'package.json',
  'install/nc-privileged-helper-linux.socket.in',
  'install/nc-privileged-helper-linux.service.in',
  'install/nc-privileged-helper-tmpfiles.in',
  'install/install-linux.sh'
]);

export const BOOTSTRAP_MAPPINGS = Object.freeze([
  ['installers/linux/install-linux.sh', 'install/install-linux.sh'],
  ['installers/macos/install-macos.sh', 'install/install-macos.sh'],
  ['installers/windows/install-windows.ps1', 'install/install-windows.ps1'],
  ['installers/linux/uninstall-linux.sh', 'install/uninstall-linux.sh'],
  ['installers/macos/uninstall-macos.sh', 'install/uninstall-macos.sh'],
  ['installers/windows/uninstall-windows.ps1', 'install/uninstall-windows.ps1'],
  ['gui-broker/nc-gui-broker.ps1', 'install/nc-gui-broker.ps1'],
  [
    'installers/linux/services/nc-privileged-helper-linux.service.in',
    'install/nc-privileged-helper-linux.service.in'
  ],
  [
    'installers/linux/services/nc-privileged-helper-linux.socket.in',
    'install/nc-privileged-helper-linux.socket.in'
  ],
  [
    'installers/linux/services/nc-privileged-helper-tmpfiles.in',
    'install/nc-privileged-helper-tmpfiles.in'
  ],
  ['installers/linux/native/linux-peercred.c', 'native/linux-peercred.c'],
  ['docs/FILESYSTEM_LAYOUT.md', 'FILESYSTEM_LAYOUT.md'],
  ['docs/MIGRATION_RUNBOOK.md', 'MIGRATION_RUNBOOK.md'],
  ['docs/UNINSTALL.md', 'UNINSTALL.md']
]);

/**
 * @param {Buffer} buffer
 */
const sha256 = (buffer) => crypto.createHash('sha256').update(buffer).digest('hex');

/**
 * @param {string} file
 */
function mustFile(file) {
  if (!fsSync.existsSync(file) || !fsSync.statSync(file).isFile()) {
    throw new Error(`RELEASE_SOURCE_MISSING:${file}`);
  }
}

/**
 * @param {string} command
 * @param {Array<string>} args
 * @param {Record<string, unknown>} [options]
 */
function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(' ')} failed: ${(result.stderr || result.stdout || '').trim()}`
    );
  }
  return result;
}

/**
 * @param {string} name
 */
export const SOURCE_PATHS = Object.freeze({
  'launcher.mjs': 'src/client/launcher.mjs',
  'singleton.mjs': 'src/client/singleton.mjs',
  'gui-launch.mjs': 'gui-broker/gui-launch.mjs',
  'browser-adapter.mjs': 'src/browser/browser-adapter.mjs',
  'browser-manager.mjs': 'src/browser/browser-manager.mjs',
  'browser-jobs.mjs': 'src/browser/browser-jobs.mjs',
  'browser-runtime.mjs': 'src/browser/browser-runtime.mjs',
  'process-sessions.mjs': 'src/process/process-sessions.mjs',
  'service-ops.mjs': 'src/services/service-ops.mjs',
  'log-ops.mjs': 'src/logs/log-ops.mjs',
  'shell.mjs': 'src/shell/shell.mjs',
  'egress-policy.mjs': 'src/policy/egress-policy.mjs',
  'client.mjs': 'src/client/client.mjs',
  'ws-client.mjs': 'src/client/ws-client.mjs',
  'structured-ops.mjs': 'src/structured-ops/structured-ops.mjs',
  'mutation-ops.mjs': 'src/filesystem/mutation-ops.mjs',
  'host-policy.mjs': 'src/policy/host-policy.mjs',
  'device-proof.mjs': 'src/client/device-proof.mjs',
  'lifecycle.mjs': 'src/lifecycle/lifecycle.mjs',
  'updater.mjs': 'src/updater/updater.mjs',
  'privileged-helper-contract.mjs': 'privileged-helper/privileged-helper-contract.mjs',
  'privileged-helper-core.mjs': 'privileged-helper/privileged-helper-core.mjs',
  'privileged-helper-ipc.mjs': 'privileged-helper/privileged-helper-ipc.mjs',
  'linux-peer-credentials.mjs': 'src/client/linux-peer-credentials.mjs',
  'privileged-helper-linux-daemon.mjs': 'privileged-helper/privileged-helper-linux-daemon.mjs',
  'privileged-helper-linux-operations.mjs':
    'privileged-helper/privileged-helper-linux-operations.mjs',
  'privileged-helper-bootstrap.mjs': 'privileged-helper/privileged-helper-bootstrap.mjs',
  'privileged-helper-client.mjs': 'privileged-helper/privileged-helper-client.mjs',
  'privileged-helper-linux-readiness.mjs':
    'privileged-helper/privileged-helper-linux-readiness.mjs',
  'tar-extract.mjs': 'src/updater/tar-extract.mjs',
  'uninstall-ops.mjs': 'src/client/uninstall-ops.mjs',
  'ws-transport.mjs': 'src/client/ws-transport.mjs',
  'agent-state.mjs': 'src/client/agent-state.mjs',
  'shell-runner.mjs': 'src/client/shell-runner.mjs',
  'shell-ops.mjs': 'src/shell/shell-ops.mjs',
  'session-reconnect.mjs': 'src/client/session-reconnect.mjs',
  'doc-extract.mjs': 'src/structured-ops/doc-extract.mjs',
  'path-auth.mjs': 'src/filesystem/path-auth.mjs',
  'sensitive-paths.mjs': 'src/filesystem/sensitive-paths.mjs',
  'diagnostics-ops.mjs': 'src/diagnostics/diagnostics-ops.mjs',
  'system-log-ops.mjs': 'src/logs/system-log-ops.mjs',
  'package-ops.mjs': 'src/packages/package-ops.mjs',
  'git-ops.mjs': 'src/git/git-ops.mjs',
  'project-ops.mjs': 'src/structured-ops/project-ops.mjs',
  'container-ops.mjs': 'src/containers/container-ops.mjs',
  'consolidated-tools.mjs': 'src/client/consolidated-tools.mjs',
  'nc-paths.mjs': 'src/client/nc-paths.mjs',
  'privileged-helper-spawn.mjs':
    'privileged-helper/privileged-helper-spawn.mjs',
  'privileged-helper-provision.mjs':
    'privileged-helper/privileged-helper-provision.mjs',
  'privileged-helper-transport-proof.mjs':
    'privileged-helper/privileged-helper-transport-proof.mjs',
  'privileged-helper-windows-service.mjs':
    'privileged-helper/privileged-helper-windows-service.mjs',
  'privileged-helper-windows-operations.mjs':
    'privileged-helper/privileged-helper-windows-operations.mjs',
  'privileged-helper-windows-config.mjs':
    'privileged-helper/privileged-helper-windows-config.mjs',
  'privileged-helper-windows-readiness.mjs':
    'privileged-helper/privileged-helper-windows-readiness.mjs',
  'privileged-helper-darwin-daemon.mjs':
    'privileged-helper/privileged-helper-darwin-daemon.mjs',
  'privileged-helper-darwin-operations.mjs':
    'privileged-helper/privileged-helper-darwin-operations.mjs',
  'privileged-helper-darwin-readiness.mjs':
    'privileged-helper/privileged-helper-darwin-readiness.mjs',
  'darwin-peer-credentials.mjs': 'src/client/darwin-peer-credentials.mjs',
  'install/nc-privileged-helper-linux.socket.in':
    'installers/linux/services/nc-privileged-helper-linux.socket.in',
  'install/nc-privileged-helper-linux.service.in':
    'installers/linux/services/nc-privileged-helper-linux.service.in',
  'install/nc-privileged-helper-tmpfiles.in':
    'installers/linux/services/nc-privileged-helper-tmpfiles.in',
  'install/install-linux.sh':
    'installers/linux/install-linux.sh'
});
function runtimeSource(name) {
  if (name === 'package.json') return null;
  const rel = SOURCE_PATHS[name];
  if (!rel) throw new Error(`UNKNOWN_RUNTIME_FILE:${name}`);
  return path.join(AGENT_ROOT, rel);
}

/**
 * @param {string} version
 */
export async function generatedRuntimePackage(version) {
  return {
    name: 'nc-client',
    version,
    private: true,
    type: 'module',
    scripts: {
      start: 'node launcher.mjs'
    },
    engines: {
      node: '>=22'
    }
  };
}

/**
 * Reads the pinned Playwright version from the canonical agent source.
 */
export async function browserRuntimePin() {
  const source = await fs.readFile(
    path.join(AGENT_ROOT, 'src/browser/browser-runtime.mjs'),
    'utf8'
  );
  const playwright = source.match(/playwright:\s*'([^']+)'/)?.[1];
  const revision = source.match(/chromiumRevision:\s*'([^']+)'/)?.[1];
  if (!playwright || !revision) throw new Error('BROWSER_RUNTIME_PIN_UNREADABLE');
  return { playwright, chromiumRevision: revision };
}

/**
 * Builds the versioned browser-runtime payload:
 * <outputRoot>/<playwright>/browser-runtime.tar.gz containing top-level
 * playwright-core/. Source: $NC_BROWSER_RUNTIME_TGZ (offline/reproducible)
 * or `npm pack playwright-core@<pin>` (network). Content-verified before
 * acceptance; a mismatched payload fails the build, never the host.
 * @param {object} [options]
 * @param {string} [options.outputRoot]
 * @param {boolean} [options.force]
 * @param {string} [options.createdAt]
 */
export async function buildBrowserRuntime({
  outputRoot = path.join(AGENT_ROOT, 'artifacts', 'browser-runtime'),
  force = false,
  createdAt = new Date().toISOString()
} = {}) {
  const pin = await browserRuntimePin();
  const releaseDir = path.resolve(outputRoot, pin.playwright);
  if (fsSync.existsSync(releaseDir)) {
    if (!force) throw new Error(`BROWSER_RUNTIME_EXISTS:${releaseDir}`);
    await fs.rm(releaseDir, { recursive: true, force: true });
  }
  await fs.mkdir(releaseDir, { recursive: true });
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), `nc-browser-runtime-${pin.playwright}-`));
  try {
    let packed = process.env.NC_BROWSER_RUNTIME_TGZ || '';
    if (!packed) {
      const pack = run('npm', ['pack', `playwright-core@${pin.playwright}`, '--pack-destination', temp]);
      const file = pack.stdout
        .split('\n')
        .map((x) => x.trim())
        .filter(Boolean)
        .pop();
      if (!file) throw new Error('BROWSER_RUNTIME_PACK_FAILED');
      packed = path.resolve(temp, file);
    } else if (!fsSync.existsSync(packed)) {
      throw new Error(`BROWSER_RUNTIME_TGZ_MISSING:${packed}`);
    }
    const extractDir = path.join(temp, 'extract');
    await fs.mkdir(extractDir, { recursive: true });
    run('tar', ['-xzf', packed, '-C', extractDir]);
    const coreDir = path.join(extractDir, 'package');
    const pkg = JSON.parse(await fs.readFile(path.join(coreDir, 'package.json'), 'utf8'));
    if (String(pkg.version || '') !== pin.playwright)
      throw new Error(
        `BROWSER_RUNTIME_VERSION_MISMATCH:expected=${pin.playwright}:got=${pkg.version || '?'}`
      );
    const browsers = JSON.parse(await fs.readFile(path.join(coreDir, 'browsers.json'), 'utf8'));
    const chromium = (browsers?.browsers || []).find(
      (/** @type {Record<string, unknown>} */ b) => b?.name === 'chromium'
    );
    if (String(chromium?.revision || '') !== pin.chromiumRevision)
      throw new Error(
        `BROWSER_RUNTIME_REVISION_MISMATCH:expected=${pin.chromiumRevision}:got=${chromium?.revision || '?'}`
      );
    if (!fsSync.existsSync(path.join(coreDir, 'cli.js')))
      throw new Error('BROWSER_RUNTIME_NO_INSTALLER');
    const stage = path.join(temp, 'stage', 'browser-runtime');
    await fs.mkdir(stage, { recursive: true });
    run('cp', ['-a', path.join(coreDir, '.'), path.join(stage, 'playwright-core')]);
    const archive = await createDeterministicTarGzip(path.join(temp, 'stage'));
    const outFile = path.join(releaseDir, 'browser-runtime.tar.gz');
    await fs.writeFile(outFile, archive, { mode: 0o640 });
    const manifest = {
      playwright: pin.playwright,
      chromium_revision: pin.chromiumRevision,
      sha256: sha256(archive),
      size_bytes: archive.length,
      created_at: createdAt
    };
    await fs.writeFile(path.join(releaseDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o640 });
    await fs.writeFile(
      path.join(outputRoot, 'latest.json'),
      JSON.stringify(manifest, null, 2) + '\n',
      { mode: 0o640 }
    );
    return { releaseDir, manifest };
  } catch (error) {
    await fs.rm(releaseDir, { recursive: true, force: true });
    throw error;
  } finally {
    await fs.rm(temp, { recursive: true, force: true });
  }
}

/**
 * @param {string} stage
 * @param {string} version
 * @param {string|null} [browserRuntimeDir] prebuilt payload dir containing browser-runtime/
 */
export async function stageRuntime(stage, version, browserRuntimeDir = null) {
  await fs.mkdir(stage, { recursive: true });
  for (const name of RUNTIME_FILES) {
    const dest = path.join(stage, name);
    if (name === 'package.json') {
      await fs.writeFile(
        dest,
        JSON.stringify(await generatedRuntimePackage(version), null, 2) + '\n',
        { mode: 0o640 }
      );
      continue;
    }
    const source = /** @type {string} */ (runtimeSource(name));
    mustFile(source);
    await fs.mkdir(path.dirname(dest), { recursive: true });
    await fs.copyFile(source, dest);
    await fs.chmod(dest, 0o640);
  }
  // The browser runtime rides every agent release (fresh installs and OTA
  // alike) so a pin change can never strand a host without its engine.
  // Absent payload is legal for air-gapped rebuilds. NOTE: string-concat
  // '/.' (path.join would normalize the dot away and nest the directory).
  if (browserRuntimeDir) {
    const source = path.join(browserRuntimeDir, 'browser-runtime');
    mustFile(path.join(source, 'playwright-core', 'package.json'));
    const target = path.join(stage, 'browser-runtime');
    await fs.mkdir(target, { recursive: true });
    run('cp', ['-a', source + '/.', target + '/.']);
  }
  for (const name of RUNTIME_FILES.filter((x) => x.endsWith('.mjs'))) {
    run(process.execPath, ['--check', name], { cwd: stage });
  }
}

/**
 * @param {string} stage
 * @param {string} version
 * @param {string|null} [browserRuntimeDir] prebuilt payload dir containing browser-runtime/
 */
async function stageBootstrap(stage, version, browserRuntimeDir = null) {
  await stageRuntime(stage, version, browserRuntimeDir);
  for (const [sourceRel, targetRel] of BOOTSTRAP_MAPPINGS) {
    const source = path.join(AGENT_ROOT, sourceRel);
    const target = path.join(stage, targetRel);
    mustFile(source);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.copyFile(source, target);
    await fs.chmod(target, targetRel.startsWith('install/') ? 0o750 : 0o640);
  }
}

/**
 * @param {Buffer} header
 * @param {number} offset
 * @param {number} length
 * @param {unknown} value
 */
function writeTarOctal(header, offset, length, value) {
  const octal = Math.max(0, Number(value) || 0)
    .toString(8)
    .padStart(length - 1, '0')
    .slice(-(length - 1));
  header.write(octal + '\0', offset, length, 'ascii');
}

/**
 * @param {string} name
 * @param {number} size
 * @param {number} mode
 */
function tarHeader(name, size, mode) {
  const normalized = String(name).replace(/\\/g, '/').replace(/^\.\//, '');
  if (!normalized) throw new Error('RELEASE_TAR_EMPTY_PATH');
  // USTAR prefix splitting for payload paths beyond 100 bytes (vendored
  // dependencies). The updater extractor already joins prefix/name.
  let nameField = normalized;
  let prefixField = '';
  if (Buffer.byteLength(normalized) > 100) {
    const idx = normalized.lastIndexOf('/', 100);
    if (idx < 0) throw new Error('RELEASE_TAR_PATH_TOO_LONG:' + normalized);
    prefixField = normalized.slice(0, idx);
    nameField = normalized.slice(idx + 1);
    if (
      !nameField ||
      Buffer.byteLength(nameField) > 100 ||
      Buffer.byteLength(prefixField) > 155
    )
      throw new Error('RELEASE_TAR_PATH_TOO_LONG:' + normalized);
  }
  const header = Buffer.alloc(512, 0);
  header.write(nameField, 0, 100, 'utf8');
  writeTarOctal(header, 100, 8, mode);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, size);
  writeTarOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0);
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  if (prefixField) header.write(prefixField, 345, 155, 'utf8');
  header.write('root', 265, 32, 'ascii');
  header.write('root', 297, 32, 'ascii');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(checksum.toString(8).padStart(6, '0').slice(-6), 148, 6, 'ascii');
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

/**
 * @param {string} root
 * @param {string} [dir]
 * @returns {Promise<Array<string>>}
 */
async function stagedFiles(root, dir = root) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...(await stagedFiles(root, full)));
    else if (entry.isFile()) {
      const rel = path.relative(root, full).split(path.sep).join('/');
      files.push(rel);
    } else {
      throw new Error('RELEASE_UNSUPPORTED_STAGE_ENTRY:' + full);
    }
  }
  return files.sort((a, b) => a.localeCompare(b, 'en'));
}

/**
 * @param {string} stage
 */
export async function createDeterministicTarGzip(stage) {
  const chunks = [];
  for (const rel of await stagedFiles(stage)) {
    const bytes = await fs.readFile(path.join(stage, ...rel.split('/')));
    const mode = rel.startsWith('install/') ? 0o750 : 0o640;
    chunks.push(tarHeader(rel, bytes.length, mode), bytes);
    const padding = (512 - (bytes.length % 512)) % 512;
    if (padding) chunks.push(Buffer.alloc(padding, 0));
  }
  chunks.push(Buffer.alloc(1024, 0));
  return zlib.gzipSync(
    Buffer.concat(chunks),
    /** @type {import('node:zlib').ZlibOptions} */ ({ level: 9, mtime: 0 })
  );
}

/**
 * @param {string} stage
 * @param {string} output
 */
async function tarDirectory(stage, output) {
  await fs.writeFile(output, await createDeterministicTarGzip(stage), { mode: 0o640 });
}

/**
 * @param {object} [options]
 * @param {string} [options.outputRoot]
 * @param {boolean} [options.force]
 * @param {string} [options.createdAt]
 */
export async function buildRelease({
  outputRoot = DEFAULT_OUTPUT_ROOT,
  force = false,
  createdAt = new Date().toISOString(),
  browserRuntimeDir = null
} = {}) {
  const agentPackage = JSON.parse(await fs.readFile(path.join(AGENT_ROOT, 'package.json'), 'utf8'));
  const version = String(agentPackage.version || '');
  if (!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(version)) {
    throw new Error('INVALID_AGENT_VERSION');
  }

  const clientSource = await fs.readFile(path.join(AGENT_ROOT, 'src/client/client.mjs'), 'utf8');
  const sourceVersion = clientSource.match(/const VERSION = '([^']+)'/)?.[1];
  if (sourceVersion !== version) {
    throw new Error(`AGENT_VERSION_DRIFT:package=${version}:client=${sourceVersion || 'missing'}`);
  }

  const releaseDir = path.resolve(outputRoot, version);
  if (fsSync.existsSync(releaseDir)) {
    if (!force) throw new Error(`CANDIDATE_ALREADY_EXISTS:${releaseDir}`);
    await fs.rm(releaseDir, { recursive: true, force: true });
  }
  await fs.mkdir(releaseDir, { recursive: true });

  const temp = await fs.mkdtemp(path.join(os.tmpdir(), `nc-agent-${version}-`));
  try {
    const runtimeStage = path.join(temp, 'runtime');
    const bootstrapStage = path.join(temp, 'bootstrap');
    await stageRuntime(runtimeStage, version, browserRuntimeDir);
    await stageBootstrap(bootstrapStage, version, browserRuntimeDir);

    const runtimeArchive = path.join(releaseDir, 'client.tar.gz');
    const bootstrapArchive = path.join(releaseDir, 'bootstrap.tar.gz');
    await tarDirectory(runtimeStage, runtimeArchive);
    await tarDirectory(bootstrapStage, bootstrapArchive);

    const runtimeBytes = await fs.readFile(runtimeArchive);
    const bootstrapBytes = await fs.readFile(bootstrapArchive);
    const manifest = {
      version,
      sha256: sha256(runtimeBytes),
      size_bytes: runtimeBytes.length,
      bootstrap_sha256: sha256(bootstrapBytes),
      bootstrap_size_bytes: bootstrapBytes.length,
      protocol_version: '1.0.0',
      created_at: createdAt,
      filesystem_contract: 'canonical-v1',
      requires_canonical_layout: true,
      candidate: true
    };
    await fs.writeFile(
      path.join(releaseDir, 'manifest.json'),
      JSON.stringify(manifest, null, 2) + '\n',
      { mode: 0o640 }
    );
    return { releaseDir, manifest };
  } catch (error) {
    await fs.rm(releaseDir, { recursive: true, force: true });
    throw error;
  } finally {
    await fs.rm(temp, { recursive: true, force: true });
  }
}

const invoked =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (invoked) {
  const force = process.argv.includes('--force');
  const outputArg = process.argv.find((x) => x.startsWith('--output='));
  const outputRoot = outputArg ? outputArg.slice('--output='.length) : DEFAULT_OUTPUT_ROOT;
  if (process.argv.includes('--browser-runtime')) {
    const runtimeOut = process.argv
      .find((x) => x.startsWith('--runtime-output='))
      ?.slice('--runtime-output='.length);
    const result = await buildBrowserRuntime({
      ...(runtimeOut ? { outputRoot: runtimeOut } : {}),
      force
    });
    console.log(JSON.stringify({ ok: true, release_dir: result.releaseDir, manifest: result.manifest }, null, 2));
  } else {
    const rtArg = process.argv.find((x) => x.startsWith('--with-browser-runtime='));
    const result = await buildRelease({
      outputRoot,
      force,
      ...(rtArg ? { browserRuntimeDir: rtArg.slice('--with-browser-runtime='.length) } : {})
    });
    console.log(
      JSON.stringify(
        {
          ok: true,
          release_dir: result.releaseDir,
          manifest: result.manifest,
          published: false
        },
        null,
        2
      )
    );
  }
}
