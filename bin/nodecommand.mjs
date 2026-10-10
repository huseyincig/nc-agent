#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(HERE, '..');

const USAGE = `nodecommand — Node Command host agent installer

Usage:
  npx nodecommand [options]

Options:
  --help, -h       Show this help message
  --version, -v    Show package version

Environment variables (passthrough to platform installer):
  NC_ROOT            Target installation directory
                     Linux:   default /opt/nc (system) or ~/.local/share/nc (user)
                     macOS:   default /opt/nc (system) or ~/Library/Application Support/nc (user)
                     Windows: default C:\\NC
  NC_USER_INSTALL    Set to 1 to force non-elevated user-level installation
  NC_SYSTEM_INSTALL  Set to 1 to require system-level service installation
  NC_SRC             Override agent source root (defaults to staged runtime tree)
`;

function getVersion() {
  try {
    const pkgPath = path.join(PKG_ROOT, 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    return pkg.version || 'unknown';
  } catch {
    return 'unknown';
  }
}

function resolveInstaller(platform) {
  const relPaths = {
    win32: ['installers/windows/install-windows.ps1', 'windows/install-windows.ps1'],
    darwin: ['installers/macos/install-macos.sh', 'macos/install-macos.sh'],
    linux: ['installers/linux/install-linux.sh', 'linux/install-linux.sh']
  };
  const candidates = relPaths[platform];
  if (!candidates) return null;
  for (const rel of candidates) {
    const full = path.join(PKG_ROOT, rel);
    if (existsSync(full)) return full;
  }
  return path.join(PKG_ROOT, candidates[0]);
}

function runInstaller(command, commandArgs, stageDir) {
  return new Promise((resolve) => {
    const child = spawn(command, commandArgs, {
      stdio: 'inherit',
      env: {
        ...process.env,
        NC_SRC: stageDir
      }
    });

    child.on('error', (err) => {
      console.error(`Failed to execute installer (${command}): ${err.message}`);
      resolve(1);
    });

    child.on('close', (code, signal) => {
      if (signal) {
        resolve(1);
      } else {
        resolve(code ?? 1);
      }
    });
  });
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(USAGE);
    process.exit(0);
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log(getVersion());
    process.exit(0);
  }

  const platform = process.platform;
  if (!['win32', 'darwin', 'linux'].includes(platform)) {
    console.error(`Error: Unsupported platform "${platform}". Node Command agent supports linux, darwin, and win32.`);
    process.exit(1);
  }

  const scriptPath = resolveInstaller(platform);
  if (!scriptPath || !existsSync(scriptPath)) {
    console.error(`Error: Installer script not found at ${scriptPath}`);
    process.exit(1);
  }

  const version = getVersion();
  let stageDir = null;

  try {
    stageDir = mkdtempSync(path.join(os.tmpdir(), 'nodecommand-stage-'));
    const releaseModulePath = pathToFileURL(
      path.join(PKG_ROOT, 'scripts/package-release.mjs')
    ).href;
    const { stageRuntime } = await import(releaseModulePath);
    await stageRuntime(stageDir, version, null);

    const peercredCandidates = [
      path.join(PKG_ROOT, 'installers/linux/native/linux-peercred.c'),
      path.join(PKG_ROOT, 'native/linux-peercred.c')
    ];
    for (const pc of peercredCandidates) {
      if (existsSync(pc)) {
        mkdirSync(path.join(stageDir, 'native'), { recursive: true });
        copyFileSync(pc, path.join(stageDir, 'native/linux-peercred.c'));
        break;
      }
    }
  } catch (err) {
    if (stageDir && existsSync(stageDir)) {
      try {
        rmSync(stageDir, { recursive: true, force: true });
      } catch {}
    }
    console.error(`Error: Failed to prepare installer staging tree: ${err.message}`);
    process.exit(1);
  }

  const cleanup = () => {
    if (stageDir && existsSync(stageDir)) {
      try {
        rmSync(stageDir, { recursive: true, force: true });
      } catch {}
    }
  };
  process.on('SIGINT', () => { cleanup(); process.exit(130); });
  process.on('SIGTERM', () => { cleanup(); process.exit(143); });

  let command;
  let commandArgs;

  if (platform === 'win32') {
    command = 'powershell';
    commandArgs = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, ...args];
  } else if (platform === 'darwin' || platform === 'linux') {
    command = 'bash';
    commandArgs = [scriptPath, ...args];
  }

  let exitCode = 1;
  try {
    exitCode = await runInstaller(command, commandArgs, stageDir);
  } finally {
    cleanup();
  }

  process.exit(exitCode);
}

main();
