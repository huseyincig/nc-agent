/**
 * Project task operations for the NC agent (contract 5.16.0).
 * Pure detectors/parsers are exported for unit tests; handlers exec
 * argv-form commands (no shell) with bounded output, mirroring git-ops.mjs.
 * Reads gate the repo path against read roots; runners additionally require
 * write-roots membership (builds emit artifacts). task_run executes ONLY
 * tasks declared by the project manifests (re-resolved at exec time);
 * free-form commands stay exclusive to shell_exec.
 */
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import { realAllowed } from './structured-ops.mjs';
import { forbidAgentTreeWrite } from '../filesystem/mutation-ops.mjs';
import { policyExtraRoots } from '../policy/host-policy.mjs';
import { captureSpawnIdentity, terminateSessionTree, terminateSessionTreeAsync } from '../process/process-sessions.mjs';
import { shellEnvironment } from '../client/shell-runner.mjs';

const run = promisify(execFile);
const MAX_TASKS = 200;
const TASK_RE = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
const RUN_ENV = { CI: '1', NO_COLOR: '1', TERM: 'dumb' };

/**
 * Hub-directed kill registry for project executions (task/test/lint):
 * jobId -> tree-kill, consumed on settle. Mirrors shellAbortByJob.
 */
const taskAbortByJob = new Map();
/**
 * @param {unknown} jobId
 */
export function cancelProjectTask(jobId) {
  const key = String(jobId || '');
  if (!key) return false;
  const kill = taskAbortByJob.get(key);
  if (!kill) return false;
  taskAbortByJob.delete(key);
  try {
    kill();
  } catch {}
  return true;
}

const ok = (/** @type {unknown} */ result_payload) => ({
  status: 'completed',
  exit_code: 0,
  stdout: '',
  stderr: '',
  error: null,
  duration_ms: 0,
  result_payload
});
const fail = (/** @type {unknown} */ error) => ({
  status: 'failed',
  exit_code: null,
  stdout: '',
  stderr: '',
  error: String(error),
  duration_ms: 0,
  result_payload: {}
});

/**
 * @param {string} file
 */
async function readJson(file) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch {
    return null;
  }
}

/**
 * @param {string} file
 */
async function readText(file) {
  try {
    return await fs.readFile(file, 'utf8');
  } catch {
    return null;
  }
}

/**
 * @param {string} dir @param {string} name
 */
async function exists(dir, name) {
  try {
    await fs.access(path.join(dir, name));
    return true;
  } catch {
    return false;
  }
}

/**
 * Detect project ecosystems in a directory from marker files.
 * @param {string} dir
 */
export async function detectProjects(dir) {
  const out = [];
  const pkg = await readJson(path.join(dir, 'package.json'));
  if (pkg && typeof pkg === 'object')
    out.push({ type: 'node', manager: 'npm', markers: ['package.json'] });
  const composer = await readJson(path.join(dir, 'composer.json'));
  if (composer && typeof composer === 'object')
    out.push({ type: 'php', manager: 'composer', markers: ['composer.json'] });
  if (await exists(dir, 'Cargo.toml')) out.push({ type: 'rust', manager: 'cargo', markers: ['Cargo.toml'] });
  if (await exists(dir, 'go.mod')) out.push({ type: 'go', manager: 'go', markers: ['go.mod'] });
  if (await exists(dir, 'Makefile')) out.push({ type: 'make', manager: 'make', markers: ['Makefile'] });
  if (await exists(dir, 'justfile')) out.push({ type: 'just', manager: 'just', markers: ['justfile'] });
  if (await exists(dir, 'Taskfile.yml')) out.push({ type: 'task', manager: 'task', markers: ['Taskfile.yml'] });
  if ((await exists(dir, 'pyproject.toml')) || (await exists(dir, 'pytest.ini')) || (await exists(dir, 'setup.py')))
    out.push({ type: 'python', manager: 'pytest', markers: ['pyproject.toml'] });
  return out;
}

/**
 * Parse Makefile targets (`name:` / `name::` at line start, no `=`).
 * @param {string} text
 */
export function parseMakefileTargets(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const m = line.match(/^([A-Za-z0-9_][A-Za-z0-9_.-]*)::?([^=]*)$/);
    if (!m) continue;
    if (m[2] && m[2].includes('=')) continue;
    if (!out.some((t) => t.name === m[1])) out.push({ runner: 'make', name: m[1], command: `make ${m[1]}` });
  }
  return out;
}

/**
 * Parse `just --summary` output (space-separated recipe names).
 * @param {string} text
 */
export function parseJustSummary(text) {
  return String(text || '')
    .split(/\s+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((name) => ({ runner: 'just', name, command: `just ${name}` }));
}

/**
 * Substring marker check inside a project manifest (deterministic,
 * no TOML parser needed: section headers are line-anchored by convention).
 * @param {string} dir @param {string} file @param {string} marker
 */
async function manifestHas(dir, file, marker) {
  const text = await readText(path.join(dir, file));
  return typeof text === 'string' && text.includes(marker);
}

/**
 * Probe a binary on PATH (`--version`), true when executable.
 * @param {string} bin
 */
async function binProbe(bin) {
  try {
    await run(bin, ['--version'], { timeout: 10000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Virtualenv binary for a project dir (posix `.venv/bin`, win32
 * `.venv/Scripts`), or null. Venv wins over PATH and wrappers.
 * @param {string} dir @param {string} bin
 */
export async function venvBin(dir, bin) {
  const rel =
    process.platform === 'win32'
      ? path.join('.venv', 'Scripts', `${bin}.exe`)
      : path.join('.venv', 'bin', bin);
  const full = path.join(dir, rel);
  try {
    await fs.access(full, fsConstants.X_OK);
    return full;
  } catch {
    return null;
  }
}

/**
 * Execution wrapper for a project dir: uv (`uv.lock`) or poetry
 * (`[tool.poetry]` / `poetry.lock`). Wrappers are NOT tasks themselves;
 * they prefix pytest/ruff/mypy argv. Returns [] when neither applies.
 * @param {string} dir
 */
export async function taskWrapper(dir) {
  if (await exists(dir, 'uv.lock')) return ['uv', 'run'];
  if ((await manifestHas(dir, 'pyproject.toml', '[tool.poetry]')) || (await exists(dir, 'poetry.lock')))
    return ['poetry', 'run'];
  return [];
}

/**
 * Resolve the executable vector for a Python-ecosystem binary:
 * `.venv/bin` first, then uv/poetry wrapper, then PATH. Returns null when
 * neither venv copy nor wrapper applies and the binary is missing on PATH.
 * @param {string} dir @param {string} bin
 */
async function pythonBin(dir, bin) {
  const vb = await venvBin(dir, bin);
  if (vb) return [vb];
  const wrap = await taskWrapper(dir);
  if (wrap.length && (await binProbe(wrap[0]))) return [...wrap, bin];
  if (await binProbe(bin)) return [bin];
  return null;
}

/**
 * Glob test files under `<dir>/tests` and `<dir>/test` (bounded walk,
 * `test_*.py` / `*_test.py`). `isFile()`/`isDirectory()` do not follow
 * symlinks, so symlinked dirs are not descended and symlinked files are
 * skipped; resolveTask additionally stat-verifies every target.
 * @param {string} dir
 */
export async function globTestFiles(dir) {
  const out = [];
  const roots = ['tests', 'test'];
  /** @param {string} rel @param {number} depth */
  const walk = async (rel, depth) => {
    if (out.length >= 50 || depth > 4) return;
    let entries = [];
    try {
      entries = await fs.readdir(path.join(dir, rel), { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (out.length >= 50) return;
      if (e.name.startsWith('.') || e.name === '__pycache__') continue;
      const child = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) await walk(child, depth + 1);
      else if (
        e.isFile() &&
        (e.name.startsWith('test_') || e.name.endsWith('_test.py')) &&
        e.name.endsWith('.py')
      )
        out.push(child);
    }
  };
  for (const r of roots) await walk(r, 0);
  return out;
}

/**
 * List runnable tasks declared by project manifests.
 * @param {string} dir
 */
export async function listProjectTasks(dir) {
  const out = [];
  const push = (/** @type {Array<{runner: string, name: string, command: string}>} */ rows) => {
    for (const r of rows) {
      if (!TASK_RE.test(r.name)) continue;
      if (out.length >= MAX_TASKS) return;
      if (!out.some((t) => t.runner === r.runner && t.name === r.name)) out.push(r);
    }
  };
  const pkg = await readJson(path.join(dir, 'package.json'));
  const scripts = pkg && typeof pkg === 'object' && pkg.scripts && typeof pkg.scripts === 'object' ? pkg.scripts : null;
  if (scripts)
    push(
      Object.keys(scripts).map((name) => ({ runner: 'npm', name, command: `npm run ${name}` }))
    );
  const composer = await readJson(path.join(dir, 'composer.json'));
  const cscripts = composer && typeof composer === 'object' && composer.scripts && typeof composer.scripts === 'object' ? composer.scripts : null;
  if (cscripts)
    push(
      Object.keys(cscripts).map((name) => ({ runner: 'composer', name, command: `composer ${name}` }))
    );
  const mf = await readText(path.join(dir, 'Makefile'));
  if (mf) push(parseMakefileTargets(mf));
  try {
    const { stdout } = await run('just', ['--summary'], { timeout: 15000, cwd: dir });
    push(parseJustSummary(stdout));
  } catch {}
  await pushPythonTasks(dir, push);
  return out;
}

/**
 * Python-ecosystem task discovery: pytest (+`test` alias), targeted pytest
 * per test file, ruff (`check` + `lint` alias) and mypy (`check`). Signals
 * are manifest/config markers; binaries resolve venv-first via pythonBin.
 * tox/nox/hatch need real env/session discovery (round 2) — not listed.
 * @param {string} dir
 * @param {(rows: Array<{runner: string, name: string, command: string}>) => void} push
 */
async function pushPythonTasks(dir, push) {
  const pyProject = await readText(path.join(dir, 'pyproject.toml'));
  const hasPytestIni = await exists(dir, 'pytest.ini');
  const hasSetupPy = await exists(dir, 'setup.py');
  const hasSetupCfg = await exists(dir, 'setup.cfg');
  const isPython =
    typeof pyProject === 'string' || hasPytestIni || hasSetupPy || hasSetupCfg;
  const hasMypyIni =
    (await exists(dir, 'mypy.ini')) ||
    (await exists(dir, '.mypy.ini')) ||
    (await manifestHas(dir, 'setup.cfg', '[mypy]'));
  const hasRuffMarker =
    (typeof pyProject === 'string' && pyProject.includes('[tool.ruff]')) || false;
  const hasPytestMarker =
    hasPytestIni ||
    hasSetupPy ||
    (typeof pyProject === 'string' &&
      (pyProject.includes('[tool.pytest') || pyProject.includes('[project]')));
  const pytestBin = hasPytestMarker ? await pythonBin(dir, 'pytest') : null;
  if (pytestBin) {
    const cmd = [...pytestBin, '-q'].join(' ');
    push([
      { runner: 'pytest', name: 'test', command: cmd },
      { runner: 'pytest', name: 'pytest', command: cmd }
    ]);
    for (const f of await globTestFiles(dir)) {
      const dotted = f.replace(/\.py$/, '').split('/').join('.');
      push([{ runner: 'pytest', name: dotted, command: [...pytestBin, '-q', f].join(' ') }]);
    }
  }
  const ruffBin =
    isPython || hasRuffMarker ? await pythonBin(dir, 'ruff') : null;
  if (ruffBin) {
    const cmd = [...ruffBin, 'check', '.'].join(' ');
    push([
      { runner: 'ruff', name: 'lint', command: cmd },
      { runner: 'ruff', name: 'check', command: cmd }
    ]);
  }
  const mypyConfigured =
    hasMypyIni || (typeof pyProject === 'string' && pyProject.includes('[tool.mypy]'));
  const mypyBin = mypyConfigured ? await pythonBin(dir, 'mypy') : null;
  if (mypyBin) {
    push([{ runner: 'mypy', name: 'check', command: [...mypyBin, '.'].join(' ') }]);
  }
}

/**
 * Resolve a declared task to an argv vector. Re-resolves at exec time so
 * the task must exist in the manifests when the job runs, not just when
 * it was listed. Returns null when the task is not declared.
 * @param {string} dir @param {string} runner @param {string} name
 * @returns {Promise<Array<string>|null>}
 */
export async function resolveTask(dir, runner, name) {
  if (!TASK_RE.test(String(name || ''))) return null;
  const r = String(runner || '').toLowerCase();
  const tasks = await listProjectTasks(dir);
  const hit = tasks.find((t) => t.runner === r && t.name === name);
  if (!hit) return null;
  if (r === 'npm') return ['npm', 'run', name];
  if (r === 'composer') return ['composer', name];
  if (r === 'make') return ['make', name];
  if (r === 'just') return ['just', name];
  if (r === 'pytest') {
    const rel = name === 'test' || name === 'pytest' ? null : name.split('.').join('/') + '.py';
    if (rel) {
      const full = path.normalize(path.join(dir, rel));
      if (full !== dir && !full.startsWith(dir + path.sep)) return null;
      try {
        const st = await fs.stat(full);
        if (!st.isFile()) return null;
      } catch {
        return null;
      }
    }
    const bin = await pythonBin(dir, 'pytest');
    if (!bin) return null;
    return rel ? [...bin, '-q', rel] : [...bin, '-q'];
  }
  if (r === 'ruff') {
    const bin = await pythonBin(dir, 'ruff');
    if (!bin) return null;
    return [...bin, 'check', '.'];
  }
  if (r === 'mypy') {
    const bin = await pythonBin(dir, 'mypy');
    if (!bin) return null;
    return [...bin, '.'];
  }
  return null;
}

/**
 * Conventional zero-config test command per ecosystem (used only when the
 * project declares no test task).
 * @param {string} dir
 * @returns {Promise<{argv: Array<string>, via: string}|null>}
 */
export async function conventionalTest(dir) {
  const tasks = await listProjectTasks(dir);
  const declared = tasks.find((t) => t.name === 'test');
  if (declared) {
    const argv = await resolveTask(dir, declared.runner, 'test');
    if (argv) return { argv, via: `declared:${declared.runner}` };
  }
  if (await exists(dir, 'Cargo.toml')) return { argv: ['cargo', 'test'], via: 'conventional:cargo' };
  if (await exists(dir, 'go.mod')) return { argv: ['go', 'test', './...'], via: 'conventional:go' };
  if ((await exists(dir, 'pytest.ini')) || (await exists(dir, 'pyproject.toml')) || (await exists(dir, 'setup.py'))) {
    // Venv-aware like the declared path: never run a foreign pytest.
    const bin = await pythonBin(dir, 'pytest');
    if (bin) return { argv: [...bin, '-q'], via: 'conventional:pytest' };
  }
  const composer = await readJson(path.join(dir, 'composer.json'));
  if (composer) return { argv: ['composer', 'test'], via: 'conventional:composer' };
  if (await exists(dir, 'Makefile')) {
    const mf = (await readText(path.join(dir, 'Makefile'))) || '';
    if (parseMakefileTargets(mf).some((t) => t.name === 'test'))
      return { argv: ['make', 'test'], via: 'conventional:make' };
  }
  return null;
}

/**
 * Conventional zero-config lint command per ecosystem.
 * @param {string} dir
 * @returns {Promise<{argv: Array<string>, via: string}|null>}
 */
export async function conventionalLint(dir) {
  const tasks = await listProjectTasks(dir);
  const declared =
    tasks.find((t) => t.name === 'lint') ||
    tasks.find((t) => t.name === 'check' && (t.runner === 'ruff' || t.runner === 'mypy'));
  if (declared) {
    const argv = await resolveTask(dir, declared.runner, declared.name);
    if (argv) return { argv, via: `declared:${declared.runner}` };
  }
  if (await exists(dir, 'pyproject.toml')) {
    const bin = await pythonBin(dir, 'ruff');
    if (bin) return { argv: [...bin, 'check', '.'], via: 'conventional:ruff' };
  }
  const pkg = await readJson(path.join(dir, 'package.json'));
  if (pkg) {
    for (const [bin, argv] of /** @type {Array<[string, Array<string>]>} */ ([
      ['eslint', ['npx', '--no-install', 'eslint', '.']],
      ['biome', ['npx', '--no-install', '@biomejs/biome', 'check', '.']]
    ])) {
      try {
        await run('npx', ['--no-install', bin, '--version'], { timeout: 15000, cwd: dir });
        return { argv, via: `conventional:${bin}` };
      } catch {}
    }
  }
  if (await exists(dir, 'Cargo.toml')) {
    try {
      await run('cargo', ['clippy', '--version'], { timeout: 10000 });
      return { argv: ['cargo', 'clippy', '--', '-D', 'warnings'], via: 'conventional:clippy' };
    } catch {}
  }
  return null;
}

/**
 * Summarize test output: exit code is authoritative, counts best-effort.
 * @param {number|null} code @param {string} text
 */
export function summarizeTests(code, text) {
  const t = String(text || '');
  let passed = null;
  let failed = null;
  let m = t.match(/(\d+) failed, (\d+) passed/i) || t.match(/(\d+) passed, (\d+) failed/i);
  if (m) {
    const nums = m.slice(1, 3).map(Number);
    failed = /failed, .* passed/i.test(m[0]) ? nums[0] : nums[1];
    passed = /failed, .* passed/i.test(m[0]) ? nums[1] : nums[0];
  } else if ((m = t.match(/(\d+) passed/i))) passed = Number(m[1]);
  else if ((m = t.match(/ok\s+\S+.*in\s+[\d.]+s/i))) passed = 0;
  if ((m = t.match(/FAILED|failed \d+/i)) && failed === null && code !== 0) failed = 1;
  return { exit_code: code, passed, failed };
}

/**
 * @param {unknown} job @param {Array<string>} baseRoots
 */
async function gatedRepo(job, baseRoots) {
  const jobRec = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  const p = /** @type {Record<string, unknown>} */ (jobRec.request_payload || jobRec.payload || {});
  const raw = String(p.path || '');
  if (!raw || raw.length > 4096) throw new Error('INVALID_PATH');
  const extra = policyExtraRoots(job);
  const roots = [...baseRoots, ...extra.read];
  return { repo: await realAllowed(raw, roots, extra.allowAll === true), params: p, extra };
}

/**
 * @param {string} repo @param {unknown} job @param {Array<string>} writeRoots
 */
async function requireWrite(repo, job, writeRoots) {
  const extra = policyExtraRoots(job);
  await realAllowed(repo, [...writeRoots, ...extra.write], extra.allowAll === true);
}

/**
 * @param {object} [options]
 * @param {Array<string>} [options.readRoots]
 * @param {Array<string>} [options.writeRoots]
 * @param {string|null} [options.appRoot]
 * @param {string|null} [options.workspace]
 */
export function makeProjectHandlers({ readRoots = [], writeRoots = [], appRoot = null, workspace = null } = {}) {
  /**
   * @param {string} repo @param {Array<string>} argv @param {number} timeoutMs
   */
  // Hub-directed cancellation registry: jobId -> tree-kill. Wired from
  // handleSessionCancel so hub timeout/cancel actually stops project work
  // instead of orphaning it (shell children already had this via
  // shellAbortByJob; task/test/lint did not).
  const execTask = async (repo, argv, timeoutMs, abortKey = null) => {
    const started = Date.now();
    const MAX = 8 * 1024 * 1024;
    return await new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let settled = false;
      let stopping = false;
      let stdoutTruncated = false;
      let stderrTruncated = false;
      let wasCancelled = false;
      let timedOut = false;
      let exitCode = null;
      let forceTimer = null;
      let fallbackTimer = null;
      let child = null;
      /** @type {ReturnType<typeof captureSpawnIdentity>} */
      let taskIdentity = null;
      const key = abortKey != null && abortKey !== '' ? String(abortKey) : null;
      const finish = (code, extra) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        clearTimeout(forceTimer);
        clearTimeout(fallbackTimer);
        if (key) taskAbortByJob.delete(key);
        // A bounded fallback must also release our pipe handles. Signalling
        // remains exclusively behind the spawn-identity-verified tree kill.
        if (stopping) {
          child?.stdin?.destroy?.();
          child?.stdout?.destroy?.();
          child?.stderr?.destroy?.();
        }
        resolve({
          exit_code: typeof code === 'number' ? code : exitCode,
          stdout,
          stderr: stderr.slice(-4096),
          stdout_truncated: stdoutTruncated || stdout.length >= MAX,
          stderr_truncated: stderrTruncated || stderr.length > 4096,
          cancelled: wasCancelled,
          duration_ms: Date.now() - started,
          ...(timedOut ? { timed_out: true } : {}),
          ...(extra || {})
        });
      };
      // P2-05b: verified tree-kill (PID-reuse guard). Threads the spawn-time
      // identity (kernel identity + started_at + argv entrypoint); the pre-verify inside
      // terminateSessionTreeAsync fails closed (skipped-unverified, no
      // signal) instead of blind-killing a possibly-recycled PID/group.
      // Residual: an unverifiable PID is left running (finish still settles
      // the op as timed_out/cancelled) rather than risk signalling an
      // unrelated process. Preserves the gentle->force escalation timing
      // via the outer 1500ms timers (the async path also escalates
      // internally after its grace window; the duplicate force is idempotent).
      const taskStartedAt = new Date(started).toISOString();
      const taskExe = Array.isArray(argv) && argv.length > 0 ? String(argv[0]) : null;
      const taskArgList = Array.isArray(argv) ? argv.slice(1).map(String) : null;
      const killTree = (force) => {
        if (!child || settled) return;
        const target = child;
        void terminateSessionTreeAsync(target, {
          platform: process.platform,
          force,
          graceMs: force ? 0 : 1500,
          expectedStartedAt: taskStartedAt,
          expectedPath: taskExe,
          expectedCommandLine: taskArgList,
          expectedIdentity: taskIdentity
        }).catch(() => {});
      };
      if (key) {
        taskAbortByJob.set(key, () => {
          wasCancelled = true;
          if (stopping) return;
          stopping = true;
          clearTimeout(timer);
          killTree(false);
          forceTimer = setTimeout(() => killTree(true), 1500);
          forceTimer.unref?.();
          // Hard fallback: an unkillable tree (D-state, pid reuse race)
          // must not wedge the op forever; hub timeouts bound the wait.
          fallbackTimer = setTimeout(() => finish(null, { cancelled: true }), 10000);
          fallbackTimer.unref?.();
        });
      }
      const timer = setTimeout(() => {
        timedOut = true;
        stopping = true;
        killTree(false);
        forceTimer = setTimeout(() => {
          killTree(true);
          // Requesting force is not evidence of close. Allow a bounded
          // stdio-drain window before the last-resort pipe cleanup.
          fallbackTimer = setTimeout(() => finish(null, { timed_out: true }), 1000);
          fallbackTimer.unref?.();
        }, 1500);
        forceTimer.unref?.();
      }, Math.max(1, timeoutMs));
      if (timer.unref) timer.unref();
      try {
        child = spawn(argv[0], argv.slice(1), {
          cwd: repo,
          // L01b-2: route through the filterInheritedEnv choke point
          // (shellEnvironment) so host secrets (GITHUB_TOKEN/AWS_*) never
          // reach repo task scripts. RUN_ENV applies on top (own values).
          env: { ...shellEnvironment(), ...RUN_ENV },
          windowsHide: true,
          // Detached group leader (posix): tree-kill via kill(-pid) takes
          // npm/sh/pytest grandchildren together so stdio pipes close and
          // 'close' fires. Without this, orphaned grandchildren hold the
          // pipes and cancellation never settles.
          detached: process.platform !== 'win32'
        });
        taskIdentity = captureSpawnIdentity(child);
      } catch (e) {
        clearTimeout(timer);
        finish(null, { spawn_error: String((e && e.message) || e || '') });
        return;
      }
      child.on('error', () => {
        clearTimeout(timer);
        finish(null, { spawn_error: 'SPAWN_FAILED' });
      });
      child.on('exit', (code) => {
        if (typeof code === 'number') exitCode = code;
      });
      // Overflow: same escalate-then-finish as timeout (a surviving
      // tree must not wedge the op: SIGTERM, then SIGKILL, then settle).
      const overflow = () => {
        if (settled || stopping) return;
        stopping = true;
        clearTimeout(timer);
        killTree(false);
        forceTimer = setTimeout(() => {
          killTree(true);
          fallbackTimer = setTimeout(() => finish(null, {}), 1000);
          fallbackTimer.unref?.();
        }, 1500);
        forceTimer.unref?.();
      };
      child.stdout?.on('data', (d) => {
        if (settled) return;
        if (stopping) {
          stdoutTruncated = true;
          return;
        }
        stdout += String(d || '').slice(0, MAX - stdout.length - stderr.length);
        if (stdout.length + stderr.length >= MAX) {
          stdoutTruncated = true;
          overflow();
        }
      });
      child.stderr?.on('data', (d) => {
        if (settled) return;
        if (stopping) {
          stderrTruncated = true;
          return;
        }
        stderr += String(d || '').slice(0, MAX - stdout.length - stderr.length);
        if (stdout.length + stderr.length >= MAX) {
          stderrTruncated = true;
          overflow();
        }
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        finish(code, null);
      });
    });
  };
  // Seconds in, milliseconds out. The old code returned the raw default
  // (300/600) on missing input and capped explicit values against a
  // millisecond max — every project task died at 300-1800ms. A/B evidence:
  // project_run test/lint returned null exits while suites needed seconds.
  // Fractional seconds keep millisecond precision (0.5s -> 500ms).
  const clampTimeout = (/** @type {unknown} */ v, dfltSec, maxSec) => {
    const n = Number(v);
    const ms = Number.isFinite(n) ? Math.round(n * 1000) : Math.round(dfltSec * 1000);
    return Math.max(10, Math.min(maxSec * 1000, ms));
  };
  return {
    project_detect: async (job) => {
      try {
        const { repo } = await gatedRepo(job, readRoots);
        return ok({ platform: process.platform, path: repo, projects: await detectProjects(repo) });
      } catch (e) {
        return fail(e && e.message ? e.message : 'PROJECT_OP_FAILED');
      }
    },
    task_list: async (job) => {
      try {
        const { repo } = await gatedRepo(job, readRoots);
        return ok({ platform: process.platform, path: repo, tasks: await listProjectTasks(repo) });
      } catch (e) {
        return fail(e && e.message ? e.message : 'PROJECT_OP_FAILED');
      }
    },
    task_run: async (job) => {
      try {
        const { repo, params } = await gatedRepo(job, readRoots);
        await requireWrite(repo, job, writeRoots);
        forbidAgentTreeWrite('task_run', [repo], { appRoot, workspace });
        const runner = String(params.runner || '').toLowerCase();
        const name = String(params.task || '');
        // P4 MRTR pilot: an omitted runner resolves across all runners that
        // declare the task. Zero hits fail closed; several hits return the
        // options (never guess) so the hub can ask via input_required.
        if (!runner) {
          const tasks = await listProjectTasks(repo);
          const owners = [...new Set(tasks.filter((t) => t.name === name).map((t) => t.runner))];
          if (owners.length === 0) throw new Error('TASK_NOT_DECLARED');
          if (owners.length > 1)
            return {
              status: 'failed',
              exit_code: null,
              stdout: '',
              stderr: '',
              error: 'TASK_RUNNER_AMBIGUOUS',
              duration_ms: 0,
              result_payload: { options: owners }
            };
          const argv = await resolveTask(repo, owners[0], name);
          if (!argv) throw new Error('TASK_NOT_DECLARED');
          const r = await execTask(repo, argv, clampTimeout(params.timeout_s, 300, 1800), job?.id || job?.job_id);
          return ok({
            platform: process.platform,
            path: repo,
            runner: owners[0],
            task: name,
            ...r,
            truncated: r.stdout_truncated || r.stderr_truncated
          });
        }
        const argv = await resolveTask(repo, runner, name);
        if (!argv) throw new Error('TASK_NOT_DECLARED');
        const r = await execTask(repo, argv, clampTimeout(params.timeout_s, 300, 1800), job?.id || job?.job_id);
        return ok({
          platform: process.platform,
          path: repo,
          runner: runner.toLowerCase(),
          task: name,
          ...r,
          truncated: r.stdout_truncated || r.stderr_truncated
        });
      } catch (e) {
        return fail(e && e.message ? e.message : 'PROJECT_OP_FAILED');
      }
    },
    test_run: async (job) => {
      try {
        const { repo, params } = await gatedRepo(job, readRoots);
        await requireWrite(repo, job, writeRoots);
        forbidAgentTreeWrite('test_run', [repo], { appRoot, workspace });
        const resolved = await conventionalTest(repo);
        if (!resolved) throw new Error('TEST_UNAVAILABLE');
        const r = await execTask(repo, resolved.argv, clampTimeout(params.timeout_s, 600, 1800), job?.id || job?.job_id);
        return ok({
          platform: process.platform,
          path: repo,
          via: resolved.via,
          summary: summarizeTests(r.exit_code, r.stdout + '\n' + r.stderr),
          stdout_tail: String(r.stdout).slice(-8192),
          output_truncated: String(r.stdout).length > 8192 || r.stdout_truncated === true,
          duration_ms: r.duration_ms
        });
      } catch (e) {
        return fail(e && e.message ? e.message : 'PROJECT_OP_FAILED');
      }
    },
    lint_run: async (job) => {
      try {
        const { repo, params } = await gatedRepo(job, readRoots);
        await requireWrite(repo, job, writeRoots);
        forbidAgentTreeWrite('lint_run', [repo], { appRoot, workspace });
        const resolved = await conventionalLint(repo);
        if (!resolved) throw new Error('LINT_UNAVAILABLE');
        const r = await execTask(repo, resolved.argv, clampTimeout(params.timeout_s, 600, 1800), job?.id || job?.job_id);
        return ok({
          platform: process.platform,
          path: repo,
          via: resolved.via,
          summary: summarizeTests(r.exit_code, r.stdout + '\n' + r.stderr),
          stdout_tail: String(r.stdout).slice(-8192),
          output_truncated: String(r.stdout).length > 8192 || r.stdout_truncated === true,
          duration_ms: r.duration_ms
        });
      } catch (e) {
        return fail(e && e.message ? e.message : 'PROJECT_OP_FAILED');
      }
    }
  };
}
