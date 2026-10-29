/**
 * Container and compose operations for the NC agent (contract 5.17.0).
 * Pure parsers are exported for unit tests; handlers exec argv-form
 * commands (no shell) with bounded output, mirroring project-ops.mjs.
 * Engine auto-detects docker → podman → nerdctl; compose prefers the
 * `docker compose` plugin, then `docker-compose`, then `podman-compose`.
 * compose_op runs only allowlisted subcommands in a roots-gated project
 * directory with the agent-tree write ban.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { constants as fsConstants } from 'node:fs';
import { access } from 'node:fs/promises';
import path from 'node:path';
import { realAllowed } from '../structured-ops/structured-ops.mjs';
import { forbidAgentTreeWrite } from '../filesystem/mutation-ops.mjs';
import { policyExtraRoots } from '../policy/host-policy.mjs';
import { invokePrivilegedHelper as defaultInvokePrivilegedHelper } from '../../privileged-helper/privileged-helper-ipc.mjs';

const run = promisify(execFile);
const MAX_ROWS = 200;
const MAX_LOG_BYTES = 65536;
const COMPOSE_OPS = ['up', 'down', 'restart', 'pull', 'stop', 'start'];

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
 * PATH scan without a shell.
 * @param {string} cmd
 */
async function have(cmd) {
  const dirs = String(process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const names =
    process.platform === 'win32' && !/\.[^.\\/]+$/.test(cmd)
      ? [cmd + '.exe', cmd + '.cmd', cmd + '.bat']
      : [cmd];
  for (const dir of dirs) {
    for (const n of names) {
      try {
        await access(path.join(dir, n), fsConstants.X_OK);
        return true;
      } catch {}
    }
  }
  return false;
}

/**
 * Resolve the container engine: docker, podman or nerdctl.
 */
export async function detectEngine() {
  for (const e of ['docker', 'podman', 'nerdctl']) {
    if (await have(e)) return e;
  }
  throw new Error('CONTAINER_ENGINE_UNAVAILABLE');
}

/**
 * Resolve the compose frontend: [cmd, ...prefixArgs].
 */
export async function detectCompose() {
  if (await have('docker')) {
    try {
      await run('docker', ['compose', 'version'], { timeout: 15000 });
      return { cmd: 'docker', prefix: ['compose'] };
    } catch {}
  }
  if (await have('docker-compose')) return { cmd: 'docker-compose', prefix: [] };
  if (await have('podman-compose')) return { cmd: 'podman-compose', prefix: [] };
  if (await have('podman')) {
    try {
      await run('podman', ['compose', 'version'], { timeout: 15000 });
      return { cmd: 'podman', prefix: ['compose'] };
    } catch {}
  }
  throw new Error('COMPOSE_UNAVAILABLE');
}

/**
 * Verify socket accessibility for local daemon engines.
 * Returns true when accessible, throws error when privilege is denied.
 * @param {string} engine
 */
export async function checkSocketAccess(engine) {
  if (process.platform === 'win32') return true;
  let socketPath = null;
  if (process.env.DOCKER_HOST && process.env.DOCKER_HOST.startsWith('unix://')) {
    socketPath = process.env.DOCKER_HOST.slice(7);
  } else if (engine === 'docker') {
    socketPath = '/var/run/docker.sock';
  } else if (engine === 'podman') {
    const uid = typeof process.getuid === 'function' ? process.getuid() : null;
    const userSock = uid !== null ? `/run/user/${uid}/podman/podman.sock` : null;
    if (userSock) {
      try {
        await access(userSock, fsConstants.R_OK | fsConstants.W_OK);
        return true;
      } catch {}
    }
    socketPath = '/run/podman/podman.sock';
  }
  if (socketPath) {
    try {
      await access(socketPath, fsConstants.R_OK | fsConstants.W_OK);
    } catch (e) {
      const code = e && typeof e === 'object' && 'code' in e ? e.code : null;
      if (code === 'EACCES' || code === 'EPERM') {
        throw Object.assign(new Error('CONTAINER_PRIVILEGE_REQUIRED'), { code: 'EACCES' });
      }
    }
  }
  return true;
}

/**
 * Daemon socket path for an engine, without requiring access to it.
 * Existence (not readability) is what the helper-mediated probe needs:
 * the root helper can use a socket the agent identity cannot read.
 * @param {string} engine
 */
export function socketPathForEngine(engine) {
  if (process.platform === 'win32') return null;
  if (process.env.DOCKER_HOST && process.env.DOCKER_HOST.startsWith('unix://')) {
    return process.env.DOCKER_HOST.slice(7);
  }
  if (engine === 'docker') return '/var/run/docker.sock';
  if (engine === 'podman') return '/run/podman/podman.sock';
  return null;
}

/**
 * Helper-mediated container readiness (GAP-021 truthfulness fix): proves the
 * engine the root helper would drive is actually present — binary on PATH
 * plus a live daemon socket path — instead of treating "helper exists" as
 * "docker works". A socket the agent cannot read still counts: the root
 * helper can. A missing binary or missing socket fails closed even with a
 * healthy helper, so hosts without Docker stop advertising container_*.
 * @param {object} [options]
 * @param {(() => boolean)|null} [options.isAvailable] helper availability probe
 * @returns {Promise<{available: boolean, engine?: string, reason?: string|null}>}
 */
export async function checkHelperContainerReadiness({ isAvailable = null } = {}) {
  try {
    if (typeof isAvailable === 'function' && !isAvailable())
      return { available: false, reason: 'PRIVILEGED_HELPER_NOT_AVAILABLE' };
  } catch {
    return { available: false, reason: 'PRIVILEGED_HELPER_NOT_AVAILABLE' };
  }
  let engine;
  try {
    engine = await detectEngine();
  } catch {
    return { available: false, reason: 'CONTAINER_ENGINE_UNAVAILABLE' };
  }
  const socketPath = socketPathForEngine(engine);
  if (socketPath) {
    try {
      await access(socketPath);
    } catch {
      return { available: false, engine, reason: 'CONTAINER_ENGINE_DOWN' };
    }
  }
  return { available: true, engine, reason: null };
}

/**
 * Helper-mediated compose readiness: same presence proof for the compose
 * frontend plus the engine socket it drives. Standalone frontends
 * (docker-compose/podman-compose) talk to their engine socket by default,
 * so the socket check follows the frontend family.
 * @param {object} [options]
 * @param {(() => boolean)|null} [options.isAvailable] helper availability probe
 * @returns {Promise<{available: boolean, cmd?: string, reason?: string|null}>}
 */
export async function checkHelperComposeReadiness({ isAvailable = null } = {}) {
  try {
    if (typeof isAvailable === 'function' && !isAvailable())
      return { available: false, reason: 'PRIVILEGED_HELPER_NOT_AVAILABLE' };
  } catch {
    return { available: false, reason: 'PRIVILEGED_HELPER_NOT_AVAILABLE' };
  }
  let compose;
  try {
    compose = await detectCompose();
  } catch {
    return { available: false, reason: 'COMPOSE_UNAVAILABLE' };
  }
  const family = String(compose.cmd || '').includes('podman') ? 'podman' : 'docker';
  const socketPath = socketPathForEngine(family);
  if (socketPath && process.platform !== 'win32') {
    try {
      await access(socketPath);
    } catch {
      return { available: false, cmd: compose.cmd, reason: 'COMPOSE_ENGINE_UNREACHABLE' };
    }
  }
  return { available: true, cmd: compose.cmd, reason: null };
}

/**
 * Non-destructive readiness probe for container capability (GAP-021).
 * Distinguishes binary presence from live engine socket accessibility and identity permissions.
 * @returns {Promise<{available: boolean, engine?: string, reason?: string, stage?: 'binary'|'engine'|'identity'|'ready'}>}
 */
export async function checkContainerReadiness() {
  let engine;
  try {
    engine = await detectEngine();
  } catch {
    return { available: false, stage: 'binary', reason: 'CONTAINER_ENGINE_UNAVAILABLE' };
  }
  try {
    await checkSocketAccess(engine);
  } catch (err) {
    return { available: false, engine, stage: 'identity', reason: 'CONTAINER_PRIVILEGE_REQUIRED' };
  }
  try {
    await run(engine, ['ps', '-q', '--no-trunc'], { timeout: 5000 });
    return { available: true, engine, stage: 'ready' };
  } catch (err) {
    const msg = String((err && /** @type {any} */ (err).message) || '');
    if (/permission denied|socket|connect|privilege/i.test(msg)) {
      return { available: false, engine, stage: 'identity', reason: 'CONTAINER_PRIVILEGE_REQUIRED' };
    }
    return { available: false, engine, stage: 'engine', reason: 'CONTAINER_ENGINE_DOWN' };
  }
}

/**
 * Non-destructive readiness probe for compose capability (GAP-021).
 * Separates compose frontend and engine access prerequisites.
 * @returns {Promise<{available: boolean, cmd?: string, reason?: string, stage?: 'compose_frontend'|'engine'|'identity'|'ready'}>}
 */
export async function checkComposeReadiness() {
  let compose;
  try {
    compose = await detectCompose();
  } catch {
    return { available: false, stage: 'compose_frontend', reason: 'COMPOSE_UNAVAILABLE' };
  }
  if (compose.cmd === 'docker' || compose.cmd === 'podman') {
    try {
      await checkSocketAccess(compose.cmd);
    } catch (err) {
      return { available: false, cmd: compose.cmd, stage: 'identity', reason: 'CONTAINER_PRIVILEGE_REQUIRED' };
    }
  }
  try {
    const args = [...compose.prefix, 'ls', '--format', 'json'];
    await run(compose.cmd, args, { timeout: 5000 });
    return { available: true, cmd: compose.cmd, stage: 'ready' };
  } catch (err) {
    const msg = String((err && /** @type {any} */ (err).message) || '');
    if (/permission denied|socket|connect|privilege/i.test(msg)) {
      return { available: false, cmd: compose.cmd, stage: 'identity', reason: 'CONTAINER_PRIVILEGE_REQUIRED' };
    }
    return { available: false, cmd: compose.cmd, stage: 'engine', reason: 'COMPOSE_ENGINE_UNREACHABLE' };
  }
}

/**
 * Non-destructive readiness probe for journal readability (NC-CERT-004).
 * On Linux, verifies effective access to systemd journal (adm/systemd-journal group).
 * @param {string} [platform]
 * @returns {Promise<{available: boolean, stage: 'ready'|'identity'|'journal', reason?: string}>}
 */
export async function checkJournalReadiness(platform = process.platform) {
  if (platform !== 'linux') {
    return { available: true, stage: 'ready' };
  }
  if (!(await have('journalctl'))) {
    return { available: false, stage: 'journal', reason: 'JOURNAL_UNAVAILABLE' };
  }
  try {
    const { stdout, stderr } = await run('journalctl', ['-n', '1', '--quiet'], { timeout: 5000 });
    const combined = `${stdout || ''} ${stderr || ''}`;
    if (/insufficient permissions|not seeing messages/i.test(combined)) {
      return { available: false, stage: 'identity', reason: 'JOURNAL_PRIVILEGE_REQUIRED' };
    }
    return { available: true, stage: 'ready' };
  } catch (err) {
    const msg = String((err && (/** @type {any} */ (err).stderr || /** @type {any} */ (err).message)) || '');
    if (/permission|insufficient permissions|access denied|not seeing messages/i.test(msg)) {
      return { available: false, stage: 'identity', reason: 'JOURNAL_PRIVILEGE_REQUIRED' };
    }
    return { available: false, stage: 'journal', reason: 'JOURNAL_UNAVAILABLE' };
  }
}

/**
 * Parse `docker ps --format {{json .}}` / `podman ps --format json` rows.
 * @param {string} text
 */
export function parsePsRows(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    const t = line.trim();
    if (!t) continue;
    let r = null;
    try {
      r = JSON.parse(t.startsWith('[') ? t : t);
    } catch {
      continue;
    }
    const rows = Array.isArray(r) ? r : [r];
    for (const row of rows) {
      const rec = /** @type {Record<string, unknown>} */ (row && typeof row === 'object' ? row : {});
      const names = rec.Names ?? rec.NAMES ?? rec.Name ?? rec.name;
      const name = Array.isArray(names) ? String(names[0] || '') : String(names || '');
      const id = String(rec.ID ?? rec.Id ?? rec.id ?? '');
      if (!id && !name) continue;
      out.push({
        id: id.slice(0, 12),
        name: name.replace(/^\//, ''),
        image: String(rec.Image ?? rec.image ?? ''),
        state: String(rec.State ?? rec.state ?? rec.Status ?? rec.status ?? ''),
        status: String(rec.Status ?? rec.status ?? rec.State ?? rec.state ?? '')
      });
    }
  }
  return out;
}

/**
 * Parse `docker compose ls --format json` rows.
 * @param {string} text
 */
export function parseComposeLs(text) {
  const t = String(text || '').trim();
  if (!t) return [];
  try {
    const v = JSON.parse(t);
    const rows = Array.isArray(v) ? v : [v];
    return rows
      .map((r) => {
        const rec = /** @type {Record<string, unknown>} */ (r && typeof r === 'object' ? r : {});
        return {
          name: String(rec.Name ?? rec.name ?? ''),
          status: String(rec.Status ?? rec.status ?? ''),
          config_files: String(rec.ConfigFiles ?? rec.configFiles ?? rec.config_files ?? '')
        };
      })
      .filter((r) => r.name);
  } catch {
    return [];
  }
}

/**
 * @param {unknown} e
 */
function containerOrThrow(e) {
  const errRec = /** @type {{message?: unknown}} */ (e && typeof e === 'object' ? e : {});
  const message = String(errRec.message || (typeof e === 'string' ? e : '') || '');
  if (/command not found|not recognized|ENOENT/i.test(message))
    throw new Error('CONTAINER_ENGINE_UNAVAILABLE');
  if (/no such container|no such object/i.test(message)) throw new Error('CONTAINER_NOT_FOUND');
  if (/permission denied|access is denied|eacces|operation not permitted/i.test(message)) {
    // F15: the envelope `code` field carries a stable taxonomy code only —
    // human prose rides `message` via the hub mapper, never the code. The
    // group-membership guidance lives in the served description/registry.
    throw new Error('CONTAINER_PRIVILEGE_REQUIRED', { cause: e });
  }
  throw new Error(message.slice(0, 2000) || 'CONTAINER_OP_FAILED', { cause: e });
}

const PRIVILEGE_RE =
  /EACCES|EPERM|permission denied|access is denied|operation not permitted|cannot connect to the docker daemon|access denied|CONTAINER_PRIVILEGE_REQUIRED|PRIVILEGE_REQUIRED/i;

/**
 * @param {unknown} job
 */
function payloadOf(job) {
  const r = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  return /** @type {Record<string, unknown>} */ (r.request_payload || r.payload || {});
}

/**
 * Extract the centrally-signed privileged-helper envelope. The control plane
 * attaches it as `request_payload.privileged_authorization` (service verbs
 * merge it into the original payload; deep-system verbs dispatch with the
 * envelope as the payload). `privileged_envelope` is accepted as an alias.
 * @param {unknown} job
 */
function extractPrivilegedAuthorization(job) {
  if (!job || typeof job !== 'object' || Array.isArray(job)) return null;
  const rec = /** @type {Record<string, unknown>} */ (job);
  for (const key of ['privileged_authorization', 'privileged_envelope']) {
    const v = rec[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) return v;
  }
  const payload = payloadOf(job);
  for (const key of ['privileged_authorization', 'privileged_envelope']) {
    const v = payload[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) return v;
  }
  return null;
}

/**
 * @param {unknown} e
 */
function isPrivilegeError(e) {
  const rec = /** @type {{code?: unknown, stdout?: unknown, stderr?: unknown, message?: unknown, cause?: unknown}} */ (
    e && typeof e === 'object' ? e : {}
  );
  if (rec.code === 'EACCES' || rec.code === 'EPERM') return true;
  const parts = [rec.message, rec.stdout, rec.stderr, typeof e === 'string' ? e : '']
    .map((x) => String(x || ''))
    .filter(Boolean);
  // execFile failures carry `code` as the exit code (number) plus message on
  // `message`; check the mapped cause chain as well.
  try {
    const cause = /** @type {{message?: unknown}} */ (rec.cause || {});
    if (cause && cause.message) parts.push(String(cause.message));
  } catch {}
  return PRIVILEGE_RE.test(parts.join('\n'));
}

/**
 * Dispatch the signed envelope to the helper socket/pipe. Returns the
 * helper `result` on success, throws the ORIGINAL direct error when the
 * helper is unavailable, has no envelope, or reports failure — so the
 * control plane observes the user-space EACCES/CONTAINER_PRIVILEGE_REQUIRED.
 * @param {unknown} job
 * @param {unknown} directError
 * @param {(request: unknown) => Promise<unknown>|null} invoke
 * @param {(() => boolean)|null} isAvailable
 */
async function dispatchHelperResult(job, directError, invoke, isAvailable) {
  let available = typeof invoke === 'function';
  if (available && typeof isAvailable === 'function') {
    try {
      available = isAvailable();
    } catch {
      available = false;
    }
  }
  const authorization = extractPrivilegedAuthorization(job);
  if (!available || !authorization) throw directError;
  let reply;
  try {
    reply = await invoke(authorization);
  } catch {
    throw directError;
  }
  const rec = reply && typeof reply === 'object' ? /** @type {Record<string, any>} */ (reply) : null;
  if (!rec || rec.ok !== true) throw directError;
  const result = rec.result && typeof rec.result === 'object' ? rec.result : null;
  if (!result || result.success !== true) throw directError;
  return result;
}

/**
 * @param {unknown} job @param {Array<string>} baseRoots
 */
async function gatedDir(job, baseRoots, write = false) {
  const jobRec = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  const p = /** @type {Record<string, unknown>} */ (jobRec.request_payload || jobRec.payload || {});
  const raw = String(p.project_dir || p.path || '');
  if (!raw || raw.length > 4096) throw new Error('INVALID_PATH');
  const extra = policyExtraRoots(job);
  const roots = [...baseRoots, ...(write ? extra.write : extra.read)];
  return { dir: await realAllowed(raw, roots, extra.allowAll === true), params: p, extra };
}

/**
 * Project only bounded diagnostics from the already retrieved engine record.
 * @param {Record<string, any>} info
 */
function containerDiagnostics(info) {
  const exitCode = info.State?.ExitCode;
  const oomKilled = info.State?.OOMKilled;
  const restartCount = info.RestartCount;
  const restartPolicy = info.HostConfig?.RestartPolicy?.Name;
  const composeWorkingDir = info.Config?.Labels?.['com.docker.compose.project.working_dir'];
  return {
    exit_code: Number.isSafeInteger(exitCode) ? exitCode : null,
    oom_killed: typeof oomKilled === 'boolean' ? oomKilled : null,
    restart_count: Number.isSafeInteger(restartCount) && restartCount >= 0 ? restartCount : null,
    restart_policy: typeof restartPolicy === 'string' && /^[a-z][a-z0-9-]{0,63}$/i.test(restartPolicy)
      ? restartPolicy : null,
    compose_working_dir: typeof composeWorkingDir === 'string' && composeWorkingDir.length > 0 &&
      composeWorkingDir.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(composeWorkingDir)
      ? composeWorkingDir : null
  };
}

/**
 * @param {object} [options]
 * @param {Array<string>} [options.readRoots]
 * @param {Array<string>} [options.writeRoots]
 * @param {string|null} [options.appRoot]
 * @param {string|null} [options.workspace]
 * @param {(request: unknown) => Promise<unknown>} [options.invokePrivilegedHelper]
 * @param {() => boolean} [options.isPrivilegedHelperAvailable]
 */
export function makeContainerHandlers({ readRoots = [], writeRoots = [], appRoot = null, workspace = null, invokePrivilegedHelper = null, isPrivilegedHelperAvailable = null } = {}) {
  const invoke = invokePrivilegedHelper ?? defaultInvokePrivilegedHelper;
  return {
    container_list: async (job) => {
      try {
        const engine = await detectEngine();
        try {
          await checkSocketAccess(engine);
        } catch (socketError) {
          if (isPrivilegeError(socketError)) {
            try {
              const helperResult = await dispatchHelperResult(
                job,
                socketError,
                invoke,
                isPrivilegedHelperAvailable
              );
              const rows = parsePsRows(String(helperResult.output_tail || '')).slice(0, MAX_ROWS);
              return ok({
                platform: process.platform,
                engine: String(helperResult.engine || engine),
                containers: rows,
                truncated: rows.length >= MAX_ROWS,
                privileged: true
              });
            } catch {
              try {
                containerOrThrow(socketError);
              } catch (mapped) {
                return fail(mapped && mapped.message ? mapped.message : 'CONTAINER_OP_FAILED');
              }
            }
          }
          throw socketError;
        }
        const { stdout } = await run(engine, ['ps', '-a', '--format', '{{json .}}'], {
          timeout: 30000,
          maxBuffer: 4 * 1024 * 1024
        });
        const rows = parsePsRows(stdout).slice(0, MAX_ROWS);
        return ok({ platform: process.platform, engine, containers: rows, truncated: rows.length >= MAX_ROWS });
      } catch (e) {
        let mappedMessage = 'CONTAINER_OP_FAILED';
        try {
          containerOrThrow(e);
        } catch (mapped) {
          mappedMessage = mapped && mapped.message ? mapped.message : 'CONTAINER_OP_FAILED';
        }
        if (isPrivilegeError(e) || /CONTAINER_PRIVILEGE_REQUIRED/.test(String(mappedMessage))) {
          try {
            const helperResult = await dispatchHelperResult(
              job,
              e,
              invoke,
              isPrivilegedHelperAvailable
            );
            const rows = parsePsRows(String(helperResult.output_tail || '')).slice(0, MAX_ROWS);
            return ok({
              platform: process.platform,
              engine: String(helperResult.engine || 'docker'),
              containers: rows,
              truncated: rows.length >= MAX_ROWS,
              privileged: true
            });
          } catch {
            return fail(mappedMessage);
          }
        }
        return fail(mappedMessage);
      }
    },
    container_inspect: async (job) => {
      try {
        const p = (job && (job.request_payload || job.payload)) || {};
        const name = String(p.container || p.container_name || '');
        // Anchored docker-name grammar (mirrors the privileged helper): the name
        // reaches docker argv in option position, so a leading dash would parse
        // as a flag. Length, whitespace, metachar, newline and NUL all fail here.
        if (!name || !/^[A-Za-z0-9][A-Za-z0-9_.\-]{0,255}$/.test(name)) throw new Error('INVALID_CONTAINER');
        const engine = await detectEngine();
        const { stdout } = await run(engine, ['inspect', name], {
          timeout: 30000,
          maxBuffer: 4 * 1024 * 1024
        });
        let parsed = null;
        try {
          parsed = JSON.parse(String(stdout || '').trim() || 'null');
        } catch {
          throw new Error('CONTAINER_PARSE_FAILED');
        }
        const rec = Array.isArray(parsed) ? parsed[0] : parsed;
        if (!rec || typeof rec !== 'object') throw new Error('CONTAINER_NOT_FOUND');
        const info = /** @type {Record<string, unknown>} */ (rec);
        const state = /** @type {Record<string, unknown>} */ (
          info.State && typeof info.State === 'object' ? info.State : {}
        );
        const imgCfg = /** @type {{Image?: unknown}} */ (
          info.Config && typeof info.Config === 'object' ? info.Config : {}
        );
        return ok({
          platform: process.platform,
          engine,
          container: String(info.Name || info.name || name).replace(/^\//, ''),
          image: String(info.Image ?? info.image ?? imgCfg.Image ?? ''),
          state: String(state.Status ?? state.status ?? ''),
          running: state.Running === true,
          mounts: Array.isArray(info.Mounts) ? info.Mounts.length : null,
          ...containerDiagnostics(info)
        });
      } catch (e) {
        let mappedMessage = 'CONTAINER_OP_FAILED';
        try {
          containerOrThrow(e);
        } catch (mapped) {
          mappedMessage = mapped && mapped.message ? mapped.message : 'CONTAINER_OP_FAILED';
        }
        if (isPrivilegeError(e) || /CONTAINER_PRIVILEGE_REQUIRED/.test(String(mappedMessage))) {
          try {
            const helperResult = await dispatchHelperResult(
              job,
              e,
              invoke,
              isPrivilegedHelperAvailable
            );
            let parsed = null;
            try {
              parsed = JSON.parse(String(helperResult.output_tail || '').trim() || 'null');
            } catch {
              return fail(mappedMessage);
            }
            const rec = Array.isArray(parsed) ? parsed[0] : parsed;
            if (!rec || typeof rec !== 'object') return fail(mappedMessage);
            const info = /** @type {Record<string, unknown>} */ (rec);
            const state = /** @type {Record<string, unknown>} */ (
              info.State && typeof info.State === 'object' ? info.State : {}
            );
            const imgCfg = /** @type {{Image?: unknown}} */ (
              info.Config && typeof info.Config === 'object' ? info.Config : {}
            );
            const p = (job && (job.request_payload || job.payload)) || {};
            const name = String(p.container || p.container_name || helperResult.container || '');
            return ok({
              platform: process.platform,
              engine: String(helperResult.engine || 'docker'),
              container: String(info.Name || info.name || name).replace(/^\//, ''),
              image: String(info.Image ?? info.image ?? imgCfg.Image ?? ''),
              state: String(state.Status ?? state.status ?? ''),
              running: state.Running === true,
              mounts: Array.isArray(info.Mounts) ? info.Mounts.length : null,
              ...containerDiagnostics(info),
              privileged: true
            });
          } catch {
            return fail(mappedMessage);
          }
        }
        return fail(mappedMessage);
      }
    },
    container_logs: async (job) => {
      try {
        const p = (job && (job.request_payload || job.payload)) || {};
        const name = String(p.container || p.container_name || '');
        // Same anchored grammar as container_inspect (see above): option-position argv.
        if (!name || !/^[A-Za-z0-9][A-Za-z0-9_.\-]{0,255}$/.test(name)) throw new Error('INVALID_CONTAINER');
        const tail = p.tail == null ? 200 : Math.max(1, Math.min(2000, Number(p.tail) || 200));
        const engine = await detectEngine();
        const { stdout } = await run(engine, ['logs', '--tail', String(tail), name], {
          timeout: 30000,
          maxBuffer: 4 * 1024 * 1024
        });
        const text = String(stdout || '');
        const truncated = text.length >= MAX_LOG_BYTES;
        return ok({
          platform: process.platform,
          engine,
          container: name,
          truncated,
          logs: truncated ? text.slice(-MAX_LOG_BYTES) : text
        });
      } catch (e) {
        let mappedMessage = 'CONTAINER_OP_FAILED';
        try {
          containerOrThrow(e);
        } catch (mapped) {
          mappedMessage = mapped && mapped.message ? mapped.message : 'CONTAINER_OP_FAILED';
        }
        if (isPrivilegeError(e) || /CONTAINER_PRIVILEGE_REQUIRED/.test(String(mappedMessage))) {
          try {
            const helperResult = await dispatchHelperResult(
              job,
              e,
              invoke,
              isPrivilegedHelperAvailable
            );
            const text = String(helperResult.output_tail || '');
            const truncated = text.length >= MAX_LOG_BYTES;
            const p = (job && (job.request_payload || job.payload)) || {};
            const name = String(p.container || p.container_name || helperResult.container || '');
            return ok({
              platform: process.platform,
              engine: String(helperResult.engine || 'docker'),
              container: name,
              truncated,
              logs: truncated ? text.slice(-MAX_LOG_BYTES) : text,
              privileged: true
            });
          } catch {
            return fail(mappedMessage);
          }
        }
        return fail(mappedMessage);
      }
    },
    compose_list: async (job) => {
      try {
        const { cmd, prefix } = await detectCompose();
        if (cmd === 'docker' || cmd === 'podman') {
          try {
            await checkSocketAccess(cmd);
          } catch (socketError) {
            if (isPrivilegeError(socketError)) {
              try {
                const helperResult = await dispatchHelperResult(
                  job,
                  socketError,
                  invoke,
                  isPrivilegedHelperAvailable
                );
                return ok({
                  platform: process.platform,
                  frontend: String(helperResult.frontend || 'docker compose'),
                  projects: parseComposeLs(String(helperResult.output_tail || '')),
                  privileged: true
                });
              } catch {
                // F15: stable taxonomy code only (see containerOrThrow).
                return fail('CONTAINER_PRIVILEGE_REQUIRED');
              }
            }
            throw socketError;
          }
        }
        const { stdout } = await run(cmd, [...prefix, 'ls', '--format', 'json'], { timeout: 30000 });
        return ok({
          platform: process.platform,
          frontend: [cmd, ...prefix].join(' '),
          projects: parseComposeLs(stdout)
        });
      } catch (e) {
        const message = String((e && e.message) || e || '');
        if (/command not found|not recognized|ENOENT|COMPOSE_UNAVAILABLE/i.test(message))
          return fail('COMPOSE_UNAVAILABLE');
        if (isPrivilegeError(e)) {
          try {
            const helperResult = await dispatchHelperResult(
              job,
              e,
              invoke,
              isPrivilegedHelperAvailable
            );
            return ok({
              platform: process.platform,
              frontend: String(helperResult.frontend || 'docker compose'),
              projects: parseComposeLs(String(helperResult.output_tail || '')),
              privileged: true
            });
          } catch {
            // F15: stable taxonomy code only (see containerOrThrow).
            return fail('CONTAINER_PRIVILEGE_REQUIRED');
          }
        }
        return fail(message.slice(0, 2000) || 'CONTAINER_OP_FAILED');
      }
    },
    compose_op: async (job) => {
      try {
        const { dir, params, extra } = await gatedDir(job, readRoots, true);
        await realAllowed(dir, [...writeRoots, ...extra.write], extra.allowAll === true);
        forbidAgentTreeWrite('compose_op', [dir], { appRoot, workspace });
        const op = String(params.action || params.op || '').toLowerCase();
        if (!COMPOSE_OPS.includes(op)) throw new Error('INVALID_COMPOSE_OP');
        const { cmd, prefix } = await detectCompose();
        const args = [...prefix];
        if (op === 'up') args.push('up', '-d');
        else args.push(op);
        const started = Date.now();
        try {
          const { stdout } = await run(cmd, args, {
            timeout: 600000,
            cwd: dir,
            maxBuffer: 4 * 1024 * 1024
          });
          return ok({
            platform: process.platform,
            project_dir: dir,
            action: op,
            op,
            exit_code: 0,
            output_tail: String(stdout || '').slice(-4096),
            duration_ms: Date.now() - started
          });
        } catch (e) {
          if (isPrivilegeError(e)) {
            const helperResult = await dispatchHelperResult(
              job,
              e,
              invoke,
              isPrivilegedHelperAvailable
            );
            return ok({
              platform: process.platform,
              project_dir: dir,
              action: op,
              op,
              exit_code: 0,
              output_tail: String(helperResult.output_tail || '').slice(-4096),
              duration_ms: Date.now() - started,
              privileged: true
            });
          }
          containerOrThrow(e);
        }
      } catch (e) {
        const message = String((e && e.message) || e || 'CONTAINER_OP_FAILED');
        if (isPrivilegeError(e) || /CONTAINER_PRIVILEGE_REQUIRED/.test(message)) {
          try {
            const helperResult = await dispatchHelperResult(
              job,
              e,
              invoke,
              isPrivilegedHelperAvailable
            );
            const p = payloadOf(job);
            const rawDir = String(p.project_dir || p.path || '');
            const op = String(p.action || p.op || '').toLowerCase();
            return ok({
              platform: process.platform,
              project_dir: rawDir,
              action: op,
              op,
              exit_code: 0,
              output_tail: String(helperResult.output_tail || '').slice(-4096),
              duration_ms: 0,
              privileged: true
            });
          } catch {
            return fail(message);
          }
        }
        return fail(message);
      }
    }
  };
}
