/**
 * Shell execution for the Node Command agent (canonical home of executeShellJob).
 *
 * Pure with respect to the daemon: all host limits arrive via `runtime`
 * ({root, maxTimeoutSeconds, maxStdoutBytes, maxStderrBytes}); the only
 * ambient dependencies are node:child_process and process globals.
 */
import { spawn } from 'node:child_process';

/**
 * @param {unknown} job @returns {Record<string, unknown>}
 */
export function normalizedJobPayload(job) {
  const holder =
    job && typeof job === 'object'
      ? /** @type {{request_payload?: unknown, payload?: unknown}} */ (job)
      : null;
  const raw = holder?.request_payload ?? holder?.payload ?? {};
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object'
        ? /** @type {Record<string, unknown>} */ (parsed)
        : {};
    } catch {
      return {};
    }
  }
  return raw && typeof raw === 'object' ? /** @type {Record<string, unknown>} */ (raw) : {};
}


/**
 * @param {Record<string, string|undefined>} [source]
 */
function shellEnvironment(source = process.env) {
  return Object.fromEntries(
    Object.entries(source).filter(
      ([key]) => !key.startsWith('NC_') && !key.startsWith('CONTROL_PLANE_')
    )
  );
}
/**
 * @param {string} command @param {string} [platform]
 */
function shellInvocation(command, platform = process.platform) {
  if (platform === 'win32')
    return {
      file: process.env.ComSpec || process.env.COMSPEC || 'cmd.exe',
      args: ['/d', '/s', '/c', command]
    };
  return { file: '/bin/bash', args: ['-lc', command] };
}
export function shellChildDetached(platform = process.platform) {
  return platform !== 'win32';
}
/**
 * @param {import('node:child_process').ChildProcess|null|undefined} child @param {string} [platform] @param {boolean} [force]
 */
function terminateShellTree(child, platform = process.platform, force = false) {
  if (!child?.pid) return;
  if (platform === 'win32') {
    const line = 'taskkill /PID ' + child.pid + ' /T /F >NUL 2>&1';
    try {
      spawn(process.env.ComSpec || process.env.COMSPEC || 'cmd.exe', ['/d', '/s', '/c', line], {
        stdio: 'ignore'
      }).unref();
    } catch {}
    return;
  }
  try {
    process.kill(-child.pid, force ? 'SIGKILL' : 'SIGTERM');
  } catch {}
}

/**
 * @param {Array<Buffer>} chunks @param {Buffer|Uint8Array|string} chunk @param {number} currentBytes @param {number} maxBytes
 */
function appendLimited(chunks, chunk, currentBytes, maxBytes) {
  if (currentBytes >= maxBytes) return { bytes: currentBytes, truncated: true };
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  const room = maxBytes - currentBytes;
  const slice = buffer.subarray(0, room);
  if (slice.length) chunks.push(slice);
  return { bytes: currentBytes + slice.length, truncated: buffer.length > room };
}

/**
 * @param {Record<string, unknown>} job
 * @param {{maxStdoutBytes?: number, maxStderrBytes?: number}} [options]
 * @param {{root?: string, maxTimeoutSeconds?: number, maxStdoutBytes?: number, maxStderrBytes?: number}} [runtime]
 */
export async function executeShellJob(job, options = {}, runtime = {}) {
  const payload = normalizedJobPayload(job);
  const command = String(payload.command ?? job.command ?? '');
  if (!command) throw new Error('COMMAND_REQUIRED');
  const root = String(runtime.root ?? process.cwd());
  const maxTimeoutSeconds = Math.max(1, Number(runtime.maxTimeoutSeconds ?? 3600));
  const cwd = String(payload.cwd || job.cwd || root);
  const requestedTimeout = Number(payload.timeout_seconds ?? job.timeout_seconds ?? 30);
  const timeoutSeconds = Math.max(
    1,
    Math.min(Number.isFinite(requestedTimeout) ? requestedTimeout : 30, maxTimeoutSeconds)
  );
  const maxStdout = options.maxStdoutBytes || Number(runtime.maxStdoutBytes ?? 1048576);
  const maxStderr = options.maxStderrBytes || Number(runtime.maxStderrBytes ?? 1048576);
  const started = Date.now();

  return new Promise((resolve) => {
    let stdoutBytes = 0,
      stderrBytes = 0;
    let stdoutTruncated = false,
      stderrTruncated = false;
    /** @type {Array<Buffer>} */
    const stdoutChunks = [],
      /** @type {Array<Buffer>} */
      stderrChunks = [];
    let timedOut = false;
    let settled = false;
    /** @type {ReturnType<typeof setTimeout>|undefined} */
    let killTimer;
    let child;
    try {
      const invocation = shellInvocation(command);
      child = spawn(invocation.file, invocation.args, {
        cwd,
        env: shellEnvironment(),
        detached: shellChildDetached(),
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch (error) {
      resolve({
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: /** @type {Record<string, unknown>} */ (error).message,
        duration_ms: Date.now() - started
      });
      return;
    }

    child.stdout.on('data', (chunk) => {
      const r = appendLimited(stdoutChunks, chunk, stdoutBytes, maxStdout);
      stdoutBytes = r.bytes;
      stdoutTruncated ||= r.truncated;
    });
    child.stderr.on('data', (chunk) => {
      const r = appendLimited(stderrChunks, chunk, stderrBytes, maxStderr);
      stderrBytes = r.bytes;
      stderrTruncated ||= r.truncated;
    });

    const timer = setTimeout(() => {
      timedOut = true;
      terminateShellTree(child, process.platform, false);
      killTimer = setTimeout(() => terminateShellTree(child, process.platform, true), 1500);
    }, timeoutSeconds * 1000);

    /** @param {number|null} code @param {unknown} signal @param {unknown} [spawnError] */
    const finish = (code, signal, spawnError) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      const stdout = Buffer.concat(stdoutChunks).toString('utf8');
      const stderr = Buffer.concat(stderrChunks).toString('utf8');
      const duration_ms = Date.now() - started;
      if (spawnError) {
        resolve({
          status: 'failed',
          exit_code: null,
          stdout,
          stderr,
          error: /** @type {Record<string, unknown>} */ (spawnError).message,
          duration_ms,
          stdout_truncated: stdoutTruncated,
          stderr_truncated: stderrTruncated
        });
      } else if (timedOut) {
        resolve({
          status: 'timeout',
          exit_code: code ?? null,
          stdout,
          stderr,
          error: `command timeout after ${timeoutSeconds}s`,
          duration_ms,
          stdout_truncated: stdoutTruncated,
          stderr_truncated: stderrTruncated
        });
      } else {
        resolve({
          status: code === 0 ? 'completed' : 'failed',
          exit_code: code ?? null,
          stdout,
          stderr,
          error:
            code === 0
              ? null
              : `command exited with code ${code}${signal ? ` signal ${signal}` : ''}`,
          duration_ms,
          stdout_truncated: stdoutTruncated,
          stderr_truncated: stderrTruncated
        });
      }
    };
    child.once('error', (error) => finish(null, null, error));
    child.once('close', (code, signal) => finish(code, signal, null));
  });
}
