// Platform service abstraction (MCP 5.2.0): systemd / SCM / launchd
// differences stay here so models only see service_list/start/stop.
import { execFile } from 'node:child_process';
import os from 'node:os';
import { promisify } from 'node:util';

const run = promisify(execFile);
// First character excludes '-' and ':': the name reaches systemctl/sc/launchctl
// argv in option position, so a leading dash would parse as a flag (option
// injection). Legitimate unit names never start with '-' or ':'.
const SERVICE_RE = /^[A-Za-z0-9_@.][\w@.\-:]{0,127}$/;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Run a service-control verb, preserving the OS exit code and tool output
 * in the error (live Windows showed a bare "Command failed: sc start X"
 * while the real diagnosis — exit 1058, disabled service — was lost).
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {Record<string, unknown>} [options]
 */
async function runVerb(cmd, args, options) {
  try {
    return await run(cmd, args, options);
  } catch (e) {
    const rec = /** @type {{code?: unknown, stdout?: unknown, stderr?: unknown}} */ (
      e && typeof e === 'object' ? e : {}
    );
    const code = Number(rec.code);
    const out = [rec.stdout, rec.stderr]
      .map((x) => String(x || '').trim())
      .filter(Boolean)
      .join('\n')
      .slice(0, 500);
    throw new Error(
      `${cmd} ${args.join(' ')} failed${Number.isInteger(code) ? ` (exit ${code})` : ''}${out ? `: ${out}` : ''}`,
      { cause: e }
    );
  }
}

/**
 * @param {string} service
 */
function checkName(service) {
  if (typeof service !== 'string' || !SERVICE_RE.test(service)) throw new Error('INVALID_SERVICE');
}

/**
 * @param {string} platform
 */
/**
 * Pure parsers (exported for tests): `sc query` blocks, `systemctl
 * list-units` columns, `launchctl list` columns → {name, state}.
 */
export function parseScQueryServices(stdout) {
  const services = [];
  const blocks = String(stdout || '').split(/SERVICE_NAME:\s*/);
  for (const b of blocks) {
    const name = (b.split('\n')[0] || '').trim();
    if (!name) continue;
    const m = b.match(/STATE\s*:\s*\d+\s+(\S+)/);
    services.push({ name, state: m ? m[1].toLowerCase() : 'unknown' });
  }
  return services;
}

/**
 * @param {unknown} stdout
 */
export function parseSystemctlServices(stdout) {
  // Columns: UNIT LOAD ACTIVE SUB DESCRIPTION — ACTIVE is authoritative.
  return String(stdout || '')
    .split('\n')
    .map((l) => l.trim().split(/\s+/))
    .filter((p) => p[0] && p[0].endsWith('.service'))
    .map((p) => ({ name: p[0], state: p[2] || 'unknown' }));
}

/**
 * @param {unknown} stdout
 */
export function parseLaunchctlServices(stdout) {
  // Columns: PID Status Label. A live PID means running.
  return String(stdout || '')
    .split('\n')
    .slice(1)
    .map((l) => l.trim().split(/\s+/))
    .filter((p) => p.length >= 3 && p[2])
    .map((p) => ({ name: p[2], state: p[0] && p[0] !== '-' ? 'running' : 'stopped' }));
}

/**
 * Served `scope` inventory filter (service_manage action=status): `all` (default),
 * `running`, or `stopped`. Running is the platform's affirmative live state —
 * systemctl `active`, SCM `running`, launchd live PID — everything else
 * (inactive, failed, stopped, unknown, transitional) counts as stopped, so
 * the two filters partition the inventory. Case-insensitive; mirrors the
 * process_list SCOPE_INVALID fail-closed convention for unknown values.
 * @param {unknown} state raw per-platform state string
 */
export function isServiceRunningState(state) {
  const s = String(state || '').toLowerCase();
  return s === 'active' || s === 'running';
}

/**
 * Normalize the served `scope` argument. Absent/empty means `all` per the
 * registry default.
 * @param {unknown} raw
 */
export function normalizeServiceScope(raw) {
  if (raw === undefined || raw === null || raw === '') return 'all';
  return String(raw).toLowerCase();
}

/**
 * Apply the `scope` filter to an already-collected service inventory.
 * Pure (exported for tests). Filtering lives here — the agent handler owns
 * the service list — never earlier in dispatch.
 * @param {Array<{name: string, state: string}>} services
 * @param {string} scope normalized scope (`all`|`running`|`stopped`)
 */
export function filterServicesByScope(services, scope) {
  const rows = Array.isArray(services) ? services : [];
  if (scope === 'all') return [...rows];
  const wantRunning = scope === 'running';
  return rows.filter((s) =>
    wantRunning
      ? isServiceRunningState(s && s.state)
      : !isServiceRunningState(s && s.state)
  );
}

async function listServices(platform) {
  if (platform === 'win32') {
    const { stdout } = await run('sc', ['query', 'type=', 'service', 'state=', 'all'], {
      timeout: 20000,
      windowsHide: true
    });
    return parseScQueryServices(stdout);
  }
  if (platform === 'darwin') {
    const { stdout } = await run('launchctl', ['list'], { timeout: 20000 });
    return parseLaunchctlServices(stdout);
  }
  const { stdout } = await run(
    'systemctl',
    ['list-units', '--type=service', '--all', '--no-legend', '--no-pager'],
    { timeout: 20000 }
  );
  return parseSystemctlServices(stdout);
}

/**
 * Faz C: best-effort post-op state check. Never throws — returns
 * 'active', 'inactive' or 'unknown' so callers report what is true instead
 * of what was requested. Self restarts always report 'unknown': the caller
 * is about to die (or already did) and any reading would be pre-restart.
 * @param {string} platform
 * @param {string} service
 */
export async function verifyServiceState(platform, service) {
  try {
    if (platform === 'linux') {
      const userMode = isSelfUnit(service);
      const unit = service.endsWith('.service') ? service : `${service}.service`;
      const args = userMode ? ['--user', 'is-active', unit] : ['is-active', unit];
      const { stdout } = await run('systemctl', args, { timeout: 10000 });
      const state = String(stdout || '').trim();
      return state === 'active'
        ? 'active'
        : state === 'inactive' || state === 'failed'
          ? 'inactive'
          : 'unknown';
    }
    if (platform === 'win32') {
      const { stdout } = await run('sc', ['query', service], { timeout: 10000, windowsHide: true });
      const parsed = parseScQueryServices(stdout);
      const state = parsed.length > 0 ? parsed[0].state : 'unknown';
      return state === 'running' ? 'active' : state === 'stopped' ? 'inactive' : 'unknown';
    }
    if (platform === 'darwin') {
      const label = service.includes('.') ? service : 'com.nc.client';
      const domain = isSelfUnit(service) ? `gui/${os.userInfo().uid}` : 'system';
      await run('launchctl', ['print', `${domain}/${label}`], { timeout: 10000 });
      return 'active';
    }
  } catch {}
  return 'unknown';
}

/**
 * Observe boot-persistence (enablement), not liveness. Used for
 * verify-then-confirm on service_enable/service_disable.
 * @param {string} platform @param {string} service
 */
export async function verifyServiceEnabled(platform, service) {
  try {
    if (platform === 'linux') {
      const userMode = isSelfUnit(service);
      const unit = service.endsWith('.service') ? service : `${service}.service`;
      const args = userMode ? ['--user', 'is-enabled', unit] : ['is-enabled', unit];
      let out = '';
      try {
        ({ stdout: out } = await run('systemctl', args, { timeout: 10000 }));
      } catch (e) {
        // is-enabled exits non-zero when not enabled; the state is on stdout.
        const rec = /** @type {{stdout?: unknown}} */ (e && typeof e === 'object' ? e : {});
        out = String(rec.stdout || '');
      }
      const state = out.trim().split('\n')[0].trim();
      if (state === 'enabled' || state === 'enabled-runtime') return 'enabled';
      if (state === 'disabled' || state === 'masked') return 'disabled';
      return 'unknown';
    }
    if (platform === 'win32') {
      const { stdout } = await run('sc', ['qc', service], { timeout: 10000, windowsHide: true });
      const m = String(stdout || '').match(/START_TYPE\s*:\s*\d+\s+(\w+)/i);
      if (!m) return 'unknown';
      const t = m[1].toUpperCase();
      if (t === 'AUTO_START') return 'enabled';
      if (t === 'DEMAND_START' || t === 'DISABLED') return 'disabled';
      return 'unknown';
    }
    if (platform === 'darwin') {
      const label = service.includes('.') ? service : 'com.nc.client';
      const { uid } = os.userInfo();
      for (const domain of [`gui/${uid}`, 'system']) {
        try {
          const { stdout } = await run('launchctl', ['print-disabled', domain], { timeout: 10000 });
          const hit = String(stdout || '')
            .split('\n')
            .map((l) => l.match(/^\s*"([^"]+)"\s*=>\s*(.*?)\s*$/))
            .find((m) => m && m[1] === label);
          if (hit) return hit[2] === 'true' ? 'disabled' : hit[2] === 'false' ? 'enabled' : 'unknown';
        } catch {}
      }
      return 'unknown';
    }
  } catch {}
  return 'unknown';
}

/**
 * Faz C: names of our own agent unit per platform. Used only to skip
 * post-restart verification for self operations (never for routing).
 * @param {string} service
 */
export function isKnownSelfName(service) {
  const want = String(service || '').toLowerCase();
  return (
    isSelfUnit(service) ||
    want === 'nc-client' ||
    want === 'nc-client.service' ||
    want === 'ncclient' ||
    want === 'com.nc.client'
  );
}
/**
 * User-space mode (Faz A): the agent runs as the operator login user under a
 * user-domain manager (`systemd --user` / LaunchAgent / logon task). Its OWN
 * unit is manageable unprivileged; everything else follows the normal path.
 * @param {string} service
 * @param {NodeJS.ProcessEnv} [env]
 */
export function isSelfUnit(service, env = process.env) {
  if (env.NC_SERVICE_MODE !== 'user') return false;
  const own = String(env.NC_SERVICE_UNIT || 'nc-client').toLowerCase();
  const want = String(service || '').toLowerCase();
  return want === own || want === `${own}.service`;
}

/**
 * Wait until a service reads back as stopped (win32 restart gate: sc stop
 * is async and starting while STOP_PENDING races the SCM). Bounded: a hung
 * stop fails the restart instead of letting start race it.
 * @param {string} platform
 * @param {string} service
 * @param {number} [timeoutMs]
 */
async function waitForServiceInactive(platform, service, timeoutMs = 30000) {
  const t0 = Date.now();
  for (;;) {
    const state = await verifyServiceState(platform, service).catch(() => 'unknown');
    if (state === 'inactive') return;
    if (Date.now() - t0 > timeoutMs) {
      throw new Error(`SERVICE_STOP_TIMEOUT: ${service} did not reach stopped state`);
    }
    await sleep(500);
  }
}

async function controlService(platform, op, service) {
  checkName(service);
  /** @type {Record<string, unknown>} */
  let result = {};
  const wantEnabled = op === 'enable' ? true : op === 'disable' ? false : null;
  // User-mode self-management: no privilege needed, no helper involved.
  if (platform === 'linux' && isSelfUnit(service)) {
    const unit = service.endsWith('.service') ? service : `${service}.service`;
    const verbs = op === 'restart' ? ['restart'] : [op];
    for (const verb of verbs) await run('systemctl', ['--user', verb, unit], { timeout: 30000 });
    result =
      wantEnabled === null
        ? { [op === 'start' ? 'started' : op === 'stop' ? 'stopped' : 'restarted']: true }
        : { enabled: wantEnabled };
  } else if (platform === 'win32' && isSelfUnit(service)) {
    const task = process.env.NC_SERVICE_UNIT || 'NC Client';
    if (wantEnabled !== null) {
      await run('schtasks', ['/change', '/tn', task, wantEnabled ? '/enable' : '/disable'], {
        timeout: 30000,
        windowsHide: true
      });
      result = { enabled: wantEnabled };
    } else if (op === 'stop') {
      await run('schtasks', ['/end', '/tn', task], { timeout: 30000, windowsHide: true });
      result = { stopped: true };
    } else {
      if (op === 'restart') {
        await run('schtasks', ['/end', '/tn', task], { timeout: 30000, windowsHide: true }).catch(
          () => {}
        );
      }
      await run('schtasks', ['/run', '/tn', task], { timeout: 30000, windowsHide: true });
      result = { [op === 'start' ? 'started' : 'restarted']: true };
    }
  } else if (platform === 'darwin' && isSelfUnit(service)) {
    const { uid } = os.userInfo();
    const label = service.includes('.') ? service : 'com.nc.client';
    const target = `gui/${uid}/${label}`;
    if (wantEnabled !== null) {
      await run('launchctl', [wantEnabled ? 'enable' : 'disable', target], { timeout: 30000 });
      result = { enabled: wantEnabled };
    } else if (op === 'restart') {
      await run('launchctl', ['kickstart', '-k', target], { timeout: 30000 });
      result = { restarted: true };
    } else if (op === 'stop') {
      await run('launchctl', ['bootout', target], { timeout: 30000 });
      result = { stopped: true };
    } else {
      await run('launchctl', ['kickstart', target], { timeout: 30000 });
      result = { started: true };
    }
  } else {
    const runOne = async (/** @type {string} */ action) => {
      if (platform === 'win32') {
        if (action === 'enable') {
          await runVerb('sc', ['config', service, 'start=', 'auto'], {
            timeout: 30000,
            windowsHide: true
          });
          return;
        }
        if (action === 'disable') {
          await runVerb('sc', ['config', service, 'start=', 'demand'], {
            timeout: 30000,
            windowsHide: true
          });
          return;
        }
        const verb = action === 'start' ? 'start' : 'stop';
        await runVerb('sc', [verb, service], { timeout: 30000, windowsHide: true });
        return;
      }
      if (platform === 'darwin') {
        if (action === 'enable' || action === 'disable') {
          const { uid } = os.userInfo();
          const label = service.includes('.') ? service : 'com.nc.client';
          await runVerb('launchctl', [action, `gui/${uid}/${label}`], { timeout: 30000 });
          return;
        }
        if (action === 'start') await runVerb('launchctl', ['start', service], { timeout: 30000 });
        else await runVerb('launchctl', ['stop', service], { timeout: 30000 });
        return;
      }
      await runVerb('systemctl', [action, service], { timeout: 30000 });
    };
    if (wantEnabled !== null) {
      await runOne(op);
      result = { enabled: wantEnabled };
    } else if (op === 'restart') {
      try {
        await runOne('stop');
      } catch (stopError) {
        // Restarting a stopped service is not an error — but a failed stop
        // on a live service must surface instead of being masked (a bare
        // .catch(()=>{}) made macOS service_restart PASS while the same
        // service_stop FAILED). Proceed only when the service is observably
        // down; otherwise rethrow the stop failure.
        const state = await verifyServiceState(platform, service).catch(() => 'unknown');
        if (state !== 'inactive') throw stopError;
      }
      if (platform === 'win32') {
        // sc stop is async: starting while STOP_PENDING races the SCM.
        // Poll sc query until STOPPED (bounded); never start blind.
        await waitForServiceInactive(platform, service);
      }
      await runOne('start');
      result = { restarted: true };
    } else {
      await runOne(op);
      result = { [op === 'start' ? 'started' : 'stopped']: true };
    }
  }
  // Faz C verify-then-confirm: report the observed state, not the request.
  // Self operations skip liveness verification (the reader would be pre-restart);
  // enablement has no restart race so it is always observed.
  if (wantEnabled !== null) {
    const observed = await verifyServiceEnabled(platform, service).catch(() => 'unknown');
    result.verified_state = observed;
    result.detail = {
      enabled: observed === 'enabled' ? true : observed === 'disabled' ? false : null,
      verified_state: observed
    };
  } else {
    result.verified_state = isKnownSelfName(service)
      ? 'unknown'
      : await verifyServiceState(platform, service);
  }
  return result;
}

/**
 * @param {unknown} job
 */
function payloadOf(job) {
  const r = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  return /** @type {Record<string, unknown>} */ (r.request_payload || r.payload || {});
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
 * @param {string} [platform]
 * @param {object} [options]
 * @param {(request: unknown) => Promise<unknown>} [options.invokePrivilegedHelper]
 * @param {() => boolean} [options.isPrivilegedHelperAvailable]
 */
export function makeServiceHandlers(
  platform = process.platform,
  { invokePrivilegedHelper = null, isPrivilegedHelperAvailable = null } = {}
) {
  const AUTH_FAILURE_RE =
    /interactive authentication|access denied|permission denied|not authorized|operation not permitted/i;
  /**
   * Run a service verb directly; on Linux privilege failure escalate to the
   * signed service_control privileged-helper operation (dedicated
   * allowlisted systemctl verbs only — never arbitrary shell). Any other
   * failure, a missing helper, or a missing central authorization keeps the
   * original direct error so behavior without the helper is unchanged.
   */
  const controlWithFallback = async (op, service, job) => {
    try {
      return await controlService(platform, op, service);
    } catch (e) {
      const message = String((e && e.message) || e || '');
      // Bail with the original message (chained as cause) so behavior
      // without the helper is byte-identical to the direct-only path.
      // Off Linux, privilege failures name the remedy: system-domain units
      // need root and the privileged helper is Linux-only, so models stop
      // retrying what policy genuinely cannot grant on this host.
      const bail = () => {
        if (platform !== 'linux' && AUTH_FAILURE_RE.test(message)) {
          throw new Error(
            `${message} (SERVICE_PRIVILEGE_REQUIRED: system-domain units need an elevated agent identity and the privileged helper is Linux-only; user-domain units work unprivileged)`,
            { cause: e }
          );
        }
        throw new Error(message, { cause: e });
      };
      if (platform !== 'linux' || !AUTH_FAILURE_RE.test(message)) bail();
      let helperAvailable = typeof invokePrivilegedHelper === 'function';
      if (helperAvailable && typeof isPrivilegedHelperAvailable === 'function') {
        try {
          helperAvailable = isPrivilegedHelperAvailable();
        } catch {
          helperAvailable = false;
        }
      }
      const jobRecord = job && typeof job === 'object' ? job : null;
      const payloadRecord =
        jobRecord &&
        /** @type {Record<string, unknown>} */ (jobRecord).request_payload &&
        typeof (/** @type {Record<string, unknown>} */ (jobRecord).request_payload) === 'object'
          ? /** @type {Record<string, unknown>} */ (
              /** @type {Record<string, unknown>} */ (jobRecord).request_payload
            )
          : null;
      const authorization = payloadRecord ? payloadRecord.privileged_authorization : null;
      if (
        !helperAvailable ||
        !authorization ||
        typeof authorization !== 'object' ||
        Array.isArray(authorization)
      )
        bail();
      let reply;
      try {
        reply = await invokePrivilegedHelper(authorization);
      } catch (invokeError) {
        throw invokeError instanceof Error ? invokeError : e;
      }
      const rec = /** @type {{ok?: unknown, error?: unknown, result?: unknown} | null} */ (
        reply && typeof reply === 'object' ? reply : null
      );
      if (!rec || rec.ok !== true)
        throw new Error(String((rec && rec.error) || 'PRIVILEGED_HELPER_EXECUTION_FAILED'), {
          cause: e
        });
      const result = /** @type {{success?: unknown, message?: unknown}} */ (
        rec.result && typeof rec.result === 'object' ? rec.result : {}
      );
      if (result.success !== true)
        throw new Error(String(result.message || 'SERVICE_CONTROL_FAILED'), { cause: e });
      if (op === 'enable') return { enabled: true };
      if (op === 'disable') return { enabled: false };
      return { [op === 'start' ? 'started' : op === 'stop' ? 'stopped' : 'restarted']: true };
    }
  };
  const mutate = (op) => async (/** @type {unknown} */ job) => {
    try {
      const service = String(payloadOf(job).unit ?? payloadOf(job).service ?? '');
      const detail = await controlWithFallback(op, service, job);
      return ok({ service, ...detail });
    } catch (e) {
      const errorRecord = /** @type {{message?: unknown}} */ (e);
      const service = String(payloadOf(job).unit ?? payloadOf(job).service ?? '');
      // Structured prefix first (models can branch on it), original OS/tool
      // output preserved after the colon for diagnosis.
      const raw = String(errorRecord?.message ?? 'SERVICE_CONTROL_FAILED');
      const code = /^[A-Z][A-Z0-9_]+(:| )/.test(raw)
        ? raw
        : `SERVICE_CONTROL_FAILED: service_${op} ${service} failed: ${raw}`;
      return fail(code);
    }
  };
  return {
    service_list: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        const lim = p.limit == null ? 200 : Math.max(1, Math.min(5000, Number(p.limit) || 200));
        // Served `scope` filter (service_manage action=status): sibling
        // process_list fails closed on unknown scopes, so an advertised
        // value that matches nothing silently must do the same here.
        const scope = normalizeServiceScope(p.scope);
        if (scope !== 'all' && scope !== 'running' && scope !== 'stopped')
          return fail('SCOPE_INVALID');
        const allServices = await listServices(platform);
        // total_count is the post-filter inventory size (pre-truncation),
        // mirroring the package_list contains+limit accounting.
        const filtered = filterServicesByScope(allServices, scope);
        const total_count = filtered.length;
        const truncated = total_count > lim;
        // Every listed unit is queryable: service_status is gated by
        // host-policy admission, not by name.
        return ok({
          services: filtered.slice(0, lim).map((s) => ({
            ...s,
            queryable: true
          })),
          total_count,
          truncated
        });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    service_start: mutate('start'),
    service_stop: mutate('stop'),
    service_restart: mutate('restart'),
    service_enable: mutate('enable'),
    service_disable: mutate('disable')
  };
}
