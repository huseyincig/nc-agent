import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { connectWebSocket } from './ws-client.mjs';
import { makeStructuredHandlers, extendStructuredHandlers } from '../structured-ops/structured-ops.mjs';
import {
  makeDiagnosticsHandlers,
  shouldHandleDiagnosticsCli,
  runDiagnosticsCommand
} from '../diagnostics/diagnostics-ops.mjs';
import { shellInvocation, shellChildDetached } from '../shell/shell-ops.mjs';
import { reconnectDelayMs, nextSessionAttempt, SESSION_BACKOFF } from './session-reconnect.mjs';
import { makeSystemLogHandlers } from '../logs/system-log-ops.mjs';
import { makePackageHandlers } from '../packages/package-ops.mjs';
import { makeGitHandlers } from '../git/git-ops.mjs';
import { makeProjectHandlers } from '../structured-ops/project-ops.mjs';
import {
  makeContainerHandlers,
  checkContainerReadiness,
  checkComposeReadiness,
  checkJournalReadiness,
  checkHelperContainerReadiness,
  checkHelperComposeReadiness
} from '../containers/container-ops.mjs';
import { wingetAvailable, detectPackageManager } from '../packages/package-ops.mjs';
import { getDarwinConsoleUser } from '../../gui-broker/gui-launch.mjs';
import { makeMutationHandlers } from '../filesystem/mutation-ops.mjs';
import {
  makeGuiCloseHandler,
  makeGuiLaunchHandler,
  hasLiveBrokers,
  hasGuiDisplay
} from '../../gui-broker/gui-launch.mjs';
import {
  makeUpdateHandler,
  activatePreparedUpdate,
  activationInterlock,
  isActivationBusyError,
  markUpdateHealthy,
  updaterPolicy
} from '../updater/updater.mjs';
import { ncLayout, mainScriptDir } from './nc-paths.mjs';
import {
  HOST_POLICY_FEATURE,
  BROWSER_POLICY_FEATURE,
  BROWSER_POLICY_V2_FEATURE,
  WORKSPACE_ROOTS_FEATURE,
  policyBindingRecord,
  requiredCapabilitiesForOperation,
  selectWelcomePolicy
} from '../policy/host-policy.mjs';
import { createDeviceProof } from './device-proof.mjs';
import {
  makePrivilegedHelperClientHandler,
  makeFilePermissionsClientHandler
} from '../../privileged-helper/privileged-helper-client.mjs';
import {
  makeWindowsUninstallHandler,
  makeMacosUninstallHandler,
  makeLinuxUserUninstallHandler,
  isUserModeInstall
} from './uninstall-ops.mjs';
import { invokePrivilegedHelper } from '../../privileged-helper/privileged-helper-ipc.mjs';
import { linuxPrivilegedHelperReadiness } from '../../privileged-helper/privileged-helper-linux-readiness.mjs';
import { darwinPrivilegedHelperReadiness } from '../../privileged-helper/privileged-helper-darwin-readiness.mjs';
import { windowsPrivilegedHelperReadiness } from '../../privileged-helper/privileged-helper-windows-readiness.mjs';
import {
  loadTransportSecret,
  computeTransportProof
} from '../../privileged-helper/privileged-helper-transport-proof.mjs';
import {
  browserNavigateJob,
  browserInteractJob,
  browserSnapshotJob,
  browserCreateJob,
  browserCloseJob,
  browserFindJob,
  browserTabsJob,
  browserScreenshotJob,
  browserConsoleJob,
  browserNetworkJob,
  browserUploadJob,
  browserHealth
} from '../browser/browser-adapter.mjs';
import { makeProcessHandlers, sweepOrphanedSessions, countLiveSessions } from '../process/process-sessions.mjs';
import { makeServiceHandlers } from '../services/service-ops.mjs';
import {
  makeLogFollowHandlers,
  resolveLogSince,
  filterLogLinesBySince
} from '../logs/log-ops.mjs';
import { makeConsolidatedHandlers } from './consolidated-tools.mjs';

// Sub-layer modules extracted from client.mjs (Wave 3 architecture refactor)
import {
  shellTouchesAgentTree,
  defaultShellCwd,
  shellAbortByJob,
  executeShellJob,
  normalizedJobPayload,
  extractJob,
  normalizedJobId,
  isDangerousJobId,
  clampedEnvNumber
} from './shell-runner.mjs';

import {
  detectLegacyArtifacts,
  filesystemLayoutMetadata,
  agentInstallMode,
  discoverUserFolders,
  localAuditPayload,
  localAudit,
  compactTailedFile,
  boundSessionResult,
  registrationStateForClient,
  readState,
  writeState,
  resetRetirementEvidence,
  observeRetirementFailure,
  confirmCompletedUpdates,
  markInterruptedJobs
} from './agent-state.mjs';

import {
  PONG_TIMEOUT_MS,
  attachPongWatchdog,
  resultPayloadOf,
  flushSessionPending,
  configuredTransportScheme,
  getDeviceKey,
  postJson,
  postJobStart,
  postJobResult,
  applyCurrentPolicy as wsApplyCurrentPolicy,
  fetchCurrentPolicy as wsFetchCurrentPolicy,
  policyFailureResult,
  ensureJobPolicy as wsEnsureJobPolicy,
  auditPolicyFailure as wsAuditPolicyFailure,
  handleSessionCancel as transportHandleSessionCancel,
  handleSessionJob as transportHandleSessionJob,
  authenticatedHeaders
} from './ws-transport.mjs';

// WINLEX-001 preservation marker: windowsVerbatimArguments: Boolean(invocation.windowsVerbatimArguments) in shell-runner.mjs

// Daemon PATH augmentation: systemd/launchd/SCM services boot with a minimal
// PATH, so user-installed CLI tools (Homebrew, ~/.local/bin) are invisible to
// shell_exec/process_start until the agent repairs it. Runs once at startup.
// Conservative by construction: only prepends directories that exist, never
// duplicates an entry already present, never mixes Windows and POSIX paths,
// and keeps the value bounded. Only touches process.env.PATH (the boot
// environment) — never env from job payloads, files, or other untrusted
// sources. Exported for tests.
export const DAEMON_PATH_MAX_CHARS = 4096;
export const DAEMON_PATH_MAX_ENTRIES = 128;
/**
 * Candidate tool directories for a platform. POSIX covers the Homebrew
 * prefixes plus the user-local bin; Windows covers the system roots a
 * service PATH sometimes lacks. Capped by the caller. Exported for tests.
 * @param {string} platform node platform string
 * @param {string|null} homedir operator home directory (POSIX user bin)
 * @returns {Array<string>}
 */
export function daemonPathCandidates(platform, homedir = null) {
  if (platform === 'win32') return ['C:\\Windows\\System32', 'C:\\Windows'];
  const out = ['/opt/homebrew/bin', '/usr/local/bin'];
  if (typeof homedir === 'string' && homedir) out.push(path.join(homedir, '.local', 'bin'));
  return out;
}
/**
 * Prepend missing candidate tool directories to PATH (see above). Idempotent:
 * a second call changes nothing.
 * @param {object} [options]
 * @param {Record<string, string|undefined>} [options.env] defaults to process.env
 * @param {string} [options.platform] defaults to process.platform
 * @param {string|null} [options.homedir] defaults to os.homedir()
 * @param {(p: string) => boolean} [options.existsSync] existence probe (tests)
 * @returns {string} the resulting PATH value
 */
export function ensureDaemonPath({ env = process.env, platform = process.platform, homedir = null, existsSync = fsSync.existsSync } = {}) {
  try {
    const delim = platform === 'win32' ? ';' : ':';
    const norm = (/** @type {string} */ v) => {
      const s = String(v || '');
      return platform === 'win32' ? s.toLowerCase().replace(/\//g, '\\') : s;
    };
    const raw = typeof env.PATH === 'string' && env.PATH ? env.PATH : '';
    const present = raw
      ? raw
          .split(delim)
          .map((x) => String(x || '').trim())
          .filter(Boolean)
      : [];
    const seen = new Set(present.map(norm));
    let home = homedir;
    if (home == null) {
      try {
        home = os.homedir();
      } catch {
        home = '';
      }
    }
    const prepend = [];
    for (const dir of daemonPathCandidates(platform, home).slice(0, 8)) {
      if (present.length + prepend.length >= DAEMON_PATH_MAX_ENTRIES) break;
      const key = norm(dir);
      if (!dir || seen.has(key)) continue;
      let ok = false;
      try {
        ok = existsSync(dir) === true;
      } catch {
        ok = false;
      }
      if (!ok) continue;
      seen.add(key);
      prepend.push(dir);
    }
    if (!prepend.length) return raw;
    const joined = [...prepend, ...present].join(delim);
    if (joined.length <= DAEMON_PATH_MAX_CHARS) {
      env.PATH = joined;
      return joined;
    }
    // Keep the value bounded without ever truncating the original PATH:
    // shed prepended entries until it fits, else leave PATH untouched.
    while (prepend.length > 1 && [...prepend, ...present].join(delim).length > DAEMON_PATH_MAX_CHARS)
      prepend.pop();
    const bounded = [...prepend, ...present].join(delim);
    if (bounded.length > DAEMON_PATH_MAX_CHARS) return raw;
    env.PATH = bounded;
    return bounded;
  } catch {
    return (env && typeof env.PATH === 'string' && env.PATH) || '';
  }
}

try {
  ensureDaemonPath();
} catch {}

const VERSION = '0.17.24';
const layout = ncLayout();
const serverUrl = (process.env.NC_SERVER_URL || 'https://mcp.nodecommand.app').replace(/\/$/, '');
if (process.env.NODE_ENV !== 'development') {
  let parsed;
  try {
    parsed = new URL(serverUrl);
  } catch {
    throw new Error('NC_SERVER_URL_HTTPS_REQUIRED');
  }
  if (parsed.protocol !== 'https:') {
    throw new Error('NC_SERVER_URL_HTTPS_REQUIRED');
  }
}
const cfg = {
  serverUrl,
  clientId: process.env.NC_CLIENT_ID || os.hostname(),
  clientName: process.env.NC_CLIENT_NAME || os.hostname(),
  clientToken: process.env.NC_CLIENT_TOKEN || '',
  deviceKeyFile: process.env.NC_DEVICE_KEY_FILE || layout.deviceKey,
  heartbeatSeconds: clampedEnvNumber('NC_HEARTBEAT_SECONDS', 15, 5),
  retrySeconds: clampedEnvNumber('NC_RETRY_SECONDS', 10, 2),
  jobPollSeconds: clampedEnvNumber('NC_JOB_POLL_SECONDS', 2, 1),
  remoteExecEnabled: String(process.env.NC_REMOTE_EXEC_ENABLED || 'false').toLowerCase() === 'true',
  auditFile: process.env.NC_AUDIT_FILE || '',
  serverLogFile: process.env.NC_SERVER_LOG_FILE || layout.serverLog,
  tunnelLogFile: process.env.NC_TUNNEL_LOG_FILE || layout.tunnelLog,
  stateFile: process.env.NC_STATE_FILE || layout.stateFile,
  clientLog: process.env.NC_CLIENT_LOG || layout.clientLog,
  bootstrapBytes: clampedEnvNumber('NC_BOOTSTRAP_BYTES', 65536, 4096),
  maxStdoutBytes: clampedEnvNumber('NC_MAX_STDOUT_BYTES', 1048576, 4096),
  maxStderrBytes: clampedEnvNumber('NC_MAX_STDERR_BYTES', 1048576, 4096),
  maxTimeoutSeconds: clampedEnvNumber('NC_MAX_TIMEOUT_SECONDS', 3600, 1),
  sessionEnabled: String(process.env.NC_SESSION_ENABLED || 'true').toLowerCase() !== 'false',
  protocolVersion: process.env.NC_PROTOCOL_VERSION || '1.0.0',
  localAuditFile: process.env.NC_LOCAL_AUDIT_FILE || layout.auditLog,
  readRoots: String(process.env.NC_FILE_READ_ROOTS || layout.root)
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
};
const LOG_SOURCES = /** @type {Record<string, string>} */ (
  Object.freeze({
    client: cfg.clientLog,
    'mcp-server': cfg.serverLogFile,
    'mcp-tunnel': cfg.tunnelLogFile
  })
);

/**
 * @typedef {Object} AgentPolicy
 * @property {string} contract_version
 * @property {number} revision
 * @property {string} digest
 * @property {Record<string, boolean>} capabilities
 * @property {{allowed_read_roots?: Array<string>, allowed_write_roots?: Array<string>}} [roots]
 * @typedef {Object} AgentStateJob
 * @property {string} [status]
 * @property {string} [claimed_at]
 * @property {string} [tool]
 * @property {unknown} [policy_binding]
 * @property {string} [started_at]
 * @property {string} [finished_local_at]
 * @property {string} [result_sent_at]
 * @property {number} [duration_ms]
 * @property {string} [update_version]
 * @property {boolean} [cancelRequested]
 * @typedef {Object} AgentState
 * @property {Record<string, number>} offsets
 * @property {boolean} registered
 * @property {string|null} registered_client_id
 * @property {Record<string, AgentStateJob>} jobs
 * @property {Record<string, unknown>} pendingResults
 * @property {unknown} [retirement]
 * @typedef {Object} AgentSessionSocket
 * @property {(msg: unknown) => unknown} sendJson
 * @property {(code?: number, reason?: string) => unknown} close
 * @property {(reason?: string) => unknown} [destroy]
 * @property {(event: string, listener: (...args: Array<any>) => unknown) => unknown} on
 * @property {(event: string, listener: (...args: Array<any>) => unknown) => unknown} once
 * @property {(event: string, listener: (...args: Array<any>) => unknown) => unknown} removeListener
 */

/** @type {object|null} */
let liveSession = null;
/**
 * @type {Record<string, (job: Record<string, unknown>, options?: Record<string, unknown>) => Promise<Record<string, unknown>>>|null} */
let handlerRegistry = null;
let logWrites = 0;
/** @type {AgentPolicy|null} */
let currentPolicy = null;
/** Policy revision the last hello's capability filter used (null = unfiltered). */
/** @type {number|null} */
let helloPolicyRevision = null;
/** Digest of the policy the last hello's capability filter used (null = unknown). */
/** @type {string|null} */
let helloPolicyDigest = null;
/** Last observed GUI broker presence (null = not yet sampled). */
/** @type {boolean|null} */
let lastGuiBrokerPresence = null;
/** Telemetry cycles elapsed (drives periodic browser-health re-verification). */
/** @type {number} */
let telemetryCycleCount = 0;
let retired = false;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * @param {string} level @param {string} message @param {Record<string, unknown>} [extra]
 */
async function log(level, message, extra = {}) {
  const safeExtra = { ...extra };
  delete safeExtra.authorization;
  delete safeExtra.token;
  const record = { ts: new Date().toISOString(), level, message, ...safeExtra };
  const line = `${JSON.stringify(record)}\n`;
  try {
    await fs.mkdir(path.dirname(cfg.clientLog), { recursive: true });
    await fs.appendFile(cfg.clientLog, line, { mode: 0o640 });
    logWrites++;
    if (logWrites % 100 === 0) {
      await compactTailedFile(cfg.clientLog);
    }
  } catch {}
  if (level === 'error') console.error(line.trim());
  else console.log(line.trim());
}

function applyCurrentPolicy(policy, sig = null) {
  const next = /** @type {AgentPolicy} */ (
    wsApplyCurrentPolicy(policy, sig, {
      serverUrl: cfg.serverUrl,
      clientId: cfg.clientId
    })
  );
  // Monotonic cache (P7-D1): the pre-fix guard compared the just-assigned
  // policy against itself, so a stale re-announced welcome always regressed
  // the cache. Keep the newest verified revision; per-job enforcement
  // refetches fresh policy independently and fails closed on staleness.
  const sel = selectWelcomePolicy(currentPolicy, next);
  currentPolicy = /** @type {AgentPolicy} */ (sel.policy);
  if (!sel.updated) {
    log('warning', 'stale_policy_welcome_ignored', {
      reason: sel.reason,
      welcome_revision: next.revision ?? null,
      current_revision: currentPolicy?.revision ?? null
    }).catch(() => {});
  }
  return currentPolicy;
}

async function fetchCurrentPolicy() {
  const p = await wsFetchCurrentPolicy({
    serverUrl: cfg.serverUrl,
    clientId: cfg.clientId,
    clientToken: cfg.clientToken,
    deviceKeyFile: cfg.deviceKeyFile
  });
  currentPolicy = /** @type {AgentPolicy} */ (p);
  return currentPolicy;
}

async function ensureJobPolicy(job) {
  return wsEnsureJobPolicy(job, {
    serverUrl: cfg.serverUrl,
    clientId: cfg.clientId,
    clientToken: cfg.clientToken,
    deviceKeyFile: cfg.deviceKeyFile
  });
}

async function auditPolicyFailure(job, result) {
  return wsAuditPolicyFailure(job, result, (op, p, r) => localAudit(op, p, r, cfg.localAuditFile));
}

function systemPayload() {
  return {
    id: cfg.clientId,
    client_id: cfg.clientId,
    name: cfg.clientName,
    hostname: os.hostname(),
    agent_version: VERSION,
    version: VERSION,
    os: `${os.type()} ${os.release()}`,
    platform: os.platform(),
    arch: os.arch(),
    status: 'online',
    metadata: {
      cpus: os.cpus()?.length || null,
      total_memory_bytes: os.totalmem(),
      remote_exec_enabled: cfg.remoteExecEnabled,
      log_sources: Object.keys(LOG_SOURCES),
      log_delivery: 'on_demand',
      update_policy: updaterPolicy(layout),
      filesystem_layout: filesystemLayoutMetadata(layout),
      install_mode: agentInstallMode(),
      user_folders: discoverUserFolders(),
      transport: liveSession ? 'websocket' : 'http-poll',
      protocol_version: cfg.protocolVersion,
      capabilities: advertisedCapabilities(),
      browser_runtime: { ...browserHealthCache },
      helper_upgrade: readHelperUpgradeState()
    }
  };
}

async function register() {
  const result = await postJson('/api/clients/register', systemPayload(), undefined, cfg);
  await log('info', 'registered', {
    server: cfg.serverUrl,
    client_id: cfg.clientId,
    version: VERSION
  });
  return result;
}

async function heartbeat() {
  const uptime_seconds = Math.floor(os.uptime()),
    loadavg = os.loadavg(),
    free_memory_bytes = os.freemem(),
    total_memory_bytes = os.totalmem();
  return postJson(
    `/api/clients/${encodeURIComponent(cfg.clientId)}/heartbeat`,
    {
      status: 'online',
      timestamp: new Date().toISOString(),
      hostname: os.hostname(),
      uptime_seconds,
      loadavg,
      free_memory_bytes,
      total_memory_bytes,
      agent_version: VERSION,
      platform: os.platform(),
      arch: os.arch(),
      metadata: {
        cpus: os.cpus()?.length || null,
        total_memory_bytes,
        uptime_seconds,
        loadavg,
        free_memory_bytes,
        remote_exec_enabled: cfg.remoteExecEnabled,
        log_sources: Object.keys(LOG_SOURCES),
        log_delivery: 'on_demand',
        transport: liveSession ? 'websocket' : 'http-poll',
        protocol_version: cfg.protocolVersion,
        capabilities: advertisedCapabilities(),
        filesystem_layout: filesystemLayoutMetadata(layout),
        install_mode: agentInstallMode(),
        user_folders: discoverUserFolders(),
        helper_upgrade: readHelperUpgradeState()
      }
    },
    undefined,
    cfg
  );
}

async function readTailLines(file, requestedLines, contains = '', sinceMs = null) {
  const started = Date.now();
  const stat = await fs.stat(file);
  const maxReadBytes = 2 * 1024 * 1024;
  const start = Math.max(0, stat.size - maxReadBytes);
  const handle = await fs.open(file, 'r');
  let text = '';
  try {
    const buffer = Buffer.alloc(stat.size - start);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, start);
    text = buffer.subarray(0, bytesRead).toString('utf8');
  } finally {
    await handle.close();
  }
  let rows = text.split(/\r?\n/);
  if (start > 0) rows = rows.slice(1);
  if (rows.at(-1) === '') rows.pop();
  if (contains) rows = rows.filter((line) => line.includes(contains));
  // Time bound applies AFTER the tail cut, on the same rows the caller would
  // otherwise receive. It can only remove rows, never resurrect older ones:
  // rows older than the bound are excluded even when the tail window is
  // short. `truncated` stays truthful either way — start > 0 means the 2MB
  // file window itself cut older data (which may hold in-bound rows), and the
  // post-filter overflow means the lines cap cut in-bound rows.
  if (sinceMs !== null && sinceMs !== undefined) rows = filterLogLinesBySince(rows, sinceMs);
  const more = rows.length > requestedLines || start > 0;
  rows = rows.slice(-requestedLines);
  return {
    content: rows.join('\n'),
    lines_returned: rows.length,
    truncated: more,
    duration_ms: Date.now() - started
  };
}

/**
 * Agent-visible helper-upgrade state written by OTA activation
 * (helper-upgrade-state.json). Best-effort: missing/corrupt reads as null
 * so status reporting never fails because of it.
 */
function readHelperUpgradeState() {
  try {
    const raw = fsSync.readFileSync(
      path.join(String(layout?.data || ''), 'helper-upgrade-state.json'),
      'utf8'
    );
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  } catch {}
  return null;
}

async function executePrivilegeStatusJob(job = {}) {
  void job;
  const platform = process.platform;
  let username = null;
  let uid = null;
  try {
    const info = os.userInfo();
    username = typeof info.username === 'string' ? info.username : null;
    if (Number.isInteger(info.uid)) uid = info.uid;
  } catch {}
  const helper = (() => {
    try {
      return privilegedHelperAvailable();
    } catch {
      return false;
    }
  })();
  const isElevated =
    platform === 'win32'
      ? ['system', 'administrator'].includes(String(username || '').toLowerCase())
      : uid === 0;
  const mode = (() => {
    try {
      return agentInstallMode();
    } catch {
      return 'system';
    }
  })();
  return {
    status: 'completed',
    exit_code: 0,
    stdout: '',
    stderr: '',
    error: null,
    duration_ms: 0,
    result_payload: {
      platform,
      username,
      uid,
      is_elevated: Boolean(isElevated),
      helper_available: Boolean(helper),
      helper_transport: helper ? (platform === 'win32' ? 'pipe' : 'socket') : null,
      reason: helper ? null : mode === 'user' ? 'USER_INSTALL' : 'HELPER_NOT_READY',
      helper_upgrade: readHelperUpgradeState()
    }
  };
}

async function executeLogReadJob(job) {
  const payload = normalizedJobPayload(job);
  const source = String(payload.source || '');
  const file = LOG_SOURCES[source];
  if (!file)
    return {
      status: 'failed',
      source,
      content: '',
      lines_returned: 0,
      truncated: false,
      duration_ms: 0,
      error: 'LOG_SOURCE_NOT_ALLOWED'
    };
  const lines = Math.max(1, Math.min(1000, Number(payload.lines || 200)));
  const contains = typeof payload.contains === 'string' ? payload.contains.slice(0, 200) : '';
  // `since` was silently ignored here (and dropped upstream): an advertised
  // bound that filters nothing is wrong results, not a missing feature. An
  // unparseable bound fails closed with LOG_SINCE_INVALID instead of
  // degrading to an unfiltered tail.
  const sinceBound = resolveLogSince(payload.since);
  if (sinceBound.present && sinceBound.ms === null)
    return {
      status: 'failed',
      source,
      content: '',
      lines_returned: 0,
      truncated: false,
      duration_ms: 0,
      error: 'LOG_SINCE_INVALID'
    };
  try {
    const r = await readTailLines(
      file,
      lines,
      contains,
      sinceBound.present ? sinceBound.ms : null
    );
    return { status: 'completed', source, ...r, error: null };
  } catch (error) {
    const readErr = /** @type {Record<string, unknown>} */ (error);
    return {
      status: 'failed',
      source,
      content: '',
      lines_returned: 0,
      truncated: false,
      duration_ms: 0,
      error: readErr?.code === 'ENOENT' ? 'LOG_SOURCE_NOT_FOUND' : String(readErr?.message || error)
    };
  }
}

/**
 * @param {object} [args]
 * @param {unknown} [args.capabilities]
 * @param {unknown} [args.policy_identity]
 */
function mutationPolicyGate({ capabilities, policy_identity } = {}) {
  const policy = currentPolicy;
  if (!policy)
    throw Object.assign(new Error('HOST_POLICY_NOT_READY'), { code: 'HOST_POLICY_NOT_READY' });
  const identity =
    policy_identity && typeof policy_identity === 'object'
      ? /** @type {Record<string, unknown>} */ (policy_identity)
      : null;
  if (
    identity?.policy_contract_version !== policy.contract_version ||
    identity?.policy_revision !== policy.revision ||
    identity?.policy_digest !== policy.digest
  )
    throw Object.assign(new Error('HOST_POLICY_REVISION_STALE'), {
      code: 'HOST_POLICY_REVISION_STALE'
    });
  return (
    Array.isArray(capabilities) &&
    capabilities.length > 0 &&
    capabilities.every((cap) => typeof cap === 'string' && policy.capabilities?.[cap] === true)
  );
}

function advertisedCapabilities(policyForFilter = currentPolicy) {
  const all = Object.keys(getHandlers()).sort();
  const gated = browserHealthCache.available ? all : all.filter((c) => !c.startsWith('browser_'));
  let gatedByRuntime = gated;
  try {
    const guiOk = hasGuiDisplay(process.platform, process.env, {
      hasBrokers: hasLiveBrokers(layout),
      // Post-first-probe the cached console verdict rules (no per-call
      // fork); before that hasGuiDisplay falls back to a live check.
      consoleSession:
        process.platform === 'darwin' && darwinGuiCache.checked
          ? darwinGuiCache.available === true
          : undefined
    });
    if (!guiOk) gatedByRuntime = gated.filter((c) => c !== 'gui_launch' && c !== 'gui_close');
  } catch {}
  try {
    // GAP-017: Darwin helper does not implement privileged_shell_exec; advertise only if satisfied
    if (process.platform === 'darwin' || !privilegedHelperAvailable())
      gatedByRuntime = gatedByRuntime.filter((c) => c !== 'privileged_shell_exec');
  } catch {}
  try {
    // file_permissions IS implemented by the privileged helper on all three
    // OSes (linux/darwin/win32 handler maps all expose the operation; only
    // privileged_shell_exec is absent on darwin — GAP-017). Advertise on
    // every platform including darwin; the gate is readiness-only.
    if (!privilegedHelperAvailable())
      gatedByRuntime = gatedByRuntime.filter((c) => c !== 'file_permissions');
  } catch {}
  // GAP-021: effective executable state is direct readiness OR
  // helper-CONFIRMED executability (helper-mediated executability:
  // container_read via container_control, compose_list via compose_control,
  // log_read via system_log_read). The container/compose caches below fold
  // the helper-confirmed engine proof in, so advertisement consults the
  // caches only — raw "helper exists" must never advertise Docker that is
  // not there (a host with a helper but no docker binary/dead socket stays
  // hidden instead of failing every dispatch).
  let helperMediated = false;
  try {
    helperMediated = privilegedHelperAvailable();
  } catch {
    helperMediated = false;
  }
  if (!containerHealthCache.available) {
    gatedByRuntime = gatedByRuntime.filter((c) => !c.startsWith('container_'));
  }
  if (!composeHealthCache.available) {
    gatedByRuntime = gatedByRuntime.filter((c) => !c.startsWith('compose_'));
  }
  // Package tools need a real manager behind them: detectPackageManager is
  // the exact execution path, so advertisement consults the probe caches
  // that run it (windowsPackageCache/darwinPackageCache/linuxPackageCache).
  // win32 package_list stays advertised without winget (the registry
  // listing genuinely works); only the mutating tools hide. darwin/linux
  // hide the whole family when their probe fails (list genuinely needs
  // brew/apt/dnf/apk/pacman/zypper there). Fail closed before the first
  // probe: tools stay hidden until a probe confirms them (probes run before
  // the first hello and on the telemetry cadence).
  const pkgState = packageAdvertisementState({ platform: process.platform });
  if (!pkgState.list) {
    gatedByRuntime = gatedByRuntime.filter((c) => !c.startsWith('package_'));
  } else if (!pkgState.mutate) {
    gatedByRuntime = gatedByRuntime.filter(
      (c) => c !== 'package_install' && c !== 'package_remove'
    );
  }
  // NC-CERT-004: derive service_logs advertisement from effective journal
  // readability OR helper-mediated system_log_read.
  if (!journalHealthCache.available && !helperMediated) {
    gatedByRuntime = gatedByRuntime.filter((c) => c !== 'service_logs');
  }
  // package_list/manage execute unprivileged for reads and user-domain
  // managers, and escalate system scope via package_control: no runtime gate
  // beyond policy, so helper availability only widens executability.
  const policy = policyForFilter;
  if (!policy || !policy.capabilities || typeof policy.capabilities !== 'object')
    return gatedByRuntime;
  return gatedByRuntime.filter((tool) => {
    let required = [];
    try {
      required = requiredCapabilitiesForOperation(tool, {}, 'mcp') || [];
    } catch {
      return true;
    }
    if (!Array.isArray(required) || required.length === 0) return true;
    return required.every((cap) => policy.capabilities?.[cap] === true);
  });
}

const browserHealthCache = {
  checked: false,
  available: false,
  error: 'BROWSER_HEALTH_NOT_CHECKED',
  playwright: null,
  revision: null
};
let lastBrowserRefreshError = null;

const containerHealthCache = {
  checked: false,
  available: false,
  stage: 'initial',
  reason: 'CONTAINER_NOT_CHECKED'
};

const composeHealthCache = {
  checked: false,
  available: false,
  stage: 'initial',
  reason: 'COMPOSE_NOT_CHECKED'
};

const journalHealthCache = {
  checked: false,
  available: process.platform !== 'linux',
  stage: 'initial',
  reason: 'JOURNAL_NOT_CHECKED'
};

// Windows mutating-package gate: real winget presence (package_list stays
// advertised via the winget-independent registry listing).
const windowsPackageCache = {
  checked: false,
  available: false,
  reason: 'PACKAGE_HEALTH_NOT_CHECKED'
};

// macOS package gate: real brew presence. detectPackageManager('darwin')
// resolves ONLY via brew, so the probe below is the exact execution path:
// advertisement matches readiness by construction (no fixed-path allowlist
// that can disagree with the PATH scan the handler uses).
const darwinPackageCache = {
  checked: false,
  available: false,
  reason: 'PACKAGE_HEALTH_NOT_CHECKED'
};

// Linux package gate: first available manager wins (apt/dnf/apk/pacman/
// zypper, same order detectPackageManager tries). No manager anywhere on
// PATH means every package_* call would fail PACKAGE_MANAGER_UNAVAILABLE,
// so the whole family stays hidden until the probe confirms one.
const linuxPackageCache = {
  checked: false,
  available: false,
  manager: null,
  reason: 'PACKAGE_HEALTH_NOT_CHECKED'
};

/**
 * Pure advertisement classifier for the package tool family (Lesson 6
 * dynamic capability truth). Sync and side-effect free so the per-OS
 * matrix (advertised ⟺ probe OK, both branches) is unit-testable with
 * stubbed probe states; advertisedCapabilities feeds it the live caches.
 * @param {{platform?: string, windows?: {available?: boolean}, darwin?: {available?: boolean}, linux?: {available?: boolean}}} [options]
 * @returns {{list: boolean, mutate: boolean}} list = advertise package_list,
 * mutate = additionally advertise package_install/package_remove.
 */
function packageAdvertisementState({
  platform = process.platform,
  windows = windowsPackageCache,
  darwin = darwinPackageCache,
  linux = linuxPackageCache
} = {}) {
  if (platform === 'win32') {
    // Registry listing works without winget; mutation genuinely needs it.
    return { list: true, mutate: windows?.available === true };
  }
  if (platform === 'darwin') {
    // List and mutate both resolve exclusively via brew.
    const ok = darwin?.available === true;
    return { list: ok, mutate: ok };
  }
  if (platform === 'linux') {
    // List and mutate both need a native manager binary on PATH.
    const ok = linux?.available === true;
    return { list: ok, mutate: ok };
  }
  return { list: false, mutate: false };
}

// macOS GUI gate: a real console session (/dev/console owner).
const darwinGuiCache = {
  checked: false,
  available: false,
  reason: 'GUI_HEALTH_NOT_CHECKED'
};

async function refreshWindowsPackageHealth() {
  if (process.platform !== 'win32') {
    windowsPackageCache.checked = true;
    windowsPackageCache.available = true;
    windowsPackageCache.reason = null;
    return { ...windowsPackageCache };
  }
  try {
    const ok = await wingetAvailable();
    windowsPackageCache.checked = true;
    windowsPackageCache.available = ok === true;
    windowsPackageCache.reason = ok === true ? null : 'WINGET_UNAVAILABLE';
  } catch (e) {
    windowsPackageCache.checked = true;
    windowsPackageCache.available = false;
    windowsPackageCache.reason = e instanceof Error ? e.message : String(e);
  }
  return { ...windowsPackageCache };
}

async function refreshDarwinPackageHealth() {
  if (process.platform !== 'darwin') {
    darwinPackageCache.checked = true;
    darwinPackageCache.available = true;
    darwinPackageCache.reason = null;
    return { ...darwinPackageCache };
  }
  try {
    // Same resolver the handlers execute: auto must find brew or the
    // tools would fail PACKAGE_MANAGER_UNAVAILABLE at call time.
    const manager = await detectPackageManager('darwin', 'auto');
    darwinPackageCache.checked = true;
    darwinPackageCache.available = manager === 'brew';
    darwinPackageCache.reason = manager === 'brew' ? null : 'PACKAGE_MANAGER_UNAVAILABLE';
  } catch (e) {
    darwinPackageCache.checked = true;
    darwinPackageCache.available = false;
    darwinPackageCache.reason = 'PACKAGE_MANAGER_UNAVAILABLE';
  }
  return { ...darwinPackageCache };
}

async function refreshLinuxPackageHealth() {
  if (process.platform !== 'linux') {
    linuxPackageCache.checked = true;
    linuxPackageCache.available = true;
    linuxPackageCache.manager = null;
    linuxPackageCache.reason = null;
    return { ...linuxPackageCache };
  }
  try {
    // Same resolver the handlers execute: first available native manager
    // wins, none found means every package_* call would fail.
    const manager = await detectPackageManager('linux', 'auto');
    linuxPackageCache.checked = true;
    linuxPackageCache.available = typeof manager === 'string' && manager.length > 0;
    linuxPackageCache.manager = linuxPackageCache.available ? manager : null;
    linuxPackageCache.reason = linuxPackageCache.available ? null : 'PACKAGE_MANAGER_UNAVAILABLE';
  } catch (e) {
    linuxPackageCache.checked = true;
    linuxPackageCache.available = false;
    linuxPackageCache.manager = null;
    linuxPackageCache.reason = 'PACKAGE_MANAGER_UNAVAILABLE';
  }
  return { ...linuxPackageCache };
}

async function refreshDarwinGuiHealth() {
  if (process.platform !== 'darwin') {
    darwinGuiCache.checked = true;
    darwinGuiCache.available = true;
    darwinGuiCache.reason = null;
    return { ...darwinGuiCache };
  }
  try {
    const user = getDarwinConsoleUser();
    const ok = Boolean(user) && user !== 'root';
    darwinGuiCache.checked = true;
    darwinGuiCache.available = ok;
    darwinGuiCache.reason = ok ? null : 'GUI_NO_CONSOLE_SESSION';
  } catch (e) {
    darwinGuiCache.checked = true;
    darwinGuiCache.available = false;
    darwinGuiCache.reason = e instanceof Error ? e.message : String(e);
  }
  return { ...darwinGuiCache };
}

function helperMediatedExecutable() {
  try {
    return privilegedHelperAvailable();
  } catch {
    return false;
  }
}

// Helper-confirmed executability: the helper must prove the engine it
// would drive is actually present (binary + daemon socket), not merely
// exist. Never throws — a failed proof means "not available".
async function helperConfirmedContainer() {
  try {
    if (!helperMediatedExecutable()) return { available: false, reason: 'PRIVILEGED_HELPER_NOT_AVAILABLE' };
    return await checkHelperContainerReadiness({ isAvailable: helperMediatedExecutable });
  } catch (e) {
    return { available: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

async function helperConfirmedCompose() {
  try {
    if (!helperMediatedExecutable()) return { available: false, reason: 'PRIVILEGED_HELPER_NOT_AVAILABLE' };
    return await checkHelperComposeReadiness({ isAvailable: helperMediatedExecutable });
  } catch (e) {
    return { available: false, reason: e instanceof Error ? e.message : String(e) };
  }
}

async function refreshContainerHealth() {
  /** @type {{ available: boolean, stage?: string|null, reason?: string|null, engine?: string, cmd?: string }} */
  let direct = { available: false, stage: 'unknown', reason: 'CONTAINER_NOT_CHECKED' };
  try {
    direct = await checkContainerReadiness();
  } catch (e) {
    direct = {
      available: false,
      stage: 'error',
      reason: e instanceof Error ? e.message : String(e)
    };
  }
  const directOk = direct.available === true;
  const helperProof = directOk ? null : await helperConfirmedContainer();
  const helperOk = helperProof?.available === true;
  containerHealthCache.checked = true;
  containerHealthCache.available = directOk || helperOk;
  containerHealthCache.stage = directOk ? direct.stage || 'ready' : helperOk ? 'helper' : direct.stage || 'unknown';
  containerHealthCache.reason = directOk
    ? direct.reason || null
    : helperOk
      ? null
      : direct.reason || helperProof?.reason || null;
  return { ...containerHealthCache };
}

async function refreshComposeHealth() {
  /** @type {{ available: boolean, stage?: string|null, reason?: string|null, engine?: string, cmd?: string }} */
  let direct = { available: false, stage: 'unknown', reason: 'COMPOSE_NOT_CHECKED' };
  try {
    direct = await checkComposeReadiness();
  } catch (e) {
    direct = {
      available: false,
      stage: 'error',
      reason: e instanceof Error ? e.message : String(e)
    };
  }
  const directOk = direct.available === true;
  const helperProof = directOk ? null : await helperConfirmedCompose();
  const helperOk = helperProof?.available === true;
  composeHealthCache.checked = true;
  composeHealthCache.available = directOk || helperOk;
  composeHealthCache.stage = directOk ? direct.stage || 'ready' : helperOk ? 'helper' : direct.stage || 'unknown';
  composeHealthCache.reason = directOk
    ? direct.reason || null
    : helperOk
      ? null
      : direct.reason || helperProof?.reason || null;
  return { ...composeHealthCache };
}

async function refreshJournalHealth() {
  const helperOk = helperMediatedExecutable();
  try {
    const res = await checkJournalReadiness(process.platform);
    const directOk = res.available === true;
    journalHealthCache.checked = true;
    journalHealthCache.available = directOk || helperOk;
    journalHealthCache.stage = directOk
      ? res.stage || 'ready'
      : helperOk
        ? 'helper'
        : res.stage || 'unknown';
    journalHealthCache.reason = directOk
      ? res.reason || null
      : helperOk
        ? null
        : res.reason || null;
  } catch (e) {
    journalHealthCache.checked = true;
    journalHealthCache.available = helperOk;
    journalHealthCache.stage = helperOk ? 'helper' : 'error';
    journalHealthCache.reason = helperOk ? null : e instanceof Error ? e.message : String(e);
  }
  return { ...journalHealthCache };
}

function announceCapabilities() {
  try {
    const peer = /** @type {{sendJson?: unknown}} */ (liveSession);
    if (!peer || typeof peer.sendJson !== 'function')
      return { sent: false, reason: 'no-live-session' };
    const caps = advertisedCapabilities();
    /** @type {(m: unknown) => void} */ (peer.sendJson).call(peer, sessionHello());
    lastAnnouncedCapsKey = caps.join(',');
    return { sent: true, capabilities: caps.length };
  } catch (e) {
    return {
      sent: false,
      reason: e instanceof Error ? e.message.slice(0, 120) : String(e).slice(0, 120)
    };
  }
}

let lastAnnouncedCapsKey = null;
function liveCapsKey() {
  try {
    return advertisedCapabilities().join(',');
  } catch {
    return null;
  }
}

async function refreshBrowserHealth() {
  try {
    const h = await browserHealth();
    browserHealthCache.checked = true;
    browserHealthCache.available = h.available === true;
    browserHealthCache.error = h.available ? null : String(h.error || 'BROWSER_NOT_AVAILABLE');
    browserHealthCache.playwright = h.playwright || null;
    browserHealthCache.revision = h.revision || null;
  } catch {
    browserHealthCache.checked = true;
    browserHealthCache.available = false;
    browserHealthCache.error = 'BROWSER_NOT_AVAILABLE';
    browserHealthCache.playwright = null;
    browserHealthCache.revision = null;
  }
  return { ...browserHealthCache };
}

function privilegedHelperAvailable() {
  try {
    const uid = typeof process.getuid === 'function' ? process.getuid() : 0;
    const gid = typeof process.getgid === 'function' ? process.getgid() : 0;
    const base = {
      clientId: cfg.clientId,
      serviceUid: uid,
      serviceGid: gid,
      expectedKeyId: null
    };
    if (process.platform === 'linux') return linuxPrivilegedHelperReadiness(base).ok === true;
    if (process.platform === 'darwin') return darwinPrivilegedHelperReadiness(base).ok === true;
    if (process.platform === 'win32') return windowsPrivilegedHelperReadinessSync(base);
    return false;
  } catch {
    return false;
  }
}

let windowsHelperVerdict = { at: 0, ok: false };
function windowsPrivilegedHelperReadinessSync(base) {
  try {
    if (Date.now() - windowsHelperVerdict.at < 30000) return windowsHelperVerdict.ok;
    windowsHelperVerdict.at = Date.now();
    Promise.resolve()
      .then(() =>
        windowsPrivilegedHelperReadiness({
          ...base,
          pipePath: '\\\\.\\pipe\\NCPrivilegedV1',
          secretFile: path.join(String(layout?.config || ''), 'transport-secret.bin'),
          configFile: path.join(String(layout?.config || ''), 'privileged-helper.json')
        })
      )
      .then(
        (r) => {
          windowsHelperVerdict = { at: Date.now(), ok: r?.ok === true };
        },
        () => {
          windowsHelperVerdict = { at: Date.now(), ok: false };
        }
      )
      .catch(() => {});
    return windowsHelperVerdict.ok;
  } catch {
    return false;
  }
}

async function windowsTransportProof(request) {
  try {
    const secret = await loadTransportSecret(
      path.join(String(layout?.config || ''), 'transport-secret.bin')
    );
    if (!secret) return null;
    const rec = request && typeof request === 'object' ? request : {};
    return computeTransportProof(String(rec.payload_sha256 || ''), secret);
  } catch {
    return null;
  }
}

function getHandlers() {
  if (handlerRegistry) return handlerRegistry;
  const options = { readRoots: cfg.readRoots },
    base = makeStructuredHandlers(options),
    mutations = makeMutationHandlers({
      writeRoots: [layout.root],
      policyGate: mutationPolicyGate,
      appRoot: layout.root,
      workspace: layout.workspace
    }),
    processes = makeProcessHandlers({ stateDir: layout.data }),
    services = makeServiceHandlers(process.platform, {
      invokePrivilegedHelper,
      isPrivilegedHelperAvailable: privilegedHelperAvailable
    }),
    logFollow = makeLogFollowHandlers({
      logSources: Object.fromEntries(
        Object.entries(LOG_SOURCES).filter(([, v]) => typeof v === 'string' && v)
      ),
      readRoots: cfg.readRoots
    });
  const atomicHandlers = extendStructuredHandlers(
    {
      ...base,
      ...mutations,
      ...makeDiagnosticsHandlers(process.platform),
      ...makeSystemLogHandlers(process.platform, {
        invokePrivilegedHelper,
        isPrivilegedHelperAvailable: privilegedHelperAvailable
      }),
      ...makePackageHandlers(process.platform, {
        invokePrivilegedHelper,
        isPrivilegedHelperAvailable: privilegedHelperAvailable
      }),
      ...makeGitHandlers({
        readRoots: cfg.readRoots,
        writeRoots: [layout.root],
        appRoot: layout.root,
        workspace: layout.workspace
      }),
      ...makeProjectHandlers({
        readRoots: cfg.readRoots,
        writeRoots: [layout.root],
        appRoot: layout.root,
        workspace: layout.workspace
      }),
      ...makeContainerHandlers({
        readRoots: cfg.readRoots,
        writeRoots: [layout.root],
        appRoot: layout.root,
        workspace: layout.workspace,
        invokePrivilegedHelper,
        isPrivilegedHelperAvailable: privilegedHelperAvailable
      }),
      shell_exec: executeShellJob,
      log_read: executeLogReadJob,
      privilege_status: executePrivilegeStatusJob,
      browser_navigate: browserNavigateJob,
      browser_interact: browserInteractJob,
      browser_snapshot: browserSnapshotJob,
      browser_create: browserCreateJob,
      browser_close: browserCloseJob,
      browser_find: browserFindJob,
      browser_tabs: browserTabsJob,
      browser_take_screenshot: browserScreenshotJob,
      browser_console_messages: browserConsoleJob,
      browser_network_requests: browserNetworkJob,
      browser_file_upload: browserUploadJob,
      ...processes,
      ...services,
      ...logFollow,
      ...(process.platform === 'linux'
        ? {
            privileged_shell_exec: makePrivilegedHelperClientHandler({
              isAvailable: privilegedHelperAvailable
            })
          }
        : {}),
      ...(process.platform === 'win32'
        ? {
            privileged_shell_exec: makePrivilegedHelperClientHandler({
              isAvailable: privilegedHelperAvailable,
              transportProof: windowsTransportProof
            })
          }
        : {}),
      ...(process.platform === 'linux'
        ? {
            // User-mode installs own their tree and have no helper: route
            // them to the user-scope branch (systemctl --user + own-tree
            // removal). System installs keep the exact privileged-helper
            // path. The user branch only stops user-scope services and can
            // never delete a root-owned system tree unprivileged.
            client_uninstall: ((userHandler, helperHandler) => async (job) => {
              let userMode = false;
              try {
                userMode = isUserModeInstall(String(layout?.envFile || ''));
              } catch {
                userMode = false;
              }
              return userMode ? userHandler(job) : helperHandler(job);
            })(
              makeLinuxUserUninstallHandler({
                envFile: String(layout?.envFile || ''),
                root: String(layout?.root || '')
              }),
              makePrivilegedHelperClientHandler({
                isAvailable: privilegedHelperAvailable
              })
            )
          }
        : {}),
      ...(process.platform === 'linux'
        ? {
            file_permissions: makeFilePermissionsClientHandler({
              isAvailable: privilegedHelperAvailable
            })
          }
        : {}),
      ...(process.platform === 'win32'
        ? {
            file_permissions: makeFilePermissionsClientHandler({
              isAvailable: privilegedHelperAvailable,
              transportProof: windowsTransportProof
            })
          }
        : {}),
      // Darwin serves file_permissions through its helper daemon
      // (darwinPrivilegedHelperHandlers exposes the operation; GAP-017
      // only withholds privileged_shell_exec), so it registers here even
      // though privileged_shell_exec never does.
      ...(process.platform === 'darwin'
        ? {
            file_permissions: makeFilePermissionsClientHandler({
              isAvailable: privilegedHelperAvailable
            })
          }
        : {}),
      ...(process.platform === 'win32' ? { client_uninstall: makeWindowsUninstallHandler() } : {}),
      ...(process.platform === 'darwin'
        ? {
            client_uninstall: makeMacosUninstallHandler({
              envFile: String(layout?.envFile || ''),
              root: String(layout?.root || '')
            })
          }
        : {}),
      ...{
        gui_launch: makeGuiLaunchHandler({ layout }),
        gui_close: makeGuiCloseHandler({ layout })
      },
      client_update: makeUpdateHandler({
        serverUrl: cfg.serverUrl,
        clientId: cfg.clientId,
        currentVersion: VERSION,
        authHeaders: (method, absUrl, opts) =>
          authenticatedHeaders(method, absUrl, { ...cfg, ...opts }),
        layout
      })
    },
    options
  );
  handlerRegistry = {
    ...atomicHandlers,
    ...makeConsolidatedHandlers(atomicHandlers)
  };
  if (!handlerRegistry) throw new Error('HANDLER_REGISTRY_FAILED');
  return handlerRegistry;
}

async function executeByTool(job) {
  const h = getHandlers()[String(job.tool || '')];
  if (!h)
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      duration_ms: 0,
      error: 'UNSUPPORTED_TOOL:' + String(job.tool || ''),
      result_payload: {}
    };
  const started = Date.now(),
    r = await h({
      ...job,
      agent_policy_capabilities: currentPolicy?.capabilities || null,
      agent_policy_roots: currentPolicy?.roots || null
    });
  if (r.duration_ms == null) r.duration_ms = Date.now() - started;
  const op = String(job.tool || ''),
    payload = normalizedJobPayload(job);
  await localAudit(op, localAuditPayload(op, payload, r), r, cfg.localAuditFile);
  return r;
}

async function authorizePreparedUpdate(record) {
  const rawBinding =
    record && typeof record === 'object'
      ? /** @type {Record<string, unknown>} */ (record).policy_binding
      : undefined;
  const binding = rawBinding && typeof rawBinding === 'object' ? rawBinding : null;
  if (!binding) return { ok: true, bound: false };
  return ensureJobPolicy({ ...binding, tool: 'client_update', request_payload: {} });
}

/**
 * Deferred OTA activation refused by the session interlock (single bounded
 * slot: a newer deferral replaces an older one, success or a terminal error
 * clears it). The staged tree is untouched by a refusal, so retrying later
 * when sessions drain is always safe (forward-only, idempotent).
 * @type {{result: Record<string, unknown>, job_id: string, version: string|null, transport: string}|null}
 */
let deferredActivation = null;
/** Live-session probe for the OTA interlock (process-sessions table). */
function activationSessionProbe() {
  return countLiveSessions();
}
/**
 * Retry a deferred OTA activation now that the caller observed forward
 * progress (post-job flush or session ack). No-op when nothing is deferred
 * or sessions are still live. Exported for tests.
 * @param {AgentState} state
 * @param {string} transport 'http-poll' or 'session'
 */
export async function maybeRetryDeferredActivation(state, transport) {
  if (!deferredActivation) return;
  const pending = deferredActivation;
  const probe = await activationInterlock({ hasLiveSessions: activationSessionProbe });
  if (probe.blocked) return;
  const record = state && state.jobs ? state.jobs[pending.job_id] : null;
  if (record) {
    const policyCheck = await authorizePreparedUpdate(record);
    if (!policyCheck.ok) {
      deferredActivation = null;
      await log('error', 'client_update_activation_blocked', {
        job_id: pending.job_id,
        version: pending.version,
        error: policyCheck.error,
        transport,
        deferred: true
      });
      await auditPolicyFailure({ tool: 'client_update' }, policyFailureResult(policyCheck));
      return;
    }
  }
  try {
    const act = await activatePreparedUpdate(pending.result, {
      layout,
      clientId: cfg.clientId,
      serviceUid: typeof process.getuid === 'function' ? process.getuid() : 0,
      serviceGid: typeof process.getgid === 'function' ? process.getgid() : 0,
      hasLiveSessions: activationSessionProbe
    });
    deferredActivation = null;
    await log(act?.rolled_back ? 'error' : 'info', 'client_update_activated', {
      job_id: pending.job_id,
      version: pending.version,
      rolled_back: Boolean(act?.rolled_back),
      transport,
      deferred: true
    });
  } catch (error) {
    if (isActivationBusyError(error)) return;
    deferredActivation = null;
    await log('error', 'client_update_activation_failed', {
      job_id: pending.job_id,
      version: pending.version,
      error: /** @type {Record<string, unknown>} */ (error).message,
      transport,
      deferred: true
    });
  }
}

async function flushPendingResults(state) {
  for (const [jobId, rawResult] of Object.entries(state.pendingResults)) {
    const result = /** @type {Record<string, unknown>} */ (rawResult);
    try {
      await postJobResult(jobId, result, cfg);
      delete state.pendingResults[jobId];
      state.jobs[jobId] = {
        ...(state.jobs[jobId] || {}),
        status: /** @type {string} */ (result.status),
        result_sent_at: new Date().toISOString()
      };
      await writeState(state, cfg.stateFile);
      await log('info', 'job_result_sent', { job_id: jobId, status: result.status });
      if (
        state.jobs[jobId]?.tool === 'client_update' &&
        result?.status === 'completed' &&
        resultPayloadOf(result)?.activation_pending
      ) {
        const policyCheck = await authorizePreparedUpdate(state.jobs[jobId]);
        if (!policyCheck.ok) {
          await log('error', 'client_update_activation_blocked', {
            job_id: jobId,
            version: resultPayloadOf(result)?.version,
            error: policyCheck.error
          });
          await auditPolicyFailure({ tool: 'client_update' }, policyFailureResult(policyCheck));
          continue;
        }
        await log('info', 'client_update_activating', {
          job_id: jobId,
          version: resultPayloadOf(result)?.version,
          transport: 'http-poll'
        });
        try {
          const act = await activatePreparedUpdate(result, {
            layout,
            clientId: cfg.clientId,
            serviceUid: typeof process.getuid === 'function' ? process.getuid() : 0,
            serviceGid: typeof process.getgid === 'function' ? process.getgid() : 0,
            hasLiveSessions: activationSessionProbe
          });
          await log(act?.rolled_back ? 'error' : 'info', 'client_update_activated', {
            job_id: jobId,
            version: resultPayloadOf(result)?.version,
            rolled_back: Boolean(act?.rolled_back),
            transport: 'http-poll'
          });
        } catch (error) {
          if (isActivationBusyError(error)) {
            // Interlock refusal: sessions are live. Keep the staged tree and
            // retry later (forward-only, idempotent) instead of failing.
            deferredActivation = {
              result,
              job_id: jobId,
              version:
                typeof resultPayloadOf(result)?.version === 'string'
                  ? /** @type {string} */ (resultPayloadOf(result)?.version)
                  : null,
              transport: 'http-poll'
            };
            await log('warning', 'client_update_activation_deferred', {
              job_id: jobId,
              version: resultPayloadOf(result)?.version,
              error: /** @type {Record<string, unknown>} */ (error).message,
              suggested_action: 'wait',
              transport: 'http-poll'
            });
            continue;
          }
          await log('error', 'client_update_activation_failed', {
            job_id: jobId,
            version: resultPayloadOf(result)?.version,
            error: /** @type {Record<string, unknown>} */ (error).message,
            transport: 'http-poll'
          });
          throw error;
        }
      }
    } catch (error) {
      await log('error', 'job_result_retry_failed', {
        job_id: jobId,
        error: /** @type {Record<string, unknown>} */ (error).message
      });
      return false;
    }
  }
  // A previously deferred OTA activation gets its retry here: sessions that
  // were live at activation time may have drained while jobs completed.
  // Guarded — a retry failure must never fail the flush itself.
  try {
    await maybeRetryDeferredActivation(state, 'http-poll');
  } catch {}
  return true;
}

async function processOneJob(state) {
  if (!cfg.remoteExecEnabled) return { claimed: false, disabled: true };
  if (!cfg.clientToken) throw new Error('REMOTE_EXEC_REQUIRES_CLIENT_TOKEN');
  if (!(await flushPendingResults(state))) return { claimed: false, pending_result: true };

  const claimResponse = await postJson(
    `/api/clients/${encodeURIComponent(cfg.clientId)}/jobs/claim`,
    {},
    undefined,
    cfg
  );
  const job = extractJob(claimResponse);
  if (!job) return { claimed: false };
  const jobId = normalizedJobId(job);
  // P23 prototype-key guard: a `__proto__` claim id would confuse the plain-
  // object job containers (phantom duplicate via prototype fall-through).
  if (!jobId || isDangerousJobId(jobId)) throw new Error('CLAIMED_JOB_WITHOUT_ID');

  if (state.jobs[jobId]) {
    await log('error', 'duplicate_job_claim_blocked', {
      job_id: jobId,
      local_status: state.jobs[jobId].status
    });
    return { claimed: true, duplicate: true, job_id: jobId };
  }

  state.jobs[jobId] = {
    status: 'claimed',
    claimed_at: new Date().toISOString(),
    tool: String(job.tool || ''),
    policy_binding: policyBindingRecord(job)
  };
  try {
    const rp =
      job && typeof job === 'object'
        ? /** @type {Record<string, unknown>} */ (job).request_payload
        : null;
    const uv =
      rp && typeof rp === 'object'
        ? String(/** @type {Record<string, unknown>} */ (rp).version || '')
        : '';
    if (state.jobs[jobId].tool === 'client_update' && /^\d+\.\d+\.\d+/.test(uv))
      state.jobs[jobId].update_version = uv;
  } catch {}
  await writeState(state, cfg.stateFile);

  const policyCheck = await ensureJobPolicy(job);
  await postJobStart(jobId, cfg);
  state.jobs[jobId].status = 'running';
  state.jobs[jobId].started_at = new Date().toISOString();
  await writeState(state, cfg.stateFile);

  let result;
  if (!policyCheck.ok) {
    result = policyFailureResult(policyCheck);
    await auditPolicyFailure(job, result);
  } else {
    result = await executeByTool(job);
  }

  state.pendingResults[jobId] = result;
  state.jobs[jobId].status = 'result_pending';
  state.jobs[jobId].finished_local_at = new Date().toISOString();
  await writeState(state, cfg.stateFile);
  await flushPendingResults(state);
  return { claimed: true, job_id: jobId, result };
}

function sessionHello() {
  const p = systemPayload();
  const caps = advertisedCapabilities();
  return {
    type: 'hello',
    protocol_version: cfg.protocolVersion,
    client_id: cfg.clientId,
    client_version: VERSION,
    host: {
      hostname: p.hostname,
      platform: p.platform,
      arch: p.arch,
      os: p.os,
      cpus: p.metadata.cpus,
      total_memory_bytes: p.metadata.total_memory_bytes
    },
    capabilities: caps,
    features: [
      HOST_POLICY_FEATURE,
      BROWSER_POLICY_FEATURE,
      BROWSER_POLICY_V2_FEATURE,
      WORKSPACE_ROOTS_FEATURE,
      // Darwin agents advertise file_permissions but never
      // privileged_shell_exec (GAP-017): the helper feature must follow
      // either capability, or the central plan would see no helper
      // feature on macOS and refuse to sign file_permissions envelopes.
      ...(caps.includes('privileged_shell_exec') || caps.includes('file_permissions')
        ? ['privileged_helper_v1']
        : [])
    ],
    transport: { scheme: configuredTransportScheme(cfg.serverUrl) },
    metadata: p.metadata
  };
}

async function ackSessionResult(state, jobId, status) {
  // P23 prototype-key guard: `state.jobs['__proto__'] = {...}` below would
  // replace the container prototype for a wire-supplied hostile id.
  if (!jobId || isDangerousJobId(jobId)) return;
  if (!state.pendingResults[jobId]) return;
  const result = /** @type {Record<string, unknown>} */ (state.pendingResults[jobId]),
    record = state.jobs[jobId] || {};
  delete state.pendingResults[jobId];
  state.jobs[jobId] = {
    ...record,
    status: /** @type {string} */ (status || 'completed'),
    result_sent_at: new Date().toISOString()
  };
  await writeState(state, cfg.stateFile);
  await log('info', 'session_result_ack', { job_id: jobId, status });
  if (
    record.tool === 'client_update' &&
    status === 'completed' &&
    resultPayloadOf(result)?.activation_pending
  ) {
    const policyCheck = await authorizePreparedUpdate(record);
    if (!policyCheck.ok) {
      await log('error', 'client_update_activation_blocked', {
        job_id: jobId,
        version: resultPayloadOf(result)?.version,
        error: policyCheck.error
      });
      await auditPolicyFailure({ tool: 'client_update' }, policyFailureResult(policyCheck));
      return;
    }
    await log('info', 'client_update_activating', {
      job_id: jobId,
      version: resultPayloadOf(result)?.version
    });
    try {
      const act = await activatePreparedUpdate(result, {
        layout,
        clientId: cfg.clientId,
        serviceUid: typeof process.getuid === 'function' ? process.getuid() : 0,
        serviceGid: typeof process.getgid === 'function' ? process.getgid() : 0,
        hasLiveSessions: activationSessionProbe
      });
      await log(act?.rolled_back ? 'error' : 'info', 'client_update_activated', {
        job_id: jobId,
        version: resultPayloadOf(result)?.version,
        rolled_back: Boolean(act?.rolled_back)
      });
    } catch (error) {
      if (isActivationBusyError(error)) {
        deferredActivation = {
          result,
          job_id: jobId,
          version:
            typeof resultPayloadOf(result)?.version === 'string'
              ? /** @type {string} */ (resultPayloadOf(result)?.version)
              : null,
          transport: 'session'
        };
        await log('warning', 'client_update_activation_deferred', {
          job_id: jobId,
          version: resultPayloadOf(result)?.version,
          error: /** @type {Record<string, unknown>} */ (error).message,
          suggested_action: 'wait'
        });
        return;
      }
      await log('error', 'client_update_activation_failed', {
        job_id: jobId,
        version: resultPayloadOf(result)?.version,
        error: /** @type {Record<string, unknown>} */ (error).message
      });
      throw error;
    }
  }
}

async function handleSessionCancel(state, msg) {
  return transportHandleSessionCancel(state, msg, { log, stateFile: cfg.stateFile });
}

async function handleSessionJob(state, ws, msg) {
  return transportHandleSessionJob(state, ws, msg, {
    ensurePolicy: ensureJobPolicy,
    policyFailure: policyFailureResult,
    auditPolicyFail: auditPolicyFailure,
    executeTool: executeByTool,
    log,
    stateFile: cfg.stateFile
  });
}

async function runSessionOnce(state) {
  const privateKey = await getDeviceKey(cfg.deviceKeyFile),
    sessionUrl = cfg.serverUrl + '/agent/connect',
    proof = createDeviceProof({
      privateKey,
      clientId: cfg.clientId,
      method: 'GET',
      url: sessionUrl,
      credential: cfg.clientToken
    }),
    ws = /** @type {AgentSessionSocket} */ (
      await connectWebSocket(cfg.serverUrl, { token: cfg.clientToken, deviceProof: proof })
    );
  let welcomed = false;
  /** @type {(value?: unknown) => void} */
  let resolveWelcome;
  /** @type {(reason?: unknown) => void} */
  let rejectWelcome;
  const welcome = new Promise((r, j) => {
      resolveWelcome = r;
      rejectWelcome = j;
    }),
    timer = setTimeout(() => rejectWelcome(new Error('WELCOME_TIMEOUT')), 10000);

  const watchdog = attachPongWatchdog({
    onTimeout: () => {
      log('error', 'session_pong_timeout', { after_ms: PONG_TIMEOUT_MS }).catch(() => {});
      try {
        if (typeof ws.destroy === 'function') ws.destroy('pong timeout');
        else ws.close(4001, 'pong timeout');
      } catch {}
    }
  });
  ws.on('json', (m) => {
    watchdog.poke();
    if (m.type === 'welcome') {
      welcomed = true;
      clearTimeout(timer);
      try {
        if (m?.policy) applyCurrentPolicy(m.policy, m.policy_sig);
      } catch {}
      resolveWelcome(m);
      return;
    }
    if (m.type === 'request') {
      // Never void without a guard: writeState failures inside the job
      // pipeline reject, and an unhandled rejection kills the agent.
      handleSessionJob(state, ws, m).catch((e) => {
        log('error', 'session_job_async_failed', {
          job_id: String(m?.id || ''),
          error: e instanceof Error ? e.message : String(e)
        }).catch(() => {});
      });
      return;
    }
    if (m.type === 'cancel') {
      // Same unhandled-rejection guard as request/ack: cancel persists
      // state via writeState and must never kill the agent on failure.
      handleSessionCancel(state, m).catch((e) => {
        log('error', 'session_cancel_async_failed', {
          job_id: String(m?.data?.job_id || m?.id || ''),
          error: e instanceof Error ? e.message : String(e)
        }).catch(() => {});
      });
      return;
    }
    if (m.type === 'event' && m.kind === 'result_ack') {
      // Same unhandled-rejection guard: ack persists state and may
      // activate updates (which rethrows after logging).
      ackSessionResult(state, String(m.data?.job_id || ''), m.data?.status).catch((e) => {
        log('error', 'session_ack_async_failed', {
          job_id: String(m.data?.job_id || ''),
          error: e instanceof Error ? e.message : String(e)
        }).catch(() => {});
      });
      return;
    }
    if (m.type === 'ping')
      try {
        ws.sendJson({ type: 'pong', timestamp: new Date().toISOString() });
      } catch {}
    if (m.type === 'error' && m.fatal)
      rejectWelcome(new Error(m.code || m.message || 'SESSION_FATAL'));
  });
  ws.on('protocolError', (e) => rejectWelcome(e));
  const preWelcomeError = (/** @type {unknown} */ e) => rejectWelcome(e);
  ws.once('error', preWelcomeError);
  // Truthful first advertisement: no capability may race ahead of its
  // initial probe (container/compose/GAP-021, winget, darwin console).
  // Best-effort and bounded by the probe timeouts; a failed probe hides
  // its tools instead of advertising them.
  try {
    await Promise.all([
      refreshBrowserHealth(),
      refreshContainerHealth(),
      refreshComposeHealth(),
      refreshJournalHealth(),
      refreshWindowsPackageHealth(),
      refreshDarwinPackageHealth(),
      refreshLinuxPackageHealth(),
      refreshDarwinGuiHealth()
    ]);
  } catch {}
  ws.sendJson(sessionHello());
  // NB: preWelcomeError stays attached until the settle listeners below
  // are in place. Removing it here (e.g. via .finally) would reopen the
  // unguarded window over the post-welcome awaits (policy re-announce,
  // retirement reset, update health, pending flush): a socket 'error' in
  // that window has no listener and crashes the agent via EventEmitter
  // throw. The single removal point is after settled is attached.
  const w = await welcome.catch((/** @type {unknown} */ e) => {
    try {
      ws.close(4000, 'welcome failed');
    } catch {}
    // V-32.1: welcome failure skips the settled finally below, so cancel
    // the pong watchdog and the welcome timer here. Otherwise the watchdog
    // timer (once armed) and socket listeners leak on every failed welcome.
    try {
      watchdog.cancel();
    } catch {}
    try {
      clearTimeout(timer);
    } catch {}
    throw e;
  });
  // Same welcome object the handler above already applied (idempotent via
  // the monotonic cache). A policy-less welcome keeps the last verified
  // cache instead of wiping it: every enforcement path compares against
  // central-supplied identity/binding or refetches fresh, so keeping the
  // cache is availability without weakening denial.
  if (w?.policy) applyCurrentPolicy(w.policy, w.policy_sig);
  liveSession = ws;
  // Settle listeners BEFORE dropping the pre-welcome error guard: between
  // welcome and the old await below, a socket 'error' had no listener and
  // crashed the agent via EventEmitter throw.
  // The WS close code drives the reconnect decision (1012/1001/1006 reset
  // the backoff, everything else escalates). ws-client surfaces (code,
  // reason); a null code (local destroy, connect failure) keeps backoff.
  /** @type {unknown} */
  let closeCode = null;
  let closeReason = '';
  const settled = new Promise((resolve, reject) => {
    ws.once('close', (/** @type {unknown} */ code, /** @type {unknown} */ reason) => {
      closeCode = code;
      closeReason = typeof reason === 'string' ? reason : '';
      resolve(undefined);
    });
    ws.once('error', reject);
  });
  ws.removeListener('error', preWelcomeError);
  try {
    const rev = currentPolicy?.revision ?? null;
    const digest =
      currentPolicy && typeof currentPolicy.digest === 'string' ? currentPolicy.digest : null;
    if (rev !== helloPolicyRevision || digest !== helloPolicyDigest) {
      helloPolicyRevision = rev;
      helloPolicyDigest = digest;
      const announced = announceCapabilities();
      await log('info', 'capabilities_reannounced', {
        ...announced,
        reason: 'policy-welcome',
        revision: rev
      });
    }
  } catch {}
  await resetRetirementEvidence(state, cfg.stateFile);
  await log('info', 'session_connected', {
    protocol_version: w.protocol_version,
    session_id: w.session_id,
    policy_revision: currentPolicy?.revision ?? null,
    transport_scheme: configuredTransportScheme(cfg.serverUrl)
  });
  await markUpdateHealthy(layout, VERSION);
  try { await flushSessionPending(state, ws, cfg); } catch (e) { await log('error', 'flush_pending_failed', { error: String(e) }); }
  const hb = Math.max(5, Number(w.heartbeat_interval_seconds || 30)) * 1000,
    h = setInterval(() => {
      try {
        ws.sendJson({ type: 'ping', timestamp: new Date().toISOString() });
        watchdog.sentPing();
      } catch {}
    }, hb);
  try {
    await settled;
  } catch (error) {
    /** @type {Record<string, unknown>} */ (error).sessionEstablished = welcomed;
    throw error;
  } finally {
    clearInterval(h);
    watchdog.cancel();
    if (liveSession === ws) liveSession = null;
  }
  if (welcomed) {
    const error = /** @type {Error & {sessionEstablished?: boolean, closeCode?: unknown, closeReason?: string}} */ (
      new Error('SESSION_DISCONNECTED')
    );
    error.sessionEstablished = true;
    error.closeCode = closeCode;
    error.closeReason = closeReason;
    throw error;
  }
}

async function sessionLoop(state) {
  if (!cfg.sessionEnabled || !cfg.remoteExecEnabled || !cfg.clientToken) return;
  let attempt = 0;
  while (!retired) {
    const wait = SESSION_BACKOFF[Math.min(attempt, SESSION_BACKOFF.length - 1)];
    if (wait) await sleep(reconnectDelayMs(wait));
    if (retired) return;
    try {
      await runSessionOnce(state);
      attempt = 0;
    } catch (error) {
      liveSession = null;
      const sessionErr = /** @type {Record<string, unknown>} */ (error);
      const loggedAttempt = sessionErr?.sessionEstablished ? 0 : attempt;
      await log('error', 'session_failed', {
        error: sessionErr?.message || String(error),
        attempt: loggedAttempt,
        session_established: Boolean(sessionErr?.sessionEstablished),
        close_code:
          sessionErr && 'closeCode' in sessionErr
            ? Number(sessionErr.closeCode) || null
            : null
      });
      attempt = nextSessionAttempt(
        attempt,
        error && typeof error === 'object'
          ? /** @type {{sessionEstablished?: unknown}} */ (error)
          : null
      );
    }
  }
}

async function runTelemetryOnce(state) {
  if (!state) state = await readState(cfg.stateFile, cfg.clientId);
  if (!state.registered) {
    await register();
    state.registered = true;
    state.registered_client_id = cfg.clientId;
    await writeState(state, cfg.stateFile);
    await resetRetirementEvidence(state, cfg.stateFile);
  }
  if (!liveSession) await heartbeat();
  await resetRetirementEvidence(state, cfg.stateFile);
  const counts = { audit: 0 };
  if (cfg.auditFile) {
    const { forwardFile, sendAuditLine } = await import('./ws-transport.mjs');
    counts.audit = await forwardFile(
      state,
      'audit',
      cfg.auditFile,
      (line) => sendAuditLine(line, cfg),
      { bootstrapBytes: cfg.bootstrapBytes, stateFile: cfg.stateFile }
    );
  }
  await log('info', 'telemetry_cycle_ok', { counts });
  telemetryCycleCount++;
  try {
    if (telemetryCycleCount % 8 === 0) {
      const before = browserHealthCache.available;
      let refreshError = null;
      try {
        await refreshBrowserHealth();
      } catch (e) {
        refreshError = e instanceof Error ? e.message.slice(0, 160) : String(e).slice(0, 160);
      }
      if (browserHealthCache.available !== before) {
        const announced = announceCapabilities();
        await log('info', 'browser_health_changed', {
          available: browserHealthCache.available,
          ...announced
        });
      } else if (refreshError && refreshError !== lastBrowserRefreshError) {
        await log('warn', 'browser_health_refresh_failed', { error: refreshError });
      }
      lastBrowserRefreshError = refreshError;
      // Same cadence for the runtime truth caches: docker/daemon presence
      // (helper-confirmed), winget presence, darwin console session. The
      // liveCapsKey reannounce below picks up any advertisement change.
      try {
        await Promise.all([
          refreshContainerHealth(),
          refreshComposeHealth(),
          refreshJournalHealth(),
          refreshWindowsPackageHealth(),
          refreshDarwinPackageHealth(),
          refreshLinuxPackageHealth(),
          refreshDarwinGuiHealth()
        ]);
      } catch (e) {
        await log('warn', 'runtime_health_refresh_failed', {
          error: e instanceof Error ? e.message.slice(0, 160) : String(e).slice(0, 160)
        });
      }
      try {
        const key = liveCapsKey();
        if (key !== null && key !== lastAnnouncedCapsKey) {
          const announced = announceCapabilities();
          if (announced.sent) await log('info', 'browser_caps_reannounced', { ...announced });
        }
      } catch {}
    }
  } catch {}
  try {
    if (process.platform === 'win32') {
      const present = hasLiveBrokers(layout);
      if (present !== lastGuiBrokerPresence && (lastGuiBrokerPresence !== null || present)) {
        const announced = announceCapabilities();
        await log('info', 'gui_broker_presence_changed', { present, ...announced });
      }
      lastGuiBrokerPresence = present;
    }
  } catch {}
  try {
    const p = await fetchCurrentPolicy();
    const rev = p?.revision ?? null;
    const digest = p && typeof p.digest === 'string' ? p.digest : null;
    if (rev !== null && (rev !== helloPolicyRevision || digest !== helloPolicyDigest)) {
      helloPolicyRevision = rev;
      helloPolicyDigest = digest;
      const announced = announceCapabilities();
      await log('info', 'policy_revision_changed', { revision: rev, ...announced });
    }
  } catch {}
  return { state, counts };
}

async function telemetryLoop(state) {
  while (!retired) {
    try {
      await runTelemetryOnce(state);
      if (!retired) await sleep(cfg.heartbeatSeconds * 1000);
    } catch (error) {
      if (/** @type {Record<string, unknown>} */ (error)?.status === 404) {
        state.registered = false;
        state.registered_client_id = null;
      }
      if (
        await observeRetirementFailure(state, error, {
          serverUrl: cfg.serverUrl,
          clientId: cfg.clientId,
          stateFile: cfg.stateFile,
          retiredMarker: layout.retiredMarker,
          logFn: log
        })
      )
        return;
      await log('error', 'telemetry_cycle_failed', {
        error: /** @type {Record<string, unknown>} */ (error)?.message || String(error)
      });
      if (!retired) await sleep(cfg.retrySeconds * 1000);
    }
  }
}

async function jobLoop(state) {
  while (!retired) {
    try {
      if (!liveSession) await processOneJob(state);
      if (!retired) await sleep(cfg.jobPollSeconds * 1000);
    } catch (error) {
      await log('error', 'job_cycle_failed', {
        error: /** @type {Record<string, unknown>} */ (error)?.message || String(error)
      });
      if (!retired) await sleep(cfg.retrySeconds * 1000);
    }
  }
}

async function main() {
  // Diagnostics entry (node client.mjs --diagnostics [--apply]): collect a
  // redacted support bundle and exit before any agent loop starts.
  if (shouldHandleDiagnosticsCli(process.argv)) {
    const result = await runDiagnosticsCommand({ argv: process.argv, version: VERSION });
    if (result.summary) console.log(result.summary);
    if (!result.ok) process.exitCode = 1;
    return 'diagnostics';
  }
  await fs.mkdir(layout.data, { recursive: true });
  await fs.mkdir(layout.logs, { recursive: true });
  await fs.mkdir(layout.releases, { recursive: true });
  await fs.mkdir(layout.backups, { recursive: true });
  await fs.mkdir(layout.tmp, { recursive: true });
  await fs.mkdir(layout.workspace, { recursive: true });
  try {
    await fs.access(layout.retiredMarker);
    retired = true;
    await log('info', 'client_retired_marker_present', { client_id: cfg.clientId });
    return 'retired';
  } catch (error) {
    if (/** @type {Record<string, unknown>} */ (error)?.code !== 'ENOENT') throw error;
  }
  await fs.writeFile(layout.pidFile, String(process.pid) + '\n', { mode: 0o640 });
  try {
    const swept = await sweepOrphanedSessions({ stateDir: layout.data });
    if (swept.length)
      await log('info', 'process_orphan_sweep', { swept: swept.length, actions: swept });
  } catch {}
  const state = await readState(cfg.stateFile, cfg.clientId);
  if (markInterruptedJobs(state)) await writeState(state, cfg.stateFile);
  try {
    if (confirmCompletedUpdates(state, VERSION)) {
      await writeState(state, cfg.stateFile);
      await log('info', 'client_update_confirmed', { version: VERSION });
    }
  } catch {}
  try {
    const { activateStagedBrowserRuntime, activateBundledBrowserRuntime, resolveBrowserRuntime } =
      await import('../browser/browser-runtime.mjs');
    const rtBase = resolveBrowserRuntime({ root: layout.root }).base;
    const bundled = await activateBundledBrowserRuntime({
      appDir: mainScriptDir(),
      base: rtBase
    });
    const promoted = await activateStagedBrowserRuntime(rtBase);
    await log('info', 'browser_runtime_promotion', { bundled, staged: promoted });
    (async () => {
      for (let attempt = 1; attempt <= 4; attempt++) {
        try {
          const m = await import('../browser/browser-runtime.mjs');
          try {
            const core = await m.ensurePlaywrightCore(rtBase);
            await log('info', 'browser_core_convergence', { ...core });
          } catch {}
          const r = /** @type {{installed?: unknown}} */ (await m.ensureManagedBrowsers(rtBase));
          await log('info', 'browser_binary_convergence', { ...r });
          if (r.installed && !browserHealthCache.available) {
            let refreshError = null;
            try {
              await refreshBrowserHealth();
            } catch (e) {
              refreshError = e instanceof Error ? e.message.slice(0, 160) : String(e).slice(0, 160);
            }
            const announced = announceCapabilities();
            await log('info', 'browser_convergence_announced', {
              available: browserHealthCache.available,
              refresh_error: refreshError,
              ...announced
            });
          }
          if (!r.installed) {
            try {
              m.scheduleConvergenceRetry({
                base: rtBase,
                onResult: async (rr) => {
                  const rec = /** @type {{installed?: unknown}} */ (
                    typeof rr === 'object' && rr !== null ? rr : {}
                  );
                  await log('info', 'browser_binary_convergence_retry', { ...rec });
                  if (rec.installed && !browserHealthCache.available) {
                    try {
                      await Promise.all([
                        refreshBrowserHealth(),
                        refreshContainerHealth(),
                        refreshComposeHealth(),
                        refreshJournalHealth()
                      ]);
                    } catch {}
                    if (browserHealthCache.available) announceCapabilities();
                  }
                }
              });
            } catch {}
          }
          return;
        } catch (error) {
          await log('warn', 'browser_convergence_boot_retry', {
            attempt,
            error:
              error instanceof Error ? error.message.slice(0, 200) : String(error).slice(0, 200)
          });
        }
        await sleep(Math.min(60000, 5000 * attempt));
      }
    })();
  } catch {}
  try {
    await refreshBrowserHealth();
  } catch {}
  await log('info', 'browser_health', { ...browserHealthCache });
  // Initial runtime truth probes before any heartbeat/register
  // advertisement (GAP-021, winget, darwin console). Session hello
  // re-probes per connection; telemetry re-probes on its cadence.
  try {
    await Promise.all([
      refreshContainerHealth(),
      refreshComposeHealth(),
      refreshJournalHealth(),
      refreshWindowsPackageHealth(),
      refreshDarwinPackageHealth(),
      refreshLinuxPackageHealth(),
      refreshDarwinGuiHealth()
    ]);
  } catch {}
  await log('info', 'runtime_health', {
    container: { ...containerHealthCache },
    compose: { ...composeHealthCache },
    journal: { ...journalHealthCache },
    windows_package: { ...windowsPackageCache },
    darwin_package: { ...darwinPackageCache },
    linux_package: { ...linuxPackageCache },
    darwin_gui: { ...darwinGuiCache }
  });
  await log('info', 'nc-client starting', {
    server: cfg.serverUrl,
    client_id: cfg.clientId,
    version: VERSION,
    remote_exec_enabled: cfg.remoteExecEnabled,
    token_configured: Boolean(cfg.clientToken),
    session_enabled: cfg.sessionEnabled,
    protocol_version: cfg.protocolVersion,
    capabilities: advertisedCapabilities(),
    filesystem_root: layout.root,
    runtime_app_dir: mainScriptDir()
  });
  await Promise.all([telemetryLoop(state), jobLoop(state), sessionLoop(state)]);
  return retired ? 'retired' : undefined;
}

const invokedAsScript =
  process.argv[1] &&
  (process.argv[1].endsWith('/client.mjs') || process.argv[1].endsWith('\\client.mjs'));
if (invokedAsScript) {
  main().catch(async (error) => {
    await log('error', 'fatal', { error: error?.stack || String(error) });
    process.exitCode = 1;
  });
}

export {
  PONG_TIMEOUT_MS,
  advertisedCapabilities,
  agentInstallMode,
  announceCapabilities,
  attachPongWatchdog,
  boundSessionResult,
  browserHealthCache,
  containerHealthCache,
  composeHealthCache,
  journalHealthCache,
  windowsPackageCache,
  darwinPackageCache,
  linuxPackageCache,
  packageAdvertisementState,
  darwinGuiCache,
  refreshContainerHealth,
  refreshComposeHealth,
  refreshJournalHealth,
  refreshWindowsPackageHealth,
  refreshDarwinPackageHealth,
  refreshLinuxPackageHealth,
  refreshDarwinGuiHealth,
  confirmCompletedUpdates,
  defaultShellCwd,
  detectLegacyArtifacts,
  discoverUserFolders,
  executeLogReadJob,
  executePrivilegeStatusJob,
  executeShellJob,
  getHandlers,
  handleSessionCancel,
  handleSessionJob,
  localAuditPayload,
  main,
  nextSessionAttempt,
  processOneJob,
  reconnectDelayMs,
  refreshBrowserHealth,
  registrationStateForClient,
  runTelemetryOnce,
  shellAbortByJob,
  shellChildDetached,
  shellInvocation,
  shellTouchesAgentTree
};
