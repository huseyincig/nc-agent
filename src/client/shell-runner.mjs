import fsSync from 'node:fs';
import osSync from 'node:os';
import { spawn } from 'node:child_process';
import { shellInvocation, shellChildDetached } from '../shell/shell-ops.mjs';
import { ncLayout } from './nc-paths.mjs';
import { isSensitivePath, sensitiveCommandHit } from '../filesystem/sensitive-paths.mjs';

const layout = ncLayout();

/**
 * Finding 1 (HIGH) — shared inherit-blocklist for every spawned child.
 *
 * Both spawn paths (`shell_exec` here and `process_start` via
 * `sanitizedSessionEnv` in process-sessions.mjs) previously stripped only
 * our own `NC_*` / `CONTROL_PLANE_*` prefixes and inherited the rest of
 * the host environment verbatim — so `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`,
 * `OPENAI_API_KEY` etc. reached every command the agent ran, including
 * commands driven by a remote MCP client (host-secret exfiltration path).
 * Both paths now filter through THIS function, so the rule cannot drift
 * again (two copies of the prefix rule is why the hole existed twice).
 *
 * Blocklist vs allowlist (decision): an allowlist (e.g. only
 * PATH/HOME/TEMP, as the reference design does) would break legitimate
 * workflows that depend on inherited environment (LANG, TZ, JAVA_HOME,
 * PYTHONPATH, proxy vars, CI-provided config, tool homes). The inherit
 * blocklist below targets the credential class specifically and leaves
 * everything else untouched. Over-stripping errs fail-closed (a denied name
 * is simply absent from the child) and is recoverable via the opt-in
 * passthrough; under-stripping would leak. So: block by default.
 *
 * Passthrough (decision): some hosts deliberately configure tool auth the
 * agent's tools need (`gh` reading `GH_TOKEN`, `npm` reading `NPM_TOKEN`,
 * cloud SDKs reading `AWS_*`). Blocking unconditionally would silently
 * break those runs with no recourse. `NC_ENV_PASSTHROUGH` (comma-separated
 * exact names, agent-local `process.env` only) re-admits named secrets.
 * Safety properties, all pinned by tests:
 * - agent-local: read from the agent's own environment at spawn time; the
 *   remote MCP client cannot set `NC_*` keys (per-session `env` rejects
 *   them via isDangerousSessionEnvKey; `shell_exec` takes no remote env),
 *   so a remote operator can never widen the passthrough;
 * - exact names only (case-insensitive), never patterns — one entry opens
 *   one variable, never a class;
 * - cannot re-admit `NC_*` / `CONTROL_PLANE_*` (the agent's own tokens stay
 *   stripped even if listed — fail closed).
 * Explicit per-session `env` (process_start) still applies on top
 * unfiltered by this list: a remote-supplied value is the remote's OWN
 * value, not a host secret, so passing it through leaks nothing.
 */
export const NEVER_INHERIT_ENV_RE =
  /(?:TOKEN|SECRET|PASSWD|PASSWORD|PRIVATE_KEY|API_KEY|ACCESS_KEY|CREDENTIAL)/i;
/** Exact high-value credential names matching no keyword above. Kept tiny
 * and explicit on purpose: connection strings embed `user:pass@host`
 * (the same URL-credential class the display layer redacts). */
const INHERITED_ENV_EXTRA_BLOCKED = new Set(['DATABASE_URL']);
/** Agent-local opt-in passthrough list (see block comment above). */
export const ENV_PASSTHROUGH_VAR = 'NC_ENV_PASSTHROUGH';
const ENV_PASSTHROUGH_MAX_ENTRIES = 64;
const ENV_PASSTHROUGH_MAX_NAME_CHARS = 256;
const ENV_PASSTHROUGH_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
/**
 * Parse the agent-local passthrough list. Bounded (entry count, name
 * length, strict identifier shape); `NC_*` / `CONTROL_PLANE_*` entries are
 * dropped — the agent-token strip is absolute and never re-admittable.
 * @param {Record<string, string|undefined>} [source]
 * @returns {Set<string>} upper-cased exact names
 */
export function parseEnvPassthrough(source = process.env) {
  const out = new Set();
  const raw = source?.[ENV_PASSTHROUGH_VAR];
  if (typeof raw !== 'string' || !raw) return out;
  for (const part of raw.split(',')) {
    if (out.size >= ENV_PASSTHROUGH_MAX_ENTRIES) break;
    const name = part.trim();
    if (!name || name.length > ENV_PASSTHROUGH_MAX_NAME_CHARS) continue;
    if (!ENV_PASSTHROUGH_NAME_RE.test(name)) continue;
    const upper = name.toUpperCase();
    if (upper.startsWith('NC_') || upper.startsWith('CONTROL_PLANE_')) continue;
    out.add(upper);
  }
  return out;
}
/**
 * Inherit-blocklist predicate shared by every spawn path.
 * @param {unknown} key env name
 * @param {Set<string>|null} [passthrough] upper-cased exact names from parseEnvPassthrough
 */
export function isInheritableEnvKey(key, passthrough = null) {
  if (typeof key !== 'string' || !key) return false;
  const upper = key.toUpperCase();
  // Deliberate, tested rule (SEC-002): agent tokens never inherit. Folded
  // for the Windows case-insensitive block (P13-D2); a superset of the old
  // case-sensitive strip, so nothing previously stripped now passes.
  if (upper.startsWith('NC_') || upper.startsWith('CONTROL_PLANE_')) return false;
  if (passthrough instanceof Set && passthrough.has(upper)) return true;
  if (NEVER_INHERIT_ENV_RE.test(key)) return false;
  if (INHERITED_ENV_EXTRA_BLOCKED.has(upper)) return false;
  return true;
}
/**
 * Filter an environment object down to inheritable entries. THE single
 * choke point — both spawn paths must call this (directly or via
 * shellEnvironment) and never re-implement the rule.
 * @param {Record<string, string|undefined>} [source]
 * @param {Set<string>|null} [passthrough]
 */
export function filterInheritedEnv(source = process.env, passthrough = null) {
  const allow = passthrough instanceof Set ? passthrough : parseEnvPassthrough(source);
  const out = /** @type {Record<string, string|undefined>} */ ({});
  for (const [key, value] of Object.entries(source ?? {})) {
    if (!isInheritableEnvKey(key, allow)) continue;
    out[key] = value;
  }
  return out;
}
/**
 * @param {Record<string, string|undefined>} [source]
 */
export function shellEnvironment(source = process.env) {
  return filterInheritedEnv(source);
}

/**
 * A7 — process timing analytics (first-output + pattern-match telemetry).
 *
 * `duration_ms` (total wall time) already exists on every shell result; it
 * is preserved verbatim. These helpers add the two missing dimensions
 * without ever touching output bodies: only elapsed-millisecond numbers
 * leave this module, so the audit-log body ban stays intact.
 *
 * - `time_to_first_output_ms`: spawn → first stdout/stderr byte.
 * - `time_to_pattern_match_ms`: spawn → first `output_pattern` hit.
 * Both are `number|null` (never `undefined`): null means "no event"
 * (silent command, no pattern supplied, or no match before settle).
 */
export const MAX_OUTPUT_PATTERN_CHARS = 512;
export const PATTERN_MATCH_WINDOW_CHARS = 65536;
/**
 * Validate a model-supplied `output_pattern`. Literal substring semantics
 * (never RegExp: no ReDoS surface, no invalid-pattern throws). Telemetry
 * must never break execution, so anything unusable resolves to null
 * (caller records `time_to_pattern_match_ms: null`) instead of failing.
 * @param {unknown} value
 * @returns {string|null}
 */
export function normalizeOutputPattern(value) {
  if (value === undefined || value === null) return null;
  const text = String(value);
  if (!text || text.includes('\0') || text.length > MAX_OUTPUT_PATTERN_CHARS) return null;
  return text;
}
/**
 * Coerce an elapsed-ms reading to the audit-safe `number|null` form.
 * @param {unknown} value
 * @returns {number|null}
 */
export function normalizeTimingMs(value) {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? Math.floor(value)
    : null;
}

/**
 * A8-b — child priority shedding (platform-aware, agent-safe).
 *
 * Direction is deliberately one-sided: the CHILD is deprioritized, the
 * agent's own priority is never touched (no setPriority on self, no
 * negative nice, no OOM self-adjust — a mistake there takes the fleet
 * down). Lowering priority / raising oom_score_adj needs no privileges,
 * so this is best-effort and never throws: failures resolve to
 * `skipped-*` outcomes the caller may ignore.
 *
 * - Linux: `nice +10` via `os.setPriority` + `/proc/<pid>/oom_score_adj`
 *   so the OOM killer prefers the heavy child over the agent.
 * - macOS (darwin): `nice` only — no `/proc`, hence no oom_score_adj.
 * - Windows: NOT implemented — child priority classes need a different
 *   mechanism (`REALTIME_PRIORITY_CLASS` et al.) with no in-repo evidence;
 *   returns `skipped-platform` honestly instead of guessing.
 * @param {{pid?: unknown}|null|undefined} child spawned child (or `{pid}`)
 * @param {{platform?: string}} [options] injectable for deterministic tests
 */
export const CHILD_NICE_VALUE = 10;
export const CHILD_OOM_SCORE_ADJ = 500;
export function shedChildPriority(child, { platform = process.platform } = {}) {
  const outcome = { platform, nice: 'skipped', oom_score_adj: 'skipped' };
  const pid = Math.floor(Number(child?.pid));
  if (!Number.isSafeInteger(pid) || pid < 2) {
    outcome.nice = 'skipped-no-pid';
    outcome.oom_score_adj = 'skipped-no-pid';
    return outcome;
  }
  if (platform === 'win32') {
    outcome.nice = 'skipped-platform';
    outcome.oom_score_adj = 'skipped-platform';
    return outcome;
  }
  try {
    osSync.setPriority(pid, CHILD_NICE_VALUE);
    outcome.nice = 'applied';
  } catch {
    outcome.nice = 'skipped-error';
  }
  if (platform !== 'linux') {
    outcome.oom_score_adj = 'skipped-platform';
    return outcome;
  }
  try {
    fsSync.writeFileSync(`/proc/${pid}/oom_score_adj`, String(CHILD_OOM_SCORE_ADJ));
    outcome.oom_score_adj = 'applied';
  } catch {
    outcome.oom_score_adj = 'skipped-error';
  }
  return outcome;
}

const warnedConfigNames = new Set();
/**
 * One-time stderr warning for unrecognized config values (mirrors L1-P25-03:
 * name the bad value, keep the safe resolution). Warns once per process.
 * @param {string} name env/config name
 * @param {unknown} raw rejected value
 * @param {string} resolution effective value description
 */
export function warnOnceConfig(name, raw, resolution) {
  if (warnedConfigNames.has(name)) return;
  warnedConfigNames.add(name);
  try {
    console.warn(
      `[config] ignoring invalid ${name}=${JSON.stringify(String(raw))}; using ${resolution}`
    );
  } catch {}
}

/**
 * P26: numeric env with safe-default. `Math.max(floor, Number(garbage))`
 * yields NaN (not the floor), which propagated into heartbeat sleeps
 * (1ms busy-loop), shell timeouts (instant "timeout after NaNs") and byte
 * caps (silently empty outputs) with zero diagnosability. Garbage now warns
 * once and resolves to the default; finite values keep legacy floor
 * semantics exactly (negatives still clamp, no warning).
 * @param {string} name env name
 * @param {number} def default when unset/empty/unparseable
 * @param {number} min legacy floor
 * @param {Record<string, string|undefined>} [source]
 */
export function clampedEnvNumber(name, def, min, source = process.env) {
  const raw = source?.[name];
  if (raw == null || String(raw).trim() === '') return def;
  const n = Number(String(raw).trim());
  if (!Number.isFinite(n)) {
    warnOnceConfig(name, raw, `default ${def}`);
    return def;
  }
  return Math.max(min, n);
}

/**
 * P26: service-mode normalization. Only user intent selects user-mode;
 * case/whitespace variants ('User', 'user ') previously fell through to the
 * system path (provision bypassed USER_MODE_BY_DESIGN). Recognized variants
 * now match intent; other unrecognized values still resolve to 'system'
 * with a one-time warning (resolution unchanged).
 * @param {unknown} value raw mode value (env or option)
 * @param {string|null} [warnName] env name for the warn-once (null = silent)
 * @returns {'user'|'system'}
 */
export function normalizeServiceMode(value, warnName = null) {
  const folded = String(value ?? '').trim().toLowerCase();
  if (folded === 'user') return 'user';
  if (folded === '' || folded === 'system') return 'system';
  if (warnName) warnOnceConfig(warnName, value, "'system'");
  return 'system';
}

/**
 * @param {import('node:child_process').ChildProcess|null|undefined} child
 * @param {string} [platform]
 * @param {boolean} [force]
 */
export function terminateShellTree(child, platform = process.platform, force = false) {
  if (!child?.pid) return;
  if (platform === 'win32') {
    const line = 'taskkill /PID ' + child.pid + ' /T /F >NUL 2>&1';
    try {
      spawn(process.env.ComSpec || process.env.COMSPEC || 'cmd.exe', ['/d', '/s', '/c', line], {
        stdio: 'ignore',
        windowsHide: true
      }).unref();
    } catch {}
    return;
  }
  try {
    process.kill(-child.pid, force ? 'SIGKILL' : 'SIGTERM');
  } catch {}
}

/**
 * @param {Array<Buffer>} chunks
 * @param {Buffer|Uint8Array|string} chunk
 * @param {number} currentBytes
 * @param {number} maxBytes
 */
export function appendLimited(chunks, chunk, currentBytes, maxBytes) {
  if (currentBytes >= maxBytes) return { bytes: currentBytes, truncated: true };
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  const room = maxBytes - currentBytes;
  const slice = buffer.subarray(0, room);
  if (slice.length) chunks.push(slice);
  return { bytes: currentBytes + slice.length, truncated: buffer.length > room };
}

/**
 * Shared output-bounding policy (Finding 4): every layer keeps HEAD first
 * and TAIL last because failure diagnostics (compiler errors, stack traces,
 * exit summaries) print at the end, while invocation context (command,
 * headers) prints at the start. The middle is the expendable part.
 * Split: 60% head / 40% tail of the usable budget (usable = cap minus the
 * truncation marker, so a bounded value never exceeds its cap).
 */
export const OUTPUT_HEAD_RATIO = 0.6;
export const OUTPUT_TRUNCATION_MARKER = '\n…[nc: output truncated, head+tail retained]…\n';

/**
 * @param {number} maxBytes total byte budget including the marker
 * @param {number} [headRatio]
 */
export function splitOutputBudget(maxBytes, headRatio = OUTPUT_HEAD_RATIO) {
  const max = Math.max(64, Math.floor(Number(maxBytes) || 0));
  const markerBytes = Buffer.byteLength(OUTPUT_TRUNCATION_MARKER, 'utf8');
  const usable = Math.max(1, max - markerBytes);
  const ratio = Math.min(0.9, Math.max(0.1, Number(headRatio) || OUTPUT_HEAD_RATIO));
  const head = Math.floor(usable * ratio);
  return { max, head, tail: usable - head, markerBytes };
}

/**
 * One-shot head+tail truncation of a string/buffer to maxBytes.
 * @param {unknown} input
 * @param {number} maxBytes
 */
export function headTailTruncate(input, maxBytes) {
  const raw = Buffer.isBuffer(input) ? Buffer.from(input) : Buffer.from(String(input ?? ''));
  if (raw.length <= Math.max(64, Math.floor(Number(maxBytes) || 0))) {
    return { text: raw.toString('utf8'), truncated: false, omitted: 0 };
  }
  const { max, head, tail } = splitOutputBudget(maxBytes);
  void max;
  let headStr = raw.subarray(0, head).toString('utf8');
  while (Buffer.byteLength(headStr, 'utf8') > head && headStr.length > 0) {
    headStr = headStr.slice(0, -1);
  }
  let tailStr = tail > 0 ? raw.subarray(raw.length - tail).toString('utf8') : '';
  while (Buffer.byteLength(tailStr, 'utf8') > tail && tailStr.length > 0) {
    tailStr = tailStr.slice(1);
  }
  return {
    text: headStr + OUTPUT_TRUNCATION_MARKER + tailStr,
    truncated: true,
    omitted: raw.length - Buffer.byteLength(headStr, 'utf8') - Buffer.byteLength(tailStr, 'utf8')
  };
}

/**
 * Streaming head+tail accumulator for live child output. Keeps the first
 * `head` bytes verbatim and a ring of the last `tail` bytes; middle bytes
 * are dropped (counted in `dropped`). Memory is bounded by construction:
 * head budget + tail budget + one in-flight chunk, regardless of how much
 * the child emits. `truncated` is true only when bytes were actually lost
 * (matches the legacy flag semantics: under-budget output is byte-identical
 * to the old path, with no marker injected).
 * @param {number} maxBytes
 */
export function createBoundedOutput(maxBytes) {
  const { head: headBudget, tail: tailBudget } = splitOutputBudget(maxBytes);
  /** @type {Array<Buffer>} */
  const headChunks = [];
  /** @type {Array<Buffer>} */
  const tailChunks = [];
  let headBytes = 0;
  let tailBytes = 0;
  let dropped = 0;
  return {
    /** @param {Buffer|Uint8Array|string} chunk */
    append(chunk) {
      let buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (!buf.length) return { bytes: headBytes + tailBytes, truncated: dropped > 0 };
      if (headBytes < headBudget) {
        const take = Math.min(headBudget - headBytes, buf.length);
        if (take > 0) {
          headChunks.push(buf.subarray(0, take));
          headBytes += take;
        }
        buf = buf.subarray(take);
        if (!buf.length) return { bytes: headBytes + tailBytes, truncated: dropped > 0 };
      }
      tailChunks.push(buf);
      tailBytes += buf.length;
      let excess = tailBytes - tailBudget;
      while (excess > 0 && tailChunks.length > 0) {
        const first = tailChunks[0];
        if (first.length <= excess) {
          tailChunks.shift();
          tailBytes -= first.length;
          dropped += first.length;
          excess -= first.length;
        } else {
          tailChunks[0] = first.subarray(excess);
          tailBytes -= excess;
          dropped += excess;
          excess = 0;
        }
      }
      return { bytes: headBytes + tailBytes, truncated: dropped > 0 };
    },
    get truncated() {
      return dropped > 0;
    },
    get droppedBytes() {
      return dropped;
    },
    text() {
      const head = Buffer.concat(headChunks).toString('utf8');
      const tail = Buffer.concat(tailChunks).toString('utf8');
      if (dropped <= 0) return head + tail;
      return head + OUTPUT_TRUNCATION_MARKER + tail;
    }
  };
}

/**
 * Best-effort literal scan: does a shell command reference the agent tree
 * outside the writable workspace? Catches `> C:\...\NC\...` redirections and
 * absolute tool paths; intentionally NOT a sandbox (env vars, cd-relative
 * writes and pipes escape static analysis — OS permissions remain the floor).
 * @param {string} command
 * @param {string} [platform]
 */
export function shellTouchesAgentTree(command, platform = process.platform) {
  try {
    const root = layout?.root;
    if (!root || typeof root !== 'string') return false;
    const win = platform === 'win32';
    const norm = (v) => {
      let s = String(v || '');
      if (win) s = s.replace(/\//g, '\\').toLowerCase();
      else s = s.replace(/\/+/g, '/');
      return s.replace(win ? /\\+$/ : /\/+$/, '');
    };
    let text = norm(command);
    const ws = layout?.workspace;
    if (ws && typeof ws === 'string') {
      const w = norm(ws);
      if (w) text = text.split(w).join('');
    }
    const r = norm(root);
    return Boolean(r) && text.includes(r);
  } catch {
    return false;
  }
}

/**
 * Bounded tail excerpt of stderr for failure payloads (telemetry cluster:
 * 144 `exit-code-1` are "no actionable signal" — the model needs the real
 * stderr tail, not a bare code). Tail, not head: compilers/git print the
 * fatal line last. Never masks: the result stays failed.
 * @param {unknown} stderr
 * @param {number} [maxChars]
 */
export const SHELL_STDERR_EXCERPT_CHARS = 2000;
export function stderrExcerpt(stderr, maxChars = SHELL_STDERR_EXCERPT_CHARS) {
  const text = String(stderr || '');
  const cap = Math.max(256, Math.min(8192, Math.floor(Number(maxChars) || SHELL_STDERR_EXCERPT_CHARS)));
  if (text.length <= cap) return text;
  return `…[first ${text.length - cap} chars truncated]…` + text.slice(-cap);
}

/**
 * exit-128 cause parser (telemetry: 19 `exit-128`). Exit 128 is almost
 * always git (128 = fatal) or death by SIGHUP — never a "random failure".
 * Returns the real cause plus the recovery hint; unknown stays unknown
 * (with excerpt) rather than guessing.
 * @param {unknown} stderr
 * @param {unknown} signal
 */
export function classifyExit128(stderr, signal) {
  if (signal === 'SIGHUP')
    return {
      cause: 'TERMINATED_SIGHUP',
      failure_class: 'SIGNALED_SIGHUP',
      suggested_action: 'retry',
      detail:
        'shell died on SIGHUP (terminal hangup / session loss), not on a command error; retry, or run under process_start for hangup-immune long work'
    };
  const text = String(stderr || '');
  /** @param {RegExp} re */
  const hit = (re) => re.test(text);
  if (hit(/host key verification failed/i))
    return {
      cause: 'SSH_HOST_KEY_UNVERIFIED',
      failure_class: 'EXIT_128_GIT_SSH',
      suggested_action: 'change_input',
      detail: 'ssh refused the remote host key (unknown/rotated key); verify the host key out of band before retrying'
    };
  if (hit(/permission denied \(publickey\)/i) || hit(/could not read from remote repository/i))
    return {
      cause: 'SSH_AUTH_FAILED',
      failure_class: 'EXIT_128_GIT_SSH',
      suggested_action: 'change_input',
      detail: 'remote rejected the ssh credentials (missing key or key not authorized on the remote); fix credentials/URL, do not retry verbatim'
    };
  if (hit(/authentication failed/i) || hit(/invalid credentials/i) || hit(/invalid username/i))
    return {
      cause: 'GIT_CREDENTIALS_REJECTED',
      failure_class: 'EXIT_128_GIT_AUTH',
      suggested_action: 'change_input',
      detail: 'remote rejected the http credentials; fix the credential/URL, do not retry verbatim'
    };
  if (hit(/could not resolve host/i) || hit(/unable to connect/i) || hit(/connection timed out/i) || hit(/network is unreachable/i))
    return {
      cause: 'GIT_NETWORK_UNREACHABLE',
      failure_class: 'EXIT_128_GIT_NETWORK',
      suggested_action: 'retry',
      detail: 'remote host unreachable (dns/network); safe to retry after backoff'
    };
  if (hit(/repository .*not found/i) || hit(/not found.*repository/i) || hit(/empty repository/i))
    return {
      cause: 'GIT_REPO_NOT_FOUND',
      failure_class: 'EXIT_128_GIT_SSH',
      suggested_action: 'change_input',
      detail: 'remote repository does not exist (or credentials hide it); fix the URL, do not retry verbatim'
    };
  if (hit(/not a git repository/i))
    return {
      cause: 'GIT_NOT_A_REPO',
      failure_class: 'EXIT_128_GIT_LOCAL',
      suggested_action: 'change_input',
      detail: 'cwd is not inside a git repository; run from a repo checkout or clone first'
    };
  return {
    cause: 'EXIT_128_UNKNOWN',
    failure_class: 'EXIT_128_UNKNOWN',
    suggested_action: 'change_input',
    detail: 'command exited 128 with no recognized git/ssh signature; inspect the stderr excerpt'
  };
}

/**
 * Rich classification for a failed shell result. NEVER masks: the caller
 * keeps status failed; this only adds signal (exit code + bounded excerpt +
 * suggested_action) so the model reacts instead of blindly retrying the
 * same command (the 144 `exit-code-1` cluster).
 * @param {{exitCode?: number|null, signal?: unknown, stderr?: unknown}} outcome
 */
export function classifyShellFailure({ exitCode = null, signal = null, stderr = '' } = {}) {
  const excerpt = stderrExcerpt(stderr);
  const code = typeof exitCode === 'number' ? exitCode : null;
  if (typeof signal === 'string' && signal) {
    if (signal === 'SIGHUP') return { ...classifyExit128(stderr, signal), exit_code: code, stderr_excerpt: excerpt };
    return {
      cause: `TERMINATED_${signal}`,
      failure_class: `SIGNALED_${signal}`,
      suggested_action: signal === 'SIGKILL' ? 'contact_operator' : 'retry',
      detail:
        signal === 'SIGKILL'
          ? 'process was SIGKILLed from outside (oom-killer or operator); inspect host memory/state before retrying'
          : `process died on ${signal}; safe to retry once, then inspect`,
      exit_code: code,
      stderr_excerpt: excerpt
    };
  }
  if (code === 128) return { ...classifyExit128(stderr, signal), exit_code: code, stderr_excerpt: excerpt };
  if (code === 127)
    return {
      cause: 'COMMAND_NOT_FOUND',
      failure_class: 'COMMAND_NOT_FOUND',
      suggested_action: 'change_input',
      detail: 'command not found (127): fix spelling or PATH/install the tool; retrying verbatim cannot succeed',
      exit_code: code,
      stderr_excerpt: excerpt
    };
  if (code === 126)
    return {
      cause: 'COMMAND_NOT_EXECUTABLE',
      failure_class: 'COMMAND_NOT_EXECUTABLE',
      suggested_action: 'change_input',
      detail: 'found but not executable (126): fix permissions or invoke via its interpreter',
      exit_code: code,
      stderr_excerpt: excerpt
    };
  return {
    cause: `EXIT_${code}`,
    failure_class: 'COMMAND_EXIT_NONZERO',
    suggested_action: 'change_input',
    detail: `command failed with exit ${code}: read the stderr excerpt, fix the cause, do not retry verbatim`,
    exit_code: code,
    stderr_excerpt: excerpt
  };
}

/**
 * Restart-safety classification for CLIENT_RESTART_DURING_EXECUTION
 * (telemetry: 9). The marker itself is written by agent-state
 * markInterruptedJobs; this helper decides what the marker MUST say:
 * idempotent/convergent work is safe to re-run, destructive work must not
 * be, and arbitrary shell is unknown (never "safe" by default).
 * Advisory + serializable so the marker can embed it verbatim.
 * @param {unknown} tool
 */
export function restartSafetyForTool(tool) {
  const name = String(tool || '');
  if (/^(service_control|service_manage|compose_control|compose_op)$/.test(name))
    return {
      safe_to_retry: true,
      suggested_action: 'wait',
      note: `${name} verbs converge (start/stop/restart/up); safe to re-run after the agent is back`
    };
  if (/^(package_control|package_manage)$/.test(name))
    return {
      safe_to_retry: true,
      suggested_action: 'wait',
      note: `${name} install/remove converges via the system package manager; safe to re-run after the agent is back`
    };
  if (/^file_permissions$/.test(name))
    return {
      safe_to_retry: true,
      suggested_action: 'wait',
      note: 'chmod/chown converges on the target state; safe to re-run after the agent is back'
    };
  if (/^client_uninstall$/.test(name))
    return {
      safe_to_retry: false,
      suggested_action: 'contact_operator',
      note: 'uninstall is destructive and the host may already be gone; do NOT auto-retry, ask the operator'
    };
  if (/^client_update$/.test(name))
    return {
      safe_to_retry: false,
      suggested_action: 'wait',
      note: 'update may have activated before the restart (boot confirmation decides); do NOT re-issue, poll the agent version'
    };
  return {
    safe_to_retry: null,
    suggested_action: 'wait',
    note: `${name || 'this operation'} is not known-idempotent (arbitrary command); inspect job output/host state before retrying, never blindly re-run`
  };
}

/**
 * Agent-side payload fragment a CLIENT_RESTART_DURING_EXECUTION marker
 * should embed so the error says explicitly whether a retry is safe.
 * (Wiring lives in agent-state markInterruptedJobs + control-plane; this
 * module owns the classification.)
 * @param {unknown} jobOrTool tool name or job record with .tool
 */
export function restartInterruptionPayload(jobOrTool) {
  const tool =
    typeof jobOrTool === 'string'
      ? jobOrTool
      : /** @type {{tool?: unknown}|null|undefined} */ (jobOrTool)?.tool;
  const safety = restartSafetyForTool(tool);
  return {
    error: 'CLIENT_RESTART_DURING_EXECUTION',
    result_payload: {
      error_code: 'CLIENT_RESTART_DURING_EXECUTION',
      retryable: true,
      ...safety
    }
  };
}

/**
 * Guard a model-supplied working directory (P3-D1): cwd reaches spawn(2)
 * verbatim, so relative paths resolve against it AFTER the command-text
 * scans run. Without this, `cat shadow` + cwd `/etc` reads files the
 * literal scans cannot see (they only inspect command text, and bare
 * filenames never match). Absolute + length/NUL-checked + realpath-resolved
 * (symlink-aware, mirroring the privileged file_permissions discipline) +
 * credential-denylisted; fails closed. The Reference promises
 * PATH_NOT_ALLOWED / PATH_DENIED_SENSITIVE for shell cwd.
 * @param {unknown} cwd
 * @param {string} [platform]
 * @returns {string} resolved absolute cwd
 */
export function guardedCwd(cwd, platform = process.platform) {
  const raw = String(cwd || '');
  if (!raw || raw.includes('\0') || raw.length > 4096) throw new Error('INVALID_CWD');
  const absolute =
    platform === 'win32'
      ? /^(?:[A-Za-z]:[\\/]|\\\\)/.test(raw)
      : raw.startsWith('/');
  if (!absolute) throw new Error('INVALID_CWD');
  let resolved;
  try {
    resolved = fsSync.realpathSync(raw);
  } catch {
    throw new Error('INVALID_CWD');
  }
  if (isSensitivePath(resolved, platform)) throw new Error('PATH_DENIED_SENSITIVE');
  return resolved;
}

/**
 * Best-effort cwd-relative write detector: with a cwd inside the agent
 * tree, a bare `echo hi > out.txt` (or cp/mv/mkdir/git-clone into `.`)
 * lands in the agent tree while the command-text scan sees nothing.
 * Conservative by design: only consulted when the resolved cwd is already
 * inside the agent tree (outside the workspace).
 */
const CWD_RELATIVE_WRITE_RE = /(^|[\s;&|(){}])(>{1,2}|tee\b|mkdir\b|touch\b|cp\b|mv\b|unzip\b|git\s+clone\b|dd\b[^\n;&|]*\bof=|tar\b[^\n;&|]*\s-[a-zA-Z]*x|curl\b[^\n;&|]*(-o\b|--output\b)|wget\b[^\n;&|]*-O\b)/;

/**
 * Agent-tree write pre-flight (telemetry: 40 AGENT_TREE_WRITE_FORBIDDEN).
 * Detects BEFORE any spawn and returns a refusal that names allowed
 * alternative roots — the old bare throw told the model "no" without
 * telling it where "yes" lives, so it retried into the same wall.
 * Returns null when clean (execute), otherwise a result_payload fragment
 * with error/allowed_roots/suggested_action. Callers RETURN it (never
 * throw): ws-transport drops thrown payloads, keeping only the message.
 * @param {string} command
 * @param {{cwd?: string|null, platform?: string}} [options]
 */
export function agentTreeRefusal(command, { cwd = null, platform = process.platform } = {}) {
  try {
    const root = layout?.root;
    if (!root || typeof root !== 'string') return null;
    const win = platform === 'win32';
    const sep = win ? '\\' : '/';
    const norm = (v) => {
      let s = String(v || '');
      if (win) s = s.replace(/\//g, '\\').toLowerCase();
      else s = s.replace(/\/+/g, '/');
      return s.replace(win ? /\\+$/ : /\/+$/, '');
    };
    const inside = (candidate, base) => {
      const c = norm(candidate);
      const r = norm(base);
      if (!c || !r) return false;
      return c === r || c.startsWith(r.endsWith(sep) ? r : r + sep);
    };
    const textHit = shellTouchesAgentTree(command, platform);
    let cwdInsideTree = false;
    if (cwd && typeof cwd === 'string') {
      const ws = layout?.workspace;
      cwdInsideTree = inside(cwd, root) && !(ws && inside(cwd, ws));
    }
    const cwdWriteHit = Boolean(
      cwdInsideTree && CWD_RELATIVE_WRITE_RE.test(String(command || ''))
    );
    if (!textHit && !cwdWriteHit) return null;
    const allowed = [];
    if (layout?.workspace) allowed.push(layout.workspace);
    try {
      const tmp = osSync.tmpdir();
      if (tmp && !allowed.includes(tmp)) allowed.push(tmp);
    } catch {}
    return {
      error: 'AGENT_TREE_WRITE_FORBIDDEN',
      error_code: 'AGENT_TREE_WRITE_FORBIDDEN',
      failure_class: 'AGENT_TREE_WRITE_REFUSED_PREFLIGHT',
      suggested_action: 'change_input',
      allowed_roots: allowed,
      cwd_inside_agent_tree: cwdInsideTree,
      reason: textHit
        ? 'command text references the agent tree outside the writable workspace; nothing was spawned'
        : 'cwd is inside the agent tree and the command writes cwd-relative files; nothing was spawned'
    };
  } catch {
    return null;
  }
}

/** Default shell cwd: the writable workspace, falling back to the tree root. */
export function defaultShellCwd() {
  // P26-adjacent CI hardening: neither candidate may exist (fresh CI checkout
  // has no agent layout dirs), and the previous unconditional `return
  // layout.root` handed spawn() a non-existent cwd — which surfaces as
  // `spawn /bin/bash ENOENT` even though /bin/bash is present. Prefer the
  // layout paths when they exist, otherwise fall back to a scratch directory
  // that is guaranteed to exist. process.cwd() would be wrong here: it is
  // wherever the agent happened to be started, so a relative command run with
  // no explicit cwd would execute in (and could read) the operator's launch
  // directory instead of an agent-owned tree.
  for (const candidate of [layout?.workspace, layout?.root]) {
    try {
      if (candidate && fsSync.existsSync(candidate)) return candidate;
    } catch {}
  }
  return osSync.tmpdir();
}

/**
 * P1-01: per-job abort registry for cooperative cancellation. The hub sends
 * `{type:'cancel', job_id}` after marking a job terminal; handlers holding
 * killable resources (today: shell children) register an abort here keyed
 * by job id. Module scope: one agent process runs one session at a time,
 * entries are always deleted on settle. Old hub versions never send it.
 * @type {Map<string, () => void>}
 */
export const shellAbortByJob = new Map();

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
 * @param {{id?: unknown, job_id?: unknown}|null|undefined} [job]
 */
export function normalizedJobId(job) {
  return String(job?.id || job?.job_id || '');
}

/**
 * Prototype-key guard for wire-supplied job ids (P23). The job containers
 * (`state.jobs`, `state.pendingResults`) are plain objects: `__proto__` and
 * `constructor` ids read through to Object.prototype (phantom duplicate /
 * pending-result hits), `obj['__proto__'] = record` replaces the container
 * prototype, and `rec.flag = v` on an inherited reference pollutes
 * Object.prototype process-wide. Callers fail closed on these ids; legit hub
 * ids never collide with them.
 * @param {unknown} id
 */
export function isDangerousJobId(id) {
  return id === '__proto__' || id === 'constructor' || id === 'prototype';
}

/**
 * @param {unknown} claimResponse @returns {Record<string, unknown>|null}
 */
export function extractJob(claimResponse) {
  if (!claimResponse || typeof claimResponse !== 'object') return null;
  const rec = /** @type {Record<string, unknown>} */ (claimResponse);
  if (rec.job && typeof rec.job === 'object')
    return /** @type {Record<string, unknown>} */ (rec.job);
  if (Array.isArray(rec.jobs)) return /** @type {Record<string, unknown>} */ (rec.jobs[0]) || null;
  if (rec.id || rec.job_id) return rec;
  return null;
}

/**
 * @param {Record<string, unknown>} job
 * @param {{maxStdoutBytes?: number, maxStderrBytes?: number, maxTimeoutSeconds?: number}} [options]
 */
export async function executeShellJob(job, options = {}) {
  const payload = normalizedJobPayload(job);
  const command = String(payload.command ?? job.command ?? '');
  if (!command) throw new Error('COMMAND_REQUIRED');
  const startedPreflight = Date.now();
  // Pre-flight refusal (returns, never throws: thrown payloads are dropped
  // by ws-transport, keeping only the message — the allowed_roots below
  // would never reach the model). No process is spawned on this path.
  const textRefusal = agentTreeRefusal(command, { cwd: null, platform: process.platform });
  if (textRefusal)
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      error: textRefusal.error,
      duration_ms: Date.now() - startedPreflight,
      time_to_first_output_ms: null,
      time_to_pattern_match_ms: null,
      result_payload: { ...textRefusal, exit_code: null }
    };
  if (sensitiveCommandHit(command, process.platform))
    throw new Error('PATH_DENIED_SENSITIVE');
  const requestedCwd = String(payload.cwd || job.cwd || '');
  const cwd = requestedCwd ? guardedCwd(requestedCwd) : defaultShellCwd();
  const cwdRefusal = agentTreeRefusal(command, { cwd, platform: process.platform });
  if (cwdRefusal)
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      error: cwdRefusal.error,
      duration_ms: Date.now() - startedPreflight,
      time_to_first_output_ms: null,
      time_to_pattern_match_ms: null,
      result_payload: { ...cwdRefusal, exit_code: null, cwd }
    };
  const maxTimeoutSeconds = options.maxTimeoutSeconds || clampedEnvNumber('NC_MAX_TIMEOUT_SECONDS', 3600, 1);
  const requestedTimeout = Number(payload.timeout_seconds ?? job.timeout_seconds ?? 30);
  const timeoutSeconds = Math.max(
    1,
    Math.min(Number.isFinite(requestedTimeout) ? requestedTimeout : 30, maxTimeoutSeconds)
  );
  const maxStdout = options.maxStdoutBytes || clampedEnvNumber('NC_MAX_STDOUT_BYTES', 1048576, 4096);
  const maxStderr = options.maxStderrBytes || clampedEnvNumber('NC_MAX_STDERR_BYTES', 1048576, 4096);
  // A7: optional literal-substring watch for pattern-match telemetry.
  // Invalid/unusable patterns resolve to null (no match timing, no failure).
  const outputPattern = normalizeOutputPattern(payload.output_pattern ?? job.output_pattern);
  const started = Date.now();
  const abortKey = normalizedJobId(job);
  // A7 timing state: elapsed ms from `started`; null until the event fires.
  // Only numbers are recorded — chunk bodies never leave this closure.
  let firstOutputMs = null;
  let patternMatchMs = null;
  let matchTail = '';
  /** @param {Buffer|Uint8Array|string} chunk */
  const noteOutput = (chunk) => {
    const now = Date.now();
    if (firstOutputMs === null) firstOutputMs = now - started;
    if (outputPattern && patternMatchMs === null) {
      try {
        matchTail += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk ?? '');
        if (matchTail.length > PATTERN_MATCH_WINDOW_CHARS)
          matchTail = matchTail.slice(-PATTERN_MATCH_WINDOW_CHARS);
        if (matchTail.includes(outputPattern)) patternMatchMs = now - started;
      } catch {}
    }
  };

  return new Promise((resolve) => {
    // Head+tail capture (Finding 4): the tail ring keeps compiler errors and
    // exit summaries that the old head-only appendLimited dropped first.
    const stdoutAcc = createBoundedOutput(maxStdout);
    const stderrAcc = createBoundedOutput(maxStderr);
    let timedOut = false;
    let settled = false;
    /** @type {ReturnType<typeof setTimeout>|undefined} */
    let killTimer;
    let child;
    // P2-05b: spawn-time identity for the verified timeout/abort kills below
    // (started_at + shell entrypoint). Dynamic import avoids a static cycle
    // with process-sessions.mjs (which imports shell helpers from here).
    let shellStartedAt = new Date(started).toISOString();
    let shellExe = null;
    let shellArgList = null;
    const killShellTreeVerified = (force) => {
      if (!child) return;
      const target = child;
      const startedAt = shellStartedAt;
      const exe = shellExe;
      const argList = shellArgList;
      void (async () => {
        try {
          const { terminateSessionTreeAsync } = await import('../process/process-sessions.mjs');
          await terminateSessionTreeAsync(target, {
            platform: process.platform,
            force,
            graceMs: force ? 0 : 1500,
            expectedStartedAt: startedAt,
            expectedPath: exe,
            expectedCommandLine: argList
          });
        } catch {}
      })();
    };
    try {
      const invocation = shellInvocation(command);
      shellExe = invocation.file;
      shellArgList = Array.isArray(invocation.args) ? [...invocation.args] : [];
      child = spawn(invocation.file, invocation.args, {
        cwd,
        env: shellEnvironment(),
        detached: shellChildDetached(),
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        windowsVerbatimArguments: Boolean(invocation.windowsVerbatimArguments)
      });
      // A8-b: deprioritize the heavy child right after spawn (best-effort,
      // never throws; the agent's own priority is never touched).
      try {
        shedChildPriority(child);
      } catch {}
    } catch (error) {
      resolve({
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: /** @type {Record<string, unknown>} */ (error).message,
        duration_ms: Date.now() - started,
        time_to_first_output_ms: null,
        time_to_pattern_match_ms: null
      });
      return;
    }

    // stdio may be null when fds are exhausted: fail closed instead of
    // throwing inside the executor (an executor throw becomes an unhandled
    // rejection — the old code crashed the agent on EMFILE-adjacent spawn).
    if (!child?.stdout || !child?.stderr) {
      try {
        child?.kill?.('SIGKILL');
      } catch {}
      resolve({
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: 'SHELL_SPAWN_STDIO_FAILED',
        duration_ms: Date.now() - started,
        time_to_first_output_ms: null,
        time_to_pattern_match_ms: null,
        result_payload: {
          error_code: 'SHELL_SPAWN_STDIO_FAILED',
          failure_class: 'INFRA_SPAWN_FAILED',
          suggested_action: 'retry',
          detail: 'spawned shell had no capturable stdio; safe to retry'
        }
      });
      return;
    }
    child.stdout.on('data', (chunk) => {
      noteOutput(chunk);
      stdoutAcc.append(chunk);
    });
    child.stderr.on('data', (chunk) => {
      noteOutput(chunk);
      stderrAcc.append(chunk);
    });

    const timer = setTimeout(() => {
      timedOut = true;
      // P2-05b: verified timeout kill (PID-reuse guard). The pre-verify
      // inside terminateSessionTreeAsync fails closed (skipped-unverified,
      // no signal) instead of blind-signalling a possibly-recycled PID/group.
      // Residual: an unverifiable PID is left running (eventual close still
      // reports timeout) rather than risk killing an unrelated process.
      // The async path escalates internally after its grace window; the outer
      // force below is an idempotent backup preserving the original timing.
      killShellTreeVerified(false);
      killTimer = setTimeout(() => killShellTreeVerified(true), 1500);
      try {
        killTimer.unref?.();
      } catch {}
    }, timeoutSeconds * 1000);
    // Leak-free watchdog: a 3600s pending timer must not pin the agent
    // event loop by itself (the ws session owns liveness, not the timer).
    try {
      timer.unref?.();
    } catch {}

    /** @param {number|null} code @param {unknown} signal @param {unknown} [spawnError] */
    const finish = (code, signal, spawnError) => {
      if (settled) return;
      settled = true;
      try {
        shellAbortByJob.delete(abortKey);
      } catch {}
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      const stdout = stdoutAcc.text();
      const stderr = stderrAcc.text();
      const stdoutTruncated = stdoutAcc.truncated;
      const stderrTruncated = stderrAcc.truncated;
      const duration_ms = Date.now() - started;
      if (spawnError) {
        resolve({
          status: 'failed',
          exit_code: null,
          stdout,
          stderr,
          error: /** @type {Record<string, unknown>} */ (spawnError).message,
          duration_ms,
          time_to_first_output_ms: firstOutputMs,
          time_to_pattern_match_ms: patternMatchMs,
          stdout_truncated: stdoutTruncated,
          stderr_truncated: stderrTruncated,
          result_payload: {
            error_code: 'SHELL_SPAWN_FAILED',
            failure_class: 'INFRA_SPAWN_FAILED',
            suggested_action: 'retry',
            detail: 'our spawn failed (not the command); safe to retry'
          }
        });
      } else if (timedOut) {
        resolve({
          status: 'timeout',
          exit_code: code ?? null,
          stdout,
          stderr,
          error: `command timeout after ${timeoutSeconds}s`,
          duration_ms,
          time_to_first_output_ms: firstOutputMs,
          time_to_pattern_match_ms: patternMatchMs,
          stdout_truncated: stdoutTruncated,
          stderr_truncated: stderrTruncated,
          result_payload: {
            error_code: 'SHELL_TIMEOUT',
            failure_class: 'COMMAND_TIMEOUT',
            suggested_action: 'retry',
            timeout_seconds: timeoutSeconds,
            stderr_excerpt: stderrExcerpt(stderr),
            note: 'process tree was killed on timeout; for long work re-run with a larger timeout_seconds or use process_start + process_output polling'
          }
        });
      } else if (code === 0) {
        resolve({
          status: 'completed',
          exit_code: code ?? null,
          stdout,
          stderr,
          error: null,
          duration_ms,
          time_to_first_output_ms: firstOutputMs,
          time_to_pattern_match_ms: patternMatchMs,
          stdout_truncated: stdoutTruncated,
          stderr_truncated: stderrTruncated
        });
      } else {
        // Rich failure, never masked: status stays failed; the payload
        // adds exit code + bounded excerpt + suggested_action so the model
        // reacts instead of retrying verbatim.
        const signal_ = classifyShellFailure({ exitCode: code, signal, stderr });
        resolve({
          status: 'failed',
          exit_code: code ?? null,
          stdout,
          stderr,
          error:
            code === 128 && signal_.cause && signal_.cause !== 'EXIT_128_UNKNOWN'
              ? `${signal_.cause}: ${signal_.detail}`
              : `command exited with code ${code}${signal ? ` signal ${signal}` : ''}`,
          duration_ms,
          time_to_first_output_ms: firstOutputMs,
          time_to_pattern_match_ms: patternMatchMs,
          stdout_truncated: stdoutTruncated,
          stderr_truncated: stderrTruncated,
          result_payload: {
            error_code: code === 128 ? signal_.cause : `SHELL_EXIT_${code}`,
            ...signal_,
            signal: signal ?? undefined
          }
        });
      }
    };
    child.once('error', (error) => finish(null, null, error));
    child.once('close', (code, signal) => finish(code, signal, null));
    try {
      if (abortKey) {
        shellAbortByJob.set(abortKey, () => {
          if (settled) return;
          // P2-05b: verified abort kill (same PID-reuse guard as timeout).
          killShellTreeVerified(false);
          try {
            killTimer = setTimeout(() => killShellTreeVerified(true), 1500);
            killTimer.unref?.();
          } catch {}
        });
      }
    } catch {}
  });
}
