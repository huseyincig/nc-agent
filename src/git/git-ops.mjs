/**
 * Git repository operations for the NC agent (reads + git_write).
 * Pure parsers, the failure classifier and the write-arg validator are
 * exported for unit tests; handlers exec argv-form commands (no shell)
 * with bounded output, mirroring package-ops.mjs.
 * Every repo path is gated by the same roots allowlist as the file tools
 * (realAllowed) plus the sensitive-path denylist; clone targets and
 * git_write repos also pass the agent-tree write ban. Reads pre-flight
 * the repo root (`.git` walk + `rev-parse`) so failures dissect into the
 * terminal GIT_* family instead of a bare code. All git invocations pin
 * `-c safe.directory=<top>` (discovered top, never a subdirectory) and a
 * quarantined env (LC_ALL=C, no prompts/pagers) so validated paths never
 * trip dubious-ownership failures and stderr stays parseable.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import path from 'node:path';
import { realAllowed } from '../structured-ops/structured-ops.mjs';
import { forbidAgentTreeWrite } from '../filesystem/mutation-ops.mjs';
import { policyExtraRoots } from '../policy/host-policy.mjs';
import { headTailTruncate } from '../client/shell-runner.mjs';

const run = promisify(execFile);
const MAX_STATUS_ROWS = 500;
export const MAX_DIFF_BYTES = 65536;
// Per-file diff cap (ora-7 Finding 1): 16 KiB = MAX_DIFF_BYTES / 4, matching
// the reference per-file default (chatgpt-web-oauth-mcp gitops.py
// per_file_max_bytes, design only). Justification for the /4 split: even in
// the adversarial case where EVERY file is huge, the first four files'
// head+tail summaries still fit inside the 64 KiB total budget, while
// typical small files (a few KiB each) let dozens through fully. The legacy
// combined `diff` text stays capped at MAX_DIFF_BYTES; per-file detail rides
// in the additive `file_diffs` field (no contract change).
export const PER_FILE_DIFF_MAX_BYTES = 16384;
const MAX_LINES = 100;
// First character excludes '-' and '/': the branch is pushed onto `git log`
// argv ahead of '--', so a leading dash would parse as a log flag (option
// injection). Git refs never start with '-' or '/'.
const BRANCH_RE = /^[A-Za-z0-9_@.][\w@./-]{0,127}$/;
const URL_RE = /^(https:\/\/|ssh:\/\/|git@)[^\s]{1,2048}$/;

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

// Quarantined git environment (lesson 4 / SentinelX _GIT_ENV): fixed locale
// so stderr diagnostics stay English-parseable, no credential prompts
// (fail fast instead of hanging a job), no pagers, no optional index
// locks, no system-config quirks. Per-invocation `-c safe.directory=`
// (see git()) still pins ownership trust for validated paths.
const GIT_ENV = Object.freeze({
  LC_ALL: 'C',
  GIT_TERMINAL_PROMPT: '0',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_PAGER: 'cat',
  GIT_CONFIG_NOSYSTEM: '1'
});

// Pre-migration checkout layout: jobs recorded before the /opt/hhc ->
// /opt/nc-workspace move still reference the old root. A missing path
// under it is never a transient failure.
const LEGACY_HHC_PREFIX = '/opt/hhc/';

/**
 * Dissect a git failure into a distinct, terminal, actionable error.
 * git exits 128 for "not a repo", dubious ownership, permission and
 * corrupt-index failures alike — reporting them all as GIT_NOT_A_REPO
 * sends the model into retry loops. Every branch below returns a
 * `CODE: message` string whose message names the cause, the fix, and an
 * explicit do-not-retry directive. Pure and exported for unit tests.
 * @param {{repo?: unknown, raw?: unknown, message?: unknown, stderr?: unknown}} [options]
 */
export function classifyGitError({ repo = '', raw = '', message = '', stderr = '' } = {}) {
  const text = `${String(stderr || '')}\n${String(message || '')}`;
  const where = String(raw || repo || '').slice(0, 512) || '(unknown path)';
  const terminal = 'Do not retry the same path — it will keep failing.';
  if (/command not found|not recognized/i.test(text)) {
    return (
      `GIT_UNAVAILABLE: git executable is not installed or not visible to the agent. ` +
      `Contact the operator; do not retry git calls on this host.`
    );
  }
  if (/dubious ownership/i.test(text)) {
    return (
      `GIT_DUBIOUS_OWNERSHIP: git refuses '${where}' (dubious ownership: another user owns the checkout). ` +
      `${terminal} Ask the operator to run 'git config --global --add safe.directory ${where}' or chown the checkout to the agent user.`
    );
  }
  // Remote-side auth failures mention keys/credentials explicitly; they
  // must not be misreported as local filesystem permission problems.
  if (
    /permission denied \(publickey\)|could not read from remote|authentication failed|invalid credentials|terminal prompts disabled|could not resolve hostname|connection timed out|unable to connect/i.test(
      text
    )
  ) {
    return (
      `GIT_REMOTE_AUTH_FAILED: the remote rejected this operation for '${where}' (missing credentials or unreachable host). ` +
      `${terminal} Pushing/fetching needs operator-provided credentials on the host.`
    );
  }
  if (/permission denied/i.test(text)) {
    return (
      `GIT_PERMISSION_DENIED: the agent user cannot traverse '${where}' (permission denied). ` +
      `${terminal} Fix ownership/mode bits or choose an accessible checkout.`
    );
  }
  if (/index\.lock/i.test(text)) {
    return (
      `GIT_INDEX_LOCKED: '${where}' has a stale .git/index.lock (another git process holds the index). ` +
      `Wait briefly and retry once; if it persists, an operator must remove .git/index.lock.`
    );
  }
  if (/bad index|index file corrupt|index file smaller|not a valid index|unable to read index/i.test(text)) {
    return (
      `GIT_INDEX_CORRUPT: '${where}' has a corrupt .git/index. ` +
      `Status/diff/add will keep failing until an operator rebuilds it ('git read-tree --reset HEAD', or delete .git/index then 'git reset'). ${terminal}`
    );
  }
  if (/author identity unknown/i.test(text)) {
    return (
      `GIT_IDENTITY_UNKNOWN: git user.name/user.email are not configured for '${where}'. ` +
      `${terminal} Set them in the repo config before committing.`
    );
  }
  if (/non-fast-forward|fetch first|tip of your current branch is behind/i.test(text)) {
    return (
      `GIT_PUSH_NON_FAST_FORWARD: the remote rejects this push for '${where}' (non-fast-forward: the remote branch has commits you lack). ` +
      `Do not retry the same push — fetch and rebase first, or re-invoke with force:true to replace the remote branch.`
    );
  }
  if (/no such remote|unknown remote|does not appear to be a git repository/i.test(text)) {
    return (
      `GIT_UNKNOWN_REMOTE: '${where}' has no such remote configured. ` +
      `${terminal} Use a configured remote name (never a URL), or add one with 'git remote add' first.`
    );
  }
  if (/not a git repository/i.test(text)) {
    return (
      `GIT_NOT_A_REPO: '${where}' is not inside a git repository. ${terminal} ` +
      `Use a repository checkout under an allowed root, or clone one with git_clone first.`
    );
  }
  const short = String(message || stderr || '').slice(0, 500).trim();
  return `GIT_OP_FAILED: ${short || 'git command failed'}. ${terminal}`;
}

/**
 * Map a spawn-level failure (git binary missing) to GIT_UNAVAILABLE.
 * execFile reports a missing binary as ENOENT on `spawn git`; that must
 * not be confused with a missing repository path (gated earlier by
 * realAllowed and mapped to GIT_PATH_NOT_FOUND there).
 * @param {unknown} e
 * @param {{repo?: unknown, raw?: unknown}} [ctx]
 */
function gitOrThrow(e, ctx = {}) {
  const errRec = /** @type {{message?: unknown, code?: unknown}} */ (e && typeof e === 'object' ? e : {});
  const message = String(errRec.message || (typeof e === 'string' ? e : '') || '');
  const stderr = String(
    /** @type {{stderr?: unknown}} */ (errRec).stderr || ''
  );
  if (errRec.code === 'ENOENT' && /^spawn git\b/i.test(message)) throw new Error(classifyGitError({
    ...ctx,
    message: 'command not found: git',
    stderr: ''
  }));
  throw new Error(classifyGitError({ ...ctx, message, stderr }), { cause: e });
}

/**
 * Map a roots-gating failure to a terminal error. A missing directory
 * surfaces from realAllowed as FILE_NOT_FOUND (ancestor-walk detail) or
 * a bare ENOENT (raw OS signal) — callers must hear "path does not
 * exist", never a bare code, and the pre-migration /opt/hhc layout gets
 * its own migration hint. Roots denials (PATH_NOT_ALLOWED and friends)
 * pass through untouched: they are legitimate policy verdicts.
 * @param {unknown} raw @param {unknown} e
 */
function gateError(raw, e) {
  const rec = /** @type {{code?: unknown, message?: unknown, details?: unknown}} */ (
    e && typeof e === 'object' ? e : {}
  );
  const code = String(rec.code || '');
  const msg = String(rec.message || e || '');
  const missing =
    code === 'FILE_NOT_FOUND' || code === 'ENOENT' || /\bENOENT\b/i.test(msg);
  const p = String(raw || '');
  const legacy = p === '/opt/hhc' || p.startsWith(LEGACY_HHC_PREFIX);
  // The pre-migration layout never resolves under current roots: whether
  // gating reports it missing or outside the allowlist, the actionable
  // fact is the layout moved — say exactly that.
  if (legacy && (missing || code === 'PATH_NOT_ALLOWED')) {
    return new Error(
      `GIT_PATH_NOT_FOUND: '${p.slice(0, 512)}' does not exist (legacy /opt/hhc layout — checkouts moved; ` +
      `resolve the current root (usually under /opt/nc-workspace) and do not retry the old path).`
    );
  }
  if (missing) {
    const det =
      rec.details && typeof rec.details === 'object'
        ? /** @type {Record<string, unknown>} */ (rec.details)
        : null;
    const ancestor =
      det && typeof det.missing_ancestor === 'string' && det.missing_ancestor
        ? ` Nearest existing ancestor ends at '${String(det.missing_ancestor).slice(0, 256)}'.`
        : '';
    return new Error(
      `GIT_PATH_NOT_FOUND: '${p.slice(0, 512)}' does not exist.${ancestor} ` +
      `Do not retry this path — list the parent directory to find the real checkout.`
    );
  }
  return /** @type {Error} */ (e instanceof Error ? e : new Error(msg.slice(0, 2000) || 'GIT_OP_FAILED'));
}

/**
 * Parse insertion/deletion totals (P2 snapshot). `isStat` selects the
 * source: `--stat` summaries (`N files changed, ...`) or hunk +/- line
 * counts (excluding `+++`/`---` headers). The summary regex is anchored to
 * stat mode because added lines in a full diff could spoof it. Pure and
 * exported for unit tests.
 * @param {string} text @param {boolean} isStat
 */
export function parseDiffTotals(text, isStat = false) {
  const t = String(text || '');
  if (isStat) {
    const stat = t.match(/(\d+)\s+file[s]?\s+changed(?:,\s*(\d+)\s+insertion[s]?\(\+\))?(?:,\s*(\d+)\s+deletion[s]?\(-\))?/);
    if (stat) {
      return {
        insertions: stat[2] != null ? Number(stat[2]) : 0,
        deletions: stat[3] != null ? Number(stat[3]) : 0
      };
    }
    return { insertions: 0, deletions: 0 };
  }
  let insertions = 0;
  let deletions = 0;
  for (const line of t.split('\n')) {
    if (line.startsWith('+') && !line.startsWith('+++')) insertions++;
    else if (line.startsWith('-') && !line.startsWith('---')) deletions++;
  }
  return { insertions, deletions };
}

/**
 * Extract the display path from a `diff --git a/<src> b/<dst>` header line.
 * Uses the b/ (destination) side; tolerates C-style quoting for paths with
 * spaces. Falls back to the raw header (capped) when unparseable — never
 * throws, so one odd header cannot hide the other files. Pure and exported
 * for unit tests.
 * @param {string} headerLine
 */
export function diffSectionPath(headerLine) {
  const line = String(headerLine || '').trim();
  const body = line.startsWith('diff --git ') ? line.slice('diff --git '.length) : line;
  const quoted = body.match(/^"a\/(.*?)" "b\/(.*?)"$/);
  if (quoted) return String(quoted[2] || quoted[1] || '').slice(0, 1024) || body.slice(0, 256);
  const parts = body.split(' ');
  if (parts.length >= 2) {
    const src = parts[parts.length - 2];
    const dst = parts[parts.length - 1];
    if (src.startsWith('a/') && dst.startsWith('b/'))
      return dst.slice(2).slice(0, 1024) || body.slice(0, 256);
  }
  return body.slice(0, 256) || '(unknown file)';
}

/**
 * Split a full (non-stat) `git diff` text into per-file sections at
 * column-0 `diff --git ` headers. Byte-exact: sections are index slices, so
 * their concatenation reproduces the input. Hunk body lines always carry a
 * leading ` `/`+`/`-`/`\` marker, so a column-0 header line can only be a
 * real file boundary (a content line reading `diff --git ...` appears as
 * `+diff --git ...` or ` diff --git ...`, never at column 0).
 *
 * Fail-loud contract: '' → [] (clean tree); non-empty text that does not
 * start with a header throws GIT_DIFF_PARSE_FAILED instead of returning an
 * empty list that reads as "no changes". Pure and exported for unit tests.
 * @param {string} text
 */
export function splitDiffByFile(text) {
  const raw = String(text ?? '');
  if (!raw) return [];
  if (!raw.startsWith('diff --git ')) {
    throw new Error(
      `GIT_DIFF_PARSE_FAILED: full-diff text has no 'diff --git' file headers ` +
      `(${raw.length} chars). Refusing to report it as "no changes" — ` +
      `the diff source must be inspected instead.`
    );
  }
  const starts = [];
  const re = /^diff --git /gm;
  let m;
  while ((m = re.exec(raw)) !== null) starts.push(m.index);
  return starts.map((from, i) => {
    const section = raw.slice(from, i + 1 < starts.length ? starts[i + 1] : raw.length);
    const headerLine = section.split('\n', 1)[0];
    return { path: diffSectionPath(headerLine), diff: section };
  });
}

/**
 * Bound a full diff per file (ora-7 Finding 1): each section is capped at
 * PER_FILE_DIFF_MAX_BYTES with the shared 60/40 head+tail policy
 * (headTailTruncate — same marker/semantics as shell output bounding, see
 * jobs.store.mjs OUTPUT_HEAD_RATIO), so a regenerated lockfile is flagged
 * truncated while every other file still arrives. The legacy combined `diff`
 * string is the concatenation of the per-file texts, itself capped at
 * MAX_DIFF_BYTES. Allocation stays bounded: git's own execFile maxBuffer
 * (~1 MiB default) bounds the input, each section is capped, and the
 * combined text is capped.
 *
 * Additive shape `{ diff, file_diffs, truncated }`: callers keep reading
 * `diff` exactly as before; `file_diffs` rides alongside with per-file
 * `{ path, diff, truncated, original_bytes, omitted_bytes }`, so the
 * git_inspect inputSchema/outputSchema are untouched (no contract bump).
 * Pure and exported for unit tests.
 * @param {string} text raw full-diff stdout
 */
export function boundDiffByFile(text) {
  const raw = String(text ?? '');
  const rawOver = Buffer.byteLength(raw, 'utf8') > MAX_DIFF_BYTES;
  const file_diffs = splitDiffByFile(raw).map(({ path, diff }) => {
    const bounded = headTailTruncate(diff, PER_FILE_DIFF_MAX_BYTES);
    return {
      path,
      diff: bounded.text,
      truncated: bounded.truncated,
      original_bytes: Buffer.byteLength(diff, 'utf8'),
      omitted_bytes: bounded.omitted
    };
  });
  const combined = file_diffs.map((f) => f.diff).join('');
  const capped = headTailTruncate(combined, MAX_DIFF_BYTES);
  const truncated = rawOver || capped.truncated || file_diffs.some((f) => f.truncated);
  return { diff: capped.text, file_diffs, truncated };
}

/**
 * Parse `git status --porcelain=v1 --branch` output.
 * @param {string} text
 */
export function parseGitStatus(text) {
  const out = { branch: null, ahead: 0, behind: 0, staged: 0, unstaged: 0, untracked: 0, entries: [], total_entries: 0 };
  for (const line of String(text || '').split('\n')) {
    if (!line) continue;
    if (line.startsWith('## ')) {
      const head = line.slice(3);
      const m = head.match(/^(\S+?)(?:\.\.\.(\S+?))?(?: \[(?:ahead (\d+))?(?:, )?(?:behind (\d+))?\])?$/);
      if (m) {
        out.branch = m[1] === 'HEAD' ? null : m[1];
        out.ahead = Number(m[3] || 0);
        out.behind = Number(m[4] || 0);
      }
      continue;
    }
    if (line.length < 4) continue;
    const x = line[0];
    const y = line[1];
    const p = line.slice(3).trim();
    if (!p) continue;
    if (x === '?' && y === '?') out.untracked += 1;
    else {
      if (x !== ' ' && x !== '?') out.staged += 1;
      if (y !== ' ' && y !== '?') out.unstaged += 1;
    }
    out.total_entries += 1;
    if (out.entries.length < MAX_STATUS_ROWS) out.entries.push({ x, y, path: p });
  }
  return out;
}

/**
 * Parse `git log --format=%H%x1f%an%x1f%ad%x1f%s` rows.
 * @param {string} text
 */
export function parseGitLog(text) {
  const out = [];
  for (const line of String(text || '').split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split('\x1f');
    if (parts.length < 4 || !/^[0-9a-f]{40}$/.test(parts[0])) continue;
    out.push({ hash: parts[0], author: parts[1], date: parts[2], message: parts.slice(3).join('\x1f') });
  }
  return out;
}

/**
 * Parse `git branch --format` rows; the current branch is marked by
 * a leading `* `.
 * @param {string} current @param {string} all
 */
export function parseGitBranches(current, all) {
  const cur = String(current || '').trim() || null;
  const branches = String(all || '')
    .split('\n')
    .map((l) => l.trim().replace(/^\*\s+/, ''))
    .filter(Boolean);
  return { current: cur, branches };
}

/**
 * Resolve one caller-supplied stage path to a repo-relative path for
 * `git add --`. Absolute paths must already sit inside the repo; relative
 * paths resolve against the repo top. Anything escaping the repo fails
 * closed (cross-repo/tenant isolation) before git ever sees it. Pure and
 * exported for unit tests.
 * @param {string} top canonical repo root @param {unknown} entry
 */
export function stageRelPath(top, entry) {
  const s = String(entry || '');
  if (!s || s.length > 4096 || s.includes('\0'))
    throw new Error(
      `INVALID_PATH: action=add needs concrete file paths (1..4096 chars each). ` +
      `Do not retry with an empty or oversized entry.`
    );
  const abs = path.isAbsolute(s) ? path.normalize(s) : path.resolve(top, s);
  if (abs !== top && !abs.startsWith(top + path.sep))
    throw new Error(
      `GIT_PATH_ESCAPES_REPO: staged path '${s.slice(0, 256)}' is outside repository '${top}'. ` +
      `Do not retry — stage only files inside this repo.`
    );
  const rel = path.relative(top, abs);
  if (!rel || rel === '.' || rel === '..' || rel.startsWith(`..${path.sep}`))
    throw new Error(
      `INVALID_PATH: refusing to stage the repository root itself — name explicit files. ` +
      `Use git_status to list dirty paths first.`
    );
  return rel;
}

/**
 * Walk upward from a gated dir looking for `.git` (dir or gitdir file)
 * WITHOUT invoking git, so "not a repo" is detected deterministically
 * and the safe.directory pin can name the discovered top: pinning the
 * pin to a subdirectory while git discovers its parent would itself trip
 * dubious-ownership. Permission failures classify here, before any
 * shell-out. Exported for unit tests.
 * @param {unknown} start gated starting directory @param {unknown} raw caller-supplied path for messages
 */
export async function findGitTop(start, raw = '') {
  const where = String(raw || start || '').slice(0, 512) || '(unknown path)';
  let cur = path.resolve(String(start));
  for (let i = 0; i < 64; i++) {
    let hit = false;
    try {
      await fs.stat(path.join(cur, '.git'));
      hit = true;
    } catch (e) {
      const code = /** @type {{code?: unknown}} */ (e && typeof e === 'object' ? e : {}).code;
      if (code === 'EACCES' || code === 'EPERM')
        throw new Error(
          `GIT_PERMISSION_DENIED: the agent user cannot traverse '${where}' (permission denied). ` +
            `Do not retry the same path — fix ownership/mode bits or choose an accessible checkout.`,
          { cause: e }
        );
      hit = false;
    }
    if (hit) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  throw new Error(
    `GIT_NOT_A_REPO: '${where}' is not inside a git repository. ` +
    `Do not retry the same path — it will keep failing. ` +
    `Use a repository checkout under an allowed root, or clone one with git_clone first.`
  );
}

const GIT_WRITE_ACTIONS = Object.freeze(['add', 'commit', 'push', 'branch', 'fetch']);
const GIT_REMOTE_RE = /^[A-Za-z0-9_.\-]{1,128}$/;

/**
 * @typedef {{action: 'add', paths: Array<string>}} GitWriteAdd
 * @typedef {{action: 'commit', message: string}} GitWriteCommit
 * @typedef {{action: 'push', remote: string, branch: string|null, force: boolean}} GitWritePush
 * @typedef {{action: 'branch', name: string, switch: boolean}} GitWriteBranch
 * @typedef {{action: 'fetch', remote: string, depth: number|null}} GitWriteFetch
 * @typedef {GitWriteAdd|GitWriteCommit|GitWritePush|GitWriteBranch|GitWriteFetch} GitWriteArgs
 */
/**
 * Validate git_write params without touching the filesystem: every shape
 * rejection fires BEFORE pre-flight spawns git, so injection-shaped input
 * (leading-dash branches, URLs as remotes, escaping paths) fails as a
 * validation error even when the path would fail pre-flight too.
 * Containment (stageRelPath) still needs the discovered top and runs
 * after pre-flight in the handler. Pure and exported for unit tests.
 * @param {unknown} p request payload
 * @returns {GitWriteArgs}
 */
export function validateGitWriteArgs(p) {
  const rec = /** @type {Record<string, unknown>} */ (p && typeof p === 'object' ? p : {});
  const action = /** @type {GitWriteArgs['action']} */ (String(rec.action || '').toLowerCase());
  if (!GIT_WRITE_ACTIONS.includes(action))
    throw new Error(
      `INVALID_GIT_ACTION: unknown git_write action '${String(rec.action || '').slice(0, 64)}'. ` +
      `Use one of add, commit, push, branch, fetch.`
    );
  if (action === 'add') {
    const list = rec.paths;
    if (!Array.isArray(list) || list.length < 1 || list.length > 64)
      throw new Error(
        `INVALID_GIT_PATHS: action=add requires paths (1..64 repo-relative entries). ` +
        `Use git_status to list dirty paths first.`
      );
    for (const entry of list) {
      const s = String(entry || '');
      if (!s || s.length > 4096 || s.includes('\0'))
        throw new Error(
          `INVALID_PATH: action=add needs concrete file paths (1..4096 chars each). ` +
          `Do not retry with an empty or oversized entry.`
        );
      // Lexical backstop (separator-agnostic); the authoritative
      // containment check runs post-pre-flight in stageRelPath.
      if (!path.isAbsolute(s) && /(^|[\\/])\.\.([\\/]|$)/.test(s))
        throw new Error(
          `GIT_PATH_ESCAPES_REPO: staged path '${s.slice(0, 256)}' escapes the repository. ` +
          `Do not retry — stage only files inside this repo.`
        );
    }
    return { action: 'add', paths: list.map(String) };
  }
  if (action === 'commit') {
    const message = String(rec.message || '');
    if (!message.trim() || message.length > 4096)
      throw new Error(
        `INVALID_GIT_MESSAGE: action=commit requires a non-empty message (<=4096 chars). ` +
        `Do not retry with an empty message.`
      );
    return { action: 'commit', message };
  }
  if (action === 'push' || action === 'fetch') {
    const remote = String(rec.remote || 'origin');
    if (!GIT_REMOTE_RE.test(remote))
      throw new Error(
        `INVALID_GIT_REMOTE: remote must be [A-Za-z0-9_.-]{1,128} (got '${remote.slice(0, 64)}'). ` +
        `Do not retry with a URL or path here.`
      );
    if (action === 'fetch') {
      let depth = null;
      if (rec.depth != null) {
        depth = Number(rec.depth);
        if (!Number.isInteger(depth) || depth < 1 || depth > 1000000)
          throw new Error(
            `INVALID_GIT_DEPTH: depth must be an integer 1..1000000. Do not retry outside that range.`
          );
      }
      return { action: 'fetch', remote, depth };
    }
    const branch = rec.branch == null || rec.branch === '' ? null : String(rec.branch);
    if (branch !== null && !BRANCH_RE.test(branch)) throw new Error('INVALID_BRANCH');
    return { action: 'push', remote, branch, force: rec.force === true };
  }
  // action === 'branch'
  const name = String(rec.name || '');
  if (!BRANCH_RE.test(name)) throw new Error('INVALID_BRANCH');
  return { action: 'branch', name, switch: rec.switch === true };
}

/**
 * @param {unknown} job @param {Array<string>} baseRoots
 */
function gatedRepo(job, baseRoots, write = false) {
  const jobRec = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  const p = /** @type {Record<string, unknown>} */ (jobRec.request_payload || jobRec.payload || {});
  const raw = String(p.path || '');
  if (!raw || raw.length > 4096) throw new Error('INVALID_PATH');
  const extra = policyExtraRoots(job);
  const roots = [...baseRoots, ...(write ? extra.write : extra.read)];
  // Missing directories surface here as bare ENOENT: translate to the
  // terminal GIT_PATH_NOT_FOUND family (with the /opt/hhc legacy hint)
  // so the model never retries a path that cannot exist.
  const repoPromise = realAllowed(raw, roots, extra.allowAll === true).catch((e) => {
    throw gateError(raw, e);
  });
  return { repoPromise, params: p };
}

/**
 * @param {object} [options]
 * @param {Array<string>} [options.readRoots]
 * @param {Array<string>} [options.writeRoots]
 * @param {string|null} [options.appRoot]
 * @param {string|null} [options.workspace]
 */
export function makeGitHandlers({ readRoots = [], writeRoots = [], appRoot = null, workspace = null } = {}) {
  const preflight = async (repo, raw) => {
    // Walk first (no shell), pin the discovered top, confirm with git.
    const walked = await findGitTop(repo, raw);
    try {
      const { stdout } = await run(
        'git',
        ['-c', `safe.directory=${walked}`, 'rev-parse', '--show-toplevel'],
        { timeout: 15000, cwd: walked, env: { ...process.env, ...GIT_ENV } }
      );
      const top = String(stdout || '').trim();
      return top || walked;
    } catch (e) {
      gitOrThrow(e, { repo: walked, raw });
      throw e;
    }
  };
  const git = async (repo, args, timeout, raw = '') => {
    try {
      // cwd pins the operation to the validated repo: without it git would
      // silently operate on the agent process working directory instead.
      return await run('git', ['-c', `safe.directory=${repo}`, ...args], {
        timeout,
        cwd: repo,
        env: { ...process.env, ...GIT_ENV }
      });
    } catch (e) {
      gitOrThrow(e, { repo, raw });
      throw e;
    }
  };
  return {
    git_status: async (job) => {
      try {
        const { repoPromise, params } = gatedRepo(job, readRoots);
        const raw = String(params.path || '');
        const repo = await repoPromise;
        // Pre-flight first: a non-repo/missing/foreign-owned dir fails here
        // with the terminal family, never as a bare code from status.
        const top = await preflight(repo, raw);
        const { stdout } = await git(top, ['status', '--porcelain=v1', '--branch', '-uall'], 30000, raw);
        const parsed = parseGitStatus(stdout);
        const truncated = parsed.total_entries > parsed.entries.length;
        // P2 snapshot: HEAD SHA is best-effort (null on empty/unborn repos).
        let head = null;
        try {
          const rev = await git(top, ['rev-parse', 'HEAD'], 15000, raw);
          const sha = String(rev.stdout || '').trim();
          if (/^[0-9a-f]{40}$/.test(sha)) head = sha;
        } catch {}
        return ok({ platform: process.platform, path: top, ...parsed, truncated, head });
      } catch (e) {
        return fail(e && e.message ? e.message : 'GIT_OP_FAILED');
      }
    },
    git_log: async (job) => {
      try {
        const { repoPromise, params } = gatedRepo(job, readRoots);
        const raw = String(params.path || '');
        // Validate before any spawn: a leading-dash branch must fail as
        // INVALID_BRANCH even when the path would fail pre-flight too.
        const lim =
          params.limit == null ? 20 : Math.max(1, Math.min(MAX_LINES, Number(params.limit) || 20));
        const branch = typeof params.branch === 'string' && params.branch ? params.branch : null;
        if (branch && !BRANCH_RE.test(branch)) throw new Error('INVALID_BRANCH');
        const repo = await repoPromise;
        const top = await preflight(repo, raw);
        const args = [
          'log',
          `--format=%H%x1f%an%x1f%ad%x1f%s`,
          '--date=iso',
          '-n',
          String(lim)
        ];
        if (branch) args.push(branch, '--');
        const { stdout } = await git(top, args, 30000, raw);
        return ok({ platform: process.platform, path: top, commits: parseGitLog(stdout) });
      } catch (e) {
        return fail(e && e.message ? e.message : 'GIT_OP_FAILED');
      }
    },
    git_diff: async (job) => {
      try {
        const { repoPromise, params } = gatedRepo(job, readRoots);
        const raw = String(params.path || '');
        const repo = await repoPromise;
        const top = await preflight(repo, raw);
        const staged = params.staged === true;
        const statOnly = params.stat_only !== false;
        const args = statOnly
          ? ['diff', '--stat', '--no-color']
          : ['diff', '--no-color', '--no-ext-diff'];
        if (staged) args.splice(1, 0, '--cached');
        const { stdout } = await git(top, args, 30000, raw);
        const text = String(stdout || '');
        if (statOnly) {
          const truncated = text.length > MAX_DIFF_BYTES;
          // Totals are exact only on untruncated output; null otherwise
          // (the truncated flag tells the model the numbers are partial).
          const totals = truncated ? { insertions: null, deletions: null } : parseDiffTotals(text, statOnly);
          return ok({
            platform: process.platform,
            path: top,
            staged,
            stat_only: statOnly,
            truncated,
            insertions: totals.insertions,
            deletions: totals.deletions,
            diff: truncated ? text.slice(0, MAX_DIFF_BYTES) : text,
            file_diffs: []
          });
        }
        // Full patch: per-file bounding (ora-7 Finding 1). A single huge
        // file is head+tail-truncated on its own budget while the rest still
        // arrive in `file_diffs`; the legacy `diff` string stays capped at
        // MAX_DIFF_BYTES. Malformed (headerless) diff output fails loudly
        // via GIT_DIFF_PARSE_FAILED — never an empty "no changes".
        let bounded;
        try {
          bounded = boundDiffByFile(text);
        } catch (e) {
          return fail(e && e.message ? e.message : 'GIT_DIFF_PARSE_FAILED');
        }
        const totals = bounded.truncated
          ? { insertions: null, deletions: null }
          : parseDiffTotals(text, false);
        return ok({
          platform: process.platform,
          path: top,
          staged,
          stat_only: statOnly,
          truncated: bounded.truncated,
          insertions: totals.insertions,
          deletions: totals.deletions,
          diff: bounded.diff,
          file_diffs: bounded.file_diffs
        });
      } catch (e) {
        return fail(e && e.message ? e.message : 'GIT_OP_FAILED');
      }
    },
    git_branch: async (job) => {
      try {
        const { repoPromise, params } = gatedRepo(job, readRoots);
        const raw = String(params.path || '');
        const repo = await repoPromise;
        const top = await preflight(repo, raw);
        const cur = await git(top, ['branch', '--show-current'], 15000, raw);
        const all = await git(top, ['branch', '--format=%(refname:short)', '--list'], 15000, raw);
        return ok({ platform: process.platform, path: top, ...parseGitBranches(cur.stdout, all.stdout) });
      } catch (e) {
        return fail(e && e.message ? e.message : 'GIT_OP_FAILED');
      }
    },
    git_clone: async (job) => {
      try {
        const p = (job && (job.request_payload || job.payload)) || {};
        const url = String(p.url || '');
        if (!URL_RE.test(url)) throw new Error('INVALID_GIT_URL');
        const raw = String(p.path || '');
        if (!raw || raw.length > 4096) throw new Error('INVALID_PATH');
        // Clone targets usually do not exist yet: gate the parent, then
        // join a traversal-free leaf name.
        const parentRaw = path.dirname(raw);
        const leaf = path.basename(raw);
        if (!leaf || leaf === '.' || leaf === '..' || /[/\\]/.test(leaf))
          throw new Error('INVALID_PATH');
        const extra = policyExtraRoots(job);
        const roots = [...writeRoots, ...extra.write];
        const parent = await realAllowed(parentRaw, roots, extra.allowAll === true);
        const target = path.join(parent, leaf);
        forbidAgentTreeWrite('git_clone', [target], { appRoot, workspace });
        const depth =
          p.depth == null ? 1 : Math.max(1, Math.min(1000000, Number(p.depth) || 1));
        const args = ['clone', '--depth', String(depth), url, target];
        if (p.branch && BRANCH_RE.test(String(p.branch))) args.splice(1, 0, '--branch', String(p.branch));
        else if (p.branch) throw new Error('INVALID_BRANCH');
        try {
          await run('git', args, {
            timeout: 600000,
            maxBuffer: 8 * 1024 * 1024,
            env: { ...process.env, ...GIT_ENV }
          });
        } catch (e) {
          gitOrThrow(e, { repo: target, raw: target });
        }
        return ok({ platform: process.platform, path: target, url, depth, cloned: true });
      } catch (e) {
        return fail(e && e.message ? e.message : 'GIT_OP_FAILED');
      }
    },
    // Structured git writes (MCP `git_write`): stage, commit, push,
    // branch and fetch without raw shell. Every mutation runs under
    // write-roots gating plus the agent-tree write ban (same as clone),
    // pre-flights the repo root, and refuses empty stages and
    // non-fast-forward pushes without an explicit force flag.
    // `gh` is deliberately NOT exposed: it needs credentials the agent
    // may not hold, so any gh-shaped work stays shell-gated by policy.
    git_write: async (job) => {
      try {
        const p = (job && (job.request_payload || job.payload)) || {};
        // Pure validation first: injection-shaped input fails before any
        // spawn, even when the path would fail pre-flight too.
        const v = validateGitWriteArgs(p);
        const { action } = v;
        const { repoPromise, params } = gatedRepo(job, writeRoots, true);
        const raw = String(params.path || '');
        const repo = await repoPromise;
        forbidAgentTreeWrite('git_write', [repo], { appRoot, workspace });
        const top = await preflight(repo, raw);
        const g = (args, timeout) => git(top, args, timeout, raw);
        const base = { platform: process.platform, path: top, action };
        // Narrow on v.action (not the destructured copy) so TS refines
        // the validated-args union per branch.
        if (v.action === 'add') {
          // Authoritative containment against the discovered top.
          const rels = v.paths.map((entry) => stageRelPath(top, entry));
          await g(['add', '--', ...rels], 30000);
          const { stdout } = await g(['diff', '--cached', '--name-only', '-z'], 15000);
          const files = String(stdout || '').split('\0').filter(Boolean);
          return ok({ ...base, staged: files.length, files: files.slice(0, 100) });
        }
        if (v.action === 'commit') {
          const { message } = v;
          // Refuse the empty stage: `diff --cached --quiet` exits 0 when
          // nothing is staged, 1 when something is. Any other failure is a
          // real git error and classifies through the terminal family.
          let probe = 'error';
          let probeErr = null;
          try {
            await run(
              'git',
              ['-c', `safe.directory=${top}`, 'diff', '--cached', '--quiet'],
              { timeout: 15000, cwd: top, env: { ...process.env, ...GIT_ENV } }
            );
            probe = 'empty';
          } catch (e) {
            probeErr = e;
            probe =
              e && typeof e === 'object' && /** @type {{code?: unknown}} */ (e).code === 1
                ? 'staged'
                : 'error';
          }
          if (probe === 'empty')
            throw new Error(
              `GIT_NOTHING_STAGED: nothing is staged in '${top}'. ` +
              `Do not retry commit — stage files first with git_write action=add.`
            );
          if (probe === 'error') gitOrThrow(probeErr, { repo: top, raw });
          await g(['commit', '-m', message], 30000);
          const { stdout: ho } = await g(['rev-parse', 'HEAD'], 15000);
          const sha = String(ho || '').trim();
          return ok({
            ...base,
            committed: true,
            commit: /^[0-9a-f]{40}$/.test(sha) ? sha : null,
            message: message.slice(0, 200)
          });
        }
        if (v.action === 'push') {
          const { remote, branch, force } = v;
          const refArgs = branch ? [remote, branch] : [remote];
          if (!force) {
            // Dry-run first: a non-fast-forward remote refuses here with
            // GIT_PUSH_NON_FAST_FORWARD before anything is pushed.
            await g(['push', '--dry-run', ...refArgs], 120000);
            await g(['push', ...refArgs], 120000);
          } else {
            // Explicit force only: lease-guarded, never a blind --force.
            await g(['push', '--force-with-lease', ...refArgs], 120000);
          }
          return ok({ ...base, pushed: true, remote, branch, forced: force });
        }
        if (v.action === 'branch') {
          const { name } = v;
          const sw = v.switch === true;
          if (sw) await g(['checkout', '-b', name], 30000);
          else await g(['branch', name], 30000);
          return ok({ ...base, branch: name, created: true, switched: sw });
        }
        // action === 'fetch'
        const { remote, depth } = v;
        const fetchArgs = ['fetch'];
        if (depth !== null) fetchArgs.push('--depth', String(depth));
        fetchArgs.push(remote);
        await g(fetchArgs, 120000);
        return ok({ ...base, fetched: true, remote, depth });
      } catch (e) {
        return fail(e && e.message ? e.message : 'GIT_OP_FAILED');
      }
    }
  };
}
