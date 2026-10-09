// Phase 6 refactor: path validation primitives extracted from core/mutation-ops.mjs.
// Pure path/auth checks; mutations import back what they need. Behavior unchanged.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { isSensitivePath } from './sensitive-paths.mjs';

export class MutationError extends Error {
  /**
   * @param {string} code stable machine-readable code (also the message, so
   * string/regex assertions on either keep working)
   * @param {Record<string, unknown>|null} [details] structured context for
   * the denial payload (permitted roots, missing ancestor, ...). Never
   * secrets, stacks, or internal paths.
   */
  constructor(code, details = null) {
    super(code);
    /** @type {string} */
    this.code = code;
    /** @type {Record<string, unknown>|null} */
    this.details = details;
  }
}

export /** @type {(code: string, details?: Record<string, unknown>|null) => never} */
const err = (code, details = null) => {
  throw new MutationError(code, details);
};

export /**
 * @param {unknown} e
 */
const isNoEnt = (e) => !!e && typeof e === 'object' && 'code' in e && e.code === 'ENOENT';

export /**
 * @param {string} v @param {typeof import('node:path')} pathApi
 */
function normCase(v, pathApi) {
  const n = pathApi.normalize(v);
  return pathApi.sep === '\\' ? n.toLowerCase() : n;
}

export /**
 * @param {string} candidate @param {string} root @param {typeof import('node:path')} pathApi
 */
function within(candidate, root, pathApi) {
  const c = normCase(candidate, pathApi),
    r = normCase(root, pathApi);
  return c === r || c.startsWith(r.endsWith(pathApi.sep) ? r : r + pathApi.sep);
}

export /**
 * @param {string} target @param {typeof import('node:fs/promises')} fsApi
 */
async function lstatOrNull(target, fsApi) {
  try {
    return await fsApi.lstat(target);
  } catch (e) {
    if (isNoEnt(e)) return null;
    throw e;
  }
}

export /**
 * @param {Array<string>|undefined} roots @param {typeof import('node:fs/promises')} fsApi @returns {Promise<Array<string>>}
 */
async function realAllowedRoots(roots, fsApi) {
  const out = [];
  for (const root of roots || []) {
    try {
      out.push(await fsApi.realpath(root));
    } catch {}
  }
  if (!out.length) err('PATH_NOT_ALLOWED');
  return out;
}

export /**
 * @param {string} raw
 */
function validateWindowsLexicalPath(raw) {
  const value = raw.replace(/\//g, '\\');
  if (/^\\\\[?.]\\/.test(value)) err('PATH_NAMESPACE_NOT_ALLOWED');
  const afterDrive = /^[A-Za-z]:/.test(value) ? value.slice(2) : value;
  if (afterDrive.includes(':')) err('PATH_ALTERNATE_STREAM_NOT_ALLOWED');
  const reserved = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\$|CONOUT\$)(?:\.|$)/i;
  for (const segment of value.split('\\')) {
    if (!segment || segment === '.' || segment === '..' || /^[A-Za-z]:$/.test(segment)) continue;
    if (/[<>"|?*]/.test(segment) || /[\x00-\x1f]/.test(segment)) err('PATH_WINDOWS_INVALID_CHAR');
    if (/[ .]$/.test(segment)) err('PATH_WINDOWS_AMBIGUOUS_SEGMENT');
    if (reserved.test(segment)) err('PATH_RESERVED_NAME_NOT_ALLOWED');
  }
}

export /**
 * Pre-flight path normalization (TOOL_DESIGN L1): expand a leading `~` to
 * the operator home directory and resolve relative paths against `cwd`
 * BEFORE any authorization check. Normalization never bypasses the
 * allowlist — the normalized absolute path is what gets checked below.
 * `cwd = null` preserves the legacy strict gate (PATH_NOT_ABSOLUTE) for
 * direct low-level callers; high-level entry points pass process.cwd().
 * @param {string} target @param {object} [options] @param {typeof import('node:path')} [options.pathApi] @param {string|null} [options.cwd] @param {string} [options.homedir]
 */
function resolveTargetPath(target, { pathApi = path, cwd = null, homedir = null } = {}) {
  // No trimming: trailing spaces are significant on win32 (ambiguous-segment
  // rejection) and legal in posix names — normalization must not rewrite them.
  let raw = String(target || '');
  if (raw === '~' || raw.startsWith('~/') || raw.startsWith('~\\')) {
    const home = homedir || os.homedir();
    raw = raw === '~' ? home : pathApi.join(home, raw.slice(2));
  }
  if (!pathApi.isAbsolute(raw)) {
    if (cwd == null) err('PATH_NOT_ABSOLUTE');
    raw = pathApi.resolve(/** @type {string} */ (cwd), raw);
  }
  return pathApi.normalize(raw);
}

export /**
 * @param {string} target @param {object} [options] @param {typeof import('node:path')} [options.pathApi] @param {string|null} [options.cwd] @param {string} [options.homedir]
 */
function normalizeMutationPath(target, { pathApi = path, cwd = null, homedir = null } = {}) {
  const raw = String(target || '');
  if (raw.includes('\0')) err('PATH_INVALID');
  const normalized = resolveTargetPath(raw, { pathApi, cwd, homedir });
  if (pathApi.sep === '\\') validateWindowsLexicalPath(normalized);
  return normalized;
}

export /**
 * @param {string} target @param {object} options @param {typeof import('node:fs/promises')} options.fsApi @param {typeof import('node:path')} options.pathApi
 */
async function nearestExistingAncestor(target, { fsApi, pathApi }) {
  let cur = target;
  while (true) {
    const st = await lstatOrNull(cur, fsApi);
    if (st) return cur;
    const parent = pathApi.dirname(cur);
    if (parent === cur) err('PATH_NOT_ALLOWED');
    cur = parent;
  }
}

export /**
 * Credential-directory denylist (SEC-001): always enforced, even under
 * allow_all_filesystem and explicit roots. narrow by design.
 * @param {string} absPath @param {unknown} [pathApi]
 */
function denySensitivePath(absPath, pathApi = path) {
  try {
    const platform =
      pathApi && pathApi.sep === '\\'
        ? 'win32'
        : typeof process !== 'undefined'
          ? process.platform
          : 'linux';
    if (isSensitivePath(absPath, platform)) err('PATH_DENIED_SENSITIVE');
  } catch (e) {
    if (e instanceof MutationError) throw e;
  }
}

/**
 * @param {string} target @param {object} [options] @param {Array<string>} [options.roots] @param {boolean} [options.allowAll] operator full-access flag: skips allowlist membership only @param {typeof import('node:fs/promises')} [options.fsApi] @param {typeof import('node:path')} [options.pathApi] @param {{tool?: string, appRoot?: string|null, workspace?: string|null}|null} [options.treeBan] agent-tree ban enforced against the REALPATH-resolved ancestor (closes the lexical-only gap: a planted intermediate symlink inside the workspace resolves outside it but inside the agent tree; allowAll skips roots, never the tree ban) @param {string|null} [options.cwd] pre-flight relative-resolution base (null keeps the strict PATH_NOT_ABSOLUTE gate) @param {string} [options.homedir] `~` expansion base
 */
export async function authorizeMutationPath(
  target,
  { roots, allowAll = false, fsApi = fs, pathApi = path, treeBan = null, cwd = null, homedir = null } = {}
) {
  const normalized = normalizeMutationPath(target, { pathApi, cwd, homedir });
  denySensitivePath(normalized, pathApi);
  const [ancestor, realRoots] = await Promise.all([
    nearestExistingAncestor(normalized, { fsApi, pathApi }),
    allowAll === true ? [] : realAllowedRoots(roots, fsApi)
  ]);
  const realAncestor = await fsApi.realpath(ancestor);
  denySensitivePath(realAncestor, pathApi);
  if (treeBan && treeBan.appRoot) {
    forbidAgentTreeWrite(treeBan.tool || 'mutation', [normalized, realAncestor], {
      appRoot: treeBan.appRoot,
      workspace: treeBan.workspace ?? null,
      pathApi
    });
  }
  if (allowAll !== true && !realRoots.some((root) => within(realAncestor, root, pathApi)))
    err('PATH_NOT_ALLOWED', { path: normalized, configured_roots: [...realRoots] });
  return { path: normalized, ancestor, real_ancestor: realAncestor, real_roots: realRoots };
}

export /**
 * Agent-tree write ban: file tools never mutate the agent's own tree
 * (binaries, config, keys, logs, state), not even with full-access roots.
 * The designated workspace subtree stays writable (probe/scratch area).
 * Callers pass already-normalized absolute targets; move checks both ends
 * (moving OUT also mutates the tree).
 * @param {string} tool
 * @param {Array<string>} targets
 * @param {object} [options] @param {string|null} [options.appRoot] @param {string|null} [options.workspace] @param {unknown} [options.pathApi]
 */
function forbidAgentTreeWrite(tool, targets, { appRoot = null, workspace = null, pathApi = path } = {}) {
  if (!appRoot || typeof appRoot !== 'string') return;
  const norm = (v) => normCase(pathApi.normalize(String(v)), pathApi);
  const root = norm(appRoot);
  const ws = workspace && typeof workspace === 'string' ? norm(workspace) : null;
  const sep = pathApi.sep || '/';
  for (const raw of targets || []) {
    if (typeof raw !== 'string' || !raw) continue;
    let t;
    try {
      t = norm(raw);
    } catch {
      continue;
    }
    const inside = (p, r) => p === r || p.startsWith(r.endsWith(sep) ? r : r + sep);
    if (ws && inside(t, ws)) continue;
    // SECURITY: denial-time guidance only — the ban decision on this line
    // already fired, so attaching the writable workspace afterwards weakens
    // nothing. allowed_roots is agent allowlist configuration, safe to show
    // per control-plane errors.mjs ("safe to show, never a secret"), and
    // mirrors shell-runner agentTreeRefusal which already exposes
    // layout.workspace. Only the directly-writable workspace is exposed (same
    // semantics as shell allowed_roots); appRoot/configured_roots stay
    // hidden, and an empty workspace yields details=null (no fabrication).
    if (inside(t, root)) err('AGENT_TREE_WRITE_FORBIDDEN', workspace ? { allowed_roots: [workspace] } : null);
  }
}

/**
 * Absolute write targets of a mutation payload for the agent-tree ban.
 * @param {string} tool @param {Record<string, unknown>} [payload]
 */
export function mutationTargets(tool, payload = {}) {
  const p = payload && typeof payload === 'object' ? payload : {};
  const str = (v) => (typeof v === 'string' && v ? v : null);
  if (tool === 'file_move') return [str(p.source), str(p.destination ?? p.path)].filter(Boolean);
  if (tool === 'file_copy') return [str(p.source), str(p.destination)].filter(Boolean);
  const v = str(p.path);
  return v ? [v] : [];
}

