// Phase 6 refactor: path validation primitives extracted from core/mutation-ops.mjs.
// Shared path/auth checks; mutations import back what they need.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { isSensitivePath } from './sensitive-paths.mjs';

const run = promisify(execFile);
const WINDOWS_WRITE_RIGHTS = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
const SID = /^S-1-\d+(?:-\d+)+$/;

/** Directory metadata must positively establish ownership and private write access. */
export function isTrustedPosixDirectory(stat, uid = process.geteuid?.()) {
  return Number.isInteger(uid) && uid >= 0 && typeof stat?.isDirectory === 'function' && stat.isDirectory() === true &&
    (stat.uid === uid || stat.uid === 0) && Number.isInteger(stat.mode) && stat.mode >= 0 && (stat.mode & 0o022) === 0;
}

/** Evaluate translated ACL rows, never localized account names or POSIX mode bits. */
export function isTrustedWindowsDirectory(acl) {
  if (!acl || acl.reparsePoint !== false || typeof acl.userSid !== 'string' ||
      !SID.test(acl.userSid) || !Array.isArray(acl.entries)) return false;
  const trusted = new Set([acl.userSid, 'S-1-5-18', 'S-1-5-32-544']);
  if (typeof acl.ownerSid !== 'string' || !SID.test(acl.ownerSid) || !trusted.has(acl.ownerSid)) return false;
  for (const row of acl.entries) {
    if (!row || typeof row.sid !== 'string' || !SID.test(row.sid) ||
        !['Allow', 'Deny'].includes(row.type) || !Number.isInteger(row.rights) ||
        row.rights < 0 || row.rights > 0xffffffff) return false;
    if (row.type === 'Allow' && (row.rights & WINDOWS_WRITE_RIGHTS) !== 0 && !trusted.has(row.sid)) return false;
  }
  return true;
}

/** Same bounded argv-form PowerShell execution path used by agent diagnostics. */
export function createWindowsDirectoryTrustReader({ execute = run, now = Date.now } = {}) {
  const cache = new Map();
  return async (realDirectory) => {
    const key = path.win32.normalize(realDirectory).toLowerCase();
    const cached = cache.get(key);
    if (cached && now() < cached.expires) return cached.trusted;
    cache.delete(key);
    let trusted = false;
    try {
      // LiteralPath and single-quote doubling keep filenames out of executable syntax.
      const literal = realDirectory.replace(/'/g, "''");
      const script = `$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath '${literal}' -Force
$acl = Get-Acl -LiteralPath '${literal}'
$descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($acl.Sddl)
if ($null -eq $descriptor.DiscretionaryAcl) { throw 'Missing DACL' }
$rows = @($acl.Access | ForEach-Object {
  @{ sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; type = $_.AccessControlType.ToString(); rights = [uint32]$_.FileSystemRights }
})
@{ userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; ownerSid = $descriptor.Owner.Value; reparsePoint = [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint); entries = $rows } | ConvertTo-Json -Depth 5 -Compress`;
      const { stdout, stderr } = await execute('powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command', script],
        { timeout: 5000, maxBuffer: 1024 * 1024, windowsHide: true, encoding: 'utf8' });
      if (!String(stderr || '').trim()) trusted = isTrustedWindowsDirectory(JSON.parse(String(stdout)));
    } catch {
      // Query, translation, timeout and malformed output all deny without leaking diagnostics.
    }
    if (trusted) {
      if (cache.size >= 256) cache.delete(cache.keys().next().value);
      cache.set(key, { trusted, expires: now() + 60000 });
    }
    return trusted;
  };
}

const windowsDirectoryTrusted = createWindowsDirectoryTrustReader();

/** Check every real directory up to the volume root, including ancestors of configured roots. */
export async function isTrustedMutationChain(realDirectory, realRoot, {
  fsApi = fs, pathApi = path, windowsTrustReader = windowsDirectoryTrusted
} = {}) {
  if (!within(realDirectory, realRoot, pathApi)) return false;
  const chain = [];
  let current = realDirectory;
  while (true) {
    chain.push(current);
    const parent = pathApi.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  try {
    for (const directory of chain.reverse()) {
      const stat = await fsApi.stat(directory);
      const leaf = await fsApi.lstat(directory);
      if (!leaf.isDirectory() || leaf.isSymbolicLink()) return false;
      if (pathApi.sep === '\\') {
        if (!stat.isDirectory() || leaf.isSymbolicLink() || !await windowsTrustReader(directory)) return false;
      } else if (!isTrustedPosixDirectory(stat)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** Walk the full configured spelling, including alias containers above its root.
 * Never normalize link targets or skip configured-root prefixes: doing so erases
 * visited containers that may allow an attacker to replace the configured root.
 */
async function isTrustedLexicalMutationPath(lexicalPath, {
  fsApi, pathApi, windowsTrustReader
}) {
  const split = (value) => value.split(pathApi.sep === '\\' ? /[\\/]/ : '/').filter(Boolean);
  let current = pathApi.parse(lexicalPath).root;
  let pending = split(lexicalPath.slice(current.length));
  let hops = 0;
  let steps = 0;
  try {
    while (++steps <= 4096 && pending.length + steps <= 4096) {
      if (!await isTrustedMutationChain(current, current, { fsApi, pathApi, windowsTrustReader })) return false;
      if (!pending.length) return true;
      const component = pending.shift();
      if (component === '.') continue;
      if (component === '..') {
        current = pathApi.dirname(current);
        continue;
      }
      const candidate = pathApi.join(current, component);
      let stat;
      try {
        stat = await fsApi.lstat(candidate);
      } catch (e) {
        // Only a missing descendant after a completely trusted existing chain
        // may be created. Do not erase traversal after a missing component.
        return isNoEnt(e) && !pending.includes('..');
      }
      if (stat.isSymbolicLink()) {
        if (++hops > 40) return false;
        const target = await fsApi.readlink(candidate);
        if (typeof target !== 'string' || !target) return false;
        let components = split(target);
        if (pathApi.isAbsolute(target)) {
          const volume = pathApi.parse(target).root;
          if (pathApi.sep === '\\' && volume === '\\') return false;
          components = split(target.slice(volume.length));
          current = volume;
        } else if (pathApi.sep === '\\' && /^[A-Za-z]:/.test(target)) return false;
        pending = components.concat(pending);
      } else {
        // A leaf ends the walk, but its symlink hops must be walked first:
        // checking only the original parent loses file-link containers.
        // Callers retain the opened-handle type check for non-regular leaves.
        if (!stat.isDirectory()) return pending.length === 0;
        current = candidate;
      }
    }
  } catch {
    // Every metadata, link or ACL failure denies, even after canonical success.
  }
  return false;
}

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
  // L01a-15: fail closed. An unexpected error (bad pathApi, TypeError
  // inside the matcher) must propagate, never resolve to "not sensitive".
  const platform =
    pathApi && pathApi.sep === '\\'
      ? 'win32'
      : typeof process !== 'undefined'
        ? process.platform
        : 'linux';
  if (isSensitivePath(absPath, platform)) err('PATH_DENIED_SENSITIVE');
}

/**
 * @param {string} target @param {object} [options] @param {Array<string>} [options.roots] @param {boolean} [options.allowAll] operator full-access flag: skips allowlist membership only @param {typeof import('node:fs/promises')} [options.fsApi] @param {typeof import('node:path')} [options.pathApi] @param {{tool?: string, appRoot?: string|null, workspace?: string|null}|null} [options.treeBan] agent-tree ban enforced against the REALPATH-resolved ancestor (closes the lexical-only gap: a planted intermediate symlink inside the workspace resolves outside it but inside the agent tree; allowAll skips roots, never the tree ban) @param {string|null} [options.cwd] pre-flight relative-resolution base (null keeps the strict PATH_NOT_ABSOLUTE gate) @param {string} [options.homedir] `~` expansion base
 * @param {(directory: string) => Promise<boolean>} [options.windowsTrustReader] internal ACL reader injection for fixture tests
 */
export async function authorizeMutationPath(
  target,
  { roots, allowAll = false, fsApi = fs, pathApi = path, treeBan = null, cwd = null, homedir = null, windowsTrustReader = windowsDirectoryTrusted } = {}
) {
  const normalized = normalizeMutationPath(target, { pathApi, cwd, homedir });
  denySensitivePath(normalized, pathApi);
  const rootPairs = [];
  const realRoots = [];
  let ancestor, realAncestor;
  try {
    if (allowAll !== true) {
      for (const root of roots || []) {
        const lexical = normalizeMutationPath(root, { pathApi, cwd: cwd ?? process.cwd(), homedir });
        const real = await fsApi.realpath(lexical);
        rootPairs.push({ lexical, real });
        realRoots.push(real);
      }
      if (!realRoots.length) err('PATH_NOT_ALLOWED');
    }
    ancestor = await nearestExistingAncestor(normalized, { fsApi, pathApi });
    realAncestor = await fsApi.realpath(ancestor);
  } catch {
    err('PATH_NOT_ALLOWED', { path: normalized, configured_roots: [...realRoots] });
  }
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
  let trusted = false;
  try {
    // Callers also pass a parent directory itself. Include it, not just its parent.
    const stat = await fsApi.stat(realAncestor);
    const realDirectory = stat.isDirectory() ? realAncestor : pathApi.dirname(realAncestor);
    const lexicalDirectory = stat.isDirectory() ? ancestor : pathApi.dirname(ancestor);
    // Only a configured lexical spelling can anchor the walk. A deeper alias
    // resolving to the same real root must never skip configured-root children.
    const pair = rootPairs.find(({ lexical, real }) => within(lexicalDirectory, lexical, pathApi) && within(realDirectory, real, pathApi));
    const realRoot = allowAll === true
      ? pathApi.parse(realDirectory).root
      : pair?.real;
    trusted = !!realRoot && await isTrustedMutationChain(realDirectory, realRoot, { fsApi, pathApi, windowsTrustReader });
    if (trusted) {
      trusted = await isTrustedLexicalMutationPath(ancestor, { fsApi, pathApi, windowsTrustReader });
    }
  } catch {
    // No metadata or incomplete ancestry is never evidence of a trusted namespace.
    trusted = false;
  }
  if (!trusted) err('PATH_NOT_ALLOWED', { path: normalized, configured_roots: [...realRoots] });
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

