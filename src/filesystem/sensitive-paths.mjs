/**
 * Credential-directory denylist (SEC-001). Evaluated BEFORE any allowlist or
 * allow_all_filesystem bypass, on both read and mutation paths: operator
 * intent (roots, full-access flag) can widen where work happens, never into
 * key material. Narrow by design — normal work directories never match.
 *
 * POSIX (matched against $HOME-relative and absolute forms):
 *   .ssh, .gnupg, .aws, .azure, .kube, .docker, .config/gcloud,
 *   .npmrc, .pypirc, .git-credentials, .netrc, .vault-token, .password-store
 * POSIX absolute: /etc/shadow, /etc/gshadow, /etc/sudoers, /etc/sudoers.d,
 *   /etc/ssh
 * Windows (case-insensitive): %USERPROFILE%\\AppData subtree is NOT blanket
 * denied (too broad); denied: *\\Windows\\System32 subtree, Chrome/Edge
 * Login Data + Cookies, Firefox profiles, PowerShell PSReadLine history
 * (may contain pasted secrets).
 */

const POSIX_HOME_DENY = Object.freeze([
  '.ssh',
  '.gnupg',
  '.aws',
  '.azure',
  '.kube',
  '.docker',
  '.npmrc',
  '.pypirc',
  '.git-credentials',
  '.netrc',
  '.vault-token',
  '.password-store'
]);

const POSIX_HOME_PREFIX_DENY = Object.freeze(['.config/gcloud']);

const POSIX_ABSOLUTE_DENY = Object.freeze([
  '/etc/shadow',
  '/etc/gshadow',
  '/etc/sudoers',
  '/etc/sudoers.d',
  '/etc/ssh'
]);

const WIN_SYSTEM_SUBSTRINGS = Object.freeze(['\\windows\\system32\\', '\\windows\\system32']);

const WIN_PROFILE_SUBSTRINGS = Object.freeze([
  '\\google\\chrome\\user data\\default\\login data',
  '\\google\\chrome\\user data\\default\\cookies',
  '\\google\\chrome\\user data\\default\\web data',
  '\\microsoft\\edge\\user data\\default\\login data',
  '\\microsoft\\edge\\user data\\default\\cookies',
  '\\microsoft\\edge\\user data\\default\\web data',
  '\\mozilla\\firefox\\profiles',
  '\\microsoft\\windows\\powershell\\psreadline\\consolehost_history.txt'
]);

const POSIX_SHELL_DELIM = '(?=[/\\s"\'`;&|<>()\\[\\]:,]|$)';

const POSIX_HOME_CREDENTIAL_PATTERN = [...POSIX_HOME_DENY, ...POSIX_HOME_PREFIX_DENY]
  .map((d) => d.replace(/\./g, '\\.'))
  .join('|');

const POSIX_HOME_DENY_RE = new RegExp(
  `(?:^|[\\s"\'\`=;&|<>()\\[\\]:,]|(?<=[\\s"\'\`=;&|<>()\\[\\]:,]-[a-zA-Z]))(?:/(?:home|Users)/[^/\\s"\'\`=]+|/root|~[^/\\s"\'\`=]*)/(?:${POSIX_HOME_CREDENTIAL_PATTERN})${POSIX_SHELL_DELIM}`
);

const POSIX_HIGH_RISK_RE = new RegExp(
  `(?:^|[\\s"\'\`=;&|<>()\\[\\]:,/])\\.(?:ssh|gnupg|aws)${POSIX_SHELL_DELIM}`
);

const POSIX_MAC_CREDENTIALS_RE = new RegExp(
  `(?:^|[\\s"\'\`=;&|<>()\\[\\]:,/])Library/(?:Keychains|Application(?:\\\\?\\s+)Support/com\\.apple\\.TCC)${POSIX_SHELL_DELIM}`
);

const POSIX_SYSTEM_CREDENTIALS_RE = new RegExp(
  `(?:^|[\\s"'\`=;&|<>()\\[\\]:,/])etc/(?:shadow|gshadow|sudoers(?:\\.d)?|ssh)${POSIX_SHELL_DELIM}`
);

const POSIX_KEY_FILES_RE = /id_rsa|id_ed25519/;

/**
 * Best-effort literal scan of a shell command for credential-path references
 * (SEC-001, shell side). Catches redirections and absolute tool paths that
 * name key material; intentionally NOT a sandbox — env vars, cd-relative
 * writes and pipes escape static analysis, OS permissions remain the floor.
 * @param {string} command @param {string} [platform]
 */
export function sensitiveCommandHit(command, platform = process.platform) {
  try {
    const text = String(command || '');
    if (!text) return false;
    if (platform === 'win32') {
      const lower = text.replace(/\//g, '\\').toLowerCase();
      if (/windows\\system32([\s\\"']|$)/.test(lower)) return true;
      for (const s of WIN_PROFILE_SUBSTRINGS) {
        if (lower.includes(s)) return true;
      }
      return false;
    }
    const norm = text.replace(/\/+/g, '/');
    if (POSIX_KEY_FILES_RE.test(norm)) return true;
    if (POSIX_SYSTEM_CREDENTIALS_RE.test(norm)) return true;
    if (POSIX_MAC_CREDENTIALS_RE.test(norm)) return true;
    if (POSIX_HIGH_RISK_RE.test(norm)) return true;
    if (POSIX_HOME_DENY_RE.test(norm)) return true;
    return false;
  } catch {
    return false;
  }
}
/**
 * @param {string} absPath already-normalized absolute path
 * @param {string} [platform]
 * @returns {boolean} true when the path must be denied
 */
export function isSensitivePath(absPath, platform = process.platform) {
  try {
    if (platform === 'win32') {
      const lower = String(absPath || '')
        .replace(/\//g, '\\')
        .toLowerCase();
      for (const s of WIN_SYSTEM_SUBSTRINGS) if (lower === s || lower.includes(s)) return true;
      for (const s of WIN_PROFILE_SUBSTRINGS) if (lower.includes(s)) return true;
      return false;
    }
    const norm = String(absPath || '').replace(/\/+/g, '/');
    // P12-D1 (macOS alias): /etc is a symlink to /private/etc, so a
    // realpath-resolved guardedCwd('/etc/ssh') is '/private/etc/ssh' and
    // missed the absolute denylist below (probe: isSensitivePath returned
    // false for the resolved form, true for the user form). Canonicalize
    // the alias before matching so both forms hit consistently (mirrors
    // the darwin privileged-helper (private/)?etc denylist).
    const canon = norm.replace(/^\/private\/etc(\/|$)/, '/etc$1');
    for (const a of POSIX_ABSOLUTE_DENY) {
      if (canon === a || canon.startsWith(a + '/')) return true;
    }
    const parts = norm.split('/').filter(Boolean);
    const homeIdx = parts[0] === 'home' || parts[0] === 'Users' ? 2 : parts[0] === 'root' ? 1 : -1;
    if (homeIdx > 0 && parts.length > homeIdx) {
      const rel = parts.slice(homeIdx).join('/');
      for (const d of POSIX_HOME_DENY) {
        if (rel === d || rel.startsWith(d + '/')) return true;
      }
      for (const d of POSIX_HOME_PREFIX_DENY) {
        if (rel === d || rel.startsWith(d + '/')) return true;
      }
    }
    // P13-D4 (macOS keychains): the shell-text scan already blocks
    // Library/Keychains references, but the file-path side allowed them —
    // reads/writes of keychain stores sailed through. Deny the segment pair
    // at any depth (covers ~/Library/Keychains and /Library/Keychains;
    // exact-case segments mirror the shell regex, and the realpath recheck
    // in the mutation/shell-cwd gates backstops case variants on
    // case-insensitive APFS). Narrow: no legitimate work path contains it.
    for (let i = 0; i + 1 < parts.length; i++) {
      if (parts[i] === 'Library' && parts[i + 1] === 'Keychains') return true;
    }
    // Service/home-less layouts: match well-known names at any depth only
    // for the highest-risk key stores.
    for (const d of ['.ssh', '.gnupg']) {
      if (parts.includes(d)) return true;
    }
    return false;
  } catch {
    return false;
  }
}
