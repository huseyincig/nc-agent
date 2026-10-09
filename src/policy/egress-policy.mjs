import net from 'node:net';

export const EGRESS_ALLOW_SCHEMES = Object.freeze(['http:', 'https:']);

export const EGRESS_DENY_SCHEMES = Object.freeze([
  'file:',
  'ftp:',
  'data:',
  'javascript:',
  'chrome:',
  'chrome-extension:',
  'devtools:',
  'view-source:',
  'about:',
  'blob:',
  'ws:',
  'wss:'
]);

export const CLOUD_METADATA_HOSTS = Object.freeze([
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
  'instance-data-compute',
  'metadata.azure.internal'
]);

export const CLOUD_METADATA_IPS = Object.freeze(['169.254.169.254', '100.100.100.200']);

/** @param {string} label */
function parseNumericLabel(label) {
  if (/^0[xX][0-9a-fA-F]+$/.test(label)) return parseInt(label, 16);
  if (/^0[0-7]+$/.test(label) && label.length > 1) return parseInt(label, 8);
  if (/^\d+$/.test(label)) return parseInt(label, 10);
  return null;
}

/** @param {unknown} hostname */
export function normalizeHostnameIp(hostname) {
  const host = String(hostname || '').trim();
  if (!host) return null;
  if (net.isIP(host)) return host;
  if (host.includes(':')) return null;
  const labels = host.split('.');
  if (labels.length === 0 || labels.length > 4) return null;
  const parts = [];
  for (const label of labels) {
    if (label === '') return null;
    const num = parseNumericLabel(label);
    if (num == null || !Number.isSafeInteger(num) || num < 0) return null;
    parts.push(num);
  }
  let n;
  if (parts.length === 1) {
    if (parts[0] > 0xffffffff) return null;
    n = parts[0];
  } else if (parts.length === 2) {
    if (parts[0] > 255 || parts[1] > 0xffffff) return null;
    n = parts[0] * 0x1000000 + parts[1];
  } else if (parts.length === 3) {
    if (parts[0] > 255 || parts[1] > 255 || parts[2] > 0xffff) return null;
    n = parts[0] * 0x1000000 + parts[1] * 0x10000 + parts[2];
  } else {
    if (parts.some((x) => x > 255)) return null;
    n = ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
  }
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** @param {string} ip */
function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
}

/** @param {string} ip @param {string} base @param {number} bits */
function inCidr(ip, base, bits) {
  const size = Math.pow(2, 32 - bits);
  const start = Math.floor(ipv4ToInt(base) / size) * size;
  const n = ipv4ToInt(ip);
  return n >= start && n < start + size;
}

/** @param {string} ip */
export function unwrapV6(ip) {
  let cleanIp = String(ip || '').trim();
  if (cleanIp.startsWith('[') && cleanIp.endsWith(']')) {
    cleanIp = cleanIp.slice(1, -1);
  }
  if (!net.isIPv6(cleanIp)) {
    return { kind: 'v6', ip: cleanIp };
  }

  const lastColon = cleanIp.lastIndexOf(':');
  if (lastColon === -1) {
    return { kind: 'v6', ip: cleanIp };
  }

  const lastPart = cleanIp.slice(lastColon + 1);
  let normalizedV6;
  if (net.isIPv4(lastPart)) {
    const v4Parts = lastPart.split('.').map(Number);
    const hexEquivalent =
      ((v4Parts[0] << 8) | v4Parts[1]).toString(16) +
      ':' +
      ((v4Parts[2] << 8) | v4Parts[3]).toString(16);
    normalizedV6 = cleanIp.slice(0, lastColon + 1) + hexEquivalent;
  } else {
    normalizedV6 = cleanIp;
  }

  let hextets;
  if (normalizedV6.includes('::')) {
    const parts = normalizedV6.split('::');
    if (parts.length > 2) return { kind: 'v6', ip: cleanIp };
    const leftHextets = parts[0] ? parts[0].split(':').map((h) => parseInt(h, 16)) : [];
    const rightHextets = parts[1] ? parts[1].split(':').map((h) => parseInt(h, 16)) : [];
    const missing = 8 - (leftHextets.length + rightHextets.length);
    if (missing < 0) return { kind: 'v6', ip: cleanIp };
    hextets = [...leftHextets, ...new Array(missing).fill(0), ...rightHextets];
  } else {
    hextets = normalizedV6.split(':').map((h) => parseInt(h, 16));
  }

  if (hextets.length !== 8) {
    return { kind: 'v6', ip: cleanIp };
  }

  // Check for IPv4-mapped IPv6: ::ffff:0:0/96
  // First 5 hextets must be 0, 6th hextet must be 0xffff
  if (
    hextets[0] === 0 &&
    hextets[1] === 0 &&
    hextets[2] === 0 &&
    hextets[3] === 0 &&
    hextets[4] === 0 &&
    hextets[5] === 0xffff
  ) {
    const b0 = (hextets[6] >> 8) & 0xff;
    const b1 = hextets[6] & 0xff;
    const b2 = (hextets[7] >> 8) & 0xff;
    const b3 = hextets[7] & 0xff;
    return { kind: 'v4', ip: `${b0}.${b1}.${b2}.${b3}` };
  }

  // Check for IPv4-compatible IPv6: ::/96 (deprecated but still routable,
  // e.g. ::127.0.0.1, ::169.254.169.254). Unwrap the embedded IPv4 so the
  // existing v4 deny rules (loopback, link-local, metadata) apply. Exclude
  // unspecified (::) and loopback (::1) so they keep their v6 reasons.
  if (
    hextets[0] === 0 &&
    hextets[1] === 0 &&
    hextets[2] === 0 &&
    hextets[3] === 0 &&
    hextets[4] === 0 &&
    hextets[5] === 0 &&
    !(hextets[6] === 0 && hextets[7] === 0) &&
    !(hextets[6] === 0 && hextets[7] === 1)
  ) {
    const b0 = (hextets[6] >> 8) & 0xff;
    const b1 = hextets[6] & 0xff;
    const b2 = (hextets[7] >> 8) & 0xff;
    const b3 = hextets[7] & 0xff;
    return { kind: 'v4', ip: `${b0}.${b1}.${b2}.${b3}` };
  }

  return { kind: 'v6', ip: cleanIp };
}

/** @param {string} ip */
function expandV6Hextets(ip) {
  let cleanIp = String(ip || '').trim();
  if (cleanIp.startsWith('[') && cleanIp.endsWith(']')) {
    cleanIp = cleanIp.slice(1, -1);
  }
  if (!net.isIPv6(cleanIp)) return null;
  const lastColon = cleanIp.lastIndexOf(':');
  if (lastColon === -1) return null;
  const lastPart = cleanIp.slice(lastColon + 1);
  let normalizedV6;
  if (net.isIPv4(lastPart)) {
    const v4Parts = lastPart.split('.').map(Number);
    const hexEquivalent =
      ((v4Parts[0] << 8) | v4Parts[1]).toString(16) +
      ':' +
      ((v4Parts[2] << 8) | v4Parts[3]).toString(16);
    normalizedV6 = cleanIp.slice(0, lastColon + 1) + hexEquivalent;
  } else {
    normalizedV6 = cleanIp;
  }
  let hextets;
  if (normalizedV6.includes('::')) {
    const parts = normalizedV6.split('::');
    if (parts.length > 2) return null;
    const leftHextets = parts[0] ? parts[0].split(':').map((h) => parseInt(h, 16)) : [];
    const rightHextets = parts[1] ? parts[1].split(':').map((h) => parseInt(h, 16)) : [];
    if ([...leftHextets, ...rightHextets].some((h) => !Number.isFinite(h))) return null;
    const missing = 8 - (leftHextets.length + rightHextets.length);
    if (missing < 0) return null;
    hextets = [...leftHextets, ...new Array(missing).fill(0), ...rightHextets];
  } else {
    hextets = normalizedV6.split(':').map((h) => parseInt(h, 16));
  }
  if (hextets.length !== 8 || hextets.some((h) => !Number.isFinite(h))) return null;
  return hextets;
}

/** @param {unknown} rawIp */
export function classifyIp(rawIp) {
  let ip = String(rawIp || '').trim();
  if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
  if (!net.isIP(ip)) {
    const normalized = normalizeHostnameIp(ip);
    if (!normalized) return { kind: 'invalid' };
    ip = normalized;
  }
  if (net.isIPv6(ip)) {
    const unwrapped = unwrapV6(ip);
    if (unwrapped.kind === 'v4') return classifyIp(unwrapped.ip);
    // Canonicalize before comparing: non-canonical forms like 0::1,
    // 0:0:0:0:0:0:0:1, or ::0.0.0.1 must not bypass loopback/unspecified checks.
    const canon = expandV6Hextets(ip);
    if (canon) {
      if (canon.every((h) => h === 0)) return { kind: 'v6', deny: true, reason: 'unspecified' };
      if (canon.slice(0, 7).every((h) => h === 0) && canon[7] === 1)
        return { kind: 'v6', deny: true, reason: 'loopback' };
    } else {
      const lowerElse = ip.toLowerCase();
      if (lowerElse === '::1') return { kind: 'v6', deny: true, reason: 'loopback' };
      if (lowerElse === '::') return { kind: 'v6', deny: true, reason: 'unspecified' };
    }
    const lower = ip.toLowerCase();
    const firstHextet = lower.split(':')[0] || '';
    const first = parseInt(firstHextet, 16);
    if (Number.isFinite(first)) {
      if (first >= 0xfe80 && first <= 0xfebf)
        return { kind: 'v6', deny: true, reason: 'link-local' };
      if (first >= 0xfec0 && first <= 0xfeff)
        return { kind: 'v6', deny: true, reason: 'site-local-deprecated' };
      if (first >= 0xfc00 && first <= 0xfdff)
        return { kind: 'v6', deny: false, private: true, reason: 'unique-local' };
      if (first >= 0xff00) return { kind: 'v6', deny: true, reason: 'multicast' };
    }
    return { kind: 'v6', deny: false, private: false };
  }
  if (inCidr(ip, '127.0.0.0', 8)) return { kind: 'v4', deny: true, reason: 'loopback' };
  if (inCidr(ip, '169.254.0.0', 16)) return { kind: 'v4', deny: true, reason: 'link-local' };
  if (inCidr(ip, '224.0.0.0', 4)) return { kind: 'v4', deny: true, reason: 'multicast' };
  if (inCidr(ip, '0.0.0.0', 8)) return { kind: 'v4', deny: true, reason: 'reserved' };
  if (inCidr(ip, '192.0.0.0', 24)) return { kind: 'v4', deny: true, reason: 'reserved' };
  if (inCidr(ip, '192.0.2.0', 24))
    return { kind: 'v4', deny: true, reason: 'reserved-documentation' };
  if (inCidr(ip, '198.51.100.0', 24))
    return { kind: 'v4', deny: true, reason: 'reserved-documentation' };
  if (inCidr(ip, '203.0.113.0', 24))
    return { kind: 'v4', deny: true, reason: 'reserved-documentation' };
  if (inCidr(ip, '192.88.99.0', 24)) return { kind: 'v4', deny: true, reason: 'reserved' };
  if (inCidr(ip, '240.0.0.0', 4)) return { kind: 'v4', deny: true, reason: 'reserved' };
  if (inCidr(ip, '10.0.0.0', 8) || inCidr(ip, '172.16.0.0', 12) || inCidr(ip, '192.168.0.0', 16)) {
    return { kind: 'v4', deny: false, private: true, reason: 'rfc1918' };
  }
  return { kind: 'v4', deny: false, private: false };
}

/** @param {unknown} urlString */
export function auditProjectionUrl(urlString) {
  try {
    const url = new URL(String(urlString));
    const path = url.pathname && url.pathname !== '/' ? url.pathname.slice(0, 128) : '/';
    return `${url.protocol}//${url.host.toLowerCase()}${path}`;
  } catch {
    return '(unparseable-url)';
  }
}

/**
 * @param {string} hostname
 * @param {ReadonlyArray<string>} list
 */
export function matchHostList(hostname, list) {
  const host = String(hostname || '')
    .toLowerCase()
    .replace(/\.$/, '');
  if (!host) return false;
  for (const entry of list || []) {
    const rule = String(entry || '')
      .toLowerCase()
      .replace(/\.$/, '');
    if (!rule) continue;
    if (host === rule || host.endsWith('.' + rule)) return true;
  }
  return false;
}

/**
 * @param {unknown} urlString
 * @param {{allowPrivateNetwork?: boolean, allowLoopback?: boolean, allowedHosts?: ReadonlyArray<string>, blockedHosts?: ReadonlyArray<string>, resolve?: ((hostname: string) => Promise<Array<string>>)|null, metadataIps?: ReadonlyArray<string>}} [options]
 */
export async function validateEgressUrl(
  urlString,
  {
    allowPrivateNetwork = false,
    allowLoopback = false,
    allowedHosts = [],
    blockedHosts = [],
    resolve = null,
    metadataIps = CLOUD_METADATA_IPS
  } = {}
) {
  const raw = String(urlString || '').trim();
  if (!raw) return { ok: false, error: 'URL_REQUIRED' };
  let url;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: 'URL_MALFORMED' };
  }
  if (!EGRESS_ALLOW_SCHEMES.includes(url.protocol)) {
    return { ok: false, error: 'URL_SCHEME_DENIED', scheme: url.protocol };
  }
  if (url.username || url.password) {
    return { ok: false, error: 'URL_CREDENTIALS_DENIED' };
  }
  const rawHostname = url.hostname;
  if (!rawHostname) return { ok: false, error: 'URL_HOST_REQUIRED' };
  const hostname =
    rawHostname.startsWith('[') && rawHostname.endsWith(']')
      ? rawHostname.slice(1, -1)
      : rawHostname;
  const normalizedHostForMeta = hostname.toLowerCase().replace(/\.$/, '');
  if (CLOUD_METADATA_HOSTS.includes(normalizedHostForMeta)) {
    return { ok: false, error: 'URL_METADATA_DENIED' };
  }
  // Host policy lists: blocklist first, then allowlist. Evaluated on the
  // hostname before DNS so policy intent survives rebind tricks; addresses
  // are still validated below.
  if (matchHostList(hostname, blockedHosts)) {
    return { ok: false, error: 'URL_HOST_DENIED' };
  }
  if (
    Array.isArray(allowedHosts) &&
    allowedHosts.length > 0 &&
    !matchHostList(hostname, allowedHosts)
  ) {
    return { ok: false, error: 'URL_HOST_DENIED' };
  }
  const literal = net.isIPv6(hostname) ? hostname : normalizeHostnameIp(hostname);
  if (literal) {
    return validateResolvedAddresses([literal], {
      allowPrivateNetwork,
      allowLoopback,
      metadataIps
    });
  }
  if (typeof resolve !== 'function') {
    return { ok: false, error: 'URL_DNS_VALIDATION_REQUIRED' };
  }
  let addresses;
  try {
    addresses = await resolve(hostname);
  } catch {
    return { ok: false, error: 'URL_DNS_FAILED_CLOSED' };
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    return { ok: false, error: 'URL_DNS_FAILED_CLOSED' };
  }
  return validateResolvedAddresses(addresses, { allowPrivateNetwork, allowLoopback, metadataIps });
}

/**
 * @param {Array<unknown>} addresses
 * @param {{allowPrivateNetwork?: boolean, allowLoopback?: boolean, metadataIps?: ReadonlyArray<string>}} [options]
 */
export function validateResolvedAddresses(
  addresses,
  { allowPrivateNetwork = false, allowLoopback = false, metadataIps = CLOUD_METADATA_IPS } = {}
) {
  const normalized = [];
  for (const candidate of addresses) {
    const record = /** @type {{address?: unknown}} */ (candidate);
    const ip = typeof candidate === 'string' ? candidate : record?.address;
    const norm = normalizeHostnameIp(ip);
    normalized.push(norm || String(ip));
  }
  for (const ip of normalized) {
    const unwrapped = net.isIPv6(ip) ? unwrapV6(ip) : null;
    const checkIp = unwrapped?.kind === 'v4' ? unwrapped.ip : ip;
    if (metadataIps.includes(checkIp)) return { ok: false, error: 'URL_METADATA_DENIED', address: ip };
  }
  for (const ip of normalized) {
    const cls = classifyIp(ip);
    if (cls.kind === 'invalid') return { ok: false, error: 'URL_ADDRESS_INVALID', address: ip };
    if (cls.deny && !(allowLoopback === true && cls.reason === 'loopback'))
      return { ok: false, error: 'URL_ADDRESS_DENIED', reason: cls.reason, address: ip };
    if (cls.private && !allowPrivateNetwork) {
      return { ok: false, error: 'URL_PRIVATE_NETWORK_DENIED', reason: cls.reason, address: ip };
    }
  }
  return { ok: true, addresses: normalized };
}
