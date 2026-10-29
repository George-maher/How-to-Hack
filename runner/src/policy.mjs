/**
 * Scope revalidation, independent of the API.
 *
 * The API already refused the target once. This runs again, inside the Runner,
 * immediately before a container is started — because the API's answer may be
 * minutes old, and because a compromised or buggy API process must not be able
 * to make this one start a container against a private address.
 *
 * The rules mirror backend/app/Security/Target/TargetPolicy.php.
 * test/policy.test.mjs and backend/tests/Standalone/target_policy_test.php
 * assert the same cases, so the two implementations cannot drift silently.
 */

import { isIP } from 'node:net';

export const REASONS = Object.freeze({
  ALLOWED: 'allowed',
  ALLOWED_BY_EXCEPTION: 'allowed_by_lab_exception',
  INVALID_HOST: 'invalid_host',
  UNRESOLVED: 'unresolved',
  TOO_MANY_ADDRESSES: 'too_many_addresses',
  LOOPBACK: 'loopback',
  PRIVATE: 'private_address',
  LINK_LOCAL: 'link_local',
  METADATA: 'cloud_metadata',
  CGNAT: 'carrier_grade_nat',
  MULTICAST: 'multicast',
  RESERVED: 'reserved',
  UNSPECIFIED: 'unspecified',
  NOT_ALLOWLISTED: 'not_allowlisted',
  PORT_NOT_ALLOWED: 'port_not_allowed',
  ADDRESS_NOT_ALLOWED: 'address_not_allowed',
  EXCEPTION_EXPIRED: 'lab_exception_expired',
  ADDRESS_CHANGED: 'address_changed',
  POLICY_ERROR: 'policy_error',
});

/** Endpoints that hand out cloud credentials. Never permittable. */
const METADATA_ADDRESSES = new Set([
  '169.254.169.254',
  '169.254.170.2',
  '169.254.169.253',
  'fd00:ec2::254',
  'fe80::a9fe:a9fe',
]);

const IPV4_BLOCKS = [
  ['0.0.0.0', 8, 'unspecified'],
  ['10.0.0.0', 8, 'private'],
  ['100.64.0.0', 10, 'cgnat'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link_local'],
  ['172.16.0.0', 12, 'private'],
  ['192.0.0.0', 24, 'reserved'],
  ['192.0.2.0', 24, 'reserved'],
  ['192.168.0.0', 16, 'private'],
  ['198.18.0.0', 15, 'reserved'],
  ['198.51.100.0', 24, 'reserved'],
  ['203.0.113.0', 24, 'reserved'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
];

const IPV6_BLOCKS = [
  ['::', 128, 'unspecified'],
  ['::1', 128, 'loopback'],
  ['100::', 64, 'reserved'],
  ['2001::', 32, 'reserved'],
  ['2001:db8::', 32, 'reserved'],
  ['2002::', 16, 'reserved'],
  ['fc00::', 7, 'private'],
  ['fe80::', 10, 'link_local'],
  ['ff00::', 8, 'multicast'],
  ['64:ff9b:1::', 48, 'reserved'],
];

const CLASS_REASON = {
  loopback: REASONS.LOOPBACK,
  private: REASONS.PRIVATE,
  link_local: REASONS.LINK_LOCAL,
  cgnat: REASONS.CGNAT,
  multicast: REASONS.MULTICAST,
  reserved: REASONS.RESERVED,
  unspecified: REASONS.UNSPECIFIED,
};

const NEVER_PERMITTABLE = new Set(['multicast', 'unspecified', 'metadata']);

/** @param {string} ip */
export function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;

  let value = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    value = value * 256 + n;
  }
  return value;
}

/** @param {string} ip */
export function ipv6ToBigInt(ip) {
  let address = ip;
  const zoneIndex = address.indexOf('%');
  if (zoneIndex !== -1) address = address.slice(0, zoneIndex);

  // Embedded IPv4 tail: ::ffff:127.0.0.1
  let v4Tail = null;
  const lastColon = address.lastIndexOf(':');
  const tail = address.slice(lastColon + 1);
  if (tail.includes('.')) {
    v4Tail = ipv4ToInt(tail);
    if (v4Tail === null) return null;
    address = `${address.slice(0, lastColon + 1)}0:0`;
  }

  const halves = address.split('::');
  if (halves.length > 2) return null;

  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];

  const missing = 8 - (head.length + rest.length);
  if (missing < 0) return null;

  const groups = [...head, ...Array(missing).fill('0'), ...rest];
  if (groups.length !== 8) return null;

  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    value = (value << 16n) | BigInt(Number.parseInt(group, 16));
  }

  if (v4Tail !== null) {
    value = (value & ~0xffffffffn) | BigInt(v4Tail >>> 0);
  }

  return value;
}

/** @param {bigint|number} value @param {number} prefix @param {bigint|number} network @param {number} width */
function inRange(value, prefix, network, width) {
  const shift = BigInt(width - prefix);
  return BigInt(value) >> shift === BigInt(network) >> shift;
}

/**
 * Parse the inet_aton shorthand forms (`2130706433`, `0x7f000001`, `0177.0.0.1`,
 * `127.1`) into a dotted quad. Returns null when the input is not one of them.
 *
 * @param {string} host
 */
export function parseLegacyIpv4(host) {
  if (!/^[0-9a-fx.]+$/i.test(host)) return null;

  const parts = host.split('.');
  if (parts.length > 4 || parts.some((p) => p === '')) return null;

  const numbers = [];
  for (const part of parts) {
    let value;
    if (/^0x[0-9a-f]+$/i.test(part)) value = Number.parseInt(part.slice(2), 16);
    else if (/^0[0-7]+$/.test(part)) value = Number.parseInt(part.slice(1), 8);
    else if (/^[0-9]+$/.test(part)) value = Number(part);
    else return null;

    if (!Number.isSafeInteger(value)) return null;
    numbers.push(value);
  }

  const last = numbers.pop();
  const maxLast = 2 ** (32 - 8 * numbers.length);
  if (last >= maxLast) return null;
  if (numbers.some((n) => n > 255)) return null;

  let value = last;
  numbers.forEach((n, index) => {
    value += n * 2 ** (32 - 8 * (index + 1));
  });

  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join('.');
}

/**
 * Canonical host: IP literal where possible, otherwise a lowercased name.
 *
 * @param {string} rawHost
 * @returns {string | null}
 */
export function normalizeHost(rawHost) {
  let host = String(rawHost ?? '').trim().toLowerCase();

  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  host = host.replace(/\.$/, '');

  if (host === '') return null;

  const zoneIndex = host.indexOf('%25');
  if (zoneIndex !== -1) host = host.slice(0, zoneIndex);

  if (isIP(host) !== 0) return host.toLowerCase();

  const legacy = parseLegacyIpv4(host);
  if (legacy !== null) return legacy;

  if (/[^\x20-\x7e]/.test(host)) return null;

  const label = '[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?';
  if (!new RegExp(`^${label}(?:\\.${label})*$`).test(host)) return null;

  return host;
}

/**
 * @param {string} ip canonical literal
 * @returns {string} class name
 */
export function classify(ip) {
  const version = isIP(ip);

  if (version === 4) {
    if (METADATA_ADDRESSES.has(ip)) return 'metadata';

    const value = ipv4ToInt(ip);
    if (value === null) return 'reserved';

    for (const [network, prefix, cls] of IPV4_BLOCKS) {
      if (inRange(value, prefix, ipv4ToInt(network), 32)) return cls;
    }

    return 'public';
  }

  if (version === 6) {
    if (METADATA_ADDRESSES.has(ip)) return 'metadata';

    const value = ipv6ToBigInt(ip);
    if (value === null) return 'reserved';

    // IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::/96) embed an IPv4
    // address; classify that instead of the wrapper.
    // ::ffff:0:0/96 -> the top 96 bits are zero except the 0xffff marker, so
    // shifting past the embedded IPv4 leaves exactly 0xffff.
    if (value >> 32n === 0xffffn) {
      return classify(bigIntToIpv4(value & 0xffffffffn));
    }

    const nat64 = ipv6ToBigInt('64:ff9b::');
    if (inRange(value, 96, nat64, 128)) {
      return classify(bigIntToIpv4(value & 0xffffffffn));
    }

    for (const [network, prefix, cls] of IPV6_BLOCKS) {
      if (inRange(value, prefix, ipv6ToBigInt(network), 128)) return cls;
    }

    return 'public';
  }

  return 'reserved';
}

/** @param {bigint} value */
function bigIntToIpv4(value) {
  const n = Number(value);
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.');
}

function coversCidr(ip, cidr) {
  const [network, bitsRaw] = String(cidr).split('/');
  const bits = Number(bitsRaw);

  if (isIP(ip) === 4 && isIP(network) === 4) {
    return inRange(ipv4ToInt(ip), bits, ipv4ToInt(network), 32);
  }

  if (isIP(ip) === 6 && isIP(network) === 6) {
    return inRange(ipv6ToBigInt(ip), bits, ipv6ToBigInt(network), 128);
  }

  return false;
}

function ruleMatchesHost(rule, host) {
  if (rule.host === host) return true;
  if (!rule.include_subdomains) return false;
  if (isIP(host) !== 0) return false;
  return host.endsWith(`.${rule.host}`);
}

function ruleAllowsPorts(rule, ports) {
  const allowed = Array.isArray(rule.ports) ? rule.ports : [];
  if (allowed.length === 0) return !rule.scope || rule.scope === 'allowlist';
  return ports.every((port) => allowed.includes(port));
}

function ruleCoversAddress(rule, ip) {
  const cidrs = Array.isArray(rule.cidrs) ? rule.cidrs : [];
  if (cidrs.length === 0) return true;
  return cidrs.some((cidr) => coversCidr(ip, cidr));
}

function ruleExpired(rule, now) {
  if (!rule.expires_at) return false;
  const expiry = Date.parse(rule.expires_at);
  if (Number.isNaN(expiry)) return true;
  return expiry <= now.getTime();
}

/**
 * @param {object} input
 * @param {string} input.host          host from the job (already normalized by the API)
 * @param {number[]} input.ports
 * @param {object} input.scope         { allowlist: [], lab_exceptions: [] }
 * @param {string[]} [input.pinnedIps] addresses recorded at approval time
 * @param {(host: string) => string[]} input.resolveHost
 * @param {Date} [input.now]
 */
export function evaluateTarget({ host, ports, scope, pinnedIps, resolveHost, now = new Date() }) {
  try {
    const normalized = normalizeHost(host);
    if (normalized === null) {
      return deny(REASONS.INVALID_HOST, String(host ?? ''), [], ports);
    }

    const requested = (Array.isArray(ports) && ports.length > 0 ? ports : [443])
      .map((port) => Number(port))
      .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);

    if (requested.length === 0) {
      return deny(REASONS.PORT_NOT_ALLOWED, normalized, [], []);
    }

    let addresses;
    if (isIP(normalized) !== 0) {
      addresses = [normalized];
    } else {
      addresses = Array.from(new Set((resolveHost(normalized) ?? []).filter((ip) => isIP(ip) !== 0)));
    }

    if (addresses.length === 0) return deny(REASONS.UNRESOLVED, normalized, [], requested);
    if (addresses.length > 8) return deny(REASONS.TOO_MANY_ADDRESSES, normalized, addresses, requested);

    // DNS pinning: the addresses must still be the ones that were authorised.
    if (Array.isArray(pinnedIps) && pinnedIps.length > 0) {
      const missing = pinnedIps.filter((ip) => !addresses.includes(ip));
      if (missing.length > 0) {
        return deny(REASONS.ADDRESS_CHANGED, normalized, addresses, requested);
      }
    }

    const classes = new Map(addresses.map((ip) => [ip, classify(ip)]));

    for (const [ip, cls] of classes) {
      if (cls === 'metadata') return deny(REASONS.METADATA, normalized, addresses, requested);
      if (NEVER_PERMITTABLE.has(cls)) return deny(CLASS_REASON[cls], normalized, addresses, requested);
    }

    const nonPublic = addresses.filter((ip) => classes.get(ip) !== 'public');

    if (nonPublic.length > 0) {
      if (nonPublic.length !== addresses.length) {
        // Split answer: one public, one private. Refuse the whole name.
        return deny(REASONS.ADDRESS_NOT_ALLOWED, normalized, addresses, requested);
      }

      const exceptions = (scope?.lab_exceptions ?? []).filter((rule) => ruleMatchesHost(rule, normalized));

      let expired = false;
      let portMismatch = false;

      for (const rule of exceptions) {
        if (ruleExpired(rule, now)) {
          expired = true;
          continue;
        }

        if (!ruleAllowsPorts(rule, requested)) {
          portMismatch = true;
          continue;
        }

        if (!addresses.every((ip) => ruleCoversAddress(rule, ip))) continue;

        return allow(normalized, addresses, requested, REASONS.ALLOWED_BY_EXCEPTION, rule.id ?? 'lab_exception');
      }

      if (expired) return deny(REASONS.EXCEPTION_EXPIRED, normalized, addresses, requested);
      if (portMismatch) return deny(REASONS.PORT_NOT_ALLOWED, normalized, addresses, requested);

      return deny(CLASS_REASON[classes.get(nonPublic[0])] ?? REASONS.PRIVATE, normalized, addresses, requested);
    }

    const rules = (scope?.allowlist ?? []).filter((rule) => ruleMatchesHost(rule, normalized));

    let portBlocked = false;
    let addressBlocked = false;

    for (const rule of rules) {
      if (!ruleAllowsPorts(rule, requested)) {
        portBlocked = true;
        continue;
      }

      if (!addresses.every((ip) => ruleCoversAddress(rule, ip))) {
        addressBlocked = true;
        continue;
      }

      return allow(normalized, addresses, requested, REASONS.ALLOWED, rule.id ?? 'allowlist');
    }

    if (portBlocked) return deny(REASONS.PORT_NOT_ALLOWED, normalized, addresses, requested);
    if (addressBlocked) return deny(REASONS.ADDRESS_NOT_ALLOWED, normalized, addresses, requested);

    return deny(REASONS.NOT_ALLOWLISTED, normalized, addresses, requested);
  } catch (error) {
    // Fail closed, always.
    return deny(REASONS.POLICY_ERROR, String(host ?? ''), [], ports ?? [], String(error?.message ?? error));
  }
}

function allow(host, resolvedIps, ports, reason, rule) {
  return { allowed: true, reason, host, resolvedIps, ports, matchedRule: rule ?? null };
}

function deny(reason, host, resolvedIps, ports, detail) {
  return {
    allowed: false,
    reason,
    host,
    resolvedIps: resolvedIps ?? [],
    ports: ports ?? [],
    matchedRule: null,
    detail: detail ?? null,
  };
}
