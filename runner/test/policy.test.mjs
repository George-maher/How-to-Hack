import { describe, expect, it } from 'vitest';
import {
  classify,
  evaluateTarget,
  normalizeHost,
  parseLegacyIpv4,
  REASONS,
} from '../src/policy.mjs';

const DNS = {
  'app.example.com': ['93.184.216.34'],
  'example.org': ['93.184.216.34'],
  'cdn.example.com': ['93.184.216.70'],
  'split.example.com': ['93.184.216.34', '127.0.0.1'],
  'private.example.com': ['10.1.2.3'],
  'rebind.example.com': ['93.184.216.50'],
  'many.example.com': ['93.184.216.1', '93.184.216.2', '93.184.216.3', '93.184.216.4', '93.184.216.5', '93.184.216.6', '93.184.216.7', '93.184.216.8', '93.184.216.9'],
  'unlisted.example.com': ['93.184.216.99'],
  'expired.local': ['10.0.0.7'],
  'wild.example.com': ['93.184.216.60'],
  'sub.wild.example.com': ['93.184.216.61'],
  'example.com': ['93.184.216.34'],
  'sub.app.example.com': ['93.184.216.35'],
};

const resolveHost = (host) => DNS[host] ?? [];

const SCOPE = {
  allowlist: [
    { id: 'a1', host: 'app.example.com', ports: [443], cidrs: [] },
    { id: 'a2', host: 'example.org', ports: [], cidrs: [] },
    { id: 'a3', host: 'cdn.example.com', ports: [], cidrs: ['93.184.216.0/24'] },
    { id: 'a4', host: 'wild.example.com', include_subdomains: true, ports: [], cidrs: [] },
    { id: 'a6', host: 'rebind.example.com', ports: [], cidrs: [] },
    { id: 'a5', host: '93.184.216.34', ports: [], cidrs: [] },
  ],
  lab_exceptions: [
    { id: 'lab1', host: '127.0.0.1', ports: [8080], expires_at: '2999-01-01T00:00:00Z', scope: 'lab_exception' },
    { id: 'lab2', host: 'expired.local', ports: [443], expires_at: '2000-01-01T00:00:00Z', scope: 'lab_exception' },
  ],
};

const evaluate = (host, extra = {}) =>
  evaluateTarget({
    host,
    ports: [443],
    scope: SCOPE,
    resolveHost,
    now: new Date('2026-01-01T00:00:00Z'),
    ...extra,
  });

describe('host normalization', () => {
  it('canonicalizes alternate IPv4 notations', () => {
    expect(parseLegacyIpv4('2130706433')).toBe('127.0.0.1');
    expect(parseLegacyIpv4('0x7f000001')).toBe('127.0.0.1');
    expect(parseLegacyIpv4('0177.0.0.1')).toBe('127.0.0.1');
    expect(parseLegacyIpv4('127.1')).toBe('127.0.0.1');
    expect(parseLegacyIpv4('0x7f.1')).toBe('127.0.0.1');
  });

  it('does not turn a domain into an address', () => {
    expect(parseLegacyIpv4('example.com')).toBeNull();
    expect(normalizeHost('example.com')).toBe('example.com');
  });

  it('strips brackets, trailing dots and zone ids', () => {
    expect(normalizeHost('[::1]')).toBe('::1');
    expect(normalizeHost('example.com.')).toBe('example.com');
    expect(normalizeHost('fe80::1%25eth0')).toBe('fe80::1');
  });

  it('rejects non-ASCII and malformed hosts', () => {
    expect(normalizeHost('exämple.com')).toBeNull();
    expect(normalizeHost('app example.com')).toBeNull();
    expect(normalizeHost('')).toBeNull();
  });
});

describe('address classification', () => {
  it.each([
    ['127.0.0.1', 'loopback'],
    ['10.1.2.3', 'private'],
    ['172.16.0.1', 'private'],
    ['172.31.255.255', 'private'],
    ['192.168.1.1', 'private'],
    ['172.32.0.1', 'public'],
    ['169.254.1.1', 'link_local'],
    ['169.254.169.254', 'metadata'],
    ['100.64.0.1', 'cgnat'],
    ['224.0.0.1', 'multicast'],
    ['0.0.0.0', 'unspecified'],
    ['192.0.2.1', 'reserved'],
    ['93.184.216.34', 'public'],
  ])('classifies %s as %s', (ip, expected) => {
    expect(classify(ip)).toBe(expected);
  });

  it.each([
    ['::1', 'loopback'],
    ['fe80::1', 'link_local'],
    ['fc00::1', 'private'],
    ['fd00:ec2::254', 'metadata'],
    ['::', 'unspecified'],
    ['2001:db8::1', 'reserved'],
    ['2606:4700:4700::1111', 'public'],
  ])('classifies IPv6 %s as %s', (ip, expected) => {
    expect(classify(ip)).toBe(expected);
  });

  it('looks through IPv4-mapped and NAT64 wrappers', () => {
    expect(classify('::ffff:127.0.0.1')).toBe('loopback');
    expect(classify('::ffff:7f00:1')).toBe('loopback');
    expect(classify('::ffff:169.254.169.254')).toBe('metadata');
    expect(classify('64:ff9b::7f00:1')).toBe('loopback');
  });
});

describe('allowlist decisions', () => {
  it('allows an allowlisted host', () => {
    const decision = evaluate('app.example.com');

    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe(REASONS.ALLOWED);
    expect(decision.resolvedIps).toEqual(['93.184.216.34']);
  });

  it('refuses an unlisted public host', () => {
    expect(evaluate('unlisted.example.com').reason).toBe(REASONS.NOT_ALLOWLISTED);
  });

  it('refuses a port the rule does not cover', () => {
    expect(evaluate('app.example.com', { ports: [8443] }).reason).toBe(REASONS.PORT_NOT_ALLOWED);
  });

  it('honours subdomain scope', () => {
    expect(evaluate('sub.wild.example.com').allowed).toBe(true);
    expect(evaluate('other.example.com').allowed).toBe(false);
  });

  it('refuses a host that resolves outside its approved CIDR', () => {
    const narrow = {
      ...SCOPE,
      allowlist: [{ id: 'x', host: 'cdn.example.com', ports: [], cidrs: ['198.18.0.0/15'] }],
    };

    expect(evaluate('cdn.example.com', { scope: narrow }).reason).toBe(REASONS.ADDRESS_NOT_ALLOWED);
  });
});

describe('non-public targets', () => {
  it('refuses loopback without an exception', () => {
    const scope = { allowlist: [], lab_exceptions: [] };

    expect(evaluate('127.0.0.1', { ports: [80], scope }).reason).toBe(REASONS.LOOPBACK);
  });

  it('refuses private space', () => {
    expect(evaluate('10.0.0.1').reason).toBe(REASONS.PRIVATE);
    expect(evaluate('192.168.0.1').reason).toBe(REASONS.PRIVATE);
  });

  it('refuses link-local and metadata addresses', () => {
    expect(evaluate('169.254.1.1').reason).toBe(REASONS.LINK_LOCAL);
    expect(evaluate('169.254.169.254').reason).toBe(REASONS.METADATA);
  });

  it('refuses metadata even when an exception names it', () => {
    const scope = {
      ...SCOPE,
      lab_exceptions: [{ id: 'bad', host: '169.254.169.254', ports: [80], expires_at: '2999-01-01T00:00:00Z' }],
    };

    expect(evaluate('169.254.169.254', { ports: [80], scope }).reason).toBe(REASONS.METADATA);
  });

  it('refuses alternate loopback notations', () => {
    for (const host of ['2130706433', '0x7f000001', '0177.0.0.1', '127.1']) {
      const scope = { allowlist: [], lab_exceptions: [] };
      expect(evaluate(host, { ports: [80], scope }).reason).toBe(REASONS.LOOPBACK);
    }
  });

  it('refuses an IPv6 loopback and mapped loopback', () => {
    const scope = { allowlist: [], lab_exceptions: [] };
    expect(evaluate('::1', { scope }).reason).toBe(REASONS.LOOPBACK);
    expect(evaluate('::ffff:127.0.0.1', { scope }).reason).toBe(REASONS.LOOPBACK);
    expect(evaluate('fd00:ec2::254', { scope }).reason).toBe(REASONS.METADATA);
  });

  it('refuses a name that resolves to a private address', () => {
    expect(evaluate('private.example.com', { scope: { allowlist: [], lab_exceptions: [] } }).reason)
      .toBe(REASONS.PRIVATE);
  });
});

describe('lab exceptions', () => {
  it('allows exactly the host and port in the exception', () => {
    const decision = evaluate('127.0.0.1', { ports: [8080] });

    expect(decision.allowed).toBe(true);
    expect(decision.reason).toBe(REASONS.ALLOWED_BY_EXCEPTION);
  });

  it('does not widen to other ports', () => {
    expect(evaluate('127.0.0.1', { ports: [9090] }).reason).toBe(REASONS.PORT_NOT_ALLOWED);
  });

  it('does not widen to sibling addresses', () => {
    expect(evaluate('127.0.0.2', { ports: [8080] }).reason).toBe(REASONS.LOOPBACK);
  });

  it('refuses an expired exception', () => {
    expect(evaluate('expired.local', { ports: [443] }).reason).toBe(REASONS.EXCEPTION_EXPIRED);
  });
});

describe('DNS behaviour', () => {
  it('refuses an unresolvable name', () => {
    expect(evaluate('nothing.example.com').reason).toBe(REASONS.UNRESOLVED);
  });

  it('refuses a split public/private answer', () => {
    expect(evaluate('split.example.com').reason).toBe(REASONS.ADDRESS_NOT_ALLOWED);
  });

  it('refuses a name that changed since approval', () => {
    expect(evaluate('rebind.example.com', { pinnedIps: ['93.184.216.51'] }).reason).toBe(REASONS.ADDRESS_CHANGED);
  });

  it('accepts an unchanged address', () => {
    expect(evaluate('rebind.example.com', { pinnedIps: ['93.184.216.50'] }).allowed).toBe(true);
  });

  it('refuses a name with too many addresses', () => {
    expect(evaluate('many.example.com').reason).toBe(REASONS.TOO_MANY_ADDRESSES);
  });
});

describe('failure handling', () => {
  it('fails closed when policy evaluation throws', () => {
    const result = evaluateTarget({
      host: 'app.example.com',
      ports: [443],
      scope: { allowlist: null, lab_exceptions: [] },
      resolveHost: () => {
        throw new Error('resolver exploded');
      },
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(REASONS.POLICY_ERROR);
  });

  it('refuses an invalid host', () => {
    expect(evaluate('bad host!').reason).toBe(REASONS.INVALID_HOST);
  });

  it('refuses an empty scope', () => {
    expect(evaluate('app.example.com', { scope: { allowlist: [], lab_exceptions: [] } }).reason)
      .toBe(REASONS.NOT_ALLOWLISTED);
  });
});
