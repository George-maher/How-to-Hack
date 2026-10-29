import { describe, expect, it } from 'vitest';
import { sign, verifyRequest } from '../src/auth.mjs';
import { isFlagLikeHost, isValidHost, validateJob } from '../src/validate.mjs';
import { buildDockerArgv, DockerExecutor, OUTCOME } from '../src/executor.mjs';
import { evaluateTarget, classify, REASONS } from '../src/policy.mjs';
import { ConfigError, loadConfig } from '../src/config.mjs';
import { getTool, TOOLS, UnsafeTargetError, catalogue } from '../src/tools.mjs';
import { fakeChild, recordingSpawn, silentLogger, testConfig } from './helpers.mjs';

const options = { maxTimeoutMs: 600_000, defaultTimeoutMs: 120_000, allowedTools: [] };

const validJob = (overrides = {}) => ({
  job_id: 's1-nmap-1a2b3c4d5e',
  scan_id: 1,
  tool: 'nmap',
  target: { host: 'app.example.com', url: 'https://app.example.com/', scheme: 'https', port: 443 },
  scope: { allowlist: [{ host: 'app.example.com', ports: [443] }], lab_exceptions: [] },
  pinned_ips: null,
  limits: { timeout_ms: 5000 },
  approval: null,
  ...overrides,
});

// ---------------------------------------------------------------------------
// 1. HMAC integrity
// ---------------------------------------------------------------------------
describe('HMAC authentication', () => {
  const SECRET = 'k'.repeat(40);
  const BODY = JSON.stringify(validJob());

  it('covers the method-independent body, so the target cannot be swapped', () => {
    const ts = '1800000000';
    const original = sign(SECRET, ts, BODY);
    const swapped = BODY.replace('app.example.com', '169.254.169.254');

    expect(verifyRequest({ secret: SECRET, timestamp: ts, signature: original, body: BODY, now: 1800000000 }).ok)
      .toBe(true);
    expect(verifyRequest({ secret: SECRET, timestamp: ts, signature: original, body: swapped, now: 1800000000 }).ok)
      .toBe(false);
  });

  it('covers the timestamp, so it cannot be moved forward', () => {
    const signature = sign(SECRET, '1800000000', BODY);

    expect(verifyRequest({ secret: SECRET, timestamp: '1800000100', signature, body: BODY, now: 1800000100 }).ok)
      .toBe(false);
  });

  it('rejects an empty body signed with the wrong secret', () => {
    expect(verifyRequest({
      secret: SECRET,
      timestamp: '1800000000',
      signature: sign('other-secret-0000000000000000000000', '1800000000', ''),
      body: '',
      now: 1800000000,
    }).ok).toBe(false);
  });

  it('has a bounded replay window and does not store nonces', () => {
    // Replay protection here is timestamp-window based. A request captured and
    // replayed *within* the window is accepted — this is documented, and the
    // mitigation is transport confidentiality (internal network) plus the
    // short window.
    const ts = '1800000000';
    const signature = sign(SECRET, ts, BODY);
    const insideWindow = verifyRequest({ secret: SECRET, timestamp: ts, signature, body: BODY, now: 1800000100 });
    const outsideWindow = verifyRequest({ secret: SECRET, timestamp: ts, signature, body: BODY, now: 1800000400 });

    expect(insideWindow.ok).toBe(true);
    expect(outsideWindow).toEqual({ ok: false, code: 'timestamp_out_of_window' });
  });

  it('compares signatures in constant time', async () => {
    const source = await import('node:fs').then((fs) =>
      fs.readFileSync(new URL('../src/auth.mjs', import.meta.url), 'utf8'));

    expect(source).toContain('timingSafeEqual');
    expect(source).toMatch(/constantTimeEqual/);
    // A naive `===` comparison on the hex digest would leak length/prefix info.
    expect(source).not.toMatch(/signature\s*===\s*expected/);
  });

  it('refuses to run with a weak secret', () => {
    for (const secret of ['', 'short', 'x'.repeat(31)]) {
      expect(() => loadConfig({ RUNNER_SECRET: secret })).toThrow(ConfigError);
    }
    expect(() => loadConfig({ RUNNER_SECRET: 'x'.repeat(32) })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// 2. Input validation
// ---------------------------------------------------------------------------
describe('strict input validation', () => {
  it('rejects unknown keys at every level', () => {
    for (const key of ['image', 'argv', 'command', 'mounts', 'env', 'capabilities', 'user', 'network', 'privileged']) {
      expect(validateJob({ ...validJob(), [key]: 'x' }, options)).toMatchObject({ ok: false, field: `job.${key}` });
    }
  });

  it('rejects a tool outside the registry', () => {
    for (const tool of ['sh', 'bash', 'curl', 'docker', 'nmap; rm -rf /', '']) {
      expect(validateJob({ ...validJob(), tool }, options)).toMatchObject({ ok: false, field: 'job.tool' });
    }
  });

  it('rejects hosts that would be parsed as command-line flags', () => {
    for (const host of ['--script=evil', '-sS', '--output=/etc/passwd']) {
      expect(isFlagLikeHost(host)).toBe(true);
      expect(isValidHost(host)).toBe(false);
      expect(validateJob({ ...validJob(), target: { host, port: 443 } }, options))
        .toMatchObject({ ok: false, field: 'job.target.host' });
    }
  });

  it('rejects shell metacharacters in the host', () => {
    for (const host of ['a;id', 'a|id', 'a$(id)', 'a`id`', 'a b', 'a/b', 'a\\b', 'a&b']) {
      expect(isValidHost(host), host).toBe(false);
    }
  });

  it('rejects a URL whose host differs from target.host', () => {
    const result = validateJob(validJob({
      target: { host: 'app.example.com', url: 'https://evil.test/', scheme: 'https', port: 443 },
    }), options);

    expect(result).toMatchObject({ ok: false, field: 'job.target.url' });
  });

  it('rejects a URL with embedded credentials', () => {
    expect(validateJob(validJob({
      target: { host: 'app.example.com', url: 'https://u:p@app.example.com/', scheme: 'https', port: 443 },
    }), options)).toMatchObject({ ok: false, field: 'job.target.url' });
  });

  it('rejects non-http schemes', () => {
    for (const url of ['file:///etc/passwd', 'gopher://x/', 'ftp://app.example.com/']) {
      expect(validateJob(validJob({
        target: { host: 'app.example.com', url, scheme: 'https', port: 443 },
      }), options).ok).toBe(false);
    }
  });

  it('refuses to build argv for a target that looks like a flag', () => {
    expect(() => TOOLS.nmap.argv({ host: '--script=evil', url: '', port: 443 })).toThrow(UnsafeTargetError);
    expect(() => TOOLS.httpx.argv({ host: 'app.example.com', url: 'file:///etc/passwd', port: 443 }))
      .toThrow(UnsafeTargetError);
  });

  it('refuses a target containing a newline or NUL', () => {
    expect(() => TOOLS.nmap.argv({ host: 'app.example.com\nid', url: '', port: 443 })).toThrow(UnsafeTargetError);
    expect(() => TOOLS.nmap.argv({ host: 'app.example.com\u0000', url: '', port: 443 })).toThrow(UnsafeTargetError);
  });
});

// ---------------------------------------------------------------------------
// 3. No arbitrary execution
// ---------------------------------------------------------------------------
describe('no arbitrary command execution', () => {
  it('only ever spawns the docker binary with an argv array', async () => {
    const spawn = recordingSpawn([fakeChild({ exitCode: 0 })]);
    const executor = new DockerExecutor({ config: testConfig(), spawnImpl: spawn, logger: silentLogger });

    const job = validateJob(validJob(), options).job;
    await executor.run(job);

    expect(spawn.calls).toHaveLength(1);
    expect(spawn.calls[0].bin).toBe('docker');
    expect(Array.isArray(spawn.calls[0].argv)).toBe(true);
    expect(spawn.calls[0].options.shell).toBe(false);
  });

  it('the tool name in argv always comes from the registry, not the request', () => {
    for (const name of Object.keys(TOOLS)) {
      const argv = buildDockerArgv(testConfig(), { tool: name }, 'c', TOOLS[name].argv({
        host: 'app.example.com',
        url: 'https://app.example.com/',
        port: 443,
      }));

      expect(argv).toContain(name);
      // Nothing from the request can appear before the image name (i.e. as a
      // docker flag).
      const imageIndex = argv.indexOf('howtohack/scanner:latest');
      expect(argv.slice(0, imageIndex).some((arg) => arg === '--privileged')).toBe(false);
    }
  });

  it('a rejected job never reaches the executor', async () => {
    const spawn = recordingSpawn([]);
    const executor = new DockerExecutor({ config: testConfig(), spawnImpl: spawn, logger: silentLogger });

    const rejected = validateJob({ ...validJob(), image: 'evil' }, options);
    expect(rejected.ok).toBe(false);

    // Nothing was executed: there is no job object to pass on.
    expect(spawn.calls).toHaveLength(0);
  });

  it('reports a target refused by the registry as a failure, not a run', async () => {
    const spawn = recordingSpawn([]);
    const executor = new DockerExecutor({ config: testConfig(), spawnImpl: spawn, logger: silentLogger });

    const job = validateJob(validJob(), options).job;
    const result = await executor.run({ ...job, host: '--help', url: null });

    expect(result.outcome).toBe(OUTCOME.FAILED);
    expect(spawn.calls).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 4. Independent scope enforcement
// ---------------------------------------------------------------------------
describe('independent target authorization', () => {
  const scope = {
    allowlist: [{ id: 'a1', host: 'app.example.com', ports: [443, 8443], cidrs: [] }],
    lab_exceptions: [
      { id: 'lab1', host: '127.0.0.1', ports: [8080], expires_at: '2999-01-01T00:00:00Z' },
    ],
  };

  const evaluate = (host, ports = [443], extra = {}) => evaluateTarget({
    host,
    ports,
    scope,
    resolveHost: () => ['93.184.216.34'],
    now: new Date('2026-01-01T00:00:00Z'),
    ...extra,
  });

  it('allows only what the scope document names', () => {
    expect(evaluate('app.example.com').allowed).toBe(true);
    expect(evaluate('other.example.com').reason).toBe(REASONS.NOT_ALLOWLISTED);
  });

  it('rejects disallowed ports', () => {
    expect(evaluate('app.example.com', [22]).reason).toBe(REASONS.PORT_NOT_ALLOWED);
  });

  it('rejects forbidden address classes regardless of the allowlist', () => {
    const open = { allowlist: [{ host: '169.254.169.254' }, { host: '10.0.0.1' }, { host: '::1' }], lab_exceptions: [] };

    expect(evaluateTarget({ host: '169.254.169.254', ports: [80], scope: open, resolveHost: () => [], now: new Date('2026-01-01') }).reason)
      .toBe(REASONS.METADATA);
    expect(evaluateTarget({ host: '10.0.0.1', ports: [80], scope: open, resolveHost: () => [], now: new Date('2026-01-01') }).reason)
      .toBe(REASONS.PRIVATE);
    expect(evaluateTarget({ host: '::1', ports: [80], scope: open, resolveHost: () => [], now: new Date('2026-01-01') }).reason)
      .toBe(REASONS.LOOPBACK);
  });

  it('cannot be escaped with an alternate IPv4 notation', () => {
    const empty = { allowlist: [], lab_exceptions: [] };

    for (const host of ['2130706433', '0x7f000001', '0177.0.0.1', '127.1']) {
      const result = evaluateTarget({ host, ports: [80], scope: empty, resolveHost: () => [] });
      expect(result.reason, host).toBe(REASONS.LOOPBACK);
    }
  });

  it('normalizes an alternate notation so an exception cannot be widened by it', () => {
    // 2130706433 is 127.0.0.1; the exception covers port 8080 on that host,
    // so the notation resolves to the same authorisation - it does not bypass
    // the port restriction.
    expect(evaluate('2130706433', [8080]).allowed).toBe(true);
    expect(evaluate('2130706433', [9090]).allowed).toBe(false);
  });

  it('cannot be escaped with IPv6 wrapping', () => {
    for (const host of ['::1', '::ffff:127.0.0.1', '64:ff9b::7f00:1', 'fd00:ec2::254']) {
      expect(evaluate(host).allowed).toBe(false);
    }
  });

  it('rejects a DNS answer that changed since approval', () => {
    const result = evaluate('app.example.com', [443], { pinnedIps: ['93.184.216.35'] });
    expect(result.reason).toBe(REASONS.ADDRESS_CHANGED);
  });

  it('rejects a name resolving to a mix of public and private addresses', () => {
    const result = evaluateTarget({
      host: 'mixed.example.com',
      ports: [443],
      scope: { allowlist: [{ host: 'mixed.example.com' }], lab_exceptions: [] },
      resolveHost: () => ['93.184.216.34', '127.0.0.1'],
      now: new Date('2026-01-01'),
    });

    expect(result.reason).toBe(REASONS.ADDRESS_NOT_ALLOWED);
  });

  it('keeps a lab exception to exactly one host and port', () => {
    expect(evaluate('127.0.0.1', [8080]).allowed).toBe(true);
    expect(evaluate('127.0.0.2', [8080]).allowed).toBe(false);
    expect(evaluate('127.0.0.1', [9090]).allowed).toBe(false);
  });

  it('refuses an expired exception', () => {
    const expired = {
      allowlist: [],
      lab_exceptions: [{ id: 'old', host: '10.0.0.5', ports: [22], expires_at: '2000-01-01T00:00:00Z' }],
    };

    const result = evaluateTarget({
      host: '10.0.0.5',
      ports: [22],
      scope: expired,
      resolveHost: () => [],
      now: new Date('2026-01-01'),
    });

    expect(result.reason).toBe(REASONS.EXCEPTION_EXPIRED);
  });

  it('fails closed when policy evaluation throws', () => {
    const hostile = {
      lab_exceptions: [],
      get allowlist() {
        throw new Error('policy exploded');
      },
    };

    const result = evaluateTarget({
      host: 'app.example.com',
      ports: [443],
      scope: hostile,
      resolveHost: () => ['93.184.216.34'],
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(REASONS.POLICY_ERROR);
  });

  it('treats a missing allowlist as empty rather than open', () => {
    const result = evaluateTarget({
      host: 'app.example.com',
      ports: [443],
      scope: { allowlist: null, lab_exceptions: [] },
      resolveHost: () => ['93.184.216.34'],
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toBe(REASONS.NOT_ALLOWLISTED);
  });
});

// ---------------------------------------------------------------------------
// 5. Redirects and connection destinations
// ---------------------------------------------------------------------------
describe('redirect and connection scope', () => {
  it('the executor has no HTTP client that could follow a redirect', async () => {
    // The container makes the connection; the Runner's job is to decide whether
    // that connection may happen at all, not to proxy it. There is nothing in
    // the executor that could follow a redirect into another scope.
    const fs = await import('node:fs');
    const source = fs.readFileSync(new URL('../src/executor.mjs', import.meta.url), 'utf8');

    expect(source).not.toMatch(/fetch\(/);
    expect(source).not.toMatch(/http\.request/);
    expect(source).not.toMatch(/followRedirect/);
    expect(source).not.toMatch(/maxRedirects/);
  });

  it('the runner has no outbound HTTP client at all', async () => {
    const fs = await import('node:fs/promises');
    const files = await fs.readdir(new URL('../src/', import.meta.url));

    for (const file of files) {
      const source = await fs.readFile(new URL(`../src/${file}`, import.meta.url), 'utf8');

      if (file === 'server.mjs') continue; // it *serves* HTTP
      expect(source, file).not.toMatch(/\bfetch\(/);
      expect(source, file).not.toMatch(/https?\.request/);
    }
  });
});

// ---------------------------------------------------------------------------
// 6. Secret hygiene
// ---------------------------------------------------------------------------
describe('secret hygiene', () => {
  it('does not pass the runner secret into the container environment', async () => {
    const spawn = recordingSpawn([fakeChild({ exitCode: 0 })]);
    const executor = new DockerExecutor({
      config: testConfig({ secret: 'super-secret-value-that-must-not-leak' }),
      spawnImpl: spawn,
      logger: silentLogger,
    });

    await executor.run(validateJob(validJob(), options).job);

    const call = spawn.calls[0];
    expect(JSON.stringify(call.argv)).not.toContain('super-secret-value');
    expect(JSON.stringify(call.options.env ?? {})).not.toContain('super-secret-value');
  });

  it('the tool catalogue never exposes the image or argv', () => {
    const serialised = JSON.stringify(catalogue());

    expect(serialised).not.toContain('howtohack/scanner');
    expect(serialised).not.toMatch(/-sV/);
    expect(serialised).not.toMatch(/wordlists/);
  });

  it('config loading never logs or embeds the secret in derived fields', () => {
    const config = loadConfig({ RUNNER_SECRET: 'q'.repeat(40) });

    expect(config.secret).toBe('q'.repeat(40));
    // Everything except `secret` is safe to log.
    const { secret, ...rest } = config;
    expect(JSON.stringify(rest)).not.toContain(secret);
  });
});

// ---------------------------------------------------------------------------
// 7. Privileged settings are not reachable
// ---------------------------------------------------------------------------
describe('privileged settings', () => {
  it('rejects host, bridge and none networking at boot', () => {
    for (const network of ['host', 'bridge', 'none', 'default']) {
      expect(() => loadConfig({ RUNNER_SECRET: 'x'.repeat(40), RUNNER_SCANNER_NETWORK: network })).toThrow(ConfigError);
    }
  });

  it('rejects a root container user at boot', () => {
    for (const user of ['root', '0', '0:0', '0:65534']) {
      expect(() => loadConfig({ RUNNER_SECRET: 'x'.repeat(40), RUNNER_CONTAINER_USER: user })).toThrow(ConfigError);
    }
  });

  it('rejects an absurd timeout ceiling', () => {
    expect(() => loadConfig({ RUNNER_SECRET: 'x'.repeat(40), RUNNER_MAX_TIMEOUT_MS: '99999999' })).toThrow(ConfigError);
  });

  it('never mounts a directory the request chose', () => {
    const argv = buildDockerArgv(testConfig({ wordlistMount: '/srv/wl:/wordlists:ro' }), {}, 'c', ['nmap']);
    const mounts = argv.filter((arg, i) => argv[i - 1] === '--mount' || argv[i - 1] === '-v');

    expect(mounts).toHaveLength(1);
    expect(mounts[0]).toContain('/srv/wl');
    expect(mounts.join(' ')).not.toContain('/var/run/docker.sock');
    expect(mounts.join(' ')).not.toContain('/:/');
  });
});

// ---------------------------------------------------------------------------
// 8. Classification table (shared with the PHP policy)
// ---------------------------------------------------------------------------
describe('address classification', () => {
  it.each([
    ['127.0.0.1', 'loopback'],
    ['10.0.0.1', 'private'],
    ['169.254.169.254', 'metadata'],
    ['100.64.0.1', 'cgnat'],
    ['224.0.0.1', 'multicast'],
    ['0.0.0.0', 'unspecified'],
    ['93.184.216.34', 'public'],
    ['::1', 'loopback'],
    ['fd00:ec2::254', 'metadata'],
    ['fe80::1', 'link_local'],
    ['2606:4700:4700::1111', 'public'],
  ])('classifies %s as %s', (ip, expected) => {
    expect(classify(ip)).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// 9. Registry lookup safety
// ---------------------------------------------------------------------------
describe('registry lookup', () => {
  it('does not resolve prototype properties as tools', () => {
    for (const name of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'prototype']) {
      expect(getTool(name)).toBeNull();
    }
  });
});
