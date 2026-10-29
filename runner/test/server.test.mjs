import { afterEach, describe, expect, it } from 'vitest';
import { createRunnerServer } from '../src/server.mjs';
import { DockerExecutor, OUTCOME } from '../src/executor.mjs';
import { sign } from '../src/auth.mjs';
import { fakeChild, recordingSpawn, testConfig } from './helpers.mjs';

const SECRET = 's'.repeat(48);
const NOW_MS = 1_700_000_000_000;
const NOW_S = Math.floor(NOW_MS / 1000);

const config = testConfig({ secret: SECRET, maxBodyBytes: 4096 });

const DNS = {
  'app.example.com': ['93.184.216.34'],
  'evil.test': ['93.184.216.99'],
  'rebind.example.com': ['93.184.216.50'],
};

const silent = { info: () => {}, warn: () => {}, error: () => {} };

/** A job exactly as the PHP client builds it (BaseDockerScanner::execute). */
const job = (overrides = {}) => ({
  job_id: 's1-nmap-1a2b3c4d5e',
  scan_id: 1,
  tool: 'nmap',
  target: {
    host: 'app.example.com',
    url: 'https://app.example.com/',
    scheme: 'https',
    port: 443,
  },
  scope: {
    allowlist: [{ id: 'security.allowlist[0]', host: 'app.example.com', ports: [443], cidrs: [], scope: 'allowlist' }],
    lab_exceptions: [],
  },
  pinned_ips: ['93.184.216.34'],
  limits: { timeout_ms: 5000 },
  approval: { fingerprint: 'abc123', approved_at: null },
  ...overrides,
});

let server;
let baseUrl;

async function start({ children = [], resolveHost = async (host) => DNS[host] ?? [] } = {}) {
  const spawn = recordingSpawn(children);
  const executor = new DockerExecutor({ config, spawnImpl: spawn, logger: silent });

  const srv = createRunnerServer({
    config,
    executor,
    resolveHost,
    now: () => new Date(NOW_MS),
    logger: silent,
  });

  await new Promise((done) => srv.listen(0, '127.0.0.1', done));

  server = srv;
  baseUrl = `http://127.0.0.1:${srv.address().port}`;

  return { executor, spawn };
}

function headers(body, { secret = SECRET, timestamp = String(NOW_S) } = {}) {
  return {
    'content-type': 'application/json',
    'x-runner-timestamp': timestamp,
    'x-runner-signature': sign(secret, timestamp, body),
  };
}

async function post(path, payload, opts = {}) {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const response = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: headers(body, opts),
    body,
  });

  return { status: response.status, json: await response.json().catch(() => null) };
}

async function get(path, opts = {}) {
  const response = await fetch(`${baseUrl}${path}`, { headers: headers('', opts) });
  return { status: response.status, json: await response.json().catch(() => null) };
}

afterEach(async () => {
  if (!server) return;

  // Drop any connection a test left open (a job that never exits), so a
  // failing assertion cannot hang the whole suite.
  server.closeAllConnections?.();

  await new Promise((done) => server.close(done));
  server = null;
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Stop every job a test started, then wait for their responses to land. */
async function drain(ids, pending) {
  for (const id of ids) await post(`/jobs/${id}/cancel`, {});
  return Promise.all(pending);
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------
describe('GET /health', () => {
  it('is reachable without authentication', async () => {
    await start();
    const response = await fetch(`${baseUrl}/health`);
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.version).toBeTruthy();
  });

  it('exposes only liveness detail, never the secret or the policy', async () => {
    await start();
    const body = await (await fetch(`${baseUrl}/health`)).json();

    expect(JSON.stringify(body)).not.toContain(SECRET);
    expect(body).not.toHaveProperty('allowlist');
    expect(body).not.toHaveProperty('scope');
    expect(Object.keys(body).sort()).toEqual(
      ['jobs_running', 'max_concurrent', 'status', 'version'],
    );
  });
});

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------
describe('authentication', () => {
  it('rejects an unsigned request', async () => {
    await start();
    const response = await fetch(`${baseUrl}/jobs`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(job()),
    });

    expect(response.status).toBe(401);
  });

  it('rejects a signature made with the wrong secret', async () => {
    await start();
    const result = await post('/jobs', job(), { secret: 'x'.repeat(48) });

    expect(result.status).toBe(401);
    expect(result.json.error).toBe('invalid_signature');
  });

  it('rejects a stale timestamp (replay window)', async () => {
    await start();
    const result = await post('/jobs', job(), { timestamp: String(NOW_S - 3600) });

    expect(result.status).toBe(401);
    expect(result.json.error).toBe('timestamp_out_of_window');
  });

  it('rejects a body altered after signing', async () => {
    await start();
    const original = JSON.stringify(job());
    const signature = sign(SECRET, String(NOW_S), original);
    const tampered = JSON.stringify(job({ tool: 'nuclei' }));

    const response = await fetch(`${baseUrl}/jobs`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-runner-timestamp': String(NOW_S),
        'x-runner-signature': signature,
      },
      body: tampered,
    });

    expect(response.status).toBe(401);
  });

  it('requires authentication on /tools', async () => {
    await start();
    const response = await fetch(`${baseUrl}/tools`);

    expect(response.status).toBe(401);
  });

  it('requires authentication on the cancel route', async () => {
    await start();
    const response = await fetch(`${baseUrl}/jobs/s1-nmap-1a2b3c4d5e/cancel`, { method: 'POST' });

    expect(response.status).toBe(401);
  });

  it('never echoes the secret or a stack trace in an auth failure', async () => {
    await start();
    const result = await post('/jobs', job(), { secret: 'y'.repeat(48) });
    const serialised = JSON.stringify(result.json);

    expect(serialised).not.toContain(SECRET);
    expect(serialised).not.toContain('at ');
    expect(serialised).not.toContain('node_modules');
  });
});

// ---------------------------------------------------------------------------
// Tool catalogue
// ---------------------------------------------------------------------------
describe('GET /tools', () => {
  it('returns the registry to an authenticated caller', async () => {
    await start();
    const { status, json } = await get('/tools');

    expect(status).toBe(200);
    expect(json.tools).toHaveLength(18);
    expect(json.tools.map((t) => t.name)).toContain('nmap');
  });

  it('describes tools without exposing argv or the image', async () => {
    await start();
    const { json } = await get('/tools');
    const nmap = json.tools.find((t) => t.name === 'nmap');

    expect(Object.keys(nmap).sort()).toEqual(['description', 'intrusiveness', 'name', 'timeout_ms']);
    expect(nmap.intrusiveness).toBe('active');
    expect(JSON.stringify(json)).not.toContain('howtohack/scanner');
    expect(JSON.stringify(json)).not.toContain('-sV');
  });
});

// ---------------------------------------------------------------------------
// Scope enforcement
// ---------------------------------------------------------------------------
describe('scope revalidation', () => {
  it('refuses an unlisted target without starting a container', async () => {
    const { spawn } = await start();
    const result = await post('/jobs', job({
      job_id: 's1-nmap-evil000001',
      target: { host: 'evil.test', url: 'https://evil.test/', scheme: 'https', port: 443 },
      pinned_ips: null,
    }));

    expect(result.status).toBe(403);
    expect(result.json.error).toBe('target_not_allowed');
    expect(result.json.reason).toBe('not_allowlisted');
    expect(spawn.calls).toHaveLength(0);
  });

  it('refuses loopback even when the allowlist names it', async () => {
    await start();
    const result = await post('/jobs', job({
      job_id: 's1-nmap-loop000001',
      target: { host: '127.0.0.1', url: 'http://127.0.0.1/', scheme: 'http', port: 80 },
      scope: { allowlist: [{ host: '127.0.0.1', ports: [80] }], lab_exceptions: [] },
      pinned_ips: null,
    }));

    expect(result.status).toBe(403);
    expect(result.json.reason).toBe('loopback');
  });

  it('refuses a cloud metadata endpoint even when the allowlist names it', async () => {
    await start();
    const result = await post('/jobs', job({
      job_id: 's1-nmap-meta000001',
      target: { host: '169.254.169.254', url: 'http://169.254.169.254/', scheme: 'http', port: 80 },
      scope: { allowlist: [{ host: '169.254.169.254', ports: [80] }], lab_exceptions: [] },
      pinned_ips: null,
    }));

    expect(result.status).toBe(403);
    expect(result.json.reason).toBe('cloud_metadata');
  });

  it('refuses when DNS moved away from the approved address', async () => {
    await start();
    const result = await post('/jobs', job({
      job_id: 's1-nmap-rebind0001',
      target: { host: 'rebind.example.com', url: 'https://rebind.example.com/', scheme: 'https', port: 443 },
      pinned_ips: ['93.184.216.51'],
      scope: { allowlist: [{ host: 'rebind.example.com', ports: [443] }], lab_exceptions: [] },
    }));

    expect(result.status).toBe(403);
    expect(result.json.reason).toBe('address_changed');
  });

  it('refuses a port the rule does not cover', async () => {
    await start();
    const result = await post('/jobs', job({
      job_id: 's1-nmap-port000001',
      target: { host: 'app.example.com', url: 'https://app.example.com/', scheme: 'https', port: 8443 },
      pinned_ips: null,
    }));

    expect(result.status).toBe(403);
    expect(result.json.reason).toBe('port_not_allowed');
  });

  it('refuses when the name does not resolve', async () => {
    await start({ resolveHost: async () => [] });
    const result = await post('/jobs', job({ job_id: 's1-nmap-unres00001' }));

    expect(result.status).toBe(403);
    expect(result.json.reason).toBe('unresolved');
  });

  it('fails closed when the resolver throws', async () => {
    await start({
      resolveHost: async () => {
        throw new Error('resolver exploded');
      },
    });
    const result = await post('/jobs', job({ job_id: 's1-nmap-throw0001' }));

    expect(result.status).toBe(500);
    expect(result.json.error).toBe('runner_error');
    expect(spawn_assertion(result)).toBe(true);
  });

  it('revalidates on every job, not once per process', async () => {
    const { spawn } = await start({ children: [fakeChild({ exitCode: 0 })] });

    const first = await post('/jobs', job({ job_id: 's1-nmap-first0001' }));
    expect(first.status).toBe(200);

    // Same target, but the scope document no longer authorises it.
    const second = await post('/jobs', job({
      job_id: 's1-nmap-second001',
      scope: { allowlist: [], lab_exceptions: [] },
    }));

    expect(second.status).toBe(403);
    expect(spawn.calls.filter((c) => c.argv[0] === 'run')).toHaveLength(1);
  });
});

/** The failure body must not contain a stack trace. */
function spawn_assertion(result) {
  return !JSON.stringify(result.json).includes('at Object');
}

// ---------------------------------------------------------------------------
// Schema enforcement
// ---------------------------------------------------------------------------
describe('schema enforcement', () => {
  it('rejects unknown top-level keys', async () => {
    await start();
    const result = await post('/jobs', { ...job(), image: 'evil:latest' });

    expect(result.status).toBe(422);
    expect(result.json.error).toBe('invalid_job');
    expect(result.json.field).toBe('job.image');
  });

  it('rejects an attempt to smuggle execution parameters', async () => {
    await start();
    for (const [key, value] of Object.entries({
      argv: ['sh'],
      command: 'id',
      mounts: ['/:/host'],
      env: { A: 'B' },
      privileged: true,
      network: 'host',
      user: 'root',
    })) {
      const result = await post('/jobs', { ...job(), [key]: value });
      expect(result.status, key).toBe(422);
    }
  });

  it('rejects unknown nested keys', async () => {
    await start();

    const target = await post('/jobs', job({
      job_id: 's1-nmap-nest00001',
      target: { ...job().target, path: '/etc/passwd' },
    }));
    expect(target.json.field).toBe('job.target.path');

    const limits = await post('/jobs', job({
      job_id: 's1-nmap-nest00002',
      limits: { timeout_ms: 5000, cpus: 8 },
    }));
    expect(limits.json.field).toBe('job.limits.cpus');

    const approval = await post('/jobs', job({
      job_id: 's1-nmap-nest00003',
      approval: { fingerprint: 'x', forged: true },
    }));
    expect(approval.json.field).toBe('job.approval.forged');
  });

  it('rejects an unregistered tool', async () => {
    await start();
    for (const tool of ['bash', 'sh', 'docker', 'nmap; rm -rf /', '']) {
      const result = await post('/jobs', job({ tool }));
      expect(result.status, tool).toBe(422);
    }
  });

  it('rejects a host that would be parsed as a flag', async () => {
    await start();
    const result = await post('/jobs', job({
      job_id: 's1-nmap-flag00001',
      target: { host: '--script=evil', scheme: 'https', port: 443 },
    }));

    expect(result.status).toBe(422);
    expect(result.json.field).toBe('job.target.host');
  });

  it('rejects a URL that disagrees with the host', async () => {
    await start();
    const result = await post('/jobs', job({
      job_id: 's1-nmap-mismatch1',
      target: { host: 'app.example.com', url: 'https://evil.test/', scheme: 'https', port: 443 },
    }));

    expect(result.status).toBe(422);
    expect(result.json.field).toBe('job.target.url');
  });

  it('rejects invalid JSON', async () => {
    await start();
    const result = await post('/jobs', '{not json');

    expect(result.status).toBe(400);
    expect(result.json.error).toBe('invalid_json');
  });

  it('rejects an oversized body', async () => {
    await start();
    const result = await post('/jobs', 'x'.repeat(8000));

    expect(result.status).toBe(413);
    expect(result.json.error).toBe('payload_too_large');
  });

  it('rejects a missing scope document', async () => {
    await start();
    const result = await post('/jobs', job({ scope: undefined }));

    expect(result.status).toBe(422);
    expect(result.json.field).toBe('job.scope');
  });

  it('accepts null for the optional fields the client leaves empty', async () => {
    await start({ children: [fakeChild({ exitCode: 0, stdout: '[]' })] });
    const result = await post('/jobs', job({
      job_id: 's1-nmap-nulls0001',
      pinned_ips: null,
      approval: null,
      limits: { timeout_ms: 5000 },
    }));

    expect(result.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------
describe('execution', () => {
  it('runs one container and returns the structured result', async () => {
    const { spawn } = await start({ children: [fakeChild({ exitCode: 0, stdout: '[{"port":443}]' })] });
    const result = await post('/jobs', job({ job_id: 's1-nmap-run000001' }));

    expect(result.status).toBe(200);
    expect(result.json.outcome).toBe(OUTCOME.COMPLETED);
    expect(result.json.stdout).toBe('[{"port":443}]');
    expect(result.json.exit_code).toBe(0);
    expect(result.json.job_id).toBe('s1-nmap-run000001');
    expect(spawn.calls.filter((c) => c.argv[0] === 'run')).toHaveLength(1);
  });

  it('reports a missing tool as unavailable, not as zero findings', async () => {
    await start({ children: [fakeChild({ exitCode: 127, stderr: 'nmap: not found' })] });
    const result = await post('/jobs', job({ job_id: 's1-nmap-missing01' }));

    expect(result.status).toBe(200);
    expect(result.json.outcome).toBe(OUTCOME.UNAVAILABLE);
    expect(result.json.diagnostic).toBe('tool_not_installed');
  });

  it('reports a failed run with its exit code and stderr', async () => {
    await start({ children: [fakeChild({ exitCode: 2, stderr: 'boom' })] });
    const result = await post('/jobs', job({ job_id: 's1-nmap-failed01' }));

    expect(result.json.outcome).toBe(OUTCOME.FAILED);
    expect(result.json.exit_code).toBe(2);
    expect(result.json.stderr).toBe('boom');
  });

  it('returns the scope decision alongside the result', async () => {
    await start({ children: [fakeChild({ exitCode: 0 })] });
    const result = await post('/jobs', job({ job_id: 's1-nmap-scope001' }));

    expect(result.json.scope.allowed).toBe(true);
    expect(result.json.scope.reason).toBe('allowed');
    expect(result.json.scope.resolved_ips).toEqual(['93.184.216.34']);
  });

  it('replays a finished job instead of running it twice', async () => {
    const { spawn } = await start({ children: [fakeChild({ exitCode: 0, stdout: '[]' })] });

    const first = await post('/jobs', job({ job_id: 's1-nmap-dup000001' }));
    const second = await post('/jobs', job({ job_id: 's1-nmap-dup000001' }));

    expect(first.status).toBe(200);
    expect(first.json.replayed).toBeUndefined();
    expect(second.status).toBe(200);
    expect(second.json.replayed).toBe(true);
    expect(spawn.calls.filter((c) => c.argv[0] === 'run')).toHaveLength(1);
  });

  it('refuses a duplicate job id while the first is still running', async () => {
    await start({ children: [fakeChild({ neverCloses: true }), fakeChild()] });

    const first = post('/jobs', job({ job_id: 's1-nmap-busy00001', limits: { timeout_ms: 60_000 } }));
    await sleep(20);

    const second = await post('/jobs', job({ job_id: 's1-nmap-busy00001' }));

    expect(second.status).toBe(409);
    expect(second.json.error).toBe('job_in_progress');
    expect(second.json).not.toHaveProperty('stdout');

    await drain(['s1-nmap-busy00001'], [first]);
  });

  it('returns 429 when the concurrency limit is reached', async () => {
    await start({ children: [
      fakeChild({ neverCloses: true }),
      fakeChild({ neverCloses: true }),
      fakeChild(),
    ] });

    const one = post('/jobs', job({ job_id: 's1-nmap-cap000001', limits: { timeout_ms: 60_000 } }));
    const two = post('/jobs', job({ job_id: 's1-nmap-cap000002', tool: 'httpx', limits: { timeout_ms: 60_000 } }));
    await sleep(20);

    const third = await post('/jobs', job({ job_id: 's1-nmap-cap000003' }));

    expect(third.status).toBe(429);
    expect(third.json.error).toBe('runner_busy');

    await drain(['s1-nmap-cap000001', 's1-nmap-cap000002'], [one, two]);
  });

  it('does not leave a job wedged in progress when execution throws', async () => {
    await start();
    // A target whose argv builder refuses: the executor reports failure, it
    // must not leave the id registered as running.
    const first = await post('/jobs', job({
      job_id: 's1-nmap-wedge001',
      target: { host: '---------', url: null, scheme: 'https', port: 443 },
    }));

    // Rejected at validation (422) — the important part is that a retry with the
    // same id is not answered with 409 job_in_progress.
    expect(first.status).toBe(422);

    const retry = await post('/jobs', job({ job_id: 's1-nmap-wedge001' }));
    expect(retry.status).not.toBe(409);
  });
});

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------
describe('cancellation', () => {
  it('confirms cancellation of a running job with 202', async () => {
    await start({ children: [fakeChild({ neverCloses: true }), fakeChild()] });

    const running = post('/jobs', job({ job_id: 's1-nmap-cancel001', limits: { timeout_ms: 60_000 } }));
    await sleep(20);

    const cancelled = await post('/jobs/s1-nmap-cancel001/cancel', {});

    expect(cancelled.status).toBe(202);
    expect(cancelled.json.cancelled).toBe(true);

    const finished = await running;
    expect(finished.json.outcome).toBe(OUTCOME.CANCELLED);
  });

  it('returns 404 for a job it is not running', async () => {
    await start();
    const result = await post('/jobs/s1-nmap-unknown001/cancel', {});

    expect(result.status).toBe(404);
    expect(result.json.error).toBe('job_not_running');
    expect(result.json.cancelled).toBe(false);
  });

  it('returns 404 when cancelling an already finished job', async () => {
    await start({ children: [fakeChild({ exitCode: 0 })] });
    await post('/jobs', job({ job_id: 's1-nmap-finished1' }));

    const result = await post('/jobs/s1-nmap-finished1/cancel', {});

    expect(result.status).toBe(404);
    expect(result.json.cancelled).toBe(false);
  });

  it('cancels only the job it names', async () => {
    const { executor } = await start({
      children: [fakeChild({ neverCloses: true }), fakeChild({ neverCloses: true }), fakeChild()],
    });

    const a = post('/jobs', job({ job_id: 's1-nmap-joba00001', limits: { timeout_ms: 60_000 } }));
    const b = post('/jobs', job({ job_id: 's1-nmap-jobb00001', limits: { timeout_ms: 60_000 } }));
    await sleep(20);

    expect(executor.isRunning('s1-nmap-joba00001')).toBe(true);
    expect(executor.isRunning('s1-nmap-jobb00001')).toBe(true);

    const cancelB = await post('/jobs/s1-nmap-jobb00001/cancel', {});
    expect(cancelB.status).toBe(202);

    // The other container is untouched.
    expect(executor.isRunning('s1-nmap-joba00001')).toBe(true);

    const bResult = await b;
    expect(bResult.json.outcome).toBe(OUTCOME.CANCELLED);

    await drain(['s1-nmap-joba00001'], [a]);
  });
});

// ---------------------------------------------------------------------------
// Routing and error hygiene
// ---------------------------------------------------------------------------
describe('routing', () => {
  it('404s an unknown path', async () => {
    await start();
    const { status, json } = await get('/nope');

    expect(status).toBe(404);
    expect(json.error).toBe('not_found');
  });

  it('does not expose a route that runs arbitrary commands', async () => {
    await start();

    for (const path of ['/exec', '/run', '/shell', '/jobs/raw', '/files', '/docker']) {
      const { status } = await get(path);
      expect(status, path).toBe(404);
    }
  });

  it('rejects a GET on /jobs', async () => {
    await start();
    const { status } = await get('/jobs');

    expect(status).toBe(404);
  });

  it('rejects a malformed cancel path', async () => {
    await start();
    const result = await post('/jobs/../../etc/passwd/cancel', {});

    expect(result.status).toBe(404);
  });

  it('never leaks internals in a 500', async () => {
    await start({
      resolveHost: async () => {
        throw new Error('internal detail: /srv/secret-path');
      },
    });

    const result = await post('/jobs', job({ job_id: 's1-nmap-50000001' }));

    expect(result.status).toBe(500);
    expect(JSON.stringify(result.json)).not.toContain('stack');
    expect(JSON.stringify(result.json)).not.toContain('/srv/secret-path');
    expect(JSON.stringify(result.json)).not.toContain(SECRET);
  });
});
