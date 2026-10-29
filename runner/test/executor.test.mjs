import { describe, expect, it } from 'vitest';
import {
  buildDockerArgv,
  containerNameFor,
  DockerExecutor,
  OUTCOME,
} from '../src/executor.mjs';
import { fakeChild, recordingSpawn, testConfig } from './helpers.mjs';
import { TOOLS } from '../src/tools.mjs';

const config = testConfig();

/** A minimal validated job, shaped like validateJob() output. */
const job = (overrides = {}) => ({
  jobId: 's1-nmap-1a2b3c4d5e',
  scanId: 1,
  tool: 'nmap',
  toolDefinition: TOOLS.nmap,
  host: 'app.example.com',
  url: 'https://app.example.com/',
  scheme: 'https',
  port: 443,
  scope: { allowlist: [], lab_exceptions: [] },
  pinnedIps: null,
  timeoutMs: 500,
  approvalFingerprint: null,
  ...overrides,
});

const build = (overrides = {}) => {
  const j = job(overrides);
  const containerName = containerNameFor(j.jobId);
  const args = j.toolDefinition.argv({ host: j.host, url: j.url ?? '', port: j.port });
  return { argv: buildDockerArgv(config, j, containerName, args), containerName, job: j };
};

// ---------------------------------------------------------------------------
// Container hardening
// ---------------------------------------------------------------------------
describe('container hardening', () => {
  const { argv } = build();
  const joined = argv.join(' ');

  it('starts with docker run and the job image', () => {
    expect(argv[0]).toBe('run');
    expect(argv).toContain('howtohack/scanner:latest');
  });

  it('applies every isolation flag', () => {
    expect(joined).toContain('--rm');
    expect(joined).toContain('--network scanner-net');
    expect(joined).toContain('--read-only');
    expect(joined).toContain('--cap-drop ALL');
    expect(joined).toContain('--security-opt no-new-privileges');
    expect(joined).toContain('--pids-limit 128');
    expect(joined).toContain('--memory 256m');
    expect(joined).toContain('--memory-swap 256m');
    expect(joined).toContain('--cpus 0.5');
    expect(joined).toContain('--user 65534:65534');
    expect(joined).toContain('--log-driver none');
    expect(joined).toContain('--tmpfs /tmp:rw,noexec,nosuid,size=64m');
  });

  it('never grants capabilities, host namespaces or privileged mode', () => {
    expect(joined).not.toContain('--privileged');
    expect(joined).not.toContain('--cap-add');
    expect(joined).not.toContain('--network host');
    expect(joined).not.toContain('--network=host');
    expect(joined).not.toContain('--pid host');
    expect(joined).not.toContain('--ipc host');
    expect(joined).not.toContain('--userns host');
    expect(joined).not.toContain('docker.sock');
  });

  it('does not publish ports or bind host paths beyond the read-only wordlist', () => {
    expect(joined).not.toContain('-p ');
    expect(joined).not.toContain('--publish');

    const mounts = argv.filter((arg, i) => argv[i - 1] === '--mount');
    expect(mounts).toHaveLength(0); // wordlistMount is empty in the test config
  });

  it('mounts the wordlist read-only when configured', () => {
    const withMount = buildDockerArgv(
      testConfig({ wordlistMount: '/srv/wordlists:/wordlists:ro' }),
      job(),
      'hth-test',
      ['nmap'],
    );
    const mount = withMount[withMount.indexOf('--mount') + 1];

    expect(mount).toContain('type=bind');
    expect(mount).toContain('source=/srv/wordlists');
    expect(mount).toContain('target=/wordlists');
    expect(mount).toContain('readonly');
  });

  it('passes the registry tool and its argv after the image, never a shell string', () => {
    const imageIndex = argv.indexOf('howtohack/scanner:latest');

    expect(argv[imageIndex + 1]).toBe('nmap');
    expect(argv.slice(imageIndex + 2)).toContain('app.example.com');
    expect(argv.some((arg) => arg.includes('sh -c'))).toBe(false);
    expect(argv.some((arg) => arg.includes('&&'))).toBe(false);
  });

  it('derives a docker-safe, unique container name', () => {
    const name = containerNameFor('s1-nmap-1a2b3c4d5e');

    expect(name).toMatch(/^hth-[A-Za-z0-9_.-]{1,60}$/);
    expect(name.startsWith('hth-')).toBe(true);
    expect(containerNameFor('s1-nmap-1a2b3c4d5e')).not.toBe(name);
  });

  it('sanitises hostile characters out of the container name', () => {
    expect(containerNameFor('a$(id);rm -rf /')).toMatch(/^hth-[A-Za-z0-9_.-]+$/);
  });
});

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------
const runWith = async (child, overrides = {}) => {
  const spawn = recordingSpawn([child]);
  const executor = new DockerExecutor({ config, spawnImpl: spawn, logger: silent });

  return { result: await executor.run(job(overrides)), spawn, executor };
};

const silent = { info: () => {}, warn: () => {}, error: () => {} };

describe('execution outcomes', () => {
  it('reports completed on exit 0 and keeps stdout', async () => {
    const { result } = await runWith(fakeChild({ exitCode: 0, stdout: '[{"port":443}]' }));

    expect(result.outcome).toBe(OUTCOME.COMPLETED);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe('[{"port":443}]');
    expect(result.diagnostic).toBeNull();
  });

  it('reports completed with empty output, which is distinct from failure', async () => {
    const { result } = await runWith(fakeChild({ exitCode: 0, stdout: '' }));

    expect(result.outcome).toBe(OUTCOME.COMPLETED);
    expect(result.stdout).toBe('');
  });

  it('reports failed on a non-zero exit and preserves stderr', async () => {
    const { result } = await runWith(
      fakeChild({ exitCode: 1, stderr: 'nmap: permission denied' }),
    );

    expect(result.outcome).toBe(OUTCOME.FAILED);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('permission denied');
    expect(result.diagnostic).toBe('exit_1');
  });

  it('maps a missing tool inside the image to unavailable', async () => {
    const { result } = await runWith(
      fakeChild({ exitCode: 127, stderr: 'exec: nmap: not found' }),
    );

    expect(result.outcome).toBe(OUTCOME.UNAVAILABLE);
    expect(result.diagnostic).toBe('tool_not_installed');
  });

  it('maps a non-executable tool to unavailable', async () => {
    const { result } = await runWith(fakeChild({ exitCode: 126 }));

    expect(result.outcome).toBe(OUTCOME.UNAVAILABLE);
  });

  it('maps a missing docker binary to unavailable', async () => {
    // Node reports a missing binary as an ENOENT `error` event on the child.
    const failing = fakeChild({ neverCloses: true });
    setImmediate(() =>
      failing.emit('error', Object.assign(new Error('spawn docker ENOENT'), { code: 'ENOENT' })),
    );

    const executor = new DockerExecutor({ config, spawnImpl: () => failing, logger: silent });
    const result = await executor.run(job());

    expect(result.outcome).toBe(OUTCOME.UNAVAILABLE);
    expect(result.diagnostic).toBe('docker_binary_missing');
  });

  it('treats a synchronous spawn throw as unavailable', async () => {
    const executor = new DockerExecutor({
      config,
      spawnImpl: () => {
        throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      },
      logger: silent,
    });

    const result = await executor.run(job());

    expect(result.outcome).toBe(OUTCOME.UNAVAILABLE);
    expect(result.diagnostic).toBe('docker_binary_missing');
  });

  it('reports a signalled death as failed, never as success', async () => {
    const { result } = await runWith(fakeChild({ exitCode: null, signal: 'SIGSEGV' }));

    expect(result.outcome).toBe(OUTCOME.FAILED);
    expect(result.diagnostic).toContain('SIGSEGV');
  });

  it('never reports any non-zero exit as success', async () => {
    for (const code of [1, 2, 3, 125, 128, 137, 255]) {
      const { result } = await runWith(fakeChild({ exitCode: code }));
      expect(result.outcome, String(code)).not.toBe(OUTCOME.COMPLETED);
    }
  });

  it('refuses to build argv from a host that looks like a flag', async () => {
    const spawn = recordingSpawn([]);
    const executor = new DockerExecutor({ config, spawnImpl: spawn, logger: silent });

    const result = await executor.run(job({ host: '--script=evil', url: null }));

    expect(result.outcome).toBe(OUTCOME.FAILED);
    expect(result.diagnostic).toContain('unsafe_target');
    expect(spawn.calls).toHaveLength(0);
  });

  it('records a duration for every outcome', async () => {
    const { result } = await runWith(fakeChild({ exitCode: 0 }));

    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(Number.isInteger(result.durationMs)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Output limits
// ---------------------------------------------------------------------------
describe('output handling', () => {
  it('caps stdout at maxOutputBytes and flags truncation', async () => {
    const { result } = await runWith(fakeChild({ exitCode: 0, stdout: 'x'.repeat(5000) }));

    expect(result.stdout.length).toBe(config.maxOutputBytes);
    expect(result.truncated).toBe(true);
  });

  it('caps stderr separately', async () => {
    const { result } = await runWith(fakeChild({ exitCode: 1, stderr: 'e'.repeat(5000) }));

    expect(result.stderr.length).toBe(config.maxOutputBytes);
    expect(result.truncated).toBe(true);
  });

  it('does not flag truncation for output inside the limit', async () => {
    const { result } = await runWith(fakeChild({ exitCode: 0, stdout: 'short' }));

    expect(result.truncated).toBe(false);
  });

  it('keeps stdout and stderr apart so parsing cannot read diagnostics', async () => {
    const { result } = await runWith(
      fakeChild({ exitCode: 0, stdout: '[{"a":1}]', stderr: 'warning: something' }),
    );

    expect(result.stdout).toBe('[{"a":1}]');
    expect(result.stderr).toBe('warning: something');
  });
});

// ---------------------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------------------
describe('timeouts', () => {
  it('kills the container and reports timed_out', async () => {
    const child = fakeChild({ neverCloses: true, closeOnKill: true });
    const spawn = recordingSpawn([child, fakeChild()]);
    const executor = new DockerExecutor({ config, spawnImpl: spawn, logger: silent });

    const result = await executor.run(job({ timeoutMs: 25 }));

    expect(result.outcome).toBe(OUTCOME.TIMED_OUT);
    expect(result.diagnostic).toBe('timeout');

    // The container is killed at the daemon, not just the local client.
    const kill = spawn.calls.find((call) => call.argv[0] === 'kill');
    expect(kill).toBeTruthy();
    expect(kill.argv[1]).toBe(result.containerName);
  });

  it('does not report a timed-out job as completed even if it exits 0 afterwards', async () => {
    const child = fakeChild({ exitCode: 0, delayMs: 60 });
    const spawn = recordingSpawn([child, fakeChild()]);
    const executor = new DockerExecutor({ config, spawnImpl: spawn, logger: silent });

    const result = await executor.run(job({ timeoutMs: 20 }));

    expect(result.outcome).toBe(OUTCOME.TIMED_OUT);
  });
});

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------
describe('cancellation', () => {
  it('kills a running job and reports cancelled', async () => {
    const child = fakeChild({ neverCloses: true });
    const spawn = recordingSpawn([child, fakeChild()]);
    const executor = new DockerExecutor({ config, spawnImpl: spawn, logger: silent });

    const promise = executor.run(job({ timeoutMs: 60_000 }));

    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(executor.activeCount()).toBe(1);
    expect(executor.cancel('s1-nmap-1a2b3c4d5e')).toBe(true);

    const result = await promise;

    expect(result.outcome).toBe(OUTCOME.CANCELLED);
    expect(result.diagnostic).toBe('cancelled');
  });

  it('returns false for a job it does not know', () => {
    const executor = new DockerExecutor({ config, spawnImpl: recordingSpawn([]), logger: silent });

    expect(executor.cancel('nope')).toBe(false);
    expect(executor.cancel('')).toBe(false);
  });

  it('cannot cancel a job that already finished', async () => {
    const executor = new DockerExecutor({
      config,
      spawnImpl: recordingSpawn([fakeChild({ exitCode: 0 })]),
      logger: silent,
    });

    await executor.run(job());

    expect(executor.cancel('s1-nmap-1a2b3c4d5e')).toBe(false);
  });

  it('does not cancel a different job', async () => {
    const executor = new DockerExecutor({
      config,
      spawnImpl: recordingSpawn([fakeChild({ neverCloses: true }), fakeChild()]),
      logger: silent,
    });

    const promise = executor.run(job({ jobId: 's1-nmap-aaaaaaaaaa', timeoutMs: 60_000 }));
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(executor.cancel('s1-nmap-bbbbbbbbbb')).toBe(false);
    expect(executor.cancel('s1-nmap-aaaaaaaaaa')).toBe(true);

    expect((await promise).outcome).toBe(OUTCOME.CANCELLED);
  });
});

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------
describe('cleanup', () => {
  it('releases the registry slot after success', async () => {
    const executor = new DockerExecutor({
      config,
      spawnImpl: recordingSpawn([fakeChild({ exitCode: 0 })]),
      logger: silent,
    });

    await executor.run(job());

    expect(executor.activeCount()).toBe(0);
    expect(executor.isRunning('s1-nmap-1a2b3c4d5e')).toBe(false);
  });

  it('releases the registry slot after failure', async () => {
    const executor = new DockerExecutor({
      config,
      spawnImpl: recordingSpawn([fakeChild({ exitCode: 1 })]),
      logger: silent,
    });

    await executor.run(job());

    expect(executor.activeCount()).toBe(0);
  });

  it('releases the registry slot after a timeout', async () => {
    const executor = new DockerExecutor({
      config,
      spawnImpl: recordingSpawn([fakeChild({ neverCloses: true })]),
      logger: silent,
    });

    await executor.run(job({ timeoutMs: 20 }));

    expect(executor.activeCount()).toBe(0);
  });

  it('releases the registry slot after cancellation', async () => {
    const executor = new DockerExecutor({
      config,
      spawnImpl: recordingSpawn([fakeChild({ neverCloses: true }), fakeChild()]),
      logger: silent,
    });

    const promise = executor.run(job({ timeoutMs: 60_000 }));
    await new Promise((resolve) => setTimeout(resolve, 10));
    executor.cancel('s1-nmap-1a2b3c4d5e');
    await promise;

    expect(executor.activeCount()).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Spawn safety
// ---------------------------------------------------------------------------
describe('spawn safety', () => {
  it('passes an argv array with shell disabled', async () => {
    const { spawn } = await runWith(fakeChild({ exitCode: 0 }));
    const call = spawn.calls[0];

    expect(call.bin).toBe('docker');
    expect(Array.isArray(call.argv)).toBe(true);
    expect(call.options.shell).toBe(false);
    expect(call.argv.some((arg) => arg.includes('app.example.com'))).toBe(true);
  });

  it('does not pass the runner secret to the container', async () => {
    const { spawn } = await runWith(fakeChild({ exitCode: 0 }));
    const env = spawn.calls[0].options.env ?? {};

    expect(env.RUNNER_SECRET).toBeUndefined();
    expect(env).not.toHaveProperty('RUNNER_SECRET');
  });

  it('runs exactly one container per job', async () => {
    const { spawn } = await runWith(fakeChild({ exitCode: 0 }));

    expect(spawn.calls.filter((call) => call.argv[0] === 'run')).toHaveLength(1);
  });
});
