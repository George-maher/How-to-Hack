import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';

/**
 * A fake child process for executor tests.
 *
 * Mirrors the small slice of ChildProcess the executor uses. Crucially, its
 * lifecycle starts when it is *spawned*, not when the object is created — a
 * real process cannot exit before it exists, and a fake that does produces
 * tests that pass or fail depending on timing.
 *
 * `neverCloses` models a process that only exits when killed, which is what
 * timeouts and cancellation are tested against.
 */
export function fakeChild({
  exitCode = 0,
  signal = null,
  stdout = '',
  stderr = '',
  delayMs = 5,
  closeOnKill = true,
  neverCloses = false,
  onKill,
} = {}) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.killed = false;

  child.kill = (sig) => {
    child.killed = true;
    onKill?.(sig);
    if (closeOnKill) {
      setImmediate(() => child.emit('close', null, sig ?? 'SIGKILL'));
    }
    return true;
  };

  /**
   * Start the process. Called by recordingSpawn() the moment the executor
   * spawns it, so listeners are always attached before anything is emitted.
   */
  child.begin = () => {
    if (neverCloses) return;

    setTimeout(() => {
      if (stdout) child.stdout.write(stdout);
      if (stderr) child.stderr.write(stderr);
      child.stdout.end();
      child.stderr.end();
      // Let the stream deliver its buffered data first.
      setImmediate(() => child.emit('close', exitCode, signal));
    }, delayMs);
  };

  return child;
}

/** Record every spawn call, and hand out queued fake children. */
export function recordingSpawn(children = []) {
  const calls = [];
  const queue = [...children];

  const spawn = (bin, argv, options) => {
    calls.push({ bin, argv, options });

    const child = queue.shift() ?? fakeChild();
    child.begin?.();

    return child;
  };

  spawn.calls = calls;
  return spawn;
}

export const silentLogger = { info: () => {}, warn: () => {}, error: () => {} };

export const testConfig = (overrides = {}) => ({
  port: 0,
  host: '127.0.0.1',
  secret: 'test-secret-that-is-long-enough-000',
  clockSkewSeconds: 300,
  maxBodyBytes: 64 * 1024,
  maxConcurrentJobs: 2,
  maxTimeoutMs: 600_000,
  defaultTimeoutMs: 120_000,
  maxOutputBytes: 1024,
  scannerNetwork: 'scanner-net',
  containerUser: '65534:65534',
  image: 'howtohack/scanner:latest',
  memoryMb: 256,
  cpus: 0.5,
  pidsLimit: 128,
  wordlistMount: '',
  dockerBin: 'docker',
  killGraceMs: 20,
  allowedTools: [],
  logLevel: 'silent',
  ...overrides,
});
