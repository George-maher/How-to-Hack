/**
 * One-shot container execution.
 *
 * Everything here exists to make a job's *outcome* truthful:
 *  - the process is started with an argv array, never a shell string;
 *  - the container is bounded (time, memory, CPU, PIDs, output, filesystem);
 *  - a timeout and a cancellation are different outcomes, and neither is
 *    reported as "completed with no findings";
 *  - a missing tool is `unavailable`, not an empty result;
 *  - stdout and stderr are kept apart, because parsing reads stdout and
 *    diagnostics live on stderr.
 */

import { spawn as nodeSpawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';

export const OUTCOME = Object.freeze({
  COMPLETED: 'completed',
  FAILED: 'failed',
  TIMED_OUT: 'timed_out',
  UNAVAILABLE: 'unavailable',
  CANCELLED: 'cancelled',
});

/** Exit codes docker and the shell use for "cannot execute that". */
const UNAVAILABLE_EXIT_CODES = new Set([126, 127]);

export function containerNameFor(jobId) {
  const safe = String(jobId).replace(/[^A-Za-z0-9_.-]/g, '-').slice(0, 40);
  return `hth-${safe}-${randomUUID().slice(0, 8)}`;
}

/**
 * Build the `docker run` argv. Exported so tests can assert the isolation flags
 * without a Docker daemon.
 */
export function buildDockerArgv(config, job, containerName, args) {
  const argv = [
    'run',
    '--rm',
    '--name', containerName,
    '--network', config.scannerNetwork,
    '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', String(config.pidsLimit),
    '--memory', `${config.memoryMb}m`,
    '--memory-swap', `${config.memoryMb}m`,
    '--cpus', String(config.cpus),
    '--user', config.containerUser,
    '--log-driver', 'none',
  ];

  if (config.wordlistMount) {
    argv.push('--mount', `type=bind,source=${config.wordlistMount.split(':')[0]},target=/wordlists,readonly`);
  }

  argv.push(config.image, job.tool, ...args);

  return argv;
}

export class DockerExecutor {
  /**
   * @param {object} deps
   * @param {ReturnType<import('./config.mjs').loadConfig>} deps.config
   * @param {typeof nodeSpawn} [deps.spawnImpl]
   * @param {{info: Function, warn: Function, error: Function}} [deps.logger]
   */
  constructor({ config, spawnImpl = nodeSpawn, logger = console }) {
    this.config = config;
    this.spawnImpl = spawnImpl;
    this.logger = logger;
    /** @type {Map<string, {child: import('node:child_process').ChildProcess, containerName: string, cancelled: boolean}>} */
    this.running = new Map();
  }

  /** @param {string} jobId */
  isRunning(jobId) {
    return this.running.has(jobId);
  }

  /** Number of containers currently managed by this executor. */
  activeCount() {
    return this.running.size;
  }

  /**
   * Ask a running job to stop. Returns true only when a live job was found and
   * a kill was issued — a request for an unknown job is not a success.
   *
   * @param {string} jobId
   */
  cancel(jobId) {
    const entry = this.running.get(jobId);

    if (!entry) return false;

    entry.cancelled = true;

    try {
      entry.child.kill('SIGKILL');
    } catch {
      // The process may have exited between the lookup and the kill.
    }

    // Also tell the daemon, in case the client died but the container lives.
    try {
      const kill = this.spawnImpl(this.config.dockerBin, ['kill', entry.containerName], {
        stdio: 'ignore',
        shell: false,
      });
      kill.on('error', () => {});
    } catch {
      // Best effort: the kill of the client usually takes the container with it.
    }

    return true;
  }

  /**
   * @param {object} job validated job
   * @returns {Promise<{outcome: string, exitCode: number|null, durationMs: number, stdout: string, stderr: string, truncated: boolean, diagnostic: string|null, containerName: string}>}
   */
  async run(job) {
    const startedAt = Date.now();
    const containerName = containerNameFor(job.jobId);

    let argv;

    try {
      // Defence in depth: the registry refuses to build argv from a target it
      // considers unsafe (for example a host that starts with `-`). Reaching
      // this point means schema validation let something through, so report a
      // failure rather than starting a container.
      const args = job.toolDefinition.argv({ host: job.host, url: job.url ?? '', port: job.port });
      argv = buildDockerArgv(this.config, job, containerName, args);
    } catch (error) {
      return {
        outcome: OUTCOME.FAILED,
        exitCode: null,
        durationMs: Date.now() - startedAt,
        stdout: '',
        stderr: '',
        truncated: false,
        diagnostic: `unsafe_target: ${error?.message ?? error}`,
        containerName,
      };
    }

    return new Promise((resolve) => {
      let settled = false;
      let timedOut = false;
      let stdout = '';
      let stderr = '';
      let truncated = false;
      let exitCode = null;
      let spawnError = null;
      let timeoutTimer = null;
      let graceTimer = null;

      const finish = (outcome, diagnostic = null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutTimer);
        clearTimeout(graceTimer);
        this.running.delete(job.jobId);

        resolve({
          outcome,
          exitCode,
          durationMs: Date.now() - startedAt,
          stdout,
          stderr,
          truncated,
          diagnostic,
          containerName,
        });
      };

      const append = (stream, chunk) => {
        const text = chunk.toString('utf8');
        const current = stream === 'out' ? stdout : stderr;
        const room = this.config.maxOutputBytes - current.length;

        if (room <= 0) {
          truncated = true;
          return;
        }

        const next = current + (text.length > room ? text.slice(0, room) : text);
        truncated = truncated || text.length > room;

        if (stream === 'out') stdout = next;
        else stderr = next;
      };

      let child;

      try {
        child = this.spawnImpl(this.config.dockerBin, argv, {
          stdio: ['ignore', 'pipe', 'pipe'],
          shell: false,
          env: {
            PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
            DOCKER_HOST: process.env.DOCKER_HOST ?? '',
            // Never hand the child the runner's own secret.
          },
        });
      } catch (error) {
        const code = error?.code === 'ENOENT' ? 'docker_binary_missing' : 'spawn_failed';
        spawnError = code;
        finish(OUTCOME.UNAVAILABLE, code);
        return;
      }

      timeoutTimer = setTimeout(() => {
        timedOut = true;
        try {
          child.kill('SIGKILL');
        } catch {
          // ignore
        }
        try {
          const kill = this.spawnImpl(this.config.dockerBin, ['kill', containerName], {
            stdio: 'ignore',
            shell: false,
          });
          kill.on('error', () => {});
        } catch {
          // ignore
        }
        // Do not wait forever for a client that will not report back.
        graceTimer = setTimeout(() => finish(OUTCOME.TIMED_OUT, 'container_killed'), this.config.killGraceMs ?? 2000);
      }, job.timeoutMs);

      child.on('error', (error) => {
        const code = error?.code === 'ENOENT' ? 'docker_binary_missing' : 'spawn_failed';
        spawnError = code;
        finish(OUTCOME.UNAVAILABLE, code);
      });

      child.stdout?.on('data', (chunk) => append('out', chunk));
      child.stderr?.on('data', (chunk) => append('err', chunk));

      child.on('close', (code, signal) => {
        exitCode = typeof code === 'number' ? code : null;

        if (timedOut) return finish(OUTCOME.TIMED_OUT, 'timeout');
        if (this.running.get(job.jobId)?.cancelled) return finish(OUTCOME.CANCELLED, 'cancelled');
        if (spawnError) return finish(OUTCOME.UNAVAILABLE, spawnError);

        if (signal) {
          return finish(OUTCOME.FAILED, `killed_by_${signal}`);
        }

        if (exitCode === null) return finish(OUTCOME.FAILED, 'no_exit_code');
        if (UNAVAILABLE_EXIT_CODES.has(exitCode)) return finish(OUTCOME.UNAVAILABLE, 'tool_not_installed');
        if (exitCode !== 0) return finish(OUTCOME.FAILED, `exit_${exitCode}`);

        return finish(OUTCOME.COMPLETED, null);
      });

      this.running.set(job.jobId, { child, containerName, cancelled: false });
    });
  }
}
