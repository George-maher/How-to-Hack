/**
 * In-memory job bookkeeping.
 *
 * Deliberately minimal: the Runner is a single self-hosted process, so a job
 * registry in memory is enough. What matters for correctness is that a
 * duplicate delivery of the same job_id does not run the scanner twice, and
 * that the queue is bounded so a flood of requests cannot start unbounded
 * containers.
 */
import { OUTCOME } from './executor.mjs';

const MAX_REMEMBERED = 500;

export function createJobRegistry({ maxConcurrent, maxQueued, resultTtlMs = 15 * 60_000, now = () => Date.now() }) {
  /** job_id -> { state: 'running'|'done', result, at } */
  const jobs = new Map();
  const queue = [];
  let active = 0;

  function prune() {
    const cutoff = now() - resultTtlMs;
    for (const [id, entry] of jobs) {
      if (entry.state === 'done' && entry.at < cutoff) jobs.delete(id);
    }
    while (jobs.size > MAX_REMEMBERED) {
      const oldest = [...jobs.entries()].filter(([, e]) => e.state === 'done').sort((a, b) => a[1].at - b[1].at)[0];
      if (!oldest) break;
      jobs.delete(oldest[0]);
    }
  }

  function get(jobId) {
    return jobs.get(jobId) ?? null;
  }

  function isRunning(jobId) {
    return jobs.get(jobId)?.state === 'running';
  }

  /**
   * @returns {'replay'|'conflict'|'busy'|'accepted'}
   */
  function begin(jobId) {
    prune();

    const existing = jobs.get(jobId);
    if (existing) {
      return existing.state === 'running' ? 'conflict' : 'replay';
    }

    if (active >= maxConcurrent && queue.length >= maxQueued) {
      return 'busy';
    }

    jobs.set(jobId, { state: 'running', result: null, at: now() });
    active += 1;

    return 'accepted';
  }

  function finish(jobId, result) {
    jobs.set(jobId, { state: 'done', result, at: now() });
    active = Math.max(0, active - 1);
  }

  function fail(jobId) {
    jobs.delete(jobId);
    active = Math.max(0, active - 1);
  }

  function stats() {
    return {
      active,
      known: jobs.size,
      completed: [...jobs.values()].filter((j) => j.state === 'done').length,
      queued: queue.length,
    };
  }

  return { get, isRunning, begin, finish, fail, stats, prune };
}

export { OUTCOME };
