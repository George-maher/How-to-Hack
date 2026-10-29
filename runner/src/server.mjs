/**
 * The Runner's HTTP surface.
 *
 * Four routes, all narrow:
 *   GET  /health              liveness (unauthenticated, no detail)
 *   GET  /tools               the tool catalogue (authenticated)
 *   POST /jobs                run one registered tool (authenticated)
 *   POST /jobs/:id/cancel     stop one running job (authenticated)
 *
 * There is no "run this command" route, no file route, and no proxy route.
 */

import { createServer as createHttpServer } from 'node:http';
import { isIP } from 'node:net';
import { promises as dns } from 'node:dns';

import { verifyRequest } from './auth.mjs';
import { evaluateTarget } from './policy.mjs';
import { catalogue } from './tools.mjs';
import { validateJob } from './validate.mjs';
import { OUTCOME } from './executor.mjs';

export const RUNNER_VERSION = '1.0.0';

class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

/** @param {import('node:http').IncomingMessage} req */
async function readBody(req, limit) {
  const chunks = [];
  let size = 0;

  for await (const chunk of req) {
    size += chunk.length;

    if (size > limit) {
      throw new HttpError(413, 'payload_too_large', `The request body exceeds ${limit} bytes.`);
    }

    chunks.push(chunk);
  }

  return Buffer.concat(chunks).toString('utf8');
}

/**
 * @param {object} deps
 * @param {ReturnType<import('./config.mjs').loadConfig>} deps.config
 * @param {import('./executor.mjs').DockerExecutor} deps.executor
 * @param {(host: string) => Promise<string[]>} [deps.resolveHost]
 * @param {{info: Function, warn: Function, error: Function}} [deps.logger]
 * @param {() => Date} [deps.now]
 * @param {string} [deps.version]
 */
export function createRunnerServer({ config, executor, resolveHost, logger = console, now = () => new Date(), version = RUNNER_VERSION }) {
  const defaultResolve = async (host) => {
    try {
      const answers = await dns.lookup(host, { all: true, verbatim: true });
      return answers.map((entry) => entry.address);
    } catch {
      return [];
    }
  };

  const resolver = resolveHost ?? defaultResolve;

  /** @type {Map<string, {status: string, result?: object, startedAt: number}>} */
  const jobs = new Map();

  const json = (res, status, payload) => {
    const body = JSON.stringify(payload);
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': Buffer.byteLength(body),
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    });
    res.end(body);
  };

  const authenticate = (req, rawBody) => {
    const verdict = verifyRequest({
      secret: config.secret,
      timestamp: req.headers['x-runner-timestamp'],
      signature: req.headers['x-runner-signature'],
      body: rawBody,
      skewSeconds: config.clockSkewSeconds,
      now: Math.floor(now().getTime() / 1000),
    });

    if (!verdict.ok) {
      throw new HttpError(401, verdict.code, 'The request could not be authenticated.');
    }
  };

  const handle = async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://runner.local');
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (req.method === 'GET' && path === '/health') {
      return json(res, 200, {
        status: 'ok',
        version,
        jobs_running: executor.running.size,
        max_concurrent: config.maxConcurrentJobs,
      });
    }

    const rawBody = req.method === 'POST' ? await readBody(req, config.maxBodyBytes) : '';
    authenticate(req, rawBody);

    if (req.method === 'GET' && path === '/tools') {
      return json(res, 200, { version, tools: catalogue() });
    }

    if (req.method === 'POST' && path === '/jobs') {
      return handleRunJob(rawBody, res);
    }

    const cancelMatch = /^\/jobs\/([A-Za-z0-9_-]{1,64})\/cancel$/.exec(path);
    if (req.method === 'POST' && cancelMatch) {
      const jobId = cancelMatch[1];

      if (executor.cancel(jobId)) {
        logger.info?.(`cancelled job ${jobId}`);
        return json(res, 202, { job_id: jobId, cancelled: true });
      }

      return json(res, 404, {
        job_id: jobId,
        cancelled: false,
        error: 'job_not_running',
        message: 'No running job with that id.',
      });
    }

    throw new HttpError(404, 'not_found', 'Unknown route.');
  };

  const handleRunJob = async (rawBody, res) => {
    let parsed;

    try {
      parsed = rawBody === '' ? null : JSON.parse(rawBody);
    } catch {
      throw new HttpError(400, 'invalid_json', 'The request body is not valid JSON.');
    }

    const validation = validateJob(parsed, {
      maxTimeoutMs: config.maxTimeoutMs,
      defaultTimeoutMs: config.defaultTimeoutMs,
      allowedTools: config.allowedTools,
    });

    if (!validation.ok) {
      return json(res, 422, {
        error: validation.code,
        field: validation.field,
        message: validation.message,
      });
    }

    const job = validation.job;
    const existing = jobs.get(job.jobId);

    // Idempotency: the same job id never runs twice. A replay returns what
    // happened the first time.
    if (existing?.status === 'running') {
      return json(res, 409, {
        error: 'job_in_progress',
        job_id: job.jobId,
        message: 'That job is already running.',
      });
    }

    if (existing?.result) {
      return json(res, 200, { ...existing.result, replayed: true });
    }

    if (executor.running.size >= config.maxConcurrentJobs) {
      return json(res, 429, {
        error: 'runner_busy',
        message: 'The runner is at capacity. Retry shortly.',
      });
    }

    // ── independent scope revalidation ──────────────────────────────────
    const addresses = isIP(job.host) !== 0 ? [job.host] : await resolver(job.host);
    const decision = evaluateTarget({
      host: job.host,
      ports: [job.port],
      scope: job.scope,
      pinnedIps: job.pinnedIps ?? undefined,
      resolveHost: () => addresses,
      now: now(),
    });

    if (!decision.allowed) {
      logger.warn?.(`refused job ${job.jobId}: ${decision.reason}`);

      return json(res, 403, {
        error: 'target_not_allowed',
        reason: decision.reason,
        job_id: job.jobId,
        message: `The runner refused this target (${decision.reason}).`,
      });
    }

    jobs.set(job.jobId, { status: 'running', startedAt: now().getTime() });

    let result;

    try {
      result = await executor.run(job);
    } catch (error) {
      // Never leave a job wedged in `running`: that would make every retry
      // return 409 job_in_progress forever, and the scan would hang.
      jobs.delete(job.jobId);
      logger.error?.(`job ${job.jobId} failed to execute: ${error?.message ?? error}`);

      return json(res, 500, {
        error: 'runner_error',
        job_id: job.jobId,
        message: 'The runner failed to start this job.',
      });
    }

    // A cancelled job is reported as cancelled, never as "completed with no
    // output", even if the process happened to exit 0 afterwards.
    const outcome = result.outcome;

    const payload = {
      job_id: job.jobId,
      tool: job.tool,
      outcome,
      exit_code: result.exitCode,
      duration_ms: result.durationMs,
      stdout: result.stdout,
      stderr: result.stderr,
      truncated: result.truncated,
      diagnostic: result.diagnostic,
      container: result.containerName,
      scope: {
        allowed: decision.allowed,
        reason: decision.reason,
        host: decision.host,
        resolved_ips: decision.resolvedIps,
        ports: decision.ports,
      },
      runner_version: version,
    };

    jobs.set(job.jobId, { status: 'done', result: payload, startedAt: jobs.get(job.jobId)?.startedAt ?? now().getTime() });

    // Keep the cache bounded: it exists for idempotency, not as a history.
    // Only finished entries may be evicted — evicting a running job would let
    // the same work be started twice.
    if (jobs.size > 500) {
      for (const [id, entry] of jobs) {
        if (entry.status !== 'running') {
          jobs.delete(id);
          break;
        }
      }
    }

    if (outcome !== OUTCOME.COMPLETED) {
      logger.warn?.(`job ${job.jobId} (${job.tool}) finished as ${outcome}: ${result.diagnostic ?? ''}`);
    }

    return json(res, 200, payload);
  };

  const server = createHttpServer((req, res) => {
    handle(req, res).catch((error) => {
      if (error instanceof HttpError) {
        return json(res, error.status, { error: error.code, message: error.message, ...error.extra });
      }

      // Never leak a stack trace to the caller.
      logger.error?.(`unhandled runner error: ${error?.message ?? error}`);

      return json(res, 500, {
        error: 'runner_error',
        message: 'The runner failed to handle this request.',
      });
    });
  });

  server.on('clientError', (_error, socket) => {
    if (socket.writable) {
      socket.end('HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n');
    }
  });

  return server;
}
