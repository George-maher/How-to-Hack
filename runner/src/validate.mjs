/**
 * Job schema validation.
 *
 * This is the boundary between "a service we trust a bit" and "a process that
 * starts containers". Two rules keep it narrow:
 *
 *  1. **Unknown keys are rejected, not ignored.** A future API change that
 *     starts sending `image`, `mounts` or `env` fails loudly in testing instead
 *     of silently having no effect.
 *  2. **Optional means optional, not nullable-by-accident.** The PHP client
 *     sends `pinned_ips: null` and `approval: null` when it has nothing to
 *     say, so `null` is accepted *only* where the field is genuinely optional.
 *
 * The accepted shape is the documented one (see runner/README.md), which is
 * exactly what backend/app/Scanners/Docker/BaseDockerScanner.php builds:
 *
 *   {
 *     "job_id": "s1-nmap-1a2b3c4d5e",
 *     "scan_id": 1,
 *     "tool": "nmap",
 *     "target": { "host": "app.example.com", "url": "https://…", "scheme": "https", "port": 443 },
 *     "scope": { "allowlist": [...], "lab_exceptions": [...] },
 *     "pinned_ips": ["93.184.216.34"] | null,
 *     "limits": { "timeout_ms": 120000 } | null,
 *     "approval": { "fingerprint": "…", "approved_at": null } | null
 *   }
 */

import { isIP } from 'node:net';
import { getTool } from './tools.mjs';

const JOB_KEYS = new Set([
  'job_id',
  'scan_id',
  'tool',
  'target',
  'scope',
  'pinned_ips',
  'limits',
  'approval',
]);

const TARGET_KEYS = new Set(['host', 'url', 'scheme', 'port']);
const SCOPE_KEYS = new Set(['allowlist', 'lab_exceptions']);
const LIMITS_KEYS = new Set(['timeout_ms']);
const APPROVAL_KEYS = new Set(['fingerprint', 'approved_at']);

const JOB_ID_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;
const SCHEMES = new Set(['http', 'https']);

/**
 * A host that could be read as a command-line flag is not a host.
 *
 * There is no shell anywhere in this path, but `nmap` itself parses argv: a
 * "host" of `--script=…` would be obeyed as an option. Rejecting it here means
 * the registry never has to reason about it.
 */
export function isFlagLikeHost(host) {
  return host.startsWith('-') || host.startsWith('--');
}

/**
 * Structural host check: an IP literal, or a hostname built from LDH labels.
 * Non-ASCII names are refused rather than guessed at (IDN homograph risk).
 */
export function isValidHost(host) {
  if (typeof host !== 'string' || host.length === 0 || host.length > 253) return false;
  if (isFlagLikeHost(host)) return false;
  if (/[\s/@\\?#;|&$`'"()<>{}[\]*]/.test(host)) return false;
  if (isIP(host) !== 0) return true;

  const label = '[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?';
  return new RegExp(`^${label}(?:\\.${label})*$`, 'i').test(host);
}

function fail(field, message) {
  return { ok: false, code: 'invalid_job', field, message };
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * @param {unknown} body
 * @param {{ maxTimeoutMs: number, defaultTimeoutMs: number, allowedTools?: string[] }} options
 */
export function validateJob(body, options) {
  if (!isPlainObject(body)) {
    return fail('job', 'The job must be a JSON object.');
  }

  for (const key of Object.keys(body)) {
    if (!JOB_KEYS.has(key)) return fail(`job.${key}`, `Unknown field "${key}".`);
  }

  // ── identity ───────────────────────────────────────────────────────────
  if (typeof body.job_id !== 'string' || !JOB_ID_PATTERN.test(body.job_id)) {
    return fail('job.job_id', 'job_id must match [A-Za-z0-9_-]{8,64}.');
  }

  if (!Number.isInteger(body.scan_id) || body.scan_id < 1) {
    return fail('job.scan_id', 'scan_id must be a positive integer.');
  }

  // ── tool ───────────────────────────────────────────────────────────────
  const tool = getTool(body.tool);
  if (tool === null) {
    return fail('job.tool', 'The tool is not in the runner registry.');
  }

  if (Array.isArray(options.allowedTools) && options.allowedTools.length > 0
      && !options.allowedTools.includes(body.tool)) {
    return fail('job.tool', 'The tool is disabled in this runner configuration.');
  }

  // ── target ─────────────────────────────────────────────────────────────
  const target = body.target;
  if (!isPlainObject(target)) {
    return fail('job.target', 'target is required.');
  }

  for (const key of Object.keys(target)) {
    if (!TARGET_KEYS.has(key)) return fail(`job.target.${key}`, `Unknown field "${key}".`);
  }

  if (!isValidHost(target.host)) {
    return fail('job.target.host', 'target.host must be a hostname or IP literal.');
  }

  const host = target.host;

  let scheme = 'https';

  if (target.scheme !== undefined && target.scheme !== null) {
    if (typeof target.scheme !== 'string' || !SCHEMES.has(target.scheme.toLowerCase())) {
      return fail('job.target.scheme', 'target.scheme must be http or https.');
    }
    scheme = target.scheme.toLowerCase();
  }

  if (target.url !== undefined && target.url !== null) {
    if (typeof target.url !== 'string' || target.url.length > 2048) {
      return fail('job.target.url', 'target.url must be a string of at most 2048 characters.');
    }

    let parsed;
    try {
      parsed = new URL(target.url);
    } catch {
      return fail('job.target.url', 'target.url is not a valid URL.');
    }

    if (!SCHEMES.has(parsed.protocol.replace(':', ''))) {
      return fail('job.target.url', 'target.url must use http or https.');
    }

    if (parsed.username || parsed.password) {
      return fail('job.target.url', 'target.url may not contain credentials.');
    }

    // The URL and the host must describe the same destination. Otherwise the
    // URL is a way to make a tool talk to something the policy never saw.
    if (parsed.hostname.toLowerCase() !== host.toLowerCase()) {
      return fail('job.target.url', 'target.url does not match target.host.');
    }

    scheme = parsed.protocol.replace(':', '');
  }

  const port = target.port ?? (scheme === 'https' ? 443 : 80);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return fail('job.target.port', 'target.port must be an integer between 1 and 65535.');
  }

  // ── scope ──────────────────────────────────────────────────────────────
  const scope = body.scope;
  if (!isPlainObject(scope)) {
    return fail('job.scope', 'scope is required: the runner will not evaluate an empty policy.');
  }

  for (const key of Object.keys(scope)) {
    if (!SCOPE_KEYS.has(key)) return fail(`job.scope.${key}`, `Unknown field "${key}".`);
  }

  if (!Array.isArray(scope.allowlist) || !Array.isArray(scope.lab_exceptions)) {
    return fail('job.scope', 'scope.allowlist and scope.lab_exceptions must be arrays.');
  }

  if (scope.allowlist.length > 100 || scope.lab_exceptions.length > 50) {
    return fail('job.scope', 'The scope document is too large.');
  }

  // ── optional: pinned addresses ─────────────────────────────────────────
  let pinnedIps = null;

  if (body.pinned_ips !== undefined && body.pinned_ips !== null) {
    if (!Array.isArray(body.pinned_ips) || body.pinned_ips.length > 16) {
      return fail('job.pinned_ips', 'pinned_ips must be an array of at most 16 addresses.');
    }

    for (const ip of body.pinned_ips) {
      if (typeof ip !== 'string' || isIP(ip) === 0) {
        return fail('job.pinned_ips', 'pinned_ips contains a value that is not an IP address.');
      }
    }

    pinnedIps = body.pinned_ips;
  }

  // ── optional: limits ───────────────────────────────────────────────────
  let timeoutMs = options.defaultTimeoutMs;

  if (body.limits !== undefined && body.limits !== null) {
    if (!isPlainObject(body.limits)) {
      return fail('job.limits', 'limits must be an object.');
    }

    for (const key of Object.keys(body.limits)) {
      if (!LIMITS_KEYS.has(key)) return fail(`job.limits.${key}`, `Unknown field "${key}".`);
    }

    if (body.limits.timeout_ms !== undefined) {
      if (!Number.isInteger(body.limits.timeout_ms) || body.limits.timeout_ms < 1000) {
        return fail('job.limits.timeout_ms', 'limits.timeout_ms must be an integer of at least 1000.');
      }

      // Clamp rather than reject: a caller asking for longer gets the maximum,
      // and the effective value is what the executor uses.
      timeoutMs = body.limits.timeout_ms;
    }
  }

  timeoutMs = Math.min(timeoutMs, tool.timeoutMs, options.maxTimeoutMs);

  // ── optional: approval (carried, never interpreted) ────────────────────
  let approvalFingerprint = null;

  if (body.approval !== undefined && body.approval !== null) {
    if (!isPlainObject(body.approval)) {
      return fail('job.approval', 'approval must be an object.');
    }

    for (const key of Object.keys(body.approval)) {
      if (!APPROVAL_KEYS.has(key)) return fail(`job.approval.${key}`, `Unknown field "${key}".`);
    }

    if (body.approval.fingerprint !== undefined && body.approval.fingerprint !== null) {
      if (typeof body.approval.fingerprint !== 'string' || body.approval.fingerprint.length > 128) {
        return fail('job.approval.fingerprint', 'approval.fingerprint must be a string of at most 128 characters.');
      }

      approvalFingerprint = body.approval.fingerprint;
    }

    if (body.approval.approved_at !== undefined && body.approval.approved_at !== null
        && typeof body.approval.approved_at !== 'string') {
      return fail('job.approval.approved_at', 'approval.approved_at must be a string or null.');
    }
  }

  return {
    ok: true,
    job: {
      jobId: body.job_id,
      scanId: body.scan_id,
      tool: body.tool,
      toolDefinition: tool,
      host,
      url: body.target.url ?? null,
      scheme,
      port,
      scope: {
        allowlist: scope.allowlist,
        lab_exceptions: scope.lab_exceptions,
      },
      pinnedIps,
      timeoutMs,
      approvalFingerprint,
    },
  };
}
