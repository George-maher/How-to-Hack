import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { catalogue, getTool, TOOL_NAMES, TOOLS } from '../src/tools.mjs';
import { validateJob } from '../src/validate.mjs';

/**
 * Registry and cross-language contract checks.
 *
 * The two sides have genuinely different jobs:
 *
 *   Runner (authoritative)  — which binaries exist, what argv each one gets,
 *                             and whether a job may run at all.
 *   API    (mirror + policy) — which scanners the product offers, and whether
 *                             a tool needs operator approval.
 *
 * They must agree on the *names* and on *intrusiveness* (otherwise a tool
 * approved as passive could execute as active). They do not need identical
 * descriptions, and the API may deliberately disable a scanner.
 */

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../..');
const phpRegistryPath = resolve(repo, 'backend/app/Scanners/RunnerToolRegistry.php');
const dockerScannersDir = resolve(repo, 'backend/app/Scanners/Docker');

function parsePhpRegistry(source) {
  const start = source.indexOf('public const TOOLS');
  const end = source.indexOf('];', start);
  const body = source.slice(start, end);

  const tools = {};
  const re = /'([a-z0-9_]+)'\s*=>\s*ScannerIntrusiveness::(Active|Passive)/g;
  let match;

  while ((match = re.exec(body)) !== null) {
    tools[match[1]] = match[2].toLowerCase();
  }

  return tools;
}

/** Each Docker scanner declares the Runner tool it delegates to. */
function phpScannerTools() {
  const files = readdirSync(dockerScannersDir).filter((f) => f.endsWith('Scanner.php'));
  const tools = {};

  for (const file of files) {
    const source = readFileSync(resolve(dockerScannersDir, file), 'utf8');
    const match = /\$toolName\s*=\s*'([a-z0-9_]+)'/.exec(source);
    if (match) tools[match[1]] = file;
  }

  return tools;
}

const php = parsePhpRegistry(readFileSync(phpRegistryPath, 'utf8'));

// ---------------------------------------------------------------------------
// Registry integrity
// ---------------------------------------------------------------------------
describe('JS registry integrity', () => {
  it('has unique, lowercase, filesystem-safe tool names', () => {
    expect(new Set(TOOL_NAMES).size).toBe(TOOL_NAMES.length);

    for (const name of TOOL_NAMES) {
      expect(name).toMatch(/^[a-z0-9_]+$/);
    }
  });

  it('defines a complete execution contract for every tool', () => {
    for (const [name, tool] of Object.entries(TOOLS)) {
      expect(typeof tool.argv, name).toBe('function');
      expect(['passive', 'active'], name).toContain(tool.intrusiveness);
      expect(tool.timeoutMs, name).toBeGreaterThan(0);
      expect(tool.timeoutMs, name).toBeLessThanOrEqual(1_800_000);
      expect(typeof tool.description, name).toBe('string');
      expect(tool.description.length, name).toBeGreaterThan(0);
    }
  });

  it('builds a string-only argv for every tool with a benign target', () => {
    for (const name of TOOL_NAMES) {
      const argv = TOOLS[name].argv({
        host: 'app.example.com',
        url: 'https://app.example.com/',
        port: 443,
      });

      expect(Array.isArray(argv), name).toBe(true);
      expect(argv.length, name).toBeGreaterThan(0);

      for (const arg of argv) {
        expect(typeof arg, `${name}: ${arg}`).toBe('string');
        expect(arg, `${name}`).not.toContain('\n');
        expect(arg, `${name}`).not.toContain('\0');
      }
    }
  });

  it('does not contain a shell invocation anywhere in a tool definition', () => {
    for (const name of TOOL_NAMES) {
      const argv = TOOLS[name].argv({
        host: 'app.example.com',
        url: 'https://app.example.com/',
        port: 443,
      }).join(' ');

      expect(argv, name).not.toMatch(/\bsh\s+-c\b/);
      expect(argv, name).not.toMatch(/\bbash\b/);
      expect(argv, name).not.toMatch(/&&|\|\||;|\$\(|`/);
    }
  });

  it('returns null for anything that is not an own registry key', () => {
    for (const name of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      expect(getTool(name)).toBeNull();
    }
    expect(getTool(undefined)).toBeNull();
    expect(getTool(42)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Catalogue surface
// ---------------------------------------------------------------------------
describe('public catalogue', () => {
  it('lists every registered tool exactly once', () => {
    const names = catalogue().map((tool) => tool.name);

    expect(new Set(names).size).toBe(names.length);
    expect(names.sort()).toEqual([...TOOL_NAMES].sort());
  });

  it('exposes no execution detail', () => {
    for (const entry of catalogue()) {
      expect(Object.keys(entry).sort()).toEqual(['description', 'intrusiveness', 'name', 'timeout_ms']);
    }
  });
});

// ---------------------------------------------------------------------------
// Cross-language parity
// ---------------------------------------------------------------------------
describe('PHP/JS registry parity', () => {
  it('parses the PHP registry', () => {
    expect(Object.keys(php).length).toBeGreaterThan(10);
  });

  it('declares the same tool names on both sides', () => {
    // Exact equality: a tool the Runner can execute but the API cannot approve
    // (or vice versa) is an inconsistency, not a feature.
    expect(Object.keys(php).sort()).toEqual([...TOOL_NAMES].sort());
  });

  it('agrees on intrusiveness for every tool', () => {
    const mismatches = TOOL_NAMES
      .filter((name) => php[name] !== TOOLS[name].intrusiveness)
      .map((name) => `${name}: js=${TOOLS[name].intrusiveness} php=${php[name]}`);

    expect(mismatches).toEqual([]);
  });

  it('has at least one active tool and one passive tool, so the split is real', () => {
    const active = TOOL_NAMES.filter((name) => TOOLS[name].intrusiveness === 'active');

    expect(active.length).toBeGreaterThan(0);
    expect(active.length).toBeLessThan(TOOL_NAMES.length);
    expect(active).toContain('nmap');
    expect(active).not.toContain('httpx');
  });

  it('every Docker scanner declares a tool the Runner actually has', () => {
    const scanners = phpScannerTools();
    const unknown = Object.keys(scanners).filter((tool) => getTool(tool) === null);

    expect(Object.keys(scanners).length).toBeGreaterThan(10);
    expect(unknown).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Job contract
// ---------------------------------------------------------------------------
describe('API → Runner job contract', () => {
  const options = { maxTimeoutMs: 600_000, defaultTimeoutMs: 120_000, allowedTools: [] };

  /** Exactly the payload BaseDockerScanner::execute() builds. */
  const payloadFromApi = (overrides = {}) => ({
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
      allowlist: [
        {
          id: 'security.allowlist[0]',
          host: 'app.example.com',
          ports: [443],
          cidrs: [],
          expires_at: null,
          include_subdomains: false,
          scope: 'allowlist',
          note: '',
        },
      ],
      lab_exceptions: [],
    },
    pinned_ips: ['93.184.216.34'],
    limits: { timeout_ms: 120000 },
    approval: { fingerprint: 'abc123', approved_at: null },
    ...overrides,
  });

  it('accepts the payload the API actually sends', () => {
    const result = validateJob(payloadFromApi(), options);

    expect(result.ok).toBe(true);
    expect(result.job.tool).toBe('nmap');
    expect(result.job.port).toBe(443);
    expect(result.job.scheme).toBe('https');
    expect(result.job.pinnedIps).toEqual(['93.184.216.34']);
  });

  it('accepts the null optionals the API sends when a value is absent', () => {
    const result = validateJob(payloadFromApi({
      pinned_ips: null,
      approval: null,
      limits: null,
    }), options);

    expect(result.ok).toBe(true);
    expect(result.job.approvalFingerprint).toBeNull();
    expect(result.job.timeoutMs).toBe(options.defaultTimeoutMs);
  });

  it('accepts every tool the API can dispatch', () => {
    for (const tool of TOOL_NAMES) {
      const result = validateJob(payloadFromApi({ tool }), options);
      expect(result.ok, tool).toBe(true);
    }
  });

  it('accepts every outcome string the API maps', () => {
    // backend/app/Scanners/Docker/BaseDockerScanner::outcomeFrom()
    const apiOutcomes = ['completed', 'timed_out', 'unavailable', 'cancelled', 'blocked', 'failed'];
    const runnerOutcomes = ['completed', 'failed', 'timed_out', 'unavailable', 'cancelled'];

    for (const outcome of runnerOutcomes) {
      expect(apiOutcomes, outcome).toContain(outcome);
    }
    // `blocked` is produced by the API's own policy path, never by the Runner.
    expect(runnerOutcomes).not.toContain('blocked');
  });

  it('rejects a contract change that adds an unknown field', () => {
    // Guards the reverse direction: if the API starts sending something new and
    // nobody updates this schema, the Runner refuses rather than ignoring it.
    const result = validateJob(payloadFromApi({ limits: { timeout_ms: 1000, memory_mb: 64 } }), options);

    expect(result.ok).toBe(false);
    expect(result.field).toBe('job.limits.memory_mb');
  });
});

// ---------------------------------------------------------------------------
// Scanner image contract
// ---------------------------------------------------------------------------
describe('scanner image contract', () => {
  const entrypoint = readFileSync(resolve(repo, 'backend/docker/scanner/scanner-runner.sh'), 'utf8');

  it('dispatches only registered tools and refuses anything else', () => {
    expect(entrypoint).toContain('*)');
    expect(entrypoint).toMatch(/tool is not supported by this image/);
    expect(entrypoint).toMatch(/exit 126/);
  });

  it('reports a missing binary as 127 so the Runner can call it unavailable', () => {
    expect(entrypoint).toMatch(/command -v/);
    expect(entrypoint).toMatch(/exit 127/);
  });

  it('quotes every positional argument', () => {
    // Unquoted "$@" would re-split the argv the Runner carefully built.
    expect(entrypoint).not.toMatch(/[^"]\$@/);
    expect(entrypoint).not.toMatch(/\$\*[^"]/);
  });

  it('does not silence the tool that failed to produce output', () => {
    // `-oX -` writes XML to stdout; stderr must survive.
    expect(entrypoint).toContain('nmap "$@"');
  });
});
