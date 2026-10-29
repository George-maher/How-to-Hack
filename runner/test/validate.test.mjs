import { describe, expect, it } from 'vitest';
import { validateJob } from '../src/validate.mjs';

const OPTIONS = { maxTimeoutMs: 600_000, defaultTimeoutMs: 120_000, allowedTools: [] };

const base = () => ({
  job_id: 'scan-1-nmap-a1b2c3d4',
  scan_id: 1,
  tool: 'nmap',
  target: { host: 'app.example.com', url: 'https://app.example.com/', port: 443 },
  scope: {
    allowlist: [{ id: 'a', host: 'app.example.com', ports: [443] }],
    lab_exceptions: [],
  },
});

const validate = (overrides = {}, options = OPTIONS) => validateJob({ ...base(), ...overrides }, options);

describe('job validation', () => {
  it('accepts a well-formed job', () => {
    const result = validate();

    expect(result.ok).toBe(true);
    expect(result.job.tool).toBe('nmap');
    expect(result.job.timeoutMs).toBe(120_000);
  });

  it('rejects a non-object body', () => {
    expect(validateJob([], OPTIONS)).toMatchObject({ ok: false, code: 'invalid_job', field: 'job' });
    expect(validateJob(null, OPTIONS)).toMatchObject({ ok: false, field: 'job' });
  });

  it('rejects unknown top-level fields instead of ignoring them', () => {
    const result = validate({ image: 'alpine', privileged: true });

    expect(result.ok).toBe(false);
    expect(result.field).toBe('job.image');
  });

  it('rejects unknown target fields', () => {
    expect(validate({ target: { host: 'app.example.com', port: 443, extra_flag: '-oN' } }).field)
      .toBe('job.target.extra_flag');
  });

  it('rejects unknown scope fields', () => {
    expect(validate({ scope: { allowlist: [], lab_exceptions: [], bypass: true } }).field)
      .toBe('job.scope.bypass');
  });

  it('rejects a malformed job id', () => {
    expect(validate({ job_id: 'short' }).field).toBe('job.job_id');
    expect(validate({ job_id: 'has spaces in it' }).field).toBe('job.job_id');
    expect(validate({ job_id: 'a'.repeat(65) }).field).toBe('job.job_id');
  });

  it('rejects a non-positive scan id', () => {
    expect(validate({ scan_id: 0 }).field).toBe('job.scan_id');
    expect(validate({ scan_id: '1' }).field).toBe('job.scan_id');
  });

  it('rejects a tool outside the registry', () => {
    expect(validate({ tool: 'bash' })).toMatchObject({ ok: false, field: 'job.tool' });
    expect(validate({ tool: 'sh -c id' })).toMatchObject({ ok: false, field: 'job.tool' });
  });

  it('enforces the per-runner tool allowlist when configured', () => {
    const result = validate({ tool: 'nmap' }, { ...OPTIONS, allowedTools: ['httpx'] });

    expect(result.ok).toBe(false);
    expect(result.field).toBe('job.tool');
  });

  it('requires a scope document', () => {
    expect(validate({ scope: undefined }).field).toBe('job.scope');
    expect(validate({ scope: { allowlist: [] } }).field).toBe('job.scope');
  });

  it('rejects an out-of-range port and a string port', () => {
    expect(validate({ target: { host: 'a.example.com', port: 70000 } }).field).toBe('job.target.port');
    expect(validate({ target: { host: 'a.example.com', port: '443' } }).field).toBe('job.target.port');
  });

  it('rejects a URL with credentials or a non-http scheme', () => {
    expect(validate({ target: { host: 'a.example.com', port: 443, url: 'https://u:p@a.example.com/' } }).field)
      .toBe('job.target.url');
    expect(validate({ target: { host: 'a.example.com', port: 443, url: 'file:///etc/passwd' } }).field)
      .toBe('job.target.url');
  });

  it('rejects a host containing shell metacharacters', () => {
    for (const host of ['a.example.com;id', 'a.example.com$(id)', 'a.example.com`id`', 'a b']) {
      expect(validate({ target: { host, port: 443 } }).ok).toBe(false);
    }
  });

  it('rejects pinned addresses that are not IPs', () => {
    expect(validate({ pinned_ips: ['not-an-ip'] }).field).toBe('job.pinned_ips');
    expect(validate({ pinned_ips: new Array(17).fill('93.184.216.34') }).field).toBe('job.pinned_ips');
  });

  it('clamps a long timeout to the tool ceiling', () => {
    // nmap declares a 300s ceiling of its own; the runner ceiling is 600s.
    const result = validate({ limits: { timeout_ms: 9_999_999 } });

    expect(result.ok).toBe(true);
    expect(result.job.timeoutMs).toBe(300_000);
  });

  it('clamps to the runner ceiling when it is lower than the tool ceiling', () => {
    const result = validate({ tool: 'nuclei', limits: { timeout_ms: 9_999_999 } }, {
      ...OPTIONS,
      maxTimeoutMs: 90_000,
    });

    expect(result.job.timeoutMs).toBe(90_000);
  });

  it('clamps a timeout to the tool maximum', () => {
    const result = validate({ tool: 'httpx', limits: { timeout_ms: 600_000 } });

    expect(result.job.timeoutMs).toBe(120_000);
  });

  it('rejects a sub-second timeout', () => {
    expect(validate({ limits: { timeout_ms: 500 } }).field).toBe('job.limits.timeout_ms');
  });

  it('rejects unknown limit keys', () => {
    expect(validate({ limits: { timeout_ms: 5000, memory_mb: 128 } }).field).toBe('job.limits.memory_mb');
  });

  it('defaults the port and URL when omitted', () => {
    const result = validate({ target: { host: 'app.example.com' } });

    expect(result.ok).toBe(true);
    expect(result.job.port).toBe(443);
    expect(result.job.url).toBeNull();
  });

  it('carries the approval fingerprint through without interpreting it', () => {
    const result = validate({ approval: { fingerprint: 'sha256:abc', approved_at: null } });

    expect(result.job.approvalFingerprint).toBe('sha256:abc');
  });

  it('accepts null for every optional section', () => {
    const result = validate({ pinned_ips: null, limits: null, approval: null });

    expect(result.ok).toBe(true);
    expect(result.job.pinnedIps).toBeNull();
    expect(result.job.approvalFingerprint).toBeNull();
  });

  it('rejects an approval object with an unknown key', () => {
    expect(validate({ approval: { fingerprint: 'x', forged: true } }).field).toBe('job.approval.forged');
  });
});
