import { describe, expect, it } from 'vitest';
import { sign, verifyRequest } from '../src/auth.mjs';

const SECRET = 'a-secret-that-is-definitely-long-enough';
const BODY = JSON.stringify({ job_id: 'job-12345678', tool: 'nmap' });
const NOW = 1_800_000_000;

describe('request signing', () => {
  it('accepts a correctly signed request', () => {
    const timestamp = String(NOW);
    const signature = sign(SECRET, timestamp, BODY);

    expect(verifyRequest({ secret: SECRET, timestamp, signature, body: BODY, now: NOW }).ok).toBe(true);
  });

  it('rejects a missing signature', () => {
    expect(verifyRequest({ secret: SECRET, timestamp: String(NOW), signature: undefined, body: BODY, now: NOW }))
      .toEqual({ ok: false, code: 'missing_signature' });
  });

  it('rejects a missing timestamp', () => {
    expect(verifyRequest({ secret: SECRET, timestamp: undefined, signature: 'x', body: BODY, now: NOW }))
      .toEqual({ ok: false, code: 'missing_signature' });
  });

  it('rejects a non-numeric timestamp', () => {
    expect(verifyRequest({ secret: SECRET, timestamp: 'yesterday', signature: 'x', body: BODY, now: NOW }))
      .toEqual({ ok: false, code: 'invalid_timestamp' });
  });

  it('rejects a signature over different content', () => {
    const timestamp = String(NOW);
    const signature = sign(SECRET, timestamp, BODY);
    const tampered = BODY.replace('nmap', 'ffuf');

    expect(verifyRequest({ secret: SECRET, timestamp, signature, body: tampered, now: NOW }))
      .toEqual({ ok: false, code: 'invalid_signature' });
  });

  it('rejects a signature made with another secret', () => {
    const timestamp = String(NOW);
    const signature = sign('another-secret-entirely-000000', timestamp, BODY);

    expect(verifyRequest({ secret: SECRET, timestamp, signature, body: BODY, now: NOW }).ok).toBe(false);
  });

  it('rejects a stale timestamp (replay window)', () => {
    const timestamp = String(NOW - 3600);
    const signature = sign(SECRET, timestamp, BODY);

    expect(verifyRequest({ secret: SECRET, timestamp, signature, body: BODY, now: NOW }))
      .toEqual({ ok: false, code: 'timestamp_out_of_window' });
  });

  it('rejects a timestamp from the future', () => {
    const timestamp = String(NOW + 3600);
    const signature = sign(SECRET, timestamp, BODY);

    expect(verifyRequest({ secret: SECRET, timestamp, signature, body: BODY, now: NOW }))
      .toEqual({ ok: false, code: 'timestamp_out_of_window' });
  });

  it('accepts a timestamp inside the window', () => {
    const timestamp = String(NOW - 120);
    const signature = sign(SECRET, timestamp, BODY);

    expect(verifyRequest({ secret: SECRET, timestamp, signature, body: BODY, now: NOW }).ok).toBe(true);
  });

  it('is not confused by a short or padded signature', () => {
    const timestamp = String(NOW);
    const signature = sign(SECRET, timestamp, BODY);

    expect(verifyRequest({ secret: SECRET, timestamp, signature: signature.slice(0, 20), body: BODY, now: NOW }).ok)
      .toBe(false);
    expect(verifyRequest({ secret: SECRET, timestamp, signature: `${signature}00`, body: BODY, now: NOW }).ok)
      .toBe(false);
  });

  it('produces a stable, hex-encoded digest', () => {
    expect(sign(SECRET, String(NOW), BODY)).toMatch(/^[0-9a-f]{64}$/);
    expect(sign(SECRET, String(NOW), BODY)).toBe(sign(SECRET, String(NOW), BODY));
  });
});
