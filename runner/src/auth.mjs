/**
 * Request authentication.
 *
 * Shared secret + HMAC over `timestamp.body`, compared in constant time, with a
 * bounded clock skew. The signature covers the body, so the target cannot be
 * swapped in flight; the timestamp means a captured request is useless after
 * the skew window.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

/** @param {string} secret @param {string} timestamp @param {string} body */
export function sign(secret, timestamp, body) {
  return createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
}

function constantTimeEqual(a, b) {
  const left = Buffer.from(String(a), 'utf8');
  const right = Buffer.from(String(b), 'utf8');

  if (left.length !== right.length) {
    // Still compare something fixed-length so the failure path is not a
    // trivially measurable early return.
    timingSafeEqual(left, left);
    return false;
  }

  return timingSafeEqual(left, right);
}

/**
 * @param {object} input
 * @param {string} input.secret
 * @param {string | undefined} input.timestamp
 * @param {string | undefined} input.signature
 * @param {string} input.body
 * @param {number} [input.skewSeconds]
 * @param {number} [input.now] epoch seconds
 * @returns {{ok: true} | {ok: false, code: string}}
 */
export function verifyRequest({ secret, timestamp, signature, body, skewSeconds = 300, now }) {
  if (!timestamp || !signature) {
    return { ok: false, code: 'missing_signature' };
  }

  if (!/^\d{1,12}$/.test(String(timestamp))) {
    return { ok: false, code: 'invalid_timestamp' };
  }

  const currentSeconds = now ?? Math.floor(Date.now() / 1000);
  const skew = Math.abs(currentSeconds - Number.parseInt(String(timestamp), 10));

  if (skew > skewSeconds) {
    return { ok: false, code: 'timestamp_out_of_window' };
  }

  const expected = sign(secret, String(timestamp), body);

  if (!constantTimeEqual(expected, signature)) {
    return { ok: false, code: 'invalid_signature' };
  }

  return { ok: true };
}
