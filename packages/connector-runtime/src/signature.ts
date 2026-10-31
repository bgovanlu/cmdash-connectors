// SPDX-License-Identifier: Apache-2.0
import { createHmac, timingSafeEqual } from 'node:crypto';

/**
 * ROADMAP-COMPETITIVE bet 1 item 1.3 — the collector's push signature.
 *
 * HMAC-SHA256 over `${unixSeconds}.${rawBody}`, header shaped
 * `t=<unixSeconds>,v1=<hex>`. This is deliberately the SAME construction
 * `webhook-delivery.service.ts` already uses for outbound webhooks, reused
 * rather than reinvented: one signing convention for the whole product means
 * one thing for a security reviewer to understand, and one place to fix if it
 * is ever wrong.
 *
 * The timestamp is inside the signed payload, not merely alongside it, so a
 * captured push cannot be replayed later with a fresh timestamp — changing it
 * invalidates the signature.
 *
 * The settled trade-off (bet 1's open question 8): a symmetric secret means a
 * full CMDash database compromise could forge a collector push, where Ed25519
 * would not. That was accepted in exchange for a single convention and less
 * new code. If a security review ever demands the stronger property, the
 * header carries a version tag (`v1`) precisely so a `v2` can be added
 * without breaking deployed collectors.
 */

/** Pushes older than this are refused outright, signature or not. */
export const MAX_SIGNATURE_AGE_SECONDS = 300;

export function buildSignedPayload(timestampSec: number, rawBody: string): string {
  return `${timestampSec}.${rawBody}`;
}

/** Produce the `X-CMDash-Collector-Signature` header value. */
export function signCollectorPayload(
  rawBody: string,
  secret: string,
  timestampSec: number = Math.floor(Date.now() / 1000),
): string {
  const sig = createHmac('sha256', secret)
    .update(buildSignedPayload(timestampSec, rawBody))
    .digest('hex');
  return `t=${timestampSec},v1=${sig}`;
}

export interface SignatureVerification {
  valid: boolean;
  /** Why it failed, for the server log — never returned to the caller, which
   * gets an undifferentiated 401. Telling an attacker whether the timestamp
   * or the signature was wrong is free information. */
  reason?: 'malformed' | 'expired' | 'mismatch';
}

/**
 * Verify a collector push.
 *
 * Compares in constant time via `timingSafeEqual`, after a length check —
 * that function throws on a length mismatch rather than returning false, and
 * a thrown exception is itself a timing signal.
 */
export function verifyCollectorSignature(
  rawBody: string,
  header: string | undefined,
  secret: string,
  nowSec: number = Math.floor(Date.now() / 1000),
): SignatureVerification {
  if (!header) return { valid: false, reason: 'malformed' };

  const parts = new Map<string, string>();
  for (const segment of header.split(',')) {
    const [k, v] = segment.split('=');
    if (k && v) parts.set(k.trim(), v.trim());
  }

  const t = Number(parts.get('t'));
  const provided = parts.get('v1');
  if (!Number.isFinite(t) || !provided) return { valid: false, reason: 'malformed' };

  // Checked in BOTH directions: a far-future timestamp is as much a replay
  // signal as a stale one, and only rejecting old ones lets a clock-skewed
  // or hostile client mint a signature valid indefinitely.
  if (Math.abs(nowSec - t) > MAX_SIGNATURE_AGE_SECONDS) {
    return { valid: false, reason: 'expired' };
  }

  const expected = createHmac('sha256', secret)
    .update(buildSignedPayload(t, rawBody))
    .digest('hex');

  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return { valid: false, reason: 'mismatch' };
  return timingSafeEqual(a, b) ? { valid: true } : { valid: false, reason: 'mismatch' };
}
