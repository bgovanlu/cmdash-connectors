// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import {
  MAX_SIGNATURE_AGE_SECONDS,
  signCollectorPayload,
  verifyCollectorSignature,
} from './signature.js';

const SECRET = 'collector-secret-value';
const BODY = JSON.stringify({ observations: [{ externalId: 'a' }] });
const NOW = 1_800_000_000;

describe('collector push signatures', () => {
  it('verifies a signature it just produced', () => {
    const header = signCollectorPayload(BODY, SECRET, NOW);
    expect(verifyCollectorSignature(BODY, header, SECRET, NOW).valid).toBe(true);
  });

  it('rejects a body that changed after signing', () => {
    const header = signCollectorPayload(BODY, SECRET, NOW);
    const tampered = JSON.stringify({ observations: [{ externalId: 'b' }] });
    expect(verifyCollectorSignature(tampered, header, SECRET, NOW)).toMatchObject({
      valid: false,
      reason: 'mismatch',
    });
  });

  it('rejects the wrong secret', () => {
    const header = signCollectorPayload(BODY, SECRET, NOW);
    expect(verifyCollectorSignature(BODY, header, 'other-secret', NOW).valid).toBe(false);
  });

  it('rejects a replayed push once the window has passed', () => {
    // The timestamp is inside the signed payload, so an attacker cannot
    // simply refresh it — changing t invalidates the signature.
    const header = signCollectorPayload(BODY, SECRET, NOW);
    const later = NOW + MAX_SIGNATURE_AGE_SECONDS + 1;
    expect(verifyCollectorSignature(BODY, header, SECRET, later)).toMatchObject({
      valid: false,
      reason: 'expired',
    });
  });

  it('rejects a FUTURE timestamp as firmly as a stale one', () => {
    // Only rejecting old timestamps would let a hostile client mint a
    // signature that stays valid indefinitely.
    const header = signCollectorPayload(BODY, SECRET, NOW + 10_000);
    expect(verifyCollectorSignature(BODY, header, SECRET, NOW)).toMatchObject({
      valid: false,
      reason: 'expired',
    });
  });

  it('rejects a malformed or missing header without throwing', () => {
    for (const header of [undefined, '', 'garbage', 't=abc,v1=xx', 'v1=onlysig', 't=123']) {
      expect(() => verifyCollectorSignature(BODY, header, SECRET, NOW)).not.toThrow();
      expect(verifyCollectorSignature(BODY, header, SECRET, NOW).valid).toBe(false);
    }
  });

  it('does not throw on a length-mismatched signature', () => {
    // timingSafeEqual THROWS on differing lengths rather than returning
    // false, and a thrown exception is itself a timing signal. The length
    // check has to come first.
    const header = `t=${NOW},v1=short`;
    expect(() => verifyCollectorSignature(BODY, header, SECRET, NOW)).not.toThrow();
    expect(verifyCollectorSignature(BODY, header, SECRET, NOW).valid).toBe(false);
  });

  it('carries a version tag so a stronger scheme can be added later', () => {
    // The accepted trade-off is that a full database compromise could forge a
    // push. `v1` is what lets an asymmetric `v2` be introduced without
    // breaking collectors already deployed in customer networks.
    expect(signCollectorPayload(BODY, SECRET, NOW)).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
  });
});
