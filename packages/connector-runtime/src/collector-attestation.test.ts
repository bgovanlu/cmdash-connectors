// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, createHash } from 'node:crypto';
import {
  canonicalJson,
  collectorKeyIdOf,
  collectorSigningMessage,
  constantTimeEqual,
  countsOfStates,
  decodeBase64Url,
  ed25519Verify,
  encodeBase64Url,
  enrollmentMessage,
  isSpecTimestamp,
  measurementStatementProblem,
  measurementStates,
  parseCollectorSignatureHeader,
  pushV2Message,
  rotationMessage,
  signCollectorPayloadV2,
  signMeasurement,
  spkiOf,
  verifyCollectorPushV2,
  verifyMeasurement,
  COLLECTOR_ENROLL_TAG,
  COLLECTOR_MEASUREMENT_TAG,
  COLLECTOR_PUSH_TAG,
  COLLECTOR_ROTATE_TAG,
  type MeasurementStatement,
} from './collector-attestation.js';
import { verifyCollectorSignature } from './signature.js';

const NOW = 1_800_000_000;
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const SPKI = spkiOf(publicKey);
const KID = collectorKeyIdOf(SPKI);
const IDENTITY = {
  deployment: 'https://cmdash.example',
  tenantRef: `tr_${'a'.repeat(32)}`,
  collectorKeyId: KID,
};

function statement(over: Partial<MeasurementStatement> = {}): MeasurementStatement {
  return {
    v: 0,
    deployment: IDENTITY.deployment,
    tenantRef: IDENTITY.tenantRef,
    collectorKeyId: KID,
    metric: 'edr-coverage',
    numerator: 3,
    denominator: 5,
    unknown: 1,
    measuredAt: '2027-01-15T10:00:00.000Z',
    seq: 42,
    nonce: '0123456789abcdef0123456789abcdef',
    ...over,
  };
}

describe('canonical messages (K1: domain-separated, length-unambiguous)', () => {
  it('sorts members by UTF-16 code unit and writes no whitespace', () => {
    expect(canonicalJson({ b: 1, a: 'x', A: [2, 'y'] })).toBe('{"A":[2,"y"],"a":"x","b":1}');
    // U+1F600 (D83D DE00) sorts before U+FF61 in UTF-16 order.
    expect(canonicalJson({ '｡': 1, '\u{1f600}': 2 })).toBe('{"\u{1f600}":2,"｡":1}');
  });

  it('refuses every value outside the admitted subset instead of coercing it', () => {
    for (const bad of [null, true, 1.5, -0, 2 ** 53, undefined, new Date(0), Buffer.from('x'), new Map(), '\ud800']) {
      expect(() => canonicalJson({ x: bad })).toThrow();
    }
    expect(() => canonicalJson({ '\udc00': 1 })).toThrow();
    let deep: unknown = 1;
    for (let i = 0; i < 70; i += 1) deep = [deep];
    expect(() => canonicalJson(deep)).toThrow(/deeper/);
  });

  it('is unambiguous: moving a character between two fields changes the bytes', () => {
    const a = collectorSigningMessage(COLLECTOR_PUSH_TAG, { a: 'x,', b: 'y' });
    const b = collectorSigningMessage(COLLECTOR_PUSH_TAG, { a: 'x', b: ',y' });
    expect(a.equals(b)).toBe(false);
    // Quotes and backslashes are escaped, so a value can never close its own member.
    const c = collectorSigningMessage(COLLECTOR_PUSH_TAG, { a: 'x","b":"y' });
    const d = collectorSigningMessage(COLLECTOR_PUSH_TAG, { a: 'x', b: 'y' });
    expect(c.equals(d)).toBe(false);
  });

  it('prefixes every message with its own domain tag, so no signature crosses purposes', () => {
    const tags = [COLLECTOR_ENROLL_TAG, COLLECTOR_ROTATE_TAG, COLLECTOR_PUSH_TAG, COLLECTOR_MEASUREMENT_TAG];
    expect(new Set(tags).size).toBe(4);
    for (const t of tags) expect(t.endsWith('\n')).toBe(true);
    const e = enrollmentMessage({ enrollmentId: 'e', publicKey: 'p', tokenSha256: 'h' });
    expect(e.toString('utf8')).toBe(`${COLLECTOR_ENROLL_TAG}{"enrollmentId":"e","publicKey":"p","tokenSha256":"h"}`);
    const r = rotationMessage({ ...IDENTITY, enrollmentId: 'e', oldCollectorKeyId: KID, newPublicKey: 'p', t: 5 });
    expect(r.toString('utf8').startsWith(COLLECTOR_ROTATE_TAG)).toBe(true);
    const p = pushV2Message({ ...IDENTITY, seq: 1, nonce: 'n', t: 2, bodySha256: 'h' });
    expect(p.toString('utf8')).toBe(
      `${COLLECTOR_PUSH_TAG}{"bodySha256":"h","collectorKeyId":"${KID}","deployment":"https://cmdash.example","nonce":"n","seq":1,"t":2,"tenantRef":"${IDENTITY.tenantRef}"}`,
    );
    // A measurement signature does not verify as a push signature over the same fields.
    const signed = signMeasurement(privateKey, statement());
    const bytes = decodeBase64Url(signed.statement)!;
    const sig = decodeBase64Url(signed.sig)!;
    expect(ed25519Verify(SPKI, Buffer.concat([Buffer.from(COLLECTOR_PUSH_TAG), bytes]), sig)).toBe(false);
  });

  it('decodes only canonical base64url', () => {
    expect(decodeBase64Url('AA')).toEqual(Buffer.from([0]));
    expect(decodeBase64Url('AB')).toBeNull(); // spare bits set
    expect(decodeBase64Url('AA==')).toBeNull();
    expect(decodeBase64Url('A')).toBeNull();
    expect(decodeBase64Url(7)).toBeNull();
    expect(encodeBase64Url(Buffer.from([0xfb, 0xff]))).toBe('-_8');
  });

  it('checks spec timestamps by the toISOString round trip', () => {
    expect(isSpecTimestamp('2027-01-15T10:00:00.000Z')).toBe(true);
    expect(isSpecTimestamp('2027-02-30T10:00:00.000Z')).toBe(false);
    expect(isSpecTimestamp('2027-01-15T10:00:00Z')).toBe(false);
    expect(isSpecTimestamp(3)).toBe(false);
  });

  it('compares in constant time and never throws on a length mismatch', () => {
    expect(constantTimeEqual('abc', 'abc')).toBe(true);
    expect(constantTimeEqual('abc', 'abd')).toBe(false);
    expect(constantTimeEqual('abc', 'abcd')).toBe(false);
  });
});

describe('measurements', () => {
  it('maps JSON true/false to MET/NOT_MET and everything else to UNKNOWN (unknown is never pass)', () => {
    const states = measurementStates([true, false, 'true', 1, null, undefined, true]);
    expect(states).toEqual(['MET', 'NOT_MET', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'MET']);
    expect(countsOfStates(states)).toEqual({ numerator: 2, denominator: 7, unknown: 4 });
  });

  it('signs and verifies a statement; the collector key id is derived from the SPKI', () => {
    expect(KID).toMatch(/^cmdash-collector-[0-9a-f]{16}$/);
    expect(KID).toBe(`cmdash-collector-${createHash('sha256').update(SPKI).digest('hex').slice(0, 16)}`);
    const signed = signMeasurement(privateKey, statement());
    const v = verifyMeasurement(SPKI, signed);
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.statement.numerator).toBe(3);
  });

  it('refuses a tampered, re-encoded, re-keyed or malformed statement', () => {
    const signed = signMeasurement(privateKey, statement());
    const bytes = decodeBase64Url(signed.statement)!;
    const tampered = Buffer.from(bytes.toString('utf8').replace('"numerator":3', '"numerator":4'));
    expect(verifyMeasurement(SPKI, { statement: encodeBase64Url(tampered), sig: signed.sig })).toMatchObject({ ok: false, problem: 'signature does not verify' });
    const spaced = Buffer.from(bytes.toString('utf8').replace('{', '{ '));
    expect(verifyMeasurement(SPKI, { statement: encodeBase64Url(spaced), sig: signed.sig })).toMatchObject({ ok: false, problem: 'statement bytes are not canonical' });
    const other = spkiOf(generateKeyPairSync('ed25519').publicKey);
    expect(verifyMeasurement(other, signed)).toMatchObject({ ok: false, problem: 'statement names another collector key' });
    expect(verifyMeasurement(SPKI, { statement: signed.statement, sig: 'AA' })).toMatchObject({ ok: false });
    expect(verifyMeasurement(SPKI, { statement: '', sig: signed.sig })).toMatchObject({ ok: false });
    expect(verifyMeasurement(SPKI, { statement: encodeBase64Url(Buffer.from([0xff])), sig: signed.sig })).toMatchObject({ ok: false, problem: 'statement is not UTF-8 JSON' });
    expect(verifyMeasurement(SPKI, { statement: encodeBase64Url(Buffer.from('{"a":1.5}')), sig: signed.sig })).toMatchObject({ ok: false, problem: 'statement has no canonical form' });
    expect(verifyMeasurement(SPKI, { statement: encodeBase64Url(Buffer.from('{"a":1}')), sig: signed.sig })).toMatchObject({ ok: false });
  });

  it('holds the statement to exactly its members and ranges', () => {
    expect(measurementStatementProblem(statement())).toBeNull();
    expect(measurementStatementProblem(null)).toBe('not an object');
    expect(measurementStatementProblem({ ...statement(), extra: 1 })).toMatch(/exactly/);
    const bad: Array<[Partial<MeasurementStatement> | Record<string, unknown>, RegExp]> = [
      [{ v: 1 as 0 }, /^v/],
      [{ deployment: '' }, /deployment/],
      [{ tenantRef: 'tenant-uuid' }, /tenantRef/],
      [{ collectorKeyId: 'cmdash-proof-0000000000000000' }, /collectorKeyId/],
      [{ metric: 'Bad Metric' }, /metric/],
      [{ numerator: -1 }, /counts/],
      [{ numerator: 5, unknown: 1, denominator: 5 }, /exceeds/],
      [{ measuredAt: '2027-02-30T10:00:00.000Z' }, /measuredAt/],
      [{ seq: 0 }, /seq/],
      [{ nonce: 'xyz' }, /nonce/],
    ];
    for (const [over, re] of bad) expect(measurementStatementProblem(statement(over as Partial<MeasurementStatement>))).toMatch(re);
    expect(() => signMeasurement(privateKey, statement({ seq: 0 }))).toThrow(/not a measurement statement/);
  });
});

describe('v2 push signatures', () => {
  const BODY = JSON.stringify({ connectorId: 'cc-1', mapped: [] });
  const opts = { t: NOW, seq: 7, nonce: 'ffeeddccbbaa99887766554433221100' };
  const key = { ...IDENTITY, spki: SPKI };

  it('carries a v1 HMAC a v1 verifier still accepts, and a v2 Ed25519 signature', () => {
    const header = signCollectorPayloadV2(BODY, 'secret', { ...IDENTITY, privateKey }, opts);
    expect(verifyCollectorSignature(BODY, header, 'secret', NOW).valid).toBe(true);
    expect(verifyCollectorPushV2(BODY, header, key, NOW)).toEqual({ valid: true, seq: 7, nonce: opts.nonce, t: NOW });
  });

  it('names a v1-only header as such, so the server can refuse the downgrade', () => {
    expect(verifyCollectorPushV2(BODY, `t=${NOW},v1=abcd`, key, NOW)).toEqual({ valid: false, reason: 'v1-only' });
  });

  it('refuses a changed body, another tenant, another key, a stale time or a malformed header', () => {
    const header = signCollectorPayloadV2(BODY, 'secret', { ...IDENTITY, privateKey }, opts);
    expect(verifyCollectorPushV2(`${BODY} `, header, key, NOW)).toMatchObject({ reason: 'mismatch' });
    // The tenant is inside the signed message: the same signature does not verify for another tenantRef.
    expect(verifyCollectorPushV2(BODY, header, { ...key, tenantRef: `tr_${'b'.repeat(32)}` }, NOW)).toMatchObject({ reason: 'mismatch' });
    expect(verifyCollectorPushV2(BODY, header, { ...key, collectorKeyId: 'cmdash-collector-0000000000000000' }, NOW)).toMatchObject({ reason: 'wrong-key' });
    expect(verifyCollectorPushV2(BODY, header, key, NOW + 301)).toMatchObject({ reason: 'expired' });
    // seq is signed: bumping it to dodge the replay check breaks the signature.
    expect(verifyCollectorPushV2(BODY, header.replace('seq=7', 'seq=8'), key, NOW)).toMatchObject({ reason: 'mismatch' });
    for (const bad of [undefined, '', 'garbage', `${header},t=1`, header.replace('seq=7', 'seq=07'), header.replace(/n=[0-9a-f]+/, 'n=zz'), header.replace(/v2=[^,]+/, 'v2=AA')]) {
      expect(verifyCollectorPushV2(BODY, bad, key, NOW)).toMatchObject({ valid: false });
    }
  });

  it('parses header segments strictly: a repeated name is malformed', () => {
    expect(parseCollectorSignatureHeader('t=1,v1=a')?.get('v1')).toBe('a');
    expect(parseCollectorSignatureHeader('t=1,t=2')).toBeNull();
    expect(parseCollectorSignatureHeader('t')).toBeNull();
    expect(parseCollectorSignatureHeader('x'.repeat(2000))).toBeNull();
  });
});
