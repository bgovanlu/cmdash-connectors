// SPDX-License-Identifier: Apache-2.0
import {
  createHash,
  createHmac,
  createPublicKey,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from 'node:crypto';
import { MAX_SIGNATURE_AGE_SECONDS } from './signature.js';

/**
 * ROADMAP-BLUE-OCEAN K1 — the collector's Ed25519 identity, the `v2` push
 * signature and the portable measurement attestation
 * (docs/specs/collector-attestation-v0.md).
 *
 * One key pair per collector, generated INSIDE the customer's boundary by
 * packages/collector-cli; CMDash stores the public key only. The key signs
 * four kinds of message and nothing else, each under its own domain tag, so a
 * signature made for one purpose can never be presented as another:
 *
 *   cmdash-collector-enroll-v0\n       proof of possession at registration
 *   cmdash-collector-rotate-v0\n       the old key endorsing its successor
 *   cmdash-collector-push-v2\n         one push (the `v2=` of the header)
 *   cmdash-collector-measurement-v0\n  one measurement, portable into a receipt
 *
 * message = UTF-8(tag) || canonical(fields)
 *
 * The fields are a JSON object in the receipt spec's canonical form (§3 of
 * docs/specs/proof-receipt-v0.md): strings and safe integers only, members
 * sorted by UTF-16 code unit, no whitespace. That form is length-unambiguous
 * by construction — every string is quoted and escaped, every member is
 * named — so no two different field sets serialize to the same bytes (the
 * `${t}.${body}` concatenation of v1 is only unambiguous because `t` is
 * digits).
 *
 * HMAC (`v1=`) stays on every push for transport authentication; the Ed25519
 * signature is what a CMDash database compromise cannot forge.
 */

export const COLLECTOR_KEY_ID_PREFIX = 'cmdash-collector-';
export const COLLECTOR_KEY_ID_RE = /^cmdash-collector-[0-9a-f]{16}$/;

export const COLLECTOR_ENROLL_TAG = 'cmdash-collector-enroll-v0\n';
export const COLLECTOR_ROTATE_TAG = 'cmdash-collector-rotate-v0\n';
export const COLLECTOR_PUSH_TAG = 'cmdash-collector-push-v2\n';
export const COLLECTOR_MEASUREMENT_TAG = 'cmdash-collector-measurement-v0\n';

/** A measurement older than this at push time is refused: the collector measures, then pushes. */
export const MAX_MEASUREMENT_AGE_SECONDS = 86_400;
/** The largest population one attested measurement may count (= MAX_VALUES_PER_MAPPING). */
export const MAX_ATTESTED_ITEMS = 1_000;

const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const TENANT_REF_RE = /^tr_[0-9a-f]{32}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const METRIC_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;

/**
 * The metrics a collector attests: a field mapping whose `targetField` is one
 * of these names, over JSON booleans, becomes a signed count. Everything else
 * is pushed as before, unattested. Each has a registered claim generator
 * (apps/api/src/proof/receipts/generators/collector/).
 */
export const ATTESTABLE_METRICS: Readonly<Record<string, { unit: string }>> = Object.freeze({
  'edr-coverage': { unit: 'host' },
  'mfa-enrolled': { unit: 'user' },
});

export type MeasurementState = 'MET' | 'NOT_MET' | 'UNKNOWN';

/** The fields a collector signs about one measurement (spec §3). */
export interface MeasurementStatement {
  v: 0;
  /** The issuing deployment's origin, as the receipt names it (`issuer.deployment`). */
  deployment: string;
  /** The tenant's public issuer id (`issuer.tenantRef`), never the internal tenant id. */
  tenantRef: string;
  collectorKeyId: string;
  metric: string;
  numerator: number;
  denominator: number;
  unknown: number;
  /** When the collector read the target, §4 form. A receipt's observedAt must equal it. */
  measuredAt: string;
  /** The sequence number of the push that carried it. */
  seq: number;
  /** 16 random bytes, lowercase hex: one measurement, one nonce. */
  nonce: string;
}

export class CollectorCanonicalError extends Error {}

// ─── encoding ────────────────────────────────────────────────────────────────

function isWellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i += 1;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * The receipt spec's canonical JSON (§3) for the values this module builds:
 * plain objects, arrays, well-formed strings and safe integers other than -0.
 * Anything else is refused, never coerced.
 */
export function canonicalJson(value: unknown, depth = 0): string {
  if (depth > 64) throw new CollectorCanonicalError('nesting deeper than 64');
  if (typeof value === 'string') {
    if (!isWellFormed(value)) throw new CollectorCanonicalError('a string with a lone surrogate');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new CollectorCanonicalError(`${String(value)} is not a safe integer`);
    }
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v, depth + 1)).join(',')}]`;
  if (value !== null && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const entries = Object.keys(value as Record<string, unknown>).sort();
    return `{${entries
      .map((k) => {
        if (!isWellFormed(k)) throw new CollectorCanonicalError('a member name with a lone surrogate');
        return `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k], depth + 1)}`;
      })
      .join(',')}}`;
  }
  throw new CollectorCanonicalError(`${typeof value} is not admitted in a signed message`);
}

/** `UTF-8(tag) || canonical(fields)`: the only bytes a collector key ever signs. */
export function collectorSigningMessage(tag: string, fields: Record<string, unknown>): Buffer {
  return Buffer.concat([Buffer.from(tag, 'utf8'), Buffer.from(canonicalJson(fields), 'utf8')]);
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** Strict: the canonical unpadded spelling only (a lenient decoder reads `…AB` and `…AA` alike). */
export function decodeBase64Url(s: unknown): Buffer | null {
  if (typeof s !== 'string' || !B64URL_RE.test(s) || s.length % 4 === 1) return null;
  const bytes = Buffer.from(s, 'base64url');
  return bytes.toString('base64url') === s ? bytes : null;
}

export function sha256Hex(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Constant-time string equality (lengths compared first: timingSafeEqual throws on a mismatch). */
export function constantTimeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  if (x.length !== y.length) return false;
  return timingSafeEqual(x, y);
}

// ─── keys ────────────────────────────────────────────────────────────────────

/** The 44-byte DER SPKI of an Ed25519 key (a private key yields its public half). */
export function spkiOf(key: KeyObject): Buffer {
  const pub = key.type === 'public' ? key : createPublicKey(key);
  return pub.export({ type: 'spki', format: 'der' });
}

/** `cmdash-collector-` + the first 16 hex of SHA-256(DER SPKI): derived, never configured. */
export function collectorKeyIdOf(spki: Uint8Array): string {
  return `${COLLECTOR_KEY_ID_PREFIX}${sha256Hex(spki).slice(0, 16)}`;
}

/** True for exactly the 44-byte Ed25519 SPKI shape (point checks are the server's). */
export function isEd25519Spki(spki: Uint8Array): boolean {
  const der = Buffer.from(spki);
  return der.length === 44 && der.subarray(0, 12).equals(SPKI_ED25519_PREFIX);
}

function publicKeyOfSpki(spki: Uint8Array): KeyObject | null {
  if (!isEd25519Spki(spki)) return null;
  try {
    return createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}

export function ed25519Sign(privateKey: KeyObject, message: Uint8Array): Buffer {
  return sign(null, message, privateKey);
}

/** Never throws: a malformed key or signature is `false`. */
export function ed25519Verify(spki: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  if (signature.length !== 64) return false;
  const key = publicKeyOfSpki(spki);
  if (!key) return false;
  try {
    return verify(null, message, key, signature) === true;
  } catch {
    return false;
  }
}

// ─── timestamps ──────────────────────────────────────────────────────────────

/** §4: `YYYY-MM-DDTHH:MM:SS.sssZ` naming a real instant (the toISOString round trip). */
export function isSpecTimestamp(s: unknown): s is string {
  if (typeof s !== 'string' || !TIMESTAMP_RE.test(s)) return false;
  const t = Date.parse(s);
  return Number.isFinite(t) && new Date(t).toISOString() === s && s >= '1970';
}

// ─── measurements ────────────────────────────────────────────────────────────

/**
 * One state per mapped value: JSON `true` meets, JSON `false` fails, and
 * anything else — a string, a number, null, a missing value — is UNKNOWN.
 * Unknown is never pass: it is counted in the denominator, never the numerator.
 */
export function measurementStates(values: readonly unknown[]): MeasurementState[] {
  return values.map((v) => (v === true ? 'MET' : v === false ? 'NOT_MET' : 'UNKNOWN'));
}

export function countsOfStates(states: readonly string[]): {
  numerator: number;
  denominator: number;
  unknown: number;
} {
  let numerator = 0;
  let unknown = 0;
  for (const s of states) {
    if (s === 'MET') numerator += 1;
    else if (s !== 'NOT_MET') unknown += 1;
  }
  return { numerator, denominator: states.length, unknown };
}

const STATEMENT_MEMBERS = [
  'collectorKeyId',
  'denominator',
  'deployment',
  'measuredAt',
  'metric',
  'nonce',
  'numerator',
  'seq',
  'tenantRef',
  'unknown',
  'v',
] as const;

const isCount = (n: unknown): n is number =>
  typeof n === 'number' && Number.isSafeInteger(n) && n >= 0 && n <= 1_000_000_000;

/** Why a decoded object is not a measurement statement, or null. Exactly the members above, typed. */
export function measurementStatementProblem(v: unknown): string | null {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return 'not an object';
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  if (keys.length !== STATEMENT_MEMBERS.length || keys.some((k, i) => k !== STATEMENT_MEMBERS[i])) {
    return `members must be exactly ${STATEMENT_MEMBERS.join(', ')}`;
  }
  if (o.v !== 0) return 'v must be 0';
  if (typeof o.deployment !== 'string' || o.deployment.length < 1 || o.deployment.length > 300) return 'deployment';
  if (typeof o.tenantRef !== 'string' || !TENANT_REF_RE.test(o.tenantRef)) return 'tenantRef';
  if (typeof o.collectorKeyId !== 'string' || !COLLECTOR_KEY_ID_RE.test(o.collectorKeyId)) return 'collectorKeyId';
  if (typeof o.metric !== 'string' || !METRIC_RE.test(o.metric)) return 'metric';
  if (!isCount(o.numerator) || !isCount(o.denominator) || !isCount(o.unknown)) return 'counts must be integers 0..10^9';
  if (o.numerator + o.unknown > o.denominator) return 'numerator + unknown exceeds denominator';
  if (!isSpecTimestamp(o.measuredAt)) return 'measuredAt';
  if (typeof o.seq !== 'number' || !Number.isSafeInteger(o.seq) || o.seq < 1) return 'seq';
  if (typeof o.nonce !== 'string' || !NONCE_RE.test(o.nonce)) return 'nonce';
  return null;
}

export interface SignedMeasurement {
  /** base64url of the canonical statement bytes: the bytes are signed, not an object. */
  statement: string;
  /** base64url of the 64-byte Ed25519 signature over the measurement tag and those bytes. */
  sig: string;
}

export function signMeasurement(privateKey: KeyObject, statement: MeasurementStatement): SignedMeasurement {
  const problem = measurementStatementProblem(statement);
  if (problem) throw new CollectorCanonicalError(`not a measurement statement: ${problem}`);
  const bytes = Buffer.from(canonicalJson(statement), 'utf8');
  const sig = ed25519Sign(privateKey, Buffer.concat([Buffer.from(COLLECTOR_MEASUREMENT_TAG, 'utf8'), bytes]));
  return { statement: encodeBase64Url(bytes), sig: encodeBase64Url(sig) };
}

export type MeasurementVerification =
  | { ok: true; statement: MeasurementStatement; statementBytes: Buffer; signature: Buffer }
  | { ok: false; problem: string };

/**
 * Decode and verify one signed measurement against a registered public key:
 * the bytes must be canonical (a re-serialization is byte-identical), the
 * statement well formed and naming this key, and the signature valid.
 */
export function verifyMeasurement(spki: Uint8Array, signed: { statement?: unknown; sig?: unknown }): MeasurementVerification {
  const statementBytes = decodeBase64Url(signed?.statement);
  const signature = decodeBase64Url(signed?.sig);
  if (!statementBytes || statementBytes.length === 0 || statementBytes.length > 4096) {
    return { ok: false, problem: 'statement is not canonical base64url of 1..4096 bytes' };
  }
  if (!signature || signature.length !== 64) return { ok: false, problem: 'sig is not base64url of 64 bytes' };
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(statementBytes));
  } catch {
    return { ok: false, problem: 'statement is not UTF-8 JSON' };
  }
  let recanonical: string;
  try {
    recanonical = canonicalJson(parsed);
  } catch {
    return { ok: false, problem: 'statement has no canonical form' };
  }
  if (!Buffer.from(recanonical, 'utf8').equals(statementBytes)) return { ok: false, problem: 'statement bytes are not canonical' };
  const problem = measurementStatementProblem(parsed);
  if (problem) return { ok: false, problem: `statement: ${problem}` };
  const statement = parsed as MeasurementStatement;
  if (statement.collectorKeyId !== collectorKeyIdOf(spki)) {
    return { ok: false, problem: 'statement names another collector key' };
  }
  const message = Buffer.concat([Buffer.from(COLLECTOR_MEASUREMENT_TAG, 'utf8'), statementBytes]);
  if (!ed25519Verify(spki, message, signature)) return { ok: false, problem: 'signature does not verify' };
  return { ok: true, statement, statementBytes, signature };
}

// ─── enrollment and rotation ─────────────────────────────────────────────────

/** Proof of possession at registration: binds the key to ONE enrollment and ONE token. */
export function enrollmentMessage(fields: { enrollmentId: string; publicKey: string; tokenSha256: string }): Buffer {
  return collectorSigningMessage(COLLECTOR_ENROLL_TAG, {
    enrollmentId: fields.enrollmentId,
    publicKey: fields.publicKey,
    tokenSha256: fields.tokenSha256,
  });
}

/** Rotation, signed by BOTH the old key (authority) and the new one (possession). */
export function rotationMessage(fields: {
  deployment: string;
  tenantRef: string;
  enrollmentId: string;
  oldCollectorKeyId: string;
  newPublicKey: string;
  t: number;
}): Buffer {
  return collectorSigningMessage(COLLECTOR_ROTATE_TAG, {
    deployment: fields.deployment,
    enrollmentId: fields.enrollmentId,
    newPublicKey: fields.newPublicKey,
    oldCollectorKeyId: fields.oldCollectorKeyId,
    t: fields.t,
    tenantRef: fields.tenantRef,
  });
}

// ─── the v2 push signature ───────────────────────────────────────────────────

export interface CollectorIdentityBinding {
  deployment: string;
  tenantRef: string;
  collectorKeyId: string;
}

export interface PushV2Fields extends CollectorIdentityBinding {
  seq: number;
  nonce: string;
  t: number;
  bodySha256: string;
}

export function pushV2Message(f: PushV2Fields): Buffer {
  return collectorSigningMessage(COLLECTOR_PUSH_TAG, {
    bodySha256: f.bodySha256,
    collectorKeyId: f.collectorKeyId,
    deployment: f.deployment,
    nonce: f.nonce,
    seq: f.seq,
    t: f.t,
    tenantRef: f.tenantRef,
  });
}

/**
 * The `X-CMDash-Collector-Signature` header of a v2 push:
 * `t=<sec>,v1=<hmac hex>,kid=<collector key id>,seq=<n>,n=<nonce>,v2=<base64url>`.
 * `v1` is exactly the v1 HMAC (transport), so a v1 verifier reads it unchanged.
 */
export function signCollectorPayloadV2(
  rawBody: string,
  hmacSecret: string,
  identity: CollectorIdentityBinding & { privateKey: KeyObject },
  opts: { t: number; seq: number; nonce: string },
): string {
  const hmac = createHmac('sha256', hmacSecret).update(`${opts.t}.${rawBody}`).digest('hex');
  const message = pushV2Message({
    deployment: identity.deployment,
    tenantRef: identity.tenantRef,
    collectorKeyId: identity.collectorKeyId,
    seq: opts.seq,
    nonce: opts.nonce,
    t: opts.t,
    bodySha256: sha256Hex(Buffer.from(rawBody, 'utf8')),
  });
  const v2 = encodeBase64Url(ed25519Sign(identity.privateKey, message));
  return `t=${opts.t},v1=${hmac},kid=${identity.collectorKeyId},seq=${opts.seq},n=${opts.nonce},v2=${v2}`;
}

/** The header's `k=v` segments. A repeated name makes the header malformed (null). */
export function parseCollectorSignatureHeader(header: string | undefined): Map<string, string> | null {
  if (!header || header.length > 1024) return null;
  const parts = new Map<string, string>();
  for (const segment of header.split(',')) {
    const eq = segment.indexOf('=');
    if (eq <= 0) return null;
    const k = segment.slice(0, eq).trim();
    const v = segment.slice(eq + 1).trim();
    if (!k || !v || parts.has(k)) return null;
    parts.set(k, v);
  }
  return parts;
}

export type PushV2Verification =
  | { valid: true; seq: number; nonce: string; t: number }
  | { valid: false; reason: 'v1-only' | 'malformed' | 'expired' | 'wrong-key' | 'mismatch' };

/**
 * Verify the Ed25519 half of a v2 push for ONE enrollment's registered key.
 * The HMAC half is checked separately (verifyCollectorSignature), and both
 * must pass. `v1-only` is its own reason so the server can say "downgrade".
 */
export function verifyCollectorPushV2(
  rawBody: string,
  header: string | undefined,
  key: CollectorIdentityBinding & { spki: Uint8Array },
  nowSec: number = Math.floor(Date.now() / 1000),
): PushV2Verification {
  const parts = parseCollectorSignatureHeader(header);
  if (!parts) return { valid: false, reason: 'malformed' };
  const v2 = parts.get('v2');
  if (v2 === undefined) return { valid: false, reason: 'v1-only' };
  const tRaw = parts.get('t') ?? '';
  const seqRaw = parts.get('seq') ?? '';
  const nonce = parts.get('n') ?? '';
  const kid = parts.get('kid') ?? '';
  if (!/^[1-9][0-9]{0,15}$/.test(tRaw) || !/^[1-9][0-9]{0,15}$/.test(seqRaw) || !NONCE_RE.test(nonce)) {
    return { valid: false, reason: 'malformed' };
  }
  const t = Number(tRaw);
  const seq = Number(seqRaw);
  if (!Number.isSafeInteger(t) || !Number.isSafeInteger(seq)) return { valid: false, reason: 'malformed' };
  const signature = decodeBase64Url(v2);
  if (!signature || signature.length !== 64) return { valid: false, reason: 'malformed' };
  if (Math.abs(nowSec - t) > MAX_SIGNATURE_AGE_SECONDS) return { valid: false, reason: 'expired' };
  if (!constantTimeEqual(kid, key.collectorKeyId)) return { valid: false, reason: 'wrong-key' };
  const message = pushV2Message({
    deployment: key.deployment,
    tenantRef: key.tenantRef,
    collectorKeyId: key.collectorKeyId,
    seq,
    nonce,
    t,
    bodySha256: sha256Hex(Buffer.from(rawBody, 'utf8')),
  });
  if (!ed25519Verify(key.spki, message, signature)) return { valid: false, reason: 'mismatch' };
  return { valid: true, seq, nonce, t };
}

