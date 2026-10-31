// SPDX-License-Identifier: Apache-2.0
import { envelope } from '../test-support/envelope';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  collectorKeyIdOf,
  decodeBase64Url,
  ed25519Verify,
  enrollmentMessage,
  rotationMessage,
  sha256Hex,
  spkiOf,
  verifyCollectorPushV2,
  verifyCollectorSignature,
  verifyMeasurement,
} from '@cmdash/connector-runtime';
import { generateCollectorKey, loadIdentity, nextSequence, writeIdentity, IdentityError } from './identity.js';
import { enroll, rotateKey } from './enroll.js';
import { attestMeasurements, run, runCli } from './run.js';
import { resolveConfig, resolveEnrollConfig, resolveRotateConfig } from './config.js';

/**
 * ROADMAP-BLUE-OCEAN K1 — the collector's identity: generated here, mode
 * 0600, never overwritten, never printed; enrollment with proof of
 * possession; rotation endorsed by the old key; v2 pushes with attested
 * measurements.
 */

const TENANT_REF = `tr_${'c'.repeat(32)}`;
const DEPLOYMENT = 'https://cmdash.example';
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'k1-collector-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function fetchStub(handler: (url: string, init: any) => { ok?: boolean; status?: number; json?: unknown; text?: string }) {
  const calls: Array<{ url: string; init: any }> = [];
  const fn = vi.fn(async (url: string, init: any) => {
    calls.push({ url, init });
    const r = handler(url, init);
    return {
      ok: r.ok ?? true,
      status: r.status ?? 200,
      json: async () => envelope(r.json ?? {}),
      text: async () => r.text ?? '',
    } as Response;
  });
  return { fn: fn as never, calls };
}

function identityAt(path: string) {
  const key = generateCollectorKey();
  writeIdentity(path, { enrollmentId: 'enr-1', collectorKeyId: key.collectorKeyId, deployment: DEPLOYMENT, tenantRef: TENANT_REF, privateKey: key.privateKey });
  return key;
}

describe('identity file', () => {
  it('is created with mode 0600 and round-trips; the key id is derived, not trusted', () => {
    const path = join(dir, 'id.json');
    const key = identityAt(path);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const loaded = loadIdentity(path);
    expect(loaded.collectorKeyId).toBe(key.collectorKeyId);
    expect(collectorKeyIdOf(spkiOf(loaded.privateKey))).toBe(key.collectorKeyId);
  });

  it('is never overwritten', () => {
    const path = join(dir, 'id.json');
    identityAt(path);
    expect(() => identityAt(path)).toThrow(/refusing to overwrite/);
  });

  it('is refused when other users can read it, when it is a symlink, or when its key id was edited', () => {
    const path = join(dir, 'id.json');
    identityAt(path);
    chmodSync(path, 0o644);
    expect(() => loadIdentity(path)).toThrow(/readable by other users/);
    chmodSync(path, 0o600);
    const link = join(dir, 'link.json');
    symlinkSync(path, link);
    expect(() => loadIdentity(link)).toThrow(/symlink/);
    const edited = JSON.parse(readFileSync(path, 'utf8'));
    edited.collectorKeyId = 'cmdash-collector-0000000000000000';
    const bad = join(dir, 'bad.json');
    writeFileSync(bad, JSON.stringify(edited), { mode: 0o600 });
    expect(() => loadIdentity(bad)).toThrow(/does not match its key/);
    expect(() => loadIdentity(join(dir, 'missing.json'))).toThrow(/run "cmdash-collector enroll"/);
    const junk = join(dir, 'junk.json');
    writeFileSync(junk, 'not json', { mode: 0o600 });
    expect(() => loadIdentity(junk)).toThrow(IdentityError);
  });

  it('never carries the private key into an error message', () => {
    const path = join(dir, 'id.json');
    identityAt(path);
    const pem = JSON.parse(readFileSync(path, 'utf8')).privateKey as string;
    chmodSync(path, 0o640);
    try {
      loadIdentity(path);
    } catch (err) {
      expect((err as Error).message).not.toContain(pem.split('\n')[1]);
    }
  });

  it('hands out strictly increasing sequence numbers and persists them before use', () => {
    const path = join(dir, 'id.json');
    const a = nextSequence(path, 1_000);
    const b = nextSequence(path, 1_000);
    const c = nextSequence(path, 500); // a clock that went backwards still moves forward
    expect([a, b, c]).toEqual([1_000, 1_001, 1_002]);
    expect(readFileSync(`${path}.seq`, 'utf8').trim()).toBe('1002');
    expect(statSync(`${path}.seq`).mode & 0o777).toBe(0o600);
    writeFileSync(`${path}.seq`, 'garbage', { mode: 0o600 });
    expect(() => nextSequence(path, 1)).toThrow(/corrupt/);
  });
});

describe('enroll: proof of possession, key generated locally', () => {
  const env = {
    CMDASH_API_URL: 'https://app.cmdash.example/',
    CMDASH_API_KEY: 'cmdash_ek_test',
    CMDASH_COLLECTOR_ENROLLMENT_ID: 'enr-1',
    CMDASH_COLLECTOR_REGISTRATION_TOKEN: 'one-time-token',
  };

  it('sends only the public key and a proof binding it to this enrollment and token', async () => {
    const path = join(dir, 'id.json');
    let sentKid = '';
    const { fn, calls } = fetchStub((_u, init) => {
      const body = JSON.parse(init.body);
      sentKid = collectorKeyIdOf(decodeBase64Url(body.publicKey)!);
      return { json: { collectorKeyId: sentKid, deployment: DEPLOYMENT, tenantRef: TENANT_REF } };
    });
    const lines: string[] = [];
    const code = await runCli({ ...env, CMDASH_COLLECTOR_IDENTITY: path }, ['enroll'], { fetch: fn, log: (l) => lines.push(l) });
    expect(code).toBe(0);
    expect(calls[0].url).toBe('https://app.cmdash.example/api/v2/collector/keys');
    const body = JSON.parse(calls[0].init.body);
    expect(Object.keys(body).sort()).toEqual(['enrollmentId', 'proof', 'publicKey', 'registrationToken']);
    const spki = decodeBase64Url(body.publicKey)!;
    const msg = enrollmentMessage({ enrollmentId: 'enr-1', publicKey: body.publicKey, tokenSha256: sha256Hex('one-time-token') });
    expect(ed25519Verify(spki, msg, decodeBase64Url(body.proof)!)).toBe(true);
    // Nothing private left the process, and nothing private was printed.
    const pem = JSON.parse(readFileSync(path, 'utf8')).privateKey as string;
    expect(calls[0].init.body).not.toContain('PRIVATE KEY');
    expect(lines.join('\n')).not.toContain(pem.split('\n')[1]);
    expect(lines.join('\n')).toContain(sentKid);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(loadIdentity(path).tenantRef).toBe(TENANT_REF);
  });

  it('saves nothing when the server refuses, echoes another key id, or omits the identity', async () => {
    const path = join(dir, 'id.json');
    const cfg = resolveEnrollConfig({ ...env, CMDASH_COLLECTOR_IDENTITY: path }, []);
    await expect(enroll(cfg, { fetch: fetchStub(() => ({ ok: false, status: 401 })).fn })).rejects.toThrow(/HTTP 401/);
    await expect(
      enroll(cfg, { fetch: fetchStub(() => ({ json: { collectorKeyId: 'cmdash-collector-0000000000000000', deployment: DEPLOYMENT, tenantRef: TENANT_REF } })).fn }),
    ).rejects.toThrow(/different key id/);
    await expect(
      enroll(cfg, {
        fetch: fetchStub((_u, init) => ({ json: { collectorKeyId: collectorKeyIdOf(decodeBase64Url(JSON.parse(init.body).publicKey)!) } })).fn,
      }),
    ).rejects.toThrow(/deployment and tenantRef/);
    expect(existsSync(path)).toBe(false);
  });

  it('refuses to replace an existing identity (rotation is a separate, endorsed step)', async () => {
    const path = join(dir, 'id.json');
    identityAt(path);
    const code = await runCli({ ...env, CMDASH_COLLECTOR_IDENTITY: path }, ['enroll'], { fetch: fetchStub(() => ({})).fn, log: () => {} });
    expect(code).toBe(2);
  });

  it('exits 2 when a required enroll setting is missing', async () => {
    const lines: string[] = [];
    expect(await runCli({}, ['enroll'], { log: (l) => lines.push(l) })).toBe(2);
    expect(lines.join('\n')).toMatch(/REGISTRATION_TOKEN/);
    expect(() => resolveRotateConfig({}, [])).toThrow(/Missing/);
  });
});

describe('rotate-key: endorsed by the old key, proven by the new one', () => {
  it('signs one rotation message with both keys and replaces the file atomically', async () => {
    const path = join(dir, 'id.json');
    const old = identityAt(path);
    const { fn, calls } = fetchStub((_u, init) => {
      const body = JSON.parse(init.body);
      return { json: { collectorKeyId: collectorKeyIdOf(decodeBase64Url(body.newPublicKey)!), deployment: DEPLOYMENT, tenantRef: TENANT_REF } };
    });
    const out = await rotateKey(resolveRotateConfig({ CMDASH_API_URL: 'https://x', CMDASH_API_KEY: 'k', CMDASH_COLLECTOR_IDENTITY: path }, []), { fetch: fn, now: () => 1_800_000_000_000 });
    const body = JSON.parse(calls[0].init.body);
    expect(calls[0].url).toBe('https://x/api/v2/collector/keys/rotate');
    const msg = rotationMessage({ deployment: DEPLOYMENT, tenantRef: TENANT_REF, enrollmentId: 'enr-1', oldCollectorKeyId: old.collectorKeyId, newPublicKey: body.newPublicKey, t: 1_800_000_000 });
    expect(ed25519Verify(old.spki, msg, decodeBase64Url(body.proofOld)!)).toBe(true);
    expect(ed25519Verify(decodeBase64Url(body.newPublicKey)!, msg, decodeBase64Url(body.proofNew)!)).toBe(true);
    const now = loadIdentity(path);
    expect(now.collectorKeyId).not.toBe(old.collectorKeyId);
    expect(out).toContain(now.collectorKeyId);
    expect(existsSync(`${path}.next`)).toBe(false);
  });

  it('keeps the old key when the server refuses', async () => {
    const path = join(dir, 'id.json');
    const old = identityAt(path);
    const cfg = resolveRotateConfig({ CMDASH_API_URL: 'https://x', CMDASH_API_KEY: 'k', CMDASH_COLLECTOR_IDENTITY: path }, []);
    await expect(rotateKey(cfg, { fetch: fetchStub(() => ({ ok: false, status: 409 })).fn })).rejects.toThrow(/409/);
    expect(loadIdentity(path).collectorKeyId).toBe(old.collectorKeyId);
    expect(existsSync(`${path}.next`)).toBe(false);
    const lines: string[] = [];
    expect(
      await runCli({ CMDASH_API_URL: 'https://x', CMDASH_API_KEY: 'k', CMDASH_COLLECTOR_IDENTITY: path }, ['rotate-key'], {
        fetch: fetchStub(() => ({ json: { collectorKeyId: 'cmdash-collector-0000000000000000', deployment: DEPLOYMENT, tenantRef: TENANT_REF } })).fn,
        log: (l) => lines.push(l),
      }),
    ).toBe(1);
    expect(lines.join('')).toMatch(/different key id/);
    expect(loadIdentity(path).collectorKeyId).toBe(old.collectorKeyId);
  });

  it('keeps the NEW key as <file>.next when the outcome is unknown (timeout, 5xx): never strands a rotated collector', async () => {
    const path = join(dir, 'id.json');
    const old = identityAt(path);
    const cfg = resolveRotateConfig({ CMDASH_API_URL: 'https://x', CMDASH_API_KEY: 'k', CMDASH_COLLECTOR_IDENTITY: path }, []);
    let sentKid = '';
    const timeout = (async (_u: string, init: { body: string }) => {
      sentKid = collectorKeyIdOf(decodeBase64Url(JSON.parse(init.body).newPublicKey)!);
      throw new Error('The operation was aborted due to timeout');
    }) as never;
    await expect(rotateKey(cfg, { fetch: timeout })).rejects.toThrow(/may have rotated.*kept at/);
    expect(loadIdentity(path).collectorKeyId).toBe(old.collectorKeyId);
    expect(statSync(`${path}.next`).mode & 0o777).toBe(0o600);
    expect(loadIdentity(`${path}.next`).collectorKeyId).toBe(sentKid);
    // A second rotation refuses to overwrite the kept key.
    await expect(rotateKey(cfg, { fetch: fetchStub(() => ({ ok: false, status: 503 })).fn })).rejects.toThrow(/already exists/);
    unlinkSync(`${path}.next`);
    await expect(rotateKey(cfg, { fetch: fetchStub(() => ({ ok: false, status: 503 })).fn })).rejects.toThrow(/HTTP 503.*kept at/);
    expect(existsSync(`${path}.next`)).toBe(true);
  });
});

describe('a v2 run', () => {
  const DEFINITION = {
    id: 'cc-1',
    name: 'EDR console',
    endpointUrl: 'https://edr.corp.local/api/hosts',
    httpMethod: 'GET',
    requestHeaders: null,
    requestBody: null,
    authType: 'NONE' as const,
    fieldMappings: [
      { jsonPath: '$.hosts[*].protected', targetField: 'edr-coverage', target: 'OBSERVATION' as const, observationType: 'CSPM_CONTROL_STATE' },
      { jsonPath: '$.total', targetField: 'host-count', target: 'OBSERVATION' as const, observationType: 'CSPM_CONTROL_STATE' },
    ],
  };

  it('signs the push v1 AND v2, and attests exactly the attestable metrics', async () => {
    const path = join(dir, 'id.json');
    const key = identityAt(path);
    const { fn, calls } = fetchStub((url) =>
      url.includes('/definitions')
        ? { json: { definitions: [DEFINITION] } }
        : url.includes('edr.corp.local')
          ? { text: JSON.stringify({ total: 4, hosts: [{ protected: true }, { protected: false }, { protected: 'yes' }, { protected: true }] }) }
          : { status: 201 },
    );
    const env = { CMDASH_API_URL: 'https://app', CMDASH_API_KEY: 'k', CMDASH_COLLECTOR_SECRET: 's', CMDASH_COLLECTOR_IDENTITY: path };
    const nowMs = Date.UTC(2027, 0, 15, 10, 0, 0, 123);
    const result = await run(resolveConfig(env, []), { fetch: fn, now: () => nowMs });
    expect(result.failures).toEqual([]);
    const push = calls.find((c) => c.url.includes('/collector/push'))!;
    const header = push.init.headers['X-CMDash-Collector-Signature'];
    const nowSec = Math.floor(nowMs / 1000);
    expect(verifyCollectorSignature(push.init.body, header, 's', nowSec).valid).toBe(true);
    const v2 = verifyCollectorPushV2(push.init.body, header, { deployment: DEPLOYMENT, tenantRef: TENANT_REF, collectorKeyId: key.collectorKeyId, spki: key.spki }, nowSec);
    expect(v2).toMatchObject({ valid: true, seq: nowMs });
    const body = JSON.parse(push.init.body);
    expect(body.attestations).toHaveLength(1);
    expect(body.attestations[0].states).toEqual(['MET', 'NOT_MET', 'UNKNOWN', 'MET']);
    const m = verifyMeasurement(key.spki, body.attestations[0]);
    expect(m.ok && m.statement).toMatchObject({
      metric: 'edr-coverage',
      numerator: 2,
      denominator: 4,
      unknown: 1,
      measuredAt: '2027-01-15T10:00:00.123Z',
      seq: nowMs,
      tenantRef: TENANT_REF,
      deployment: DEPLOYMENT,
    });
    // A second run in the same millisecond still gets a higher sequence number.
    await run(resolveConfig(env, []), { fetch: fn, now: () => nowMs });
    const second = calls.filter((c) => c.url.includes('/collector/push'))[1];
    expect(verifyCollectorPushV2(second.init.body, second.init.headers['X-CMDash-Collector-Signature'], { deployment: DEPLOYMENT, tenantRef: TENANT_REF, collectorKeyId: key.collectorKeyId, spki: key.spki }, nowSec)).toMatchObject({ seq: nowMs + 1 });
  });

  it('fails the run (never falls back to v1) when the identity file is unusable', async () => {
    const path = join(dir, 'id.json');
    identityAt(path);
    chmodSync(path, 0o666);
    const { fn, calls } = fetchStub(() => ({ json: { definitions: [DEFINITION] } }));
    await expect(run(resolveConfig({ CMDASH_API_URL: 'https://app', CMDASH_API_KEY: 'k', CMDASH_COLLECTOR_SECRET: 's', CMDASH_COLLECTOR_IDENTITY: path }, []), { fetch: fn })).rejects.toThrow(/readable by other users/);
    expect(calls).toHaveLength(0);
  });

  it('attestMeasurements caps the population and skips EVIDENCE mappings', () => {
    const key = generateCollectorKey();
    const identity = { enrollmentId: 'e', collectorKeyId: key.collectorKeyId, deployment: DEPLOYMENT, tenantRef: TENANT_REF, privateKey: key.privateKey };
    const out = attestMeasurements(
      [
        { targetField: 'mfa-enrolled', target: 'OBSERVATION', values: Array.from({ length: 1500 }, () => true) },
        { targetField: 'edr-coverage', target: 'EVIDENCE', values: [true] },
      ],
      identity,
      '2027-01-15T10:00:00.000Z',
      9,
    );
    expect(out).toHaveLength(1);
    expect(out[0].states).toHaveLength(1000);
  });
});
