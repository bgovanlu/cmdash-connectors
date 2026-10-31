// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectorKeyIdOf, decodeBase64Url } from '@cmdash/connector-runtime';
import { EnvelopeError, unwrapEnvelope } from './envelope.js';
import { resolveConfig, resolveEnrollConfig } from './config.js';
import { enroll } from './enroll.js';
import { run } from './run.js';
import { dataOf, envelope, fixture, wire } from '../test-support/envelope';

/**
 * ROADMAP-A1009 P1 (audit 2026-10-09 API-1): `run` read `body.definitions` off
 * the envelope (so it silently collected nothing and exited 0) and `enroll` read
 * `r.collectorKeyId` off it (so it could never recognise its own key). These
 * tests answer with the wire bodies the REAL ResponseInterceptor emits
 * (packages/shared/src/envelope/envelope-contract.fixture.json, proven by
 * apps/api/test/client-envelope-contract-a1009-p1.spec.ts).
 */

function answering(handler: (url: string, init: any) => unknown) {
  const calls: Array<{ url: string; init: any }> = [];
  const fn = vi.fn(async (url: string, init: any) => {
    calls.push({ url, init });
    const body = handler(url, init);
    return {
      ok: true,
      status: 200,
      json: async () => body,
      text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    } as Response;
  });
  return { fn: fn as never, calls };
}

const RUN_ENV = { CMDASH_API_URL: 'https://app.cmdash.example', CMDASH_API_KEY: 'cmdash_ek_test', CMDASH_COLLECTOR_SECRET: 's' };

describe('unwrapEnvelope (collector-cli copy) agrees with the shared contract', () => {
  for (const c of fixture.cases.filter((x) => x.data !== undefined)) {
    it(`unwraps "${c.name}"`, () => {
      expect(unwrapEnvelope(c.wire)).toEqual(c.data);
    });
  }

  it('refuses an un-enveloped body, an empty envelope and an error envelope', () => {
    expect(() => unwrapEnvelope(dataOf('collector.definitions'))).toThrow(EnvelopeError);
    expect(() => unwrapEnvelope(wire('void handler'))).toThrow(/no "data"/);
    expect(() =>
      unwrapEnvelope({ success: false, requestId: 'r', timestamp: 't', statusCode: 403, error: 'Forbidden', message: 'nope' }),
    ).toThrow(/nope/);
  });
});

describe('run against the real envelope', () => {
  const target = JSON.stringify({ data: { compliant: true } });

  it('runs the connectors the API assigned (not zero) when definitions arrive in the envelope', async () => {
    const { fn } = answering((url) => {
      if (url.includes('/collector/definitions')) return wire('collector.definitions');
      if (url.includes('internal.corp.local')) return target;
      return wire('collector.push');
    });
    const result = await run(resolveConfig(RUN_ENV, []), { fetch: fn });
    expect(result.connectorsRun).toBe(dataOf<{ definitions: unknown[] }>('collector.definitions').definitions.length);
    expect(result.connectorsRun).toBeGreaterThan(0);
    expect(result.failures).toEqual([]);
  });

  it('a genuinely empty assignment is still a clean zero-connector run', async () => {
    const { fn } = answering(() => wire('collector.definitions.none'));
    const result = await run(resolveConfig(RUN_ENV, []), { fetch: fn });
    expect(result.connectorsRun).toBe(0);
  });

  it('THROWS, instead of "succeeding" with nothing, when the response is not the envelope', async () => {
    const { fn } = answering(() => dataOf('collector.definitions'));
    await expect(run(resolveConfig(RUN_ENV, []), { fetch: fn })).rejects.toThrow(EnvelopeError);
  });

  it('THROWS when the envelope carries no definitions list', async () => {
    const { fn } = answering(() => envelope({ total: 0 }));
    await expect(run(resolveConfig(RUN_ENV, []), { fetch: fn })).rejects.toThrow(/no definitions list/);
  });
});

describe('enroll against the real envelope', () => {
  it('registers: the key id and identity are read from inside data', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'collector-envelope-'));
    try {
      const { collectorKeyId, deployment, tenantRef } = dataOf<{ collectorKeyId: string; deployment: string; tenantRef: string }>(
        'collector.keys.register',
      );
      expect(collectorKeyId).toMatch(/^cmdash-collector-/);
      const { fn } = answering((_u, init) => {
        const sent = JSON.parse(init.body);
        // The server echoes the id derived from the public key it was sent.
        return envelope({ collectorKeyId: collectorKeyIdOf(decodeBase64Url(sent.publicKey)!), deployment, tenantRef });
      });
      const cfg = resolveEnrollConfig(
        {
          ...RUN_ENV,
          CMDASH_COLLECTOR_ENROLLMENT_ID: 'enr-1',
          CMDASH_COLLECTOR_REGISTRATION_TOKEN: 'one-time-token',
          CMDASH_COLLECTOR_IDENTITY: join(dir, 'id.json'),
        },
        [],
      );
      await expect(enroll(cfg, { fetch: fn })).resolves.toMatch(/Registered collector key/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses an un-enveloped registration answer and saves nothing', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'collector-envelope-'));
    try {
      const { fn } = answering(() => dataOf('collector.keys.register'));
      const cfg = resolveEnrollConfig(
        {
          ...RUN_ENV,
          CMDASH_COLLECTOR_ENROLLMENT_ID: 'enr-1',
          CMDASH_COLLECTOR_REGISTRATION_TOKEN: 'one-time-token',
          CMDASH_COLLECTOR_IDENTITY: join(dir, 'id.json'),
        },
        [],
      );
      await expect(enroll(cfg, { fetch: fn })).rejects.toThrow(EnvelopeError);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
