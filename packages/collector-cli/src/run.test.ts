// SPDX-License-Identifier: Apache-2.0
import { envelope } from '../test-support/envelope';
import { describe, it, expect, vi } from 'vitest';
import { runCli, run } from './run.js';
import { resolveConfig, ConfigError } from './config.js';
import { verifyCollectorSignature } from '@cmdash/connector-runtime';

const ENV = {
  CMDASH_API_URL: 'https://app.cmdash.com',
  CMDASH_API_KEY: 'cmdash_ek_test',
  CMDASH_COLLECTOR_SECRET: 'signing-secret',
};

const DEFINITION = {
  id: 'cc-1',
  name: 'Internal patch API',
  endpointUrl: 'https://internal.corp.local/api/patches',
  httpMethod: 'GET',
  requestHeaders: null,
  requestBody: null,
  authType: 'NONE' as const,
  fieldMappings: [
    { jsonPath: '$.data.compliant', targetField: 'compliant', target: 'OBSERVATION' as const },
  ],
};

function fakeFetch(
  handlers: Record<
    string,
    () => Partial<Response> & { json?: () => unknown; text?: () => unknown }
  >,
) {
  const calls: Array<{ url: string; init: any }> = [];
  const fn = vi.fn(async (url: string, init: any) => {
    calls.push({ url, init });
    const key = Object.keys(handlers).find((k) => url.includes(k));
    if (!key) throw new Error(`unexpected fetch: ${url}`);
    const r = handlers[key]();
    return {
      ok: r.ok ?? true,
      status: r.status ?? 200,
      json: async () => envelope(r.json ? r.json() : {}),
      text: async () => (r.text ? String(r.text()) : ''),
    } as Response;
  });
  return { fn: fn as never, calls };
}

describe('configuration', () => {
  it('requires the API key and signing secret as SEPARATE credentials', () => {
    expect(() => resolveConfig({ CMDASH_API_URL: 'x', CMDASH_API_KEY: 'y' }, [])).toThrow(
      ConfigError,
    );
    // The message must explain WHY there are two, or an operator will assume
    // one is redundant and reuse the key.
    try {
      resolveConfig({ CMDASH_API_URL: 'x', CMDASH_API_KEY: 'y' }, []);
    } catch (err) {
      expect((err as Error).message).toMatch(/stolen key\s+alone cannot forge a push|cannot forge/);
    }
  });

  it('accepts flags as well as env, and strips a trailing slash', () => {
    const c = resolveConfig({}, [
      '--api-url',
      'https://app.cmdash.com/',
      '--api-key',
      'k',
      '--signing-secret',
      's',
    ]);
    expect(c.apiUrl).toBe('https://app.cmdash.com');
  });

  it('rejects a non-numeric timeout instead of silently defaulting', () => {
    expect(() => resolveConfig({ ...ENV, CMDASH_COLLECTOR_TIMEOUT_MS: 'soon' }, [])).toThrow(
      /positive number/,
    );
  });
});

describe('a collector run', () => {
  it('fetches definitions, calls the customer target, and pushes a SIGNED result', async () => {
    const { fn, calls } = fakeFetch({
      '/collector/definitions': () => ({ json: () => ({ definitions: [DEFINITION] }) }),
      'internal.corp.local': () => ({ text: () => JSON.stringify({ data: { compliant: 42 } }) }),
      '/collector/push': () => ({ status: 201 }),
    });

    const result = await run(resolveConfig(ENV, []), { fetch: fn });
    expect(result).toMatchObject({ connectorsRun: 1, observationsPushed: 1, failures: [] });

    const push = calls.find((c) => c.url.includes('/collector/push'))!;
    const header = push.init.headers['X-CMDash-Collector-Signature'];
    // The push is verifiable with the signing secret and NOT with the API
    // key — that separation is the security property of the whole item.
    expect(verifyCollectorSignature(push.init.body, header, 'signing-secret').valid).toBe(true);
    expect(verifyCollectorSignature(push.init.body, header, 'cmdash_ek_test').valid).toBe(false);
  });

  it('reaches a PRIVATE address, which is the entire point', async () => {
    // CMDash's own adapter refuses these via safeFetch. A collector running
    // inside the customer's network must not, or it cannot do its job.
    const { fn, calls } = fakeFetch({
      '/collector/definitions': () => ({ json: () => ({ definitions: [DEFINITION] }) }),
      'internal.corp.local': () => ({ text: () => JSON.stringify({ data: { compliant: 1 } }) }),
      '/collector/push': () => ({ status: 201 }),
    });
    await run(resolveConfig(ENV, []), { fetch: fn });
    expect(calls.some((c) => c.url.includes('internal.corp.local'))).toBe(true);
  });

  it('pushes NOTHING on a dry run but still reports what it would have sent', async () => {
    const { fn, calls } = fakeFetch({
      '/collector/definitions': () => ({ json: () => ({ definitions: [DEFINITION] }) }),
      'internal.corp.local': () => ({ text: () => JSON.stringify({ data: { compliant: 5 } }) }),
    });
    const result = await run(resolveConfig({ ...ENV, CMDASH_COLLECTOR_DRY_RUN: 'true' }, []), {
      fetch: fn,
    });
    expect(result.observationsPushed).toBe(1);
    expect(calls.some((c) => c.url.includes('/collector/push'))).toBe(false);
  });

  it('treats a connector whose mappings ALL fail as a failure, not a quiet success', async () => {
    const { fn } = fakeFetch({
      '/collector/definitions': () => ({ json: () => ({ definitions: [DEFINITION] }) }),
      'internal.corp.local': () => ({ text: () => JSON.stringify({ data: {} }) }),
    });
    const result = await run(resolveConfig(ENV, []), { fetch: fn });
    expect(result.failures).toHaveLength(1);
    expect(result.failures[0].message).toMatch(/no mapping matched/);
  });

  it('keeps going when one connector breaks', async () => {
    const second = { ...DEFINITION, id: 'cc-2' };
    let hit = 0;
    const { fn } = fakeFetch({
      '/collector/definitions': () => ({ json: () => ({ definitions: [DEFINITION, second] }) }),
      'internal.corp.local': () =>
        hit++ === 0
          ? { ok: false, status: 500 }
          : { text: () => JSON.stringify({ data: { compliant: 3 } }) },
      '/collector/push': () => ({ status: 201 }),
    });
    const result = await run(resolveConfig(ENV, []), { fetch: fn });
    expect(result.connectorsRun).toBe(2);
    expect(result.failures).toHaveLength(1);
    expect(result.observationsPushed).toBe(1);
  });
});

describe('exit codes — a scheduler only sees this', () => {
  it('exits 2 on a configuration problem', async () => {
    const lines: string[] = [];
    const code = await runCli({}, [], { log: (l) => lines.push(l) });
    expect(code).toBe(2);
    expect(lines.join('\n')).toMatch(/Missing required configuration/);
  });

  it('exits 1 when any connector failed', async () => {
    // A partial failure reported as success is exactly the silent-failure
    // class this product exists to surface — a scheduler seeing 0 never alerts.
    const { fn } = fakeFetch({
      '/collector/definitions': () => ({ json: () => ({ definitions: [DEFINITION] }) }),
      'internal.corp.local': () => ({ ok: false, status: 503 }),
    });
    const code = await runCli(ENV, [], { fetch: fn, log: () => {} });
    expect(code).toBe(1);
  });

  it('exits 0 on a clean run', async () => {
    const { fn } = fakeFetch({
      '/collector/definitions': () => ({ json: () => ({ definitions: [DEFINITION] }) }),
      'internal.corp.local': () => ({ text: () => JSON.stringify({ data: { compliant: 9 } }) }),
      '/collector/push': () => ({ status: 201 }),
    });
    expect(await runCli(ENV, [], { fetch: fn, log: () => {} })).toBe(0);
  });

  it('exits 0 with nothing to do when no definitions are assigned', async () => {
    const { fn } = fakeFetch({
      '/collector/definitions': () => ({ json: () => ({ definitions: [] }) }),
    });
    expect(await runCli(ENV, [], { fetch: fn, log: () => {} })).toBe(0);
  });
});
