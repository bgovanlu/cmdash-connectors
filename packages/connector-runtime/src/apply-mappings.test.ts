// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { applyFieldMappings, buildRequest } from './apply-mappings.js';
import type { ConnectorDefinition } from './types.js';

function def(overrides: Partial<ConnectorDefinition> = {}): ConnectorDefinition {
  return {
    id: 'c1',
    name: 'Internal API',
    endpointUrl: 'https://example.com/api',
    httpMethod: 'GET',
    requestHeaders: null,
    requestBody: null,
    authType: 'NONE',
    fieldMappings: [{ jsonPath: '$.data.total', targetField: 'total', target: 'OBSERVATION' }],
    ...overrides,
  };
}

describe('applyFieldMappings — the step both sides share', () => {
  it('extracts a mapped value', () => {
    const { mapped, errors } = applyFieldMappings(def(), { data: { total: 7 } });
    expect(errors).toHaveLength(0);
    expect(mapped[0]).toMatchObject({ targetField: 'total', values: [7] });
  });

  it('reports a mapping that matched nothing instead of dropping it', () => {
    // "the source stopped sending this field" and "the sync worked" must not
    // look the same to an operator.
    const { mapped, errors } = applyFieldMappings(def(), { data: {} });
    expect(mapped).toHaveLength(0);
    expect(errors[0]).toMatchObject({ targetField: 'total' });
  });

  it('reports an invalid path as an error rather than throwing', () => {
    const d = def({
      fieldMappings: [{ jsonPath: '$.a[?(@.x>1)]', targetField: 'a', target: 'OBSERVATION' }],
    });
    const { errors } = applyFieldMappings(d, {});
    expect(errors[0].message).toMatch(/filter expressions/);
  });

  it('caps how many values one wildcard mapping may yield', () => {
    const d = def({
      fieldMappings: [{ jsonPath: '$.items[*]', targetField: 'items', target: 'OBSERVATION' }],
    });
    const { mapped } = applyFieldMappings(d, { items: Array.from({ length: 5000 }, (_, i) => i) });
    expect(mapped[0].values).toHaveLength(1000);
  });
});

describe('buildRequest', () => {
  it('sends no credential for NONE', () => {
    const req = buildRequest(def(), '');
    expect(req.headers).not.toHaveProperty('Authorization');
  });

  it('puts an API key in the configured header', () => {
    const d = def({
      authType: 'API_KEY_HEADER',
      requestHeaders: { 'x-cmdash-api-key-header': 'X-Tenant-Token' },
    });
    expect(buildRequest(d, 'k1').headers).toMatchObject({ 'X-Tenant-Token': 'k1' });
  });

  it('puts an API key in the query string, and NOT in a header', () => {
    const req = buildRequest(def({ authType: 'API_KEY_QUERY' }), 'k9');
    expect(req.url).toContain('api_key=k9');
    expect(req.headers).not.toHaveProperty('X-API-Key');
  });

  it('base64-encodes basic auth', () => {
    const req = buildRequest(def({ authType: 'BASIC_AUTH' }), 'user:pass');
    expect(req.headers.Authorization).toBe(`Basic ${Buffer.from('user:pass').toString('base64')}`);
  });

  it('treats a minted client-credentials token as a bearer', () => {
    const req = buildRequest(def({ authType: 'OAUTH2_CLIENT_CREDENTIALS' }), 'minted');
    expect(req.headers.Authorization).toBe('Bearer minted');
  });
});
