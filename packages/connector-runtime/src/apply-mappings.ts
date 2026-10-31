// SPDX-License-Identifier: Apache-2.0
import { evaluateJsonPath } from './json-path.js';
import {
  ConnectorDefinition,
  MAX_VALUES_PER_MAPPING,
  MappedValue,
  MappingError,
  MappingOutcome,
} from './types.js';

/**
 * Apply a definition's field mappings to a parsed response body.
 *
 * This is THE shared step between CMDash's hosted adapter and the customer's
 * collector. Both call this function on the same definition and the same
 * response, so a mapping proven in the wizard's dry run cannot behave
 * differently when the collector runs it later — which is the whole reason
 * this package exists rather than the logic living in apps/api.
 *
 * A mapping that matches nothing is REPORTED, never silently dropped: "the
 * source stopped sending this field" and "the sync worked" must not look the
 * same to an operator.
 */
export function applyFieldMappings(
  definition: Pick<ConnectorDefinition, 'fieldMappings'>,
  body: unknown,
): MappingOutcome {
  const mapped: MappedValue[] = [];
  const errors: MappingError[] = [];

  for (const m of definition.fieldMappings) {
    try {
      const values = evaluateJsonPath(body, m.jsonPath);
      if (values.length === 0) {
        errors.push({
          targetField: m.targetField,
          jsonPath: m.jsonPath,
          message: 'matched nothing in the response',
        });
        continue;
      }
      mapped.push({
        targetField: m.targetField,
        target: m.target,
        observationType: m.observationType,
        values: values.slice(0, MAX_VALUES_PER_MAPPING),
      });
    } catch (err) {
      errors.push({
        targetField: m.targetField,
        jsonPath: m.jsonPath,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return { mapped, errors };
}

/**
 * Build the outbound headers and URL for a definition plus its credential.
 *
 * Returned rather than sent, so the caller supplies the transport: apps/api
 * must go through `safeFetch` (SSRF-pinned, redirect-refusing) while the
 * collector runs inside the customer's own network where that constraint
 * does not apply and would block the private targets it exists to reach.
 */
export function buildRequest(
  definition: ConnectorDefinition,
  credential: string,
): { url: string; method: string; headers: Record<string, string>; body?: string } {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...(definition.requestHeaders ?? {}),
  };
  let url = definition.endpointUrl;

  switch (definition.authType) {
    case 'NONE':
      break;
    case 'API_KEY_HEADER':
      headers[headerNameFor(definition)] = credential;
      break;
    case 'API_KEY_QUERY': {
      const u = new URL(definition.endpointUrl);
      u.searchParams.set(queryParamFor(definition), credential);
      url = u.toString();
      break;
    }
    case 'BEARER_TOKEN':
    case 'OAUTH2_CLIENT_CREDENTIALS':
      headers.Authorization = `Bearer ${credential}`;
      break;
    case 'BASIC_AUTH':
      // The credential holds "user:password" for this mode; encoding happens
      // here so the plaintext pair is never assembled into a log line.
      headers.Authorization = `Basic ${Buffer.from(credential).toString('base64')}`;
      break;
  }

  return {
    url,
    method: definition.httpMethod || 'GET',
    headers,
    body: definition.requestBody ?? undefined,
  };
}

export function headerNameFor(definition: ConnectorDefinition): string {
  const name = (definition.requestHeaders ?? {})['x-cmdash-api-key-header'];
  return name && name.length > 0 ? name : 'X-API-Key';
}

export function queryParamFor(definition: ConnectorDefinition): string {
  const name = (definition.requestHeaders ?? {})['x-cmdash-api-key-query'];
  return name && name.length > 0 ? name : 'api_key';
}
