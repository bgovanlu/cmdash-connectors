// SPDX-License-Identifier: Apache-2.0
/**
 * The shape a declarative connector definition takes on the wire.
 *
 * Deliberately transport- and framework-free: this package is imported by
 * NestJS services and by a dependency-light CLI, and neither should have to
 * carry the other's runtime.
 */

export type ConnectorAuthType =
  | 'NONE'
  | 'API_KEY_HEADER'
  | 'API_KEY_QUERY'
  | 'BEARER_TOKEN'
  | 'BASIC_AUTH'
  | 'OAUTH2_CLIENT_CREDENTIALS';

export interface ConnectorFieldMapping {
  jsonPath: string;
  targetField: string;
  target: 'OBSERVATION' | 'EVIDENCE';
  observationType?: string;
}

export interface ConnectorDefinition {
  id: string;
  name: string;
  endpointUrl: string;
  httpMethod: string;
  requestHeaders: Record<string, string> | null;
  requestBody: string | null;
  authType: ConnectorAuthType;
  fieldMappings: ConnectorFieldMapping[];
}

/** One extracted value, before it becomes an observation or evidence. */
export interface MappedValue {
  targetField: string;
  target: 'OBSERVATION' | 'EVIDENCE';
  observationType?: string;
  values: unknown[];
}

export interface MappingError {
  targetField: string;
  jsonPath: string;
  message: string;
}

export interface MappingOutcome {
  mapped: MappedValue[];
  errors: MappingError[];
}

/** Cap on values one `[*]` mapping may yield. */
export const MAX_VALUES_PER_MAPPING = 1_000;
