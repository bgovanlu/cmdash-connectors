// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * ROADMAP-A1009 P1 (audit 2026-10-09 API-1) — test-only access to the response
 * envelope contract fixture, `packages/shared/src/envelope/
 * envelope-contract.fixture.json`. Its `wire` bodies are proven byte-for-byte
 * equal to what the real `ResponseInterceptor` emits by
 * `apps/api/test/client-envelope-contract-a1009-p1.spec.ts`.
 *
 * Every fake server in this package's tests answers through `envelope()` /
 * `wire()`: a fake that answers with an un-enveloped body is how `run` and
 * `enroll` passed their tests while being unable to work against the API.
 *
 * Lives outside `src/` so it is never compiled into the published package.
 */
interface FixtureCase {
  name: string;
  wire: unknown;
  data?: unknown;
}
interface Fixture {
  envelopeTemplate: { success: true; requestId: string; timestamp: string };
  cases: FixtureCase[];
}

export const fixture = JSON.parse(
  readFileSync(
    join(__dirname, '..', '..', 'shared', 'src', 'envelope', 'envelope-contract.fixture.json'),
    'utf8',
  ),
) as Fixture;

/** The wire body the real interceptor produced for fixture case `name`. */
export function wire(name: string): unknown {
  const found = fixture.cases.find((c) => c.name === name);
  if (!found) throw new Error(`no envelope fixture case "${name}"`);
  return JSON.parse(JSON.stringify(found.wire));
}

/** The payload inside `wire(name)`. */
export function dataOf<T = unknown>(name: string): T {
  return (wire(name) as { data: T }).data;
}

/** Wrap any payload exactly as the interceptor does (same template). */
export function envelope(data: unknown): unknown {
  return { ...fixture.envelopeTemplate, data };
}
