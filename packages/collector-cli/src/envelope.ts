// SPDX-License-Identifier: Apache-2.0
/**
 * ROADMAP-A1009 P1 (audit 2026-10-09 API-1) — reading the API's response envelope.
 *
 * The API wraps EVERY success in `{ success: true, requestId, timestamp, data }`
 * (`ResponseInterceptor`). This CLI read `body.definitions` and
 * `r.collectorKeyId` off the wrapper itself: `run` therefore saw an empty list
 * and exited 0 having collected NOTHING, and `enroll` could never recognise the
 * key it had just registered.
 *
 * This is a standalone copy of `unwrapEnvelope` from `@cmdash/shared`
 * (`packages/shared/src/envelope/index.ts`): the collector ships to customers as
 * its own npm package and cannot depend on a private monorepo package.
 * `envelope.test.ts` pins it to the fixture the real `ResponseInterceptor` is
 * proven to emit (`packages/shared/src/envelope/envelope-contract.fixture.json`).
 *
 * A body that is not the envelope THROWS. Every collector route is enveloped,
 * and "tolerate an unwrapped body" is exactly how the empty-run bug hid.
 */

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EnvelopeError';
  }
}

function isApiEnvelope(body: unknown): body is { success: true; requestId: string; timestamp: string; data?: unknown } {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return false;
  const b = body as Record<string, unknown>;
  return b.success === true && typeof b.requestId === 'string' && typeof b.timestamp === 'string';
}

/** The payload inside a parsed success envelope; throws when `body` is not one or has no `data`. */
export function unwrapEnvelope<T>(body: unknown): T {
  if (body !== null && typeof body === 'object' && !Array.isArray(body) && (body as { success?: unknown }).success === false) {
    const message = (body as { message?: unknown }).message;
    throw new EnvelopeError(
      `server returned an error envelope: ${Array.isArray(message) ? message.join('; ') : String(message ?? 'unknown error')}`,
    );
  }
  if (!isApiEnvelope(body)) {
    throw new EnvelopeError(
      'response is not the { success, requestId, timestamp, data } envelope; refusing to guess at its shape',
    );
  }
  if (!('data' in body)) throw new EnvelopeError('response envelope has no "data" field');
  return body.data as T;
}
