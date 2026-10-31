// SPDX-License-Identifier: Apache-2.0
import { existsSync } from 'node:fs';
import {
  ed25519Sign,
  encodeBase64Url,
  enrollmentMessage,
  rotationMessage,
  sha256Hex,
  COLLECTOR_KEY_ID_RE,
} from '@cmdash/connector-runtime';
import type { EnrollConfig, RotateConfig } from './config.js';
import {
  commitStagedIdentity,
  discardStagedIdentity,
  generateCollectorKey,
  loadIdentity,
  stageIdentity,
  writeIdentity,
  IdentityError,
} from './identity.js';
import type { Fetcher, RunDeps } from './run.js';
import { unwrapEnvelope } from './envelope.js';

/**
 * ROADMAP-BLUE-OCEAN K1 — registering and rotating the collector's key.
 *
 * `enroll` generates the key pair HERE, inside the customer's boundary, and
 * sends CMDash the public key with a proof of possession: an Ed25519
 * signature over (enrollment id, public key, SHA-256 of the one-time
 * registration token). The server accepts it once, for that enrollment only,
 * so a key cannot be registered by someone who does not hold it, nor moved to
 * another enrollment or tenant with a replayed proof.
 *
 * `rotate-key` generates a successor and sends a message signed by BOTH keys:
 * the old one proves the rotation is authorized, the new one proves
 * possession. The server retires the old key; measurements it signed before
 * stay verifiable.
 */

/** The server answered with a 4xx: it did NOT register or rotate anything. */
export class ServerRefusedError extends Error {}

interface RegistrationResponse {
  collectorKeyId?: string;
  deployment?: string;
  tenantRef?: string;
}

async function postJson(
  doFetch: Fetcher,
  url: string,
  apiKey: string,
  body: Record<string, unknown>,
  timeoutMs: number,
): Promise<RegistrationResponse> {
  const res = await doFetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
    timeoutMs,
  });
  if (!res.ok) {
    // A 4xx is a definite refusal: nothing changed on the server. Anything
    // else (5xx) leaves the server's state unknown.
    if (res.status >= 400 && res.status < 500) throw new ServerRefusedError(`CMDash refused the key: HTTP ${res.status}`);
    throw new Error(`CMDash did not confirm the key: HTTP ${res.status}`);
  }
  // `POST /v2/collector/keys[/rotate]` answers `{ success, requestId, timestamp,
  // data: { collectorKeyId, deployment, tenantRef } }`. Reading the wrapper made
  // `checkResponse` reject every genuine registration (audit 2026-10-09 API-1).
  return unwrapEnvelope<RegistrationResponse>(await res.json());
}

/** The server must echo the key id this collector derived, and a usable identity. */
function checkResponse(r: RegistrationResponse, expectedKeyId: string): { deployment: string; tenantRef: string } {
  if (r.collectorKeyId !== expectedKeyId || !COLLECTOR_KEY_ID_RE.test(expectedKeyId)) {
    throw new Error('CMDash registered a different key id than this collector generated; nothing was saved');
  }
  if (typeof r.deployment !== 'string' || !r.deployment || typeof r.tenantRef !== 'string' || !/^tr_[0-9a-f]{32}$/.test(r.tenantRef)) {
    throw new Error('CMDash did not return the deployment and tenantRef this collector signs; nothing was saved');
  }
  return { deployment: r.deployment, tenantRef: r.tenantRef };
}

export async function enroll(config: EnrollConfig, deps: RunDeps = {}): Promise<string> {
  const doFetch = deps.fetch ?? (globalThis.fetch as unknown as Fetcher);
  if (existsSync(config.identityFile)) {
    throw new IdentityError(
      `${config.identityFile} already exists; use "cmdash-collector rotate-key" to replace a registered key`,
    );
  }
  const key = generateCollectorKey();
  const publicKey = encodeBase64Url(key.spki);
  const proof = encodeBase64Url(
    ed25519Sign(
      key.privateKey,
      enrollmentMessage({
        enrollmentId: config.enrollmentId,
        publicKey,
        tokenSha256: sha256Hex(config.registrationToken),
      }),
    ),
  );
  const response = await postJson(
    doFetch,
    `${config.apiUrl}/api/v2/collector/keys`,
    config.apiKey,
    { enrollmentId: config.enrollmentId, registrationToken: config.registrationToken, publicKey, proof },
    config.timeoutMs,
  );
  const bound = checkResponse(response, key.collectorKeyId);
  writeIdentity(config.identityFile, {
    enrollmentId: config.enrollmentId,
    collectorKeyId: key.collectorKeyId,
    ...bound,
    privateKey: key.privateKey,
  });
  return `Registered collector key ${key.collectorKeyId}; identity saved to ${config.identityFile} (mode 0600). Pushes are now signed v2.`;
}

export async function rotateKey(config: RotateConfig, deps: RunDeps = {}): Promise<string> {
  const doFetch = deps.fetch ?? (globalThis.fetch as unknown as Fetcher);
  const old = loadIdentity(config.identityFile);
  const next = generateCollectorKey();
  const newPublicKey = encodeBase64Url(next.spki);
  const t = Math.floor((deps.now ? deps.now() : Date.now()) / 1000);
  const message = rotationMessage({
    deployment: old.deployment,
    tenantRef: old.tenantRef,
    enrollmentId: old.enrollmentId,
    oldCollectorKeyId: old.collectorKeyId,
    newPublicKey,
    t,
  });
  // Staged first: if the server accepts and the process then dies, the new
  // key is on disk (as <file>.next) rather than lost.
  const staged = stageIdentity(config.identityFile, {
    enrollmentId: old.enrollmentId,
    collectorKeyId: next.collectorKeyId,
    deployment: old.deployment,
    tenantRef: old.tenantRef,
    privateKey: next.privateKey,
  });
  try {
    const response = await postJson(
      doFetch,
      `${config.apiUrl}/api/v2/collector/keys/rotate`,
      config.apiKey,
      {
        enrollmentId: old.enrollmentId,
        newPublicKey,
        t,
        proofOld: encodeBase64Url(ed25519Sign(old.privateKey, message)),
        proofNew: encodeBase64Url(ed25519Sign(next.privateKey, message)),
      },
      config.timeoutMs,
    );
    const bound = checkResponse(response, next.collectorKeyId);
    if (bound.deployment !== old.deployment || bound.tenantRef !== old.tenantRef) {
      throw new Error('CMDash reported another deployment or tenant for this collector; the old key is kept');
    }
  } catch (err) {
    // Only a definite refusal proves the old key is still the registered one.
    // A timeout, a dropped connection, a 5xx or an unexpected answer may come
    // AFTER the server rotated: deleting the new key then would leave this
    // collector with a retired key and no way back but an admin re-key.
    if (err instanceof ServerRefusedError) {
      discardStagedIdentity(staged);
      throw err;
    }
    throw new Error(
      `${err instanceof Error ? err.message : String(err)}. CMDash may have rotated to the new key, so it is kept at ${staged} (mode 0600). ` +
        `If pushes with the current identity are now refused, move it into place (mv ${staged} ${config.identityFile}); otherwise delete it before rotating again.`,
    );
  }
  commitStagedIdentity(staged, config.identityFile);
  return `Rotated collector key ${old.collectorKeyId} -> ${next.collectorKeyId}; identity saved to ${config.identityFile} (mode 0600).`;
}
