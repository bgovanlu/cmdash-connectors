// SPDX-License-Identifier: Apache-2.0
import { createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { collectorKeyIdOf, spkiOf, COLLECTOR_KEY_ID_RE } from '@cmdash/connector-runtime';

/**
 * ROADMAP-BLUE-OCEAN K1 — the collector's Ed25519 identity, generated and
 * kept INSIDE the customer's boundary.
 *
 * The private key is written once, to a file the collector creates with mode
 * 0600 and refuses to overwrite; it is never sent anywhere, never logged, and
 * never printed (every error below names the file, not its content). A file
 * whose permissions let the group or others read it is refused at load, the
 * way ssh refuses an open private key: a key other local users can read is
 * not inside anyone's boundary.
 *
 * Next to it, `<file>.seq` holds the last push sequence number. The server
 * refuses a push whose sequence number is not above the last one it accepted
 * for this collector (the replay defence), so the collector persists the
 * number BEFORE it sends.
 */

export const IDENTITY_FORMAT = 'cmdash-collector-identity';

export interface CollectorIdentity {
  enrollmentId: string;
  collectorKeyId: string;
  /** The issuing deployment's origin, as CMDash reported it at registration. */
  deployment: string;
  /** The tenant's public issuer id, as CMDash reported it at registration. */
  tenantRef: string;
  privateKey: KeyObject;
}

export class IdentityError extends Error {}

interface IdentityFile {
  format: string;
  v: number;
  enrollmentId: string;
  collectorKeyId: string;
  deployment: string;
  tenantRef: string;
  privateKey: string;
}

export function generateCollectorKey(): { privateKey: KeyObject; spki: Buffer; collectorKeyId: string } {
  const { privateKey } = generateKeyPairSync('ed25519');
  const spki = spkiOf(privateKey);
  return { privateKey, spki, collectorKeyId: collectorKeyIdOf(spki) };
}

/** Create a file with mode 0600 that must not exist yet (O_EXCL): a key is never written over another. */
function writeNewPrivateFile(path: string, content: string): void {
  let fd: number;
  try {
    fd = openSync(path, 'wx', 0o600);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    throw new IdentityError(
      code === 'EEXIST'
        ? `${path} already exists; refusing to overwrite a collector identity`
        : `cannot create ${path} (${code ?? 'error'})`,
    );
  }
  try {
    writeSync(fd, content);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function assertPrivateFile(path: string): void {
  let st;
  try {
    st = lstatSync(path);
  } catch {
    throw new IdentityError(`no collector identity at ${path}; run "cmdash-collector enroll" first`);
  }
  if (!st.isFile()) throw new IdentityError(`${path} is not a regular file (a symlink is refused)`);
  if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
    throw new IdentityError(
      `${path} is readable by other users (mode ${(st.mode & 0o777).toString(8)}); run "chmod 600 ${path}"`,
    );
  }
}

export function serializeIdentity(identity: CollectorIdentity): string {
  const file: IdentityFile = {
    format: IDENTITY_FORMAT,
    v: 0,
    enrollmentId: identity.enrollmentId,
    collectorKeyId: identity.collectorKeyId,
    deployment: identity.deployment,
    tenantRef: identity.tenantRef,
    privateKey: identity.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
  return `${JSON.stringify(file, null, 2)}\n`;
}

export function writeIdentity(path: string, identity: CollectorIdentity): void {
  writeNewPrivateFile(path, serializeIdentity(identity));
}

export function loadIdentity(path: string): CollectorIdentity {
  assertPrivateFile(path);
  let file: IdentityFile;
  try {
    file = JSON.parse(readFileSync(path, 'utf8')) as IdentityFile;
  } catch {
    throw new IdentityError(`${path} is not a collector identity file`);
  }
  if (file?.format !== IDENTITY_FORMAT || file.v !== 0) throw new IdentityError(`${path} is not a collector identity file`);
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({ key: file.privateKey, format: 'pem' });
  } catch {
    throw new IdentityError(`${path} does not hold a readable private key`);
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new IdentityError(`${path} does not hold an Ed25519 key`);
  const collectorKeyId = collectorKeyIdOf(spkiOf(privateKey));
  // The id is derived from the key; a file whose stated id disagrees was edited.
  if (!COLLECTOR_KEY_ID_RE.test(file.collectorKeyId) || file.collectorKeyId !== collectorKeyId) {
    throw new IdentityError(`${path}: the stated collector key id does not match its key`);
  }
  for (const k of ['enrollmentId', 'deployment', 'tenantRef'] as const) {
    if (typeof file[k] !== 'string' || file[k].length === 0) throw new IdentityError(`${path}: missing ${k}`);
  }
  return {
    enrollmentId: file.enrollmentId,
    collectorKeyId,
    deployment: file.deployment,
    tenantRef: file.tenantRef,
    privateKey,
  };
}

/** Replace the identity atomically (rotation): write `<path>.next` (0600, O_EXCL), then rename over. */
export function stageIdentity(path: string, identity: CollectorIdentity): string {
  const next = `${path}.next`;
  writeNewPrivateFile(next, serializeIdentity(identity));
  return next;
}

export function commitStagedIdentity(staged: string, path: string): void {
  renameSync(staged, path);
}

export function discardStagedIdentity(staged: string): void {
  if (existsSync(staged)) unlinkSync(staged);
}

/**
 * The next push sequence number: above the last one used AND at least the
 * current time in milliseconds, so a lost `.seq` file (a restored VM) still
 * moves forward. Persisted before the push is sent.
 */
export function nextSequence(path: string, nowMs: number): number {
  const seqPath = `${path}.seq`;
  let last = 0;
  if (existsSync(seqPath)) {
    assertPrivateFile(seqPath);
    const raw = readFileSync(seqPath, 'utf8').trim();
    if (!/^[0-9]{1,16}$/.test(raw)) throw new IdentityError(`${seqPath} is corrupt; delete it to resume from the clock`);
    last = Number(raw);
  }
  const next = Math.max(last + 1, Math.floor(nowMs));
  if (!Number.isSafeInteger(next)) throw new IdentityError('push sequence exhausted');
  const tmp = `${seqPath}.tmp`;
  if (existsSync(tmp)) unlinkSync(tmp);
  writeNewPrivateFile(tmp, `${next}\n`);
  renameSync(tmp, seqPath);
  return next;
}
