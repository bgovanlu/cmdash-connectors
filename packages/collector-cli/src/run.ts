// SPDX-License-Identifier: Apache-2.0
import { randomBytes } from 'node:crypto';
import {
  applyFieldMappings,
  buildRequest,
  countsOfStates,
  measurementStates,
  signCollectorPayload,
  signCollectorPayloadV2,
  signMeasurement,
  ATTESTABLE_METRICS,
  MAX_ATTESTED_ITEMS,
  type ConnectorDefinition,
  type MappedValue,
  type SignedMeasurement,
} from '@cmdash/connector-runtime';
import {
  ConfigError,
  resolveConfig,
  resolveEnrollConfig,
  resolveRotateConfig,
  type CollectorConfig,
} from './config.js';
import { loadIdentity, nextSequence, IdentityError, type CollectorIdentity } from './identity.js';
import { enroll, rotateKey } from './enroll.js';
import { unwrapEnvelope } from './envelope.js';

/**
 * ROADMAP-COMPETITIVE bet 1 item 1.3 — the collector run.
 *
 * ONE-SHOT, not a daemon: the customer's own scheduler invokes it (cron,
 * Task Scheduler, a Kubernetes CronJob). That is a deliberate simplicity
 * choice for the air-gapped and CUI audience this item targets — a binary
 * with no held-open connections and no local persistence is far easier for a
 * security team to review and approve under change control than a
 * long-running service.
 *
 * The collector reaches targets CMDash cannot: that is the whole point. It
 * therefore does NOT apply CMDash's SSRF guard to those requests — inside a
 * customer's own network, a private address is the expected destination, not
 * an attack. What it does instead is push results back over one authenticated,
 * signed channel, so the only thing crossing the boundary is data the
 * customer's own definition selected.
 */

export interface RunResult {
  connectorsRun: number;
  observationsPushed: number;
  failures: Array<{ connectorId: string; message: string }>;
}

export interface Fetcher {
  (url: string, init: RequestInit & { timeoutMs?: number }): Promise<Response>;
}

/** Injectable so tests never open a socket. */
export interface RunDeps {
  fetch?: Fetcher;
  log?: (line: string) => void;
  now?: () => number;
}

export async function runCli(
  env: NodeJS.ProcessEnv,
  argv: string[],
  deps: RunDeps = {},
): Promise<number> {
  const log = deps.log ?? ((line: string) => console.log(line));

  // ROADMAP-BLUE-OCEAN K1 — the two identity commands. Neither prints key
  // material: they report the key id (a public fingerprint) and the file path.
  if (argv[0] === 'enroll' || argv[0] === 'rotate-key') {
    try {
      const result =
        argv[0] === 'enroll'
          ? await enroll(resolveEnrollConfig(env, argv.slice(1)), deps)
          : await rotateKey(resolveRotateConfig(env, argv.slice(1)), deps);
      log(result);
      return 0;
    } catch (err) {
      if (err instanceof ConfigError || err instanceof IdentityError) {
        log(err.message);
        return 2;
      }
      log(`${argv[0]} failed: ${err instanceof Error ? err.message : String(err)}`);
      return 1;
    }
  }

  let config: CollectorConfig;
  try {
    config = resolveConfig(env, argv);
  } catch (err) {
    if (err instanceof ConfigError) {
      log(err.message);
      return 2;
    }
    throw err;
  }

  try {
    const result = await run(config, deps);
    log(
      `Ran ${result.connectorsRun} connector(s); pushed ${result.observationsPushed} value(s)` +
        (config.dryRun ? ' (DRY RUN — nothing was sent)' : '') +
        (result.failures.length > 0 ? `; ${result.failures.length} failed` : ''),
    );
    for (const f of result.failures) log(`  ! ${f.connectorId}: ${f.message}`);
    // A partial failure is still a failure: a scheduler that sees exit 0
    // will not alert, and a collector nobody notices has stopped working is
    // the whole silent-failure class this product exists to surface.
    return result.failures.length > 0 ? 1 : 0;
  } catch (err) {
    log(`Collector run failed: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

export async function run(config: CollectorConfig, deps: RunDeps = {}): Promise<RunResult> {
  const doFetch = deps.fetch ?? (globalThis.fetch as unknown as Fetcher);
  // Loaded before anything is fetched: a broken identity is a configuration
  // failure, not a run that silently falls back to unattested v1 pushes.
  const identity = config.identityFile ? loadIdentity(config.identityFile) : null;
  const definitions = await fetchDefinitions(config, doFetch);

  const result: RunResult = { connectorsRun: 0, observationsPushed: 0, failures: [] };

  for (const definition of definitions) {
    result.connectorsRun++;
    try {
      const mapped = await executeOne(definition, config, doFetch);
      if (!config.dryRun && mapped.length > 0) {
        await pushResults(definition, mapped, config, doFetch, deps.now, identity);
      }
      result.observationsPushed += mapped.reduce((n, m) => n + m.values.length, 0);
    } catch (err) {
      // One broken connector must not stop the rest of the run.
      result.failures.push({
        connectorId: definition.id,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return result;
}

/** Definitions assigned to this collector, from CMDash. */
async function fetchDefinitions(
  config: CollectorConfig,
  doFetch: Fetcher,
): Promise<ConnectorDefinition[]> {
  const url = config.connectorId
    ? `${config.apiUrl}/api/v2/collector/definitions?connectorId=${encodeURIComponent(config.connectorId)}`
    : `${config.apiUrl}/api/v2/collector/definitions`;

  const res = await doFetch(url, {
    method: 'GET',
    headers: { Authorization: `Bearer ${config.apiKey}`, Accept: 'application/json' },
    timeoutMs: config.timeoutMs,
  });
  if (!res.ok) {
    throw new Error(`Could not fetch connector definitions: HTTP ${res.status}`);
  }
  // `GET /v2/collector/definitions` answers `{ success, requestId, timestamp,
  // data: { definitions } }`. Reading `body.definitions` off the wrapper made
  // every run "succeed" with zero connectors (audit 2026-10-09 API-1), so a
  // body without a definitions ARRAY is a failure, never an empty run.
  const data = unwrapEnvelope<{ definitions?: ConnectorDefinition[] }>(await res.json());
  if (!data || !Array.isArray(data.definitions)) {
    throw new Error('Could not read connector definitions: the response has no definitions list');
  }
  return data.definitions;
}

/** Call the customer's own target and map the response. */
async function executeOne(
  definition: ConnectorDefinition,
  config: CollectorConfig,
  doFetch: Fetcher,
): Promise<MappedValue[]> {
  // The credential for a COLLECTOR-mode connector is supplied by the
  // customer's own environment, keyed by connector id. CMDash never holds it
  // — that is the difference between a hosted connector and this one, and it
  // is why a collector can reach a system CMDash is not trusted with.
  const credential =
    process.env[`CMDASH_CONNECTOR_SECRET_${definition.id.replace(/-/g, '_')}`] ?? '';

  const req = buildRequest(definition, credential);
  const res = await doFetch(req.url, {
    method: req.method,
    headers: req.headers,
    body: req.body,
    timeoutMs: config.timeoutMs,
  });
  if (!res.ok) throw new Error(`target returned HTTP ${res.status}`);

  let parsed: unknown;
  const text = await res.text();
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('target did not return valid JSON');
  }

  const { mapped, errors } = applyFieldMappings(definition, parsed);
  if (mapped.length === 0 && errors.length > 0) {
    // Everything failed to map. Loud, not a successful run of nothing.
    throw new Error(
      `no mapping matched: ${errors.map((e) => `${e.targetField} (${e.message})`).join(', ')}`,
    );
  }
  return mapped;
}

/**
 * ROADMAP-BLUE-OCEAN K1 — the attested measurements of one push: every
 * OBSERVATION mapping whose target field names an attestable metric becomes
 * counts over its values (JSON true meets, false fails, anything else is
 * unknown), signed by this collector's key. The per-item states travel with
 * it, unsigned by the measurement but covered by the push's v2 signature.
 */
export function attestMeasurements(
  mapped: MappedValue[],
  identity: CollectorIdentity,
  measuredAt: string,
  seq: number,
): Array<SignedMeasurement & { states: string[] }> {
  const out: Array<SignedMeasurement & { states: string[] }> = [];
  for (const m of mapped) {
    if (m.target !== 'OBSERVATION' || !Object.prototype.hasOwnProperty.call(ATTESTABLE_METRICS, m.targetField)) continue;
    const states = measurementStates(m.values.slice(0, MAX_ATTESTED_ITEMS));
    const counts = countsOfStates(states);
    const signed = signMeasurement(identity.privateKey, {
      v: 0,
      deployment: identity.deployment,
      tenantRef: identity.tenantRef,
      collectorKeyId: identity.collectorKeyId,
      metric: m.targetField,
      ...counts,
      measuredAt,
      seq,
      nonce: randomBytes(16).toString('hex'),
    });
    out.push({ ...signed, states });
  }
  return out;
}

/** Push results back, signed (v1 HMAC always; v2 Ed25519 when the collector has an identity). */
async function pushResults(
  definition: ConnectorDefinition,
  mapped: MappedValue[],
  config: CollectorConfig,
  doFetch: Fetcher,
  now?: () => number,
  identity?: CollectorIdentity | null,
): Promise<void> {
  const nowMs = now ? now() : Date.now();
  const collectedAt = new Date(nowMs).toISOString();
  const timestampSec = Math.floor(nowMs / 1000);
  let rawBody: string;
  let signatureHeader: string;
  if (identity) {
    // Persisted BEFORE the push: a sequence number is never used twice, even
    // when the push fails and the scheduler runs the collector again.
    const seq = nextSequence(config.identityFile!, nowMs);
    const attestations = attestMeasurements(mapped, identity, collectedAt, seq);
    rawBody = JSON.stringify({ connectorId: definition.id, collectedAt, mapped, attestations });
    signatureHeader = signCollectorPayloadV2(rawBody, config.signingSecret, identity, {
      t: timestampSec,
      seq,
      nonce: randomBytes(16).toString('hex'),
    });
  } else {
    rawBody = JSON.stringify({ connectorId: definition.id, collectedAt, mapped });
    signatureHeader = signCollectorPayload(rawBody, config.signingSecret, timestampSec);
  }

  const res = await doFetch(`${config.apiUrl}/api/v2/collector/push`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.apiKey}`,
      'Content-Type': 'application/json',
      // Signed with a secret the API key alone does not grant. A stolen
      // bearer token cannot forge this.
      'X-CMDash-Collector-Signature': signatureHeader,
    },
    body: rawBody,
    timeoutMs: config.timeoutMs,
  });

  if (!res.ok) throw new Error(`push rejected: HTTP ${res.status}`);
}
