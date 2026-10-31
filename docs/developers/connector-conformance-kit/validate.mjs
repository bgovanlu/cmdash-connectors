#!/usr/bin/env node
/**
 * CMDash connector conformance kit — validate.mjs
 *
 * ROADMAP-COMPETITIVE bet 1 item 1.4. Validates a candidate connector
 * definition (the shape `ConnectorTemplate.definition` / a `CustomConnector`
 * row carries — see definition.schema.json in this folder) against the same
 * rules `apps/api/src/integration/custom/custom-connector.service.ts`'s
 * `validateDefinition` and `apps/api/src/integration/custom/json-path.ts`
 * enforce server-side, so a contributor finds a mistake before submitting a
 * template for review, not after.
 *
 * Zero dependencies, plain Node (>=18), no monorepo package required — copy
 * this one file (plus definition.schema.json if you also want portable JSON
 * Schema validation) out of the repo and it still runs:
 *
 *   node validate.mjs path/to/your-definition.json
 *
 * WHAT THIS DOES NOT DO: it cannot check that `endpointUrl` resolves to a
 * public address (CMDash's `assertSafeUrl` does DNS resolution against the
 * real network at save time AND at every run — this script does not touch
 * the network at all, on purpose, so it is safe to run against an untrusted
 * definition file). It cannot check field mappings against a REAL response
 * body either — that is what the dry-run route in the product itself is for
 * (`POST /integrations/custom-connectors/:id/dry-run`). This script is the
 * SHAPE check: would the server accept this at authoring time.
 *
 * ─── PARITY REQUIREMENT ──────────────────────────────────────────────────
 *
 * `parseJsonPath` below is a byte-for-byte-equivalent COPY of
 * `apps/api/src/integration/custom/json-path.ts`'s parser (same grammar,
 * same REJECTED list, same STEP regex) — not an import, because this file is
 * published for use OUTSIDE the monorepo (see the file header above) and
 * that module lives in `apps/api`'s private application source, not a
 * published package. This is the exact same shape as
 * `packages/shared/src/content-hub/canonicalize.ts` and its own duplicated
 * twin `scripts/content-hub/lib/canonicalize.mjs` — see that file's own
 * "PARITY REQUIREMENT" comment for the precedent. The two JSONPath copies
 * MUST accept and reject the identical set of inputs or a contributor's
 * "conformant" definition could still be rejected by the real server, or
 * worse, a definition this script rejects could actually be fine. Drift is
 * caught by `apps/api/test/connector-template-conformance-kit.spec.ts`,
 * which runs a fixed battery of paths through BOTH copies and fails the
 * build the moment they disagree. If you change the grammar in ONE of these
 * two files, change it in the other in the same commit.
 *
 * Fixed test vectors both copies must agree on (see the drift spec for the
 * full battery):
 *   accept: "$", "$.data.total", "data.total", "$.items[0].id", "$.items[*]"
 *   reject: "$..deep", "$.items[0:2]", "$.items[0,1]", "$[?(1==1)]", "$.a(b)"
 */

import { readFileSync } from 'node:fs';

// ─── JSONPath — PARITY COPY, see header ────────────────────────────────

class JsonPathSyntaxError extends Error {
  constructor(path, reason) {
    super(`Invalid JSONPath "${path}": ${reason}`);
    this.name = 'JsonPathSyntaxError';
  }
}

const REJECTED = [
  {
    test: /\[\s*\?/,
    reason:
      'filter expressions ([?(...)]) are not supported — they are the JSONPath feature that ' +
      'executes code, and this evaluator has no code path that could run one',
  },
  { test: /\.\./, reason: 'recursive descent (..) is not supported; write the full path instead' },
  { test: /\[[^\]]*:[^\]]*\]/, reason: 'array slices ([1:3]) are not supported' },
  { test: /\[[^\]]*,[^\]]*\]/, reason: 'unions ([0,1]) are not supported' },
  { test: /[()]/, reason: 'script expressions are not supported' },
];

export function parseJsonPath(path) {
  const trimmed = path.trim();
  if (!trimmed) throw new JsonPathSyntaxError(path, 'path is empty');

  for (const { test, reason } of REJECTED) {
    if (test.test(trimmed)) throw new JsonPathSyntaxError(path, reason);
  }

  let rest = trimmed;
  if (rest === '$') return [];
  if (rest.startsWith('$')) rest = rest.slice(1);
  else if (!rest.startsWith('[') && !rest.startsWith('.')) rest = `.${rest}`;

  const steps = [];
  const STEP =
    /^(?:\.([A-Za-z_$][\w$-]*)|\[\s*(\*)\s*\]|\[\s*(\d+)\s*\]|\[\s*'([^']*)'\s*\]|\[\s*"([^"]*)"\s*\])/;

  while (rest.length > 0) {
    const m = STEP.exec(rest);
    if (!m) {
      throw new JsonPathSyntaxError(path, `cannot parse from "${rest.slice(0, 20)}"`);
    }
    const [full, dotName, star, index, singleQuoted, doubleQuoted] = m;
    if (dotName !== undefined) steps.push({ kind: 'member', name: dotName });
    else if (star !== undefined) steps.push({ kind: 'wildcard' });
    else if (index !== undefined) steps.push({ kind: 'index', index: Number(index) });
    else steps.push({ kind: 'member', name: singleQuoted ?? doubleQuoted });
    rest = rest.slice(full.length);
  }
  return steps;
}

export function isValidJsonPath(path) {
  try {
    parseJsonPath(path);
    return true;
  } catch {
    return false;
  }
}

// ─── Definition shape checks — mirrors custom-connector.service.ts's
//     validateDefinition (bounds kept in sync by hand; see that file). ────

const FIELD_LIMITS = {
  endpointUrl: 2048,
  httpMethod: 10,
  requestBody: 10_000,
  jsonPath: 500,
  targetField: 120,
};
const MAX_FIELD_MAPPINGS = 50;
const AUTH_TYPES = [
  'NONE',
  'API_KEY_HEADER',
  'API_KEY_QUERY',
  'BEARER_TOKEN',
  'BASIC_AUTH',
  'OAUTH2_CLIENT_CREDENTIALS',
];
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH'];
const OBSERVATION_TYPES = [
  'CSPM_CONTROL_STATE',
  'DETECTION_TECHNIQUE',
  'ATTACK_COVERAGE',
  'VULN_SLA_ADHERENCE',
  'IDENTITY_POSTURE',
  'BAS_CONTROL_VALIDATION',
  'SCAP_RULE_RESULT',
  'HUMAN_RISK',
  'RECOVERY_TEST_RESULT',
];

/** Validate one definition object. Returns a list of error strings — empty
 * means conformant. Never throws on a malformed input; a bad shape is
 * reported like any other finding. */
export function validateDefinition(def) {
  const errors = [];
  const err = (msg) => errors.push(msg);

  if (!def || typeof def !== 'object' || Array.isArray(def)) {
    return ['definition must be a JSON object'];
  }

  if (typeof def.endpointUrl !== 'string' || !def.endpointUrl.trim()) {
    err('endpointUrl is required and must be a non-empty string');
  } else {
    if (def.endpointUrl.length > FIELD_LIMITS.endpointUrl) {
      err(`endpointUrl must be at most ${FIELD_LIMITS.endpointUrl} characters`);
    }
    if (!/^https?:\/\//i.test(def.endpointUrl)) {
      err('endpointUrl must start with http:// or https://');
    }
    // NOTE: cannot check "resolves to a public address" here — see header.
  }

  const method = (def.httpMethod ?? 'GET').toUpperCase();
  if (!HTTP_METHODS.includes(method)) {
    err(`httpMethod must be one of ${HTTP_METHODS.join(', ')} (got "${def.httpMethod}")`);
  }

  if (def.requestHeaders != null) {
    if (typeof def.requestHeaders !== 'object' || Array.isArray(def.requestHeaders)) {
      err('requestHeaders must be an object of string -> string');
    } else {
      for (const [k, v] of Object.entries(def.requestHeaders)) {
        if (typeof v !== 'string') err(`requestHeaders["${k}"] must be a string`);
        if (/authorization|api.?key|secret|password|token/i.test(k)) {
          err(
            `requestHeaders["${k}"] looks like a credential. A header TEMPLATE must never contain a ` +
              'literal secret value — secrets are supplied by the installing tenant at install time, ' +
              'never baked into the shared definition.',
          );
        }
      }
    }
  }

  if (def.requestBody != null) {
    if (typeof def.requestBody !== 'string') err('requestBody must be a string');
    else if (def.requestBody.length > FIELD_LIMITS.requestBody) {
      err(`requestBody must be at most ${FIELD_LIMITS.requestBody} characters`);
    }
  }

  if (!AUTH_TYPES.includes(def.authType)) {
    err(`authType must be one of ${AUTH_TYPES.join(', ')} (got "${def.authType}")`);
  }

  if (!Array.isArray(def.fieldMappings) || def.fieldMappings.length === 0) {
    err('fieldMappings must be a non-empty array');
  } else {
    if (def.fieldMappings.length > MAX_FIELD_MAPPINGS) {
      err(`fieldMappings must have at most ${MAX_FIELD_MAPPINGS} entries`);
    }
    const seen = new Set();
    def.fieldMappings.forEach((m, i) => {
      const where = `fieldMappings[${i}]`;
      if (!m || typeof m !== 'object') {
        err(`${where} must be an object`);
        return;
      }
      if (typeof m.jsonPath !== 'string' || !m.jsonPath.trim()) {
        err(`${where}.jsonPath is required`);
      } else {
        if (m.jsonPath.length > FIELD_LIMITS.jsonPath) {
          err(`${where}.jsonPath must be at most ${FIELD_LIMITS.jsonPath} characters`);
        }
        try {
          parseJsonPath(m.jsonPath);
        } catch (e) {
          err(`${where}.jsonPath: ${e.message}`);
        }
      }
      if (typeof m.targetField !== 'string' || !m.targetField.trim()) {
        err(`${where}.targetField is required`);
      } else if (m.targetField.length > FIELD_LIMITS.targetField) {
        err(`${where}.targetField must be at most ${FIELD_LIMITS.targetField} characters`);
      } else if (seen.has(m.targetField)) {
        err(
          `${where}.targetField "${m.targetField}" is a duplicate — every mapping needs a distinct target`,
        );
      } else {
        seen.add(m.targetField);
      }
      if (m.target !== 'OBSERVATION' && m.target !== 'EVIDENCE') {
        err(`${where}.target must be "OBSERVATION" or "EVIDENCE" (got "${m.target}")`);
      } else if (m.target === 'OBSERVATION') {
        if (!OBSERVATION_TYPES.includes(m.observationType)) {
          err(
            `${where}.observationType must be one of the FROZEN vocabulary [${OBSERVATION_TYPES.join(', ')}] ` +
              `when target is OBSERVATION (got "${m.observationType}") — see definition.schema.json`,
          );
        }
      } else if (m.observationType !== undefined) {
        err(
          `${where}.observationType must be absent when target is EVIDENCE (got "${m.observationType}")`,
        );
      }
    });
  }

  return errors;
}

// ─── CLI ──────────────────────────────────────────────────────────────

function main(argv) {
  const path = argv[2];
  if (!path) {
    console.error('usage: node validate.mjs <definition.json>');
    process.exit(2);
  }
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (e) {
    console.error(`could not read ${path}: ${e.message}`);
    process.exit(2);
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    console.error(`${path} is not valid JSON: ${e.message}`);
    process.exit(1);
  }

  const errors = validateDefinition(parsed);
  if (errors.length === 0) {
    console.log(`PASS — ${path} is a conformant connector definition.`);
    console.log(
      'Reminder: this checks SHAPE only. assertSafeUrl (network reachability) and a real dry-run ' +
        'still happen server-side when you submit — see docs/developers/connector-development.md.',
    );
    process.exit(0);
  }

  console.error(`FAIL — ${path} is not conformant (${errors.length} issue(s)):`);
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}

// Only run the CLI when this file is executed directly — `import`ing it (as
// the drift spec does) must not have a side effect.
if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv);
}
