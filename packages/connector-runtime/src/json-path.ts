// SPDX-License-Identifier: Apache-2.0
/**
 * A deliberately narrow JSONPath subset, hand-rolled.
 *
 * Lives in this package, not in apps/api, because the SAME evaluator has to
 * run in two places: CMDash's own hosted adapter and the customer's
 * self-hosted collector. A connector a tenant dry-run-tests in the wizard
 * must behave identically when the collector later executes it inside their
 * network — and the only way to guarantee that is for both to run this code,
 * not two implementations that agree today.
 *
 * ROADMAP-COMPETITIVE bet 1 item 1.1 evaluates paths that a TENANT AUTHORS
 * and stores, then runs server-side against a third-party response. That
 * makes the expression language an attack surface, not a convenience.
 *
 * The plan's first choice was `jsonpath-plus` with `preventEval: true`, with
 * an explicit instruction to prefer a hand-rolled subset "if the
 * conformance/security review has any doubt". The review found doubt:
 * jsonpath-plus carries two published RCE advisories, GHSA-pppg-cpfq-h7wr
 * (CRITICAL) and GHSA-hw8r-x6gr-5gjp (HIGH), both reachable through its
 * filter-expression evaluator. `preventEval: true` closes that today, but it
 * is one dependency bump — or one option that stops being honoured — away
 * from handing tenant-authored strings to `eval` inside a GRC product.
 *
 * So there is no dependency and no evaluator. This module supports exactly:
 *
 *   $                    the root
 *   .name  /  ['name']  /  ["name"]      object member access
 *   [0]                                   array index
 *   [*]                                   every element of an array,
 *                                         or every value of an object
 *
 * and nothing else. There is no filter syntax (`[?(...)]`), no script
 * expression, no recursive descent, no slice, and no union — the four
 * constructs that make a JSONPath library a code-execution risk. A path that
 * uses any of them is REJECTED at authoring time with an explanatory error,
 * rather than silently matching nothing at run time.
 */

export class JsonPathSyntaxError extends Error {
  constructor(
    readonly path: string,
    reason: string,
  ) {
    super(`Invalid JSONPath "${path}": ${reason}`);
    this.name = 'JsonPathSyntaxError';
  }
}

type Step =
  { kind: 'member'; name: string } | { kind: 'index'; index: number } | { kind: 'wildcard' };

/** Constructs we deliberately do not support, with the reason a user sees. */
const REJECTED: Array<{ test: RegExp; reason: string }> = [
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

/**
 * Parse a path into steps, or throw. Call this when a mapping is SAVED so a
 * tenant finds out at authoring time, not on the first scheduled sync.
 */
export function parseJsonPath(path: string): Step[] {
  const trimmed = path.trim();
  if (!trimmed) throw new JsonPathSyntaxError(path, 'path is empty');

  for (const { test, reason } of REJECTED) {
    if (test.test(trimmed)) throw new JsonPathSyntaxError(path, reason);
  }

  let rest = trimmed;
  if (rest === '$') return [];
  if (rest.startsWith('$')) rest = rest.slice(1);
  else if (!rest.startsWith('[') && !rest.startsWith('.')) rest = `.${rest}`; // tolerate a bare "a.b"

  const steps: Step[] = [];
  // One regex, anchored and consumed left to right, so anything the grammar
  // does not describe is a hard parse error rather than a silent skip.
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
    else steps.push({ kind: 'member', name: (singleQuoted ?? doubleQuoted) as string });
    rest = rest.slice(full.length);
  }
  return steps;
}

/** True if `path` parses. Never throws — for UI validation. */
export function isValidJsonPath(path: string): boolean {
  try {
    parseJsonPath(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Evaluate a parsed path against a document, returning EVERY match.
 *
 * A path with no wildcard yields at most one value; `[*]` is what makes the
 * result a list. Missing members yield no match rather than `undefined`, so a
 * caller can tell "the source omitted this field" from "the source sent null".
 */
export function evaluateJsonPath(doc: unknown, path: string | Step[]): unknown[] {
  const steps = typeof path === 'string' ? parseJsonPath(path) : path;
  let current: unknown[] = [doc];

  for (const step of steps) {
    const next: unknown[] = [];
    for (const node of current) {
      if (node === null || node === undefined) continue;

      if (step.kind === 'member') {
        // Reject prototype-chain access outright: a tenant-authored path must
        // never be able to walk into __proto__ or constructor and read
        // something that is not part of the response document.
        if (step.name === '__proto__' || step.name === 'constructor' || step.name === 'prototype') {
          continue;
        }
        if (typeof node === 'object' && Object.prototype.hasOwnProperty.call(node, step.name)) {
          next.push((node as Record<string, unknown>)[step.name]);
        }
      } else if (step.kind === 'index') {
        if (Array.isArray(node) && step.index < node.length) next.push(node[step.index]);
      } else {
        if (Array.isArray(node)) next.push(...node);
        else if (typeof node === 'object') next.push(...Object.values(node as object));
      }
    }
    current = next;
    if (current.length === 0) return [];
  }
  return current;
}

/** Convenience: the first match, or `undefined`. */
export function evaluateJsonPathFirst(doc: unknown, path: string | Step[]): unknown {
  return evaluateJsonPath(doc, path)[0];
}
