// SPDX-License-Identifier: Apache-2.0
/**
 * ROADMAP-COMPETITIVE bet 1 item 1.3 — collector configuration.
 *
 * Env vars only, no config file. A one-shot binary invoked by the customer's
 * own scheduler already has an environment; adding a file format would mean a
 * second thing to secure, review and get wrong, and a secret on disk is
 * harder to rotate than one in a secret manager's env injection.
 */

export interface CollectorConfig {
  /** CMDash base URL, e.g. https://app.cmdash.com */
  apiUrl: string;
  /** `cmdash_ek_...` — authenticates the collector. */
  apiKey: string;
  /** HMAC secret issued once at enrollment. Signs every push. */
  signingSecret: string;
  /** Optional: run only this connector rather than every assigned one. */
  connectorId?: string;
  /** Print what would be pushed without pushing it. */
  dryRun: boolean;
  /** Per-request timeout against the customer's OWN targets. */
  timeoutMs: number;
  /**
   * ROADMAP-BLUE-OCEAN K1 — the collector's Ed25519 identity file. When set,
   * every push carries a `v2` signature and every attestable metric a signed
   * measurement; when absent, the collector pushes `v1` (HMAC) only, which an
   * enrollment registered with a key refuses.
   */
  identityFile?: string;
}

/** `cmdash-collector enroll`: register a freshly generated key against one enrollment. */
export interface EnrollConfig {
  apiUrl: string;
  apiKey: string;
  enrollmentId: string;
  registrationToken: string;
  identityFile: string;
  timeoutMs: number;
}

/** `cmdash-collector rotate-key`: replace the key, endorsed by the current one. */
export interface RotateConfig {
  apiUrl: string;
  apiKey: string;
  identityFile: string;
  timeoutMs: number;
}

export class ConfigError extends Error {}

/**
 * ROADMAP-V90 J9 — the single source of truth for this CLI's flags.
 *
 * `resolveConfig` below reads every flag through this table (via
 * `flagValue`) rather than repeating each `--flag`/env-var pair as a second
 * set of string literals, and `help.ts`'s `renderHelp()` renders `--help`
 * from this same table — so a flag added or renamed here is the only edit
 * needed for both the parser and the usage text to agree; they cannot drift
 * into two different lists of "the real flags" the way a hand-written
 * `--help` string next to a hand-written parser can.
 */
export interface FlagDef {
  /** The `--flag-name` (without the leading `--`). */
  flag: string;
  /** The env var this flag falls back to (flags win when both are set). */
  envVar: string;
  /** `<value>` placeholder for `--help`; omitted for a boolean/presence flag. */
  valueName?: string;
  required: boolean;
  description: string;
}

export const FLAG_DEFS: readonly FlagDef[] = [
  {
    flag: 'api-url',
    envVar: 'CMDASH_API_URL',
    valueName: '<url>',
    required: true,
    description: 'CMDash base URL, e.g. https://app.cmdash.com',
  },
  {
    flag: 'api-key',
    envVar: 'CMDASH_API_KEY',
    valueName: '<key>',
    required: true,
    description: 'cmdash_ek_... API key that authenticates the collector',
  },
  {
    flag: 'signing-secret',
    envVar: 'CMDASH_COLLECTOR_SECRET',
    valueName: '<secret>',
    required: true,
    description: 'HMAC secret issued once at enrollment; signs every push',
  },
  {
    flag: 'connector-id',
    envVar: 'CMDASH_CONNECTOR_ID',
    valueName: '<id>',
    required: false,
    description: 'Run only this connector rather than every assigned one',
  },
  {
    flag: 'dry-run',
    envVar: 'CMDASH_COLLECTOR_DRY_RUN',
    required: false,
    description: 'Print what would be pushed without pushing it',
  },
  {
    flag: 'timeout-ms',
    envVar: 'CMDASH_COLLECTOR_TIMEOUT_MS',
    valueName: '<ms>',
    required: false,
    description: "Per-request timeout against the customer's own targets (default: 30000)",
  },
  {
    flag: 'identity-file',
    envVar: 'CMDASH_COLLECTOR_IDENTITY',
    valueName: '<path>',
    required: false,
    description:
      'Ed25519 identity file (mode 0600) created by "enroll"; signs every push (v2) and every attested measurement',
  },
  {
    flag: 'enrollment-id',
    envVar: 'CMDASH_COLLECTOR_ENROLLMENT_ID',
    valueName: '<id>',
    required: false,
    description: 'enroll only: the collector enrollment id shown when the collector was enrolled',
  },
  {
    flag: 'registration-token',
    envVar: 'CMDASH_COLLECTOR_REGISTRATION_TOKEN',
    valueName: '<token>',
    required: false,
    description: 'enroll only: the one-time key registration token shown with the enrollment',
  },
];

function flagDef(name: string): FlagDef {
  const def = FLAG_DEFS.find((d) => d.flag === name);
  if (!def) throw new Error(`no FlagDef registered for --${name}`);
  return def;
}

/** `--flag` value if present, else that flag's fallback env var. */
function flagValue(flags: Map<string, string>, env: NodeJS.ProcessEnv, name: string): string | undefined {
  const def = flagDef(name);
  return flags.get(def.flag) ?? env[def.envVar];
}

export function resolveConfig(env: NodeJS.ProcessEnv, argv: string[]): CollectorConfig {
  const flags = parseFlags(argv);

  const apiUrl = flagValue(flags, env, 'api-url');
  const apiKey = flagValue(flags, env, 'api-key');
  const signingSecret = flagValue(flags, env, 'signing-secret');

  const missing: string[] = [];
  if (!apiUrl) missing.push('CMDASH_API_URL (or --api-url)');
  if (!apiKey) missing.push('CMDASH_API_KEY (or --api-key)');
  if (!signingSecret) missing.push('CMDASH_COLLECTOR_SECRET (or --signing-secret)');
  if (missing.length > 0) {
    throw new ConfigError(
      `Missing required configuration:\n  ${missing.join('\n  ')}\n\n` +
        `The API key and the signing secret are deliberately SEPARATE credentials: a stolen key ` +
        `alone cannot forge a push, and one collector can be revoked without rotating every key ` +
        `on the account.`,
    );
  }

  const timeoutMs = timeoutOf(flags, env);

  return {
    apiUrl: apiUrl!.replace(/\/+$/, ''),
    apiKey: apiKey!,
    signingSecret: signingSecret!,
    connectorId: flagValue(flags, env, 'connector-id'),
    dryRun: flags.has('dry-run') || env[flagDef('dry-run').envVar] === 'true',
    timeoutMs,
    identityFile: flagValue(flags, env, 'identity-file'),
  };
}

function timeoutOf(flags: Map<string, string>, env: NodeJS.ProcessEnv): number {
  const timeoutRaw = flagValue(flags, env, 'timeout-ms');
  const timeoutMs = timeoutRaw ? Number(timeoutRaw) : 30_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new ConfigError(`--timeout-ms must be a positive number, got "${timeoutRaw}"`);
  }
  return timeoutMs;
}

function requireAll(pairs: Array<[string | undefined, string]>): void {
  const missing = pairs.filter(([v]) => !v).map(([, name]) => name);
  if (missing.length > 0) {
    throw new ConfigError(`Missing required configuration:\n  ${missing.join('\n  ')}`);
  }
}

/** ROADMAP-BLUE-OCEAN K1 — `cmdash-collector enroll`. */
export function resolveEnrollConfig(env: NodeJS.ProcessEnv, argv: string[]): EnrollConfig {
  const flags = parseFlags(argv);
  const apiUrl = flagValue(flags, env, 'api-url');
  const apiKey = flagValue(flags, env, 'api-key');
  const enrollmentId = flagValue(flags, env, 'enrollment-id');
  const registrationToken = flagValue(flags, env, 'registration-token');
  const identityFile = flagValue(flags, env, 'identity-file');
  requireAll([
    [apiUrl, 'CMDASH_API_URL (or --api-url)'],
    [apiKey, 'CMDASH_API_KEY (or --api-key)'],
    [enrollmentId, 'CMDASH_COLLECTOR_ENROLLMENT_ID (or --enrollment-id)'],
    [registrationToken, 'CMDASH_COLLECTOR_REGISTRATION_TOKEN (or --registration-token)'],
    [identityFile, 'CMDASH_COLLECTOR_IDENTITY (or --identity-file)'],
  ]);
  return {
    apiUrl: apiUrl!.replace(/\/+$/, ''),
    apiKey: apiKey!,
    enrollmentId: enrollmentId!,
    registrationToken: registrationToken!,
    identityFile: identityFile!,
    timeoutMs: timeoutOf(flags, env),
  };
}

/** ROADMAP-BLUE-OCEAN K1 — `cmdash-collector rotate-key`. */
export function resolveRotateConfig(env: NodeJS.ProcessEnv, argv: string[]): RotateConfig {
  const flags = parseFlags(argv);
  const apiUrl = flagValue(flags, env, 'api-url');
  const apiKey = flagValue(flags, env, 'api-key');
  const identityFile = flagValue(flags, env, 'identity-file');
  requireAll([
    [apiUrl, 'CMDASH_API_URL (or --api-url)'],
    [apiKey, 'CMDASH_API_KEY (or --api-key)'],
    [identityFile, 'CMDASH_COLLECTOR_IDENTITY (or --identity-file)'],
  ]);
  return {
    apiUrl: apiUrl!.replace(/\/+$/, ''),
    apiKey: apiKey!,
    identityFile: identityFile!,
    timeoutMs: timeoutOf(flags, env),
  };
}

function parseFlags(argv: string[]): Map<string, string> {
  const out = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const eq = arg.indexOf('=');
    if (eq !== -1) {
      out.set(arg.slice(2, eq), arg.slice(eq + 1));
    } else if (argv[i + 1] && !argv[i + 1].startsWith('--')) {
      out.set(arg.slice(2), argv[++i]);
    } else {
      out.set(arg.slice(2), 'true');
    }
  }
  return out;
}
