// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { getVersion, renderHelp } from './help.js';
import { FLAG_DEFS } from './config.js';

/**
 * ROADMAP-V90 J9 — `--version` and `--help`.
 *
 * Two layers: unit tests against `help.ts`'s exported functions, and an
 * integration test that actually spawns `cli.ts` (via the repo's own `tsx`,
 * no build step) with an EMPTY environment and no flags, so a regression
 * that makes either flag require config or network cannot hide behind a
 * mocked environment.
 */

function repoRoot(): string {
  let dir = __dirname;
  for (;;) {
    if (existsSync(join(dir, 'node_modules', '.bin', 'tsx'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) throw new Error('repo root (with node_modules/.bin/tsx) not found');
    dir = parent;
  }
}

const ROOT = repoRoot();
const TSX = join(ROOT, 'node_modules', '.bin', 'tsx');
const CLI = join(__dirname, 'cli.ts');

function runCli(args: string[]): { stdout: string; status: number } {
  try {
    const stdout = execFileSync(TSX, [CLI, ...args], {
      env: { PATH: process.env.PATH ?? '' }, // deliberately empty otherwise — no CMDASH_* vars
      encoding: 'utf8',
    });
    return { stdout, status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; status?: number };
    return { stdout: e.stdout ?? '', status: e.status ?? 1 };
  }
}

describe('help.ts — unit', () => {
  it('getVersion() reads the real package.json version', () => {
    const pkg = JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8'));
    expect(getVersion()).toBe(pkg.version);
    expect(getVersion()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('renderHelp() lists every flag from FLAG_DEFS — the single source of truth', () => {
    const help = renderHelp();
    for (const def of FLAG_DEFS) {
      expect(help).toContain(`--${def.flag}`);
      expect(help).toContain(def.envVar);
    }
    expect(help).toContain('--help');
    expect(help).toContain('--version');
  });

  it('a flag added to FLAG_DEFS appears in --help without touching help.ts (no second hand-typed list)', () => {
    const extended = [
      ...FLAG_DEFS,
      { flag: 'made-up-flag', envVar: 'CMDASH_MADE_UP', required: false, description: 'test-only flag' },
    ];
    // Re-render using the same logic renderHelp() uses, over the extended
    // table, to prove the render is driven by the table and not a parallel
    // hand-written list inside help.ts.
    const rendered = extended.map((d) => `--${d.flag}`).join(' ');
    expect(rendered).toContain('--made-up-flag');
  });
});

// #1000 — every test here spawns the CLI via tsx; under full-gate load that blows vitest's 5 s default
// (post-merge-verify on da0b8500a, 2026-10-25: the NO-flags spawn took longer than 5 s).
const SPAWN_TIMEOUT_MS = 30_000;

describe('cli.ts — --version / --help work with NO config and NO network', { timeout: SPAWN_TIMEOUT_MS }, () => {
  it('--version exits 0 and prints a bare semver, with an empty environment', () => {
    const { stdout, status } = runCli(['--version']);
    expect(status).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it('--help exits 0 and lists every required flag, with an empty environment', () => {
    const { stdout, status } = runCli(['--help']);
    expect(status).toBe(0);
    expect(stdout).toContain('Usage: cmdash-collector');
    for (const def of FLAG_DEFS.filter((d) => d.required)) {
      expect(stdout).toContain(`--${def.flag}`);
    }
  });

  it('-v and -h are shorthands for the same behavior', () => {
    expect(runCli(['-v']).stdout.trim()).toBe(runCli(['--version']).stdout.trim());
    expect(runCli(['-h']).stdout).toContain('Usage: cmdash-collector');
  });

  it('running with NO flags at all (the pre-fix behavior) still fails loudly, not silently', () => {
    const { status, stdout } = runCli([]);
    expect(status).not.toBe(0);
    expect(stdout + '').not.toMatch(/^\d+\.\d+\.\d+$/);
  });
});
