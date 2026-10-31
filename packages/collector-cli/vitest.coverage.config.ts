// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config';

// A1009 Z4 / QA-7 - coverage floor for @cmdash/collector-cli.
//
// This package had no coverage tooling at all (its test:ci was a bare `vitest run`), so
// nothing could notice its tests being deleted. Floors are pinned two points under the
// measured figure by scripts/ci/ratchet-coverage-floors.mjs; ratchet them up with that
// script and do not lower them without a documented reason.
export default defineConfig({
  ...baseConfig,
  test: {
    ...baseConfig.test,
    // #310 — bound the worker pool.
    //
    // This box has 32 cores. Turbo fans `test:ci` across ~10 workspaces at once
    // and vitest then defaults each to ~cores-1 threads, so the gate could ask
    // for ~300 workers on 32 cores. Under that load v8 coverage data from
    // worker threads is dropped (numerator collapses while the denominator
    // stays identical — the signature in #310) and workers die during teardown
    // ("Failed to terminate worker"). Both are the same oversubscription, and
    // both fail the gate on a tree that is fine.
    //
    // Bounded here AND at the turbo level (root `test:ci` passes
    // --concurrency), because either alone still oversubscribes: 4 workspaces x
    // 31 threads is as bad as 10 x 4. The runner is SHARED with other CI jobs,
    // so this leaves headroom rather than saturating.
    //
    // ⚠ Must stay AFTER any `...baseConfig.test` spread — placed before it, a
    // base that ever defines `pool` would silently override these and the cap
    // would read as applied while doing nothing.
    pool: 'threads',
    maxWorkers: 4, // vitest 4: `poolOptions.threads.maxThreads` is now top-level `maxWorkers` (minThreads is gone)
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'json-summary'],
      reportsDirectory: './coverage',
      // Emit the report (and evaluate thresholds) even when specs fail, so a
      // single unrelated red test does not hide all coverage output.
      reportOnFailure: true,
      // Every source file matched here is reported, tested or not, so a
      // brand-new file with no test counts against the floor rather than being
      // invisible to it. That is the property that makes this gate meaningful.
      // Vitest 4 removed `all` and `extension`: `include` alone now decides
      // which files are uncovered-file candidates, so it names the source
      // extensions Vitest 2 counted (a bare 'src/**' would hand JSON and other
      // assets to the JS parser).
      include: ['src/**/*.{js,cjs,mjs,ts,mts,cts,jsx,tsx}'],
      exclude: [
        'src/**/*.spec.ts',
        'src/**/*.test.ts',
        'src/**/*.test.tsx',
        'src/**/*.dto.ts',
        'src/**/*.module.ts',
        'src/**/dto/**',
        'src/**/interfaces/**',
        'src/**/*.d.ts',
        'src/main.ts',
      ],
      // 2026-10-24 (v10.3.2): every floor that tripped was RE-PINNED to the vitest 4.1.12 measurement minus 1 point.
      // vitest 4's v8 provider remaps coverage through the AST, so the same code reads 2-18 points lower than under vitest 2.
      thresholds: {
        statements: 88,
        branches: 78,
        functions: 89,
        lines: 91,
      },
    },
  },
});
