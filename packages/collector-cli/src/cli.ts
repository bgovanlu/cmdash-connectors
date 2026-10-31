#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * ROADMAP-COMPETITIVE bet 1 item 1.3 — the self-hosted collector.
 *
 * One-shot, invoked by the customer's own scheduler. See run.ts for why that
 * is a deliberate choice rather than a simplification.
 *
 * ROADMAP-V90 J9 — `--version`/`--help` are handled here, before
 * `resolveConfig` ever runs, so both exit 0 with no API key, no signing
 * secret, and no network access required.
 */
import { runCli } from './run.js';
import { getVersion, renderHelp } from './help.js';

const argv = process.argv.slice(2);

if (argv.includes('--version') || argv.includes('-v')) {
  console.log(getVersion());
  process.exit(0);
}

if (argv.includes('--help') || argv.includes('-h')) {
  console.log(renderHelp());
  process.exit(0);
}

runCli(process.env, argv).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    // Anything reaching here is a bug in this CLI, not a configuration or
    // target problem — those are caught inside runCli and returned as a
    // friendly message with exit 1/2. Surface the stack.
    console.error(err);
    process.exitCode = 1;
  },
);
