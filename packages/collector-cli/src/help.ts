// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FLAG_DEFS } from './config.js';

/**
 * ROADMAP-V90 J9 — `--version` and `--help`.
 *
 * `getVersion()` reads the package's own `package.json` next to the
 * compiled `dist/` (or, in dev, next to `src/`) — never a hand-typed
 * string that can drift from what actually got published. It requires no
 * network access and no API key, so `cmdash-collector --version` works
 * even with none of `FLAG_DEFS`' required flags set.
 */
export function getVersion(): string {
  const pkgPath = join(__dirname, '..', 'package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version: string };
  return pkg.version;
}

/** `--help` text, generated from `FLAG_DEFS` — see that table's doc comment. */
export function renderHelp(): string {
  const lines: string[] = [];
  lines.push('cmdash-collector — one-shot collector that runs CMDash connector');
  lines.push('definitions inside your own network and pushes the results back.');
  lines.push('');
  lines.push('Usage: cmdash-collector [flags]              run every assigned connector');
  lines.push('       cmdash-collector enroll [flags]       generate this collector\'s Ed25519 key and register it');
  lines.push('       cmdash-collector rotate-key [flags]   replace the key, endorsed by the current one');
  lines.push('');
  lines.push('Flags:');

  const flagCol = (def: (typeof FLAG_DEFS)[number]) =>
    def.valueName ? `--${def.flag} ${def.valueName}` : `--${def.flag}`;
  const width = Math.max(...FLAG_DEFS.map((d) => flagCol(d).length), '--help'.length) + 2;

  for (const def of FLAG_DEFS) {
    const label = flagCol(def).padEnd(width);
    const required = def.required ? ' (required)' : '';
    lines.push(`  ${label}${def.description}${required} [env: ${def.envVar}]`);
  }
  lines.push(`  ${'--help, -h'.padEnd(width)}Show this help and exit`);
  lines.push(`  ${'--version, -v'.padEnd(width)}Print the installed version and exit`);
  lines.push('');
  lines.push('Every flag above also has an env-var fallback (shown in brackets); an');
  lines.push('explicit flag always wins over the env var.');

  return lines.join('\n');
}
