# Maturity content packs

Data, not code — the maturity-engine analogue of `packages/shared/src/landscape`.
One JSON file per `MaturityModel`, named `<slug>.json`, matching the format
defined in [`docs/design/maturity-engine.md`](../../../../docs/design/maturity-engine.md)
§4 and encoded machine-readably in [`pack.schema.json`](./pack.schema.json)
(JSON Schema draft 2020-12).

Packs are authored and applied with the scripts in
[`scripts/maturity/`](../../../../scripts/maturity/), never edited by hand
in place — see [`scripts/maturity/author-pack.md`](../../../../scripts/maturity/author-pack.md)
for the authoring playbook:

```
node scripts/maturity/validate-pack.mjs  <pack.json>                  # structural + cross-field checks
node scripts/maturity/apply-pack.mjs     <pack.json> [--dry-run]      # validate, then write <slug>.json here
```

Each file is loaded by a dedicated pack loader at install/upgrade time (not
the CSV framework-import path, which is the wrong shape for ordinal levels).
`model.slug` is the stable identity across versions; `model.version` and
`packFormatVersion` are compared on upgrade, and dimension `previousKeys`
carry renames forward. See §4 of the design doc for the full version-migration
story.

Every pack's `model.provenance` (`publisher`, `sourceDoc`, `sourceUrl`,
`license`) is mandatory and shown to tenants before they adopt the model.
