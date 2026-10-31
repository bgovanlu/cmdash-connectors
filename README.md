# CMDash Connectors

Everything needed to write, check and run a CMDash connector outside CMDash, plus the community and maturity content packs. Questions and pack proposals go to this repository's Discussions.

| Directory | What it is |
|---|---|
| [`packages/connector-runtime`](packages/connector-runtime) | the execution engine for declarative connectors (JSONPath mappings, signatures, collector attestation) |
| [`packages/collector-cli`](packages/collector-cli) | `cmdash-collector`, the one-shot collector that runs connector definitions inside your network |
| [`docs/developers/connector-conformance-kit`](docs/developers/connector-conformance-kit) | the connector definition schema, a zero-dependency validator and examples; the guide is `docs/developers/connector-development.md` |
| [`packages/shared/src/content-hub/community-packs`](packages/shared/src/content-hub/community-packs) | signed community maturity packs and the trust root (data only; see `docs/content-hub/submitting-a-pack.md`) |
| [`packages/shared/src/maturity-packs`](packages/shared/src/maturity-packs) | the built-in maturity packs and their JSON Schema (data only) |

Version 0.2.0. Each directory has its own README.

## Licence

Apache-2.0; see `LICENSE` and `NOTICE`. Third-party dependencies are listed in `THIRD_PARTY_NOTICES.md`.
This repository is mirrored from the CMDash monorepo; the CMDash platform itself is proprietary.

## Security

See `SECURITY.md`. Do not open a public issue for a vulnerability.
