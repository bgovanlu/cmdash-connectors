# Contributing to CMDash Connectors

Thank you for helping. This repository holds the parts of CMDash that run on your side or that anyone can
check without CMDash: the connector runtime, the self-hosted collector, the connector conformance kit, and the
community and maturity content packs. It is Apache-2.0. The CMDash platform itself is proprietary and is not
in this repository (ADR 0011, "Open edges, commercial core").

There are three kinds of contribution, and each has its own path.

## 1. A connector definition

A connector is a **declarative definition**: an HTTP request template plus a list of JSONPath field mappings.
It is data, never code, and it never runs inside CMDash as a program. The full guide is
`docs/developers/connector-development.md`.

1. **Check its shape.** Validate your definition with the conformance kit, which needs only Node 18 or later
   and no network:

   ```sh
   node docs/developers/connector-conformance-kit/validate.mjs path/to/your-definition.json
   ```

   `docs/developers/connector-conformance-kit/definition.schema.json` is the same rules as a portable JSON
   Schema, for any other validator. The kit's README says what passing does and does not prove.

2. **Run it against the real source.** In a CMDash workspace, create the connector under Integrations →
   Custom Connectors and use its dry run. The dry run issues the real request and shows what every mapping
   extracted, through the same code path a scheduled sync takes. Fix anything it shows before you submit.

3. **Submit it for review.** An owner or admin of your workspace submits the working connector from
   Integrations → Custom Connectors → Browse Templates → Submit yours. A CMDash reviewer checks the exact
   definition; once it is published it appears in the community gallery on cmdash.com with the date it was
   reviewed and the SHA-256 of the reviewed content. That checksum is not a signature: it lets anyone check
   that what they install is what was reviewed.

Never put a credential in a definition. The kit rejects a header that looks like a hard-coded secret; the
person who installs your connector supplies their own credential, which stays in their workspace.

## 2. A community maturity pack

The step-by-step guide is `docs/content-hub/submitting-a-pack.md`. In short:

1. Add `packages/shared/src/content-hub/community-packs/<your-pack-slug>/pack.json`, in the format of
   `packages/shared/src/maturity-packs/pack.schema.json`. Fill in `model.provenance` accurately (publisher,
   source document, source URL, licence): it is what every organization sees before it installs your pack.
   Pick a `model.slug` that does not collide with a built-in model.
2. Open a pull request with `pack.json` only. You do not sign it.
3. A maintainer reviews the mapping and the provenance, validates the pack, and signs it with a key in
   `packages/shared/src/content-hub/trust-root.json`. The signature (`signature.json`) is added in the same
   pull request. A pack is never edited after it is signed without being signed again.

## 3. A change to the runtime, the collector or the kit

Open an issue or a Discussion first for anything larger than a bug fix, so the design can be agreed before
you write it. Then open a pull request that:

- keeps the CI workflow green: it builds and typechecks the runtime and the collector, runs their tests,
  and checks the conformance kit's valid example, on every pull request;
- adds a test for the behavior it changes;
- does not import any package that is not in this repository.

`docs/developers/connector-conformance-kit/validate.mjs` carries a copy of CMDash's server-side JSONPath
parser, and the two must agree byte for byte. If you find a path the kit accepts and the server rejects, or
the reverse, report it as a bug rather than working around it.

## How a pull request lands

This repository is published from CMDash's main repository. A maintainer reviews your pull request here; when
it is accepted, it is applied in the main repository with you credited as an author, and it comes back here
with the next published version.

## Questions

Use this repository's Discussions for questions about writing a connector or a pack, the collector, or what
is being built next. Report a security issue privately to security@cmdash.com, never in a public issue or
Discussion (see `SECURITY.md`).

## Licence

This repository is licensed under Apache-2.0 (`LICENSE`). Under section 5 of that licence, a contribution you
submit for inclusion is provided under the same terms, unless you state otherwise in writing.

Everyone taking part is expected to follow the CMDash community code of conduct, published at
https://www.cmdash.com/community/code-of-conduct.
