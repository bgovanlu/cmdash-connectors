# Connector conformance kit

ROADMAP-COMPETITIVE bet 1 item 1.4. This folder is what "publishing the connector SDK" means in
practice — see [`../connector-development.md`](../connector-development.md) for the full guide.
There is no new runtime package here on purpose: a contributed connector is a **declarative
definition** (an HTTP request template plus a JSONPath field-mapping list), not compiled code that
would run inside CMDash's process. Publishing the SDK is publishing the shape of that definition
and a way to check a candidate against it, not a library to install.

## What's in this folder

- **`definition.schema.json`** — a portable [JSON Schema](https://json-schema.org/) describing a
  connector definition. Validate with any tool, in any language: `ajv`, `python-jsonschema`,
  an online validator, whatever you already have. This is the fastest way to check the shape of a
  definition without installing anything CMDash-specific.
- **`validate.mjs`** — a zero-dependency Node script that checks everything the schema can, plus
  one thing it can't: whether each `jsonPath` actually parses under CMDash's deliberately narrow
  JSONPath grammar (see below). Run it directly:

  ```
  node validate.mjs examples/valid-example.json
  node validate.mjs path/to/your-definition.json
  ```

  Requires only Node 18+. Copy this one file out of the repo and it still runs — it does not
  `import` anything from the rest of the monorepo, and it never touches the network.

- **`examples/valid-example.json`** / **`examples/invalid-example.json`** — a definition that
  passes, and one that fails on four independent, deliberately different grounds (a header that
  looks like a hardcoded credential, a JSONPath filter expression, an observation type outside the
  frozen vocabulary, and a duplicate target field) so you can see what each failure mode actually
  reports.

## What this kit proves, and what it does not

Passing `validate.mjs` means a definition has the right SHAPE. It does **not** mean:

- **The endpoint is reachable and safe.** CMDash validates that `endpointUrl` (and any OAuth2
  `tokenUrl`) resolves to a public address, at save time AND again on every scheduled run — this
  is a live network + DNS check this
  offline script cannot and deliberately does not perform.
- **The field mappings actually match the source's real response.** That is what the product's own
  dry-run does (`POST /integrations/custom-connectors/:id/dry-run`) — it issues the real request
  and shows exactly what each mapping extracted, against the live target, through the exact same
  code path a scheduled sync takes. Run it before you submit a template for review.
- **A human reviewer will approve it.** Passing conformance is a precondition for submission, not
  a substitute for review. See `connector-development.md`'s "Submitting a template" section for
  what a reviewer is looking for.

## The JSONPath grammar, and why it's this narrow

CMDash supports exactly: `$` (root), `.name` / `['name']` / `["name"]` (member access), `[0]`
(index), `[*]` (wildcard). No filter expressions (`[?(...)]`), no recursive descent (`..`), no
slices, no unions. This is a security decision: those four constructs are what make a JSONPath
engine capable of evaluating code, and a mapping you author runs server-side, on CMDash's own
infrastructure, against a response CMDash fetched — the very definition of an untrusted-input code
path. `validate.mjs`'s `parseJsonPath` is a byte-for-byte parity copy of the real server-side
parser; the reasoning includes the two published RCE advisories in the general-purpose library CMDash
considered and rejected for this exact reason.

**Parity is enforced, not just promised.** CMDash runs a fixed battery of paths through both
copies in its own test suite and fails the build if they ever disagree.
If you find a path this kit accepts that the real server rejects (or vice versa), that is a bug —
please report it rather than working around it.

## Next step: submitting a template

Once your definition passes conformance and a dry-run against the real source, an OWNER/ADMIN on
your workspace submits it for review from **Integrations → Custom Connectors → Browse Templates →
Submit yours**, or `POST /integrations/connector-templates/submit/:customConnectorId`. See
`connector-development.md` for the full submission-to-publication lifecycle, and for exactly what
"CMDash-reviewed" does and does not claim about a published template.
