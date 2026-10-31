# Connector development guide

ROADMAP-COMPETITIVE bet 1 item 1.4. This is CMDash's answer to "publish an SDK so partners and
customers become connector supply instead of waiting for a CMDash release" — but the shape of that
answer is deliberately narrower than "SDK" usually implies, and it's worth being explicit about
that before anything else here makes sense.

## What you're actually building: data, not code

There is no `@cmdash/connector-sdk` package to install, and there is no compiled adapter class to
write and submit. What you build and share is a **declarative connector definition** — an HTTP
request template plus a JSONPath field-mapping list — in exactly the shape item 1.1's
tenant-defined custom connectors already use. It is a JSON document, not a program.

This is a deliberate boundary, not a v1 limitation waiting to be lifted:

- A **compiled, community-contributed adapter** would run inside CMDash's own application process
  with full database and dependency-injection access. That is a real supply-chain risk — a
  malicious or merely careless adapter could read or write anything the CMDash API server itself
  can — and this plan does not take it on.
- A **declarative definition** is inert data until a tenant installs it into their own
  `CustomConnector`, at which point it runs through exactly the same execution path — SSRF
  protection, rate limiting, circuit breaking, the narrow JSONPath evaluator — as one a tenant wrote
  by hand. Sharing the definition changes nothing about how safely it executes.

If what you actually need is to package and run logic that a declarative request/JSONPath template
cannot express, this program is not the right fit for it — that is real engineering work CMDash
would need to do as a vendor adapter, not something a definition file can become.

## The definition shape

A connector definition is the same object `ConnectorTemplate.definition` stores and a
`CustomConnector` row's own fields describe:

```jsonc
{
  "endpointUrl": "https://api.example.com/v1/status", // http(s), must resolve publicly
  "httpMethod": "GET", // GET | POST | PUT | PATCH
  "requestHeaders": { "Accept": "application/json" }, // static, NON-SECRET only
  "requestBody": null, // string template, POST/PUT/PATCH only
  "authType": "BEARER_TOKEN", // see auth types below
  "fieldMappings": [
    {
      "jsonPath": "$.data.controls[*].state",
      "targetField": "controlState",
      "target": "OBSERVATION", // OBSERVATION | EVIDENCE
      "observationType": "CSPM_CONTROL_STATE", // required when target is OBSERVATION
    },
  ],
}
```

The full, authoritative shape (including field-by-field limits) lives in
[`connector-conformance-kit/definition.schema.json`](connector-conformance-kit/definition.schema.json)
— a portable JSON Schema, not CMDash-specific tooling. The field-by-field walkthrough — what each
auth type expects, the JSONPath subset with worked examples, and the OBSERVATION-vs-EVIDENCE choice
— is [`docs/integration-setup-custom-connector.md`](../integration-setup-custom-connector.md), the
same guide a tenant authoring a connector by hand already uses; this document does not repeat it.

**No credential ever belongs in a definition.** `requestHeaders`/`requestBody` are non-secret
templates. A tenant supplies their own credential — API key, bearer token, username/password, or
OAuth2 client-credentials pair — at install time, and it is stored through the same
encrypted-at-rest path (never a header string) every built-in connector's credential uses. A
definition with a literal secret baked into a header is exactly what
[the conformance kit](connector-conformance-kit/) flags, and exactly what a reviewer will reject on
sight.

## Build it, prove it, then share it

1. **Author it as your own custom connector first.** Integrations → Custom Connectors → New
   connector (or `POST /integrations/custom-connectors`). Use dry-run repeatedly until every mapping
   resolves against the real source — dry-run issues the actual request and shows exactly what each
   mapping extracted, through the identical code path a scheduled sync takes, so nothing about
   "works in the wizard" can drift from "works when scheduled".
2. **Validate the shape standalone**, optionally, before or alongside step 1 —
   `node connector-conformance-kit/validate.mjs your-definition.json` (zero dependencies, runs
   outside this repo). It catches the same shape and JSONPath-grammar issues the server does, so a
   submission doesn't bounce back on something mechanical.
3. **Submit it for review** once it works: `POST /integrations/connector-templates/submit/:id` with
   your working connector's id (or Integrations → Custom Connectors → Browse Templates → Submit
   yours). This copies the definition — never the connection or credential — into a new template
   row visible only to you, `UNDER_REVIEW`.
4. **A CMDash reviewer looks at it.** There is no automated approval path. A person checks the
   request target and mappings look like what they claim to be, that no field mapping is a vector
   for something it shouldn't be, and that the category/description make sense to someone browsing
   the catalog. This is a human process — expect it to take longer than a CI pipeline would.
5. **Published or rejected.** Check `GET /integrations/connector-templates/mine` (or the same Browse
   Templates screen) to see the outcome. A rejection carries a reason where the reviewer left one.

## "CMDash-reviewed", never "signed"

Once published, a template carries a SHA-256 checksum of its definition's canonical JSON, plus who
reviewed it and when. Read that checksum for exactly what it is and nothing more:

> **This exact byte content was reviewed by CMDash on this date.** That's the whole claim. It is
> verifiable — recompute the hash over the canonical JSON and compare. It is **not** a claim about
> who originally authored the definition, and it is **not** cryptographic proof of provenance the
> way a code-signing certificate or a Sigstore attestation would be. CMDash has no code-signing
> infrastructure in this product today, and "reviewed" is the accurate word for what actually
> happened — a person looked at it. **Never call this "signed" in anything user-facing** — that
> word promises a provenance guarantee this mechanism does not provide, and doing so would be a
> larger and more consequential change than adding a word suggests.

If you're building tooling that consumes CMDash's published templates and want to verify a
checksum yourself: canonicalize the `definition` JSON (recursively sort object keys, UTF-8 encode — the exact
algorithm CMDash uses) and SHA-256 it. A mismatch means the stored definition changed
since it was last reviewed.

## Installing someone else's template

Browse published templates at `GET /integrations/connector-templates` or Integrations → Custom
Connectors → Browse Templates. Installing one (`POST
/integrations/connector-templates/:templateId/install`) copies the definition into a brand new
`CustomConnector` that belongs entirely to you — you supply your own credential, it consumes one of
your own `maxIntegrations` slots exactly like any other connector, and it runs on your own schedule.
There is no ongoing link back to the template or its original author; installing is a one-time copy,
not a subscription.

## FAQ

**Does my organization need to be on a particular tier to do any of this?** Defining a custom
connector (including submitting or installing a template) requires the same entitlement as item
1.1's custom connectors generally — see `docs/integration-setup-custom-connector.md`'s
Prerequisites.

**Can I edit a template after I submit it?** Not directly — submit a fresh one from an updated
connector if you need to change something before it's reviewed. There is currently no "resubmit" or
"delete my own rejected submission" action; if you need either, ask CMDash support.

**What happens to connectors that already installed a template if it's later taken down?** Nothing.
Installing COPIES the definition; a deprecated or removed template only stops appearing in the
browse listing going forward. Your own connector keeps running exactly as configured.

**Where does a malicious or merely broken template get caught?** Three independent places, on
purpose: the conformance shape check (this kit), a human reviewer before anything is published, and
`assertSafeUrl`/`safeFetch` at every single run — including a dry-run — regardless of who authored
the definition or how long ago it was reviewed. A hostname that resolved publicly last month can
resolve to a private address today, and every run is checked as if it were the first.
