# Submitting a community maturity pack

This is the author-facing guide to publishing a maturity pack through
CMDash's content hub. If you want the security design (signature scheme,
trust root, install pipeline), see `docs/design/content-hub.md` instead —
this doc is just "how do I get my pack in front of a tenant's install
button."

## What a submission contains

A directory under
`packages/shared/src/content-hub/community-packs/<your-pack-slug>/`
containing exactly two files:

```
community-packs/
  your-pack-slug/
    pack.json        # the content pack itself
    signature.json    # detached signature over pack.json, added at review time
```

- **`pack.json`** — a maturity content pack in the format defined by
  `packages/shared/src/maturity-packs/pack.schema.json` and
  `docs/design/maturity-engine.md` §4: one `model` (slug/name/version/
  minOrdinal/maxOrdinal/provenance), an ordinal `levels` ladder, and a
  `dimensions` list with `controlMappings` referencing existing framework
  controls by `(frameworkSlug, controlKey)`.
  - `model.provenance` is **mandatory** (`publisher`, `sourceDoc`,
    `sourceUrl`, `license`) — this is what every tenant sees on the
    pre-install screen, so make it accurate. `sourceUrl` must be
    `http://` or `https://`.
  - **Your `model.slug` must not collide with a built-in model's slug**
    (`nist-csf-2-tiers`, `cis-controls-ig`, `c2m2`, `cisa-ztmm`,
    `identity-posture`, `human-risk`, `tool-coverage`) — the install
    pipeline hard-rejects a pack whose declared slug matches an existing
    built-in, exactly to stop a submission from impersonating official
    content. If you're forking/adapting a built-in framework, pick a
    clearly distinct slug (e.g. `acme-nist-csf-2-variant`).
  - You do **not** need to author `signature.json` yourself — see
    "How it's reviewed" below.

- **`signature.json`** — added by whoever signs the pack (a maintainer, or
  you, if you hold a trust-root key already):

  ```json
  {
    "keyId": "cmdash-official-2026",
    "algorithm": "ed25519",
    "signature": "<base64>",
    "signedAt": "2026-07-21T00:00:00.000Z"
  }
  ```

  It signs the **canonicalized bytes** of `pack.json` — never edit
  `pack.json` after it's been signed without re-signing (any edit at all,
  even reordering fields cosmetically, produces the same canonical bytes
  only if the *content* is unchanged — see `docs/design/content-hub.md`'s
  canonicalization section for exactly what varies vs. what doesn't).

## How you submit

1. Author `pack.json`. Validate it locally before opening a PR:

   ```
   node scripts/maturity/validate-pack.mjs path/to/your/pack.json
   ```

   This runs the full two-layer gate (structural JSON-Schema +
   cross-field rules) — fix everything it reports before moving on.

2. Open a PR adding
   `packages/shared/src/content-hub/community-packs/<your-pack-slug>/pack.json`
   only (no `signature.json` yet — you can't sign it; you don't hold a
   trust-root private key).

3. A maintainer reviews the PR like any other content change: does the
   framework mapping make sense, is the provenance accurate, does the
   `model.slug` avoid impersonating a built-in, are the control mappings
   real and not gratuitously vague. Once approved:

   ```
   node scripts/content-hub/sign-pack.mjs \
     packages/shared/src/content-hub/community-packs/<your-pack-slug>/pack.json \
     <path-to-maintainer's-private-key.pem> \
     <keyId>
   ```

   `sign-pack.mjs` re-runs the same `validate-pack.mjs` gate itself and
   refuses to sign an invalid pack — it will not produce a
   `signature.json` for something that wouldn't install anyway.

4. The maintainer commits the resulting `signature.json` alongside
   `pack.json` in the same PR, and merges.

5. On the next deploy, your pack ships inside the API image (same
   mechanism as `packages/shared/src/maturity-packs/` — the whole
   `packages/shared` directory, including `content-hub/community-packs/`,
   is copied verbatim, and `tsc` copies referenced `.json` files into
   `dist/` at build time) and appears in every tenant's content hub
   (`GET /content-hub/packs`), verified and ready to install.

## How CI validates it

`scripts/content-hub/verify-submission.mjs` walks every directory under
`packages/shared/src/content-hub/community-packs/` and, for each,
re-checks the exact two things the runtime install pipeline checks:

1. `pack.json` passes `validate-pack.mjs`'s full structural + cross-field
   gate (the same command you ran locally in step 1).
2. `signature.json` verifies against an **active** entry in
   `packages/shared/src/content-hub/trust-root.json` for the declared
   `keyId`.

Run it yourself any time:

```
node scripts/content-hub/verify-submission.mjs
```

Exit code `0` means every submission verifies; `1` means at least one
failed, with the specific reason printed per pack. **This script is not
yet wired into `.github/workflows/ci.yml`** (that file belongs to a
separate, concurrent workstream) — until it is, a reviewer should run it
by hand before merging a `content-hub/community-packs/**` PR, and a
follow-up should add it as a CI step so an unsigned/invalid submission
can never merge silently.

## Getting a trust-root key of your own

If you're a recurring publisher (not a one-off submission signed by a
maintainer), you can hold your own key: run
`scripts/content-hub/generate-keypair.mjs <keyId> <your-org-name> --out
<somewhere-outside-this-repo>.pem`, send the printed public-key entry to a
maintainer, and — after they're satisfied you're a legitimate,
identifiable publisher — it gets added to `trust-root.json` via a normal,
reviewed PR (see `docs/design/content-hub.md`'s "how a key is added").
**Never send the private key file anywhere** — only the printed JSON entry
(which contains just the public key) should ever leave your machine.

## Revocation / getting removed

Contact a maintainer. Your key's `trust-root.json` entry gets its `status`
flipped to `"revoked"` in a normal PR — every pack you've ever signed
immediately stops verifying (existing tenant installs of your packs are
untouched — installing is a one-time write, not a live subscription — but
no tenant can newly install or re-verify one of your packs as trusted
going forward, and the content hub's pre-install badge shows it as
untrusted for anyone who hasn't installed it yet).
