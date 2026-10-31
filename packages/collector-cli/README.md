# CMDash Collector

A one-shot collector that runs your CMDash connector definitions **inside your own network** and pushes the results back.

It exists for estates CMDash cannot reach: air-gapped segments, CUI enclaves, anything behind a firewall that will never accept an inbound connection from a SaaS platform. CMDash's hosted connectors deliberately refuse private and link-local addresses as an anti-SSRF control; a collector running on your side has no such constraint, because there a private address is the expected destination.

## It is not a daemon

The collector runs once and exits. Your own scheduler invokes it — cron, Task Scheduler, a Kubernetes CronJob. That is deliberate: a binary with no held-open connections and no local persistence is far easier for a security team to review and approve under change control than a long-running service.

## Two credentials, not one

```
CMDASH_API_URL=https://app.cmdash.com
CMDASH_API_KEY=cmdash_ek_...          # authenticates the request
CMDASH_COLLECTOR_SECRET=<64 hex>      # signs the body
```

They are separate on purpose:

- A stolen API key **alone cannot forge a push** — the body must carry a valid HMAC signature.
- One collector can be **revoked without rotating every API key** on your account.

The signing secret is shown exactly once, when you enroll the collector in CMDash. There is no endpoint that returns it again; a secret you can re-read is a secret with two places to steal it from. If it is lost, re-enroll — that is cheap.

## Attested mode: the collector's own Ed25519 key

Enrolled with `attested: true`, the collector also holds an Ed25519 key it generates itself:

```bash
cmdash-collector enroll --enrollment-id <id> --registration-token <token> --identity-file ./collector-identity.json
CMDASH_COLLECTOR_IDENTITY=./collector-identity.json cmdash-collector    # every push now signed v2
cmdash-collector rotate-key --identity-file ./collector-identity.json   # endorsed by the old key
```

- The private key is created on this machine, written once with mode 0600, never sent, never
  printed. A file other users can read is refused.
- Every push carries the HMAC (`v1=`) **and** an Ed25519 signature (`v2=`) over the deployment,
  the tenant, the key id, a sequence number, a nonce, the time and the body's hash. CMDash refuses
  a v1-only push from an attested collector, and any sequence number it has already seen.
- A mapping whose target field is `edr-coverage` or `mfa-enrolled`, over JSON `true`/`false`
  values, becomes a signed measurement (anything else counts as unknown). Receipts built from it
  carry the collector's signature, verifiable with `cmdash-verify --collector-attestation`.

Specification: `docs/specs/collector-attestation-v0.md`.

## Per-connector credentials stay with you

For a `COLLECTOR`-mode connector, CMDash never holds the credential for your target system. The collector reads it from its own environment:

```
CMDASH_CONNECTOR_SECRET_<connector id with dashes as underscores>=...
```

This is the difference that lets a collector reach a system you would not give CMDash access to.

## Usage

```bash
cmdash-collector                       # run every assigned connector
cmdash-collector --dry-run             # show what would be pushed, push nothing
cmdash-collector --connector-id cc-123 # run one
cmdash-collector --timeout-ms 60000
```

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Every connector ran and pushed |
| `1`  | At least one connector failed |
| `2`  | Configuration problem — nothing ran |

A partial failure exits `1`, not `0`. A scheduler that sees success never alerts, and a collector nobody notices has stopped working is exactly the silent failure this product exists to surface.

## Why a mapping proven in the wizard behaves the same here

The dry run in the CMDash web wizard and this collector execute the **same code** — `@cmdash/connector-runtime` — not two implementations that happen to agree today. A JSONPath mapping you prove in the browser extracts the same values when the collector runs it against the same response.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE` in this directory. This is one of the open edges of CMDash
(ADR 0011, `docs/decisions/0011-open-edges-commercial-core.md`); the CMDash platform it talks to is
proprietary.
