# packages/connector-runtime

`@cmdash/connector-runtime`: the shared execution engine for declarative custom connectors. The CMDash API's
adapter and the self-hosted collector ([`packages/collector-cli`](../collector-cli/README.md)) both run connector
definitions through this one engine, so a definition behaves the same in the cloud and inside a customer network.

Developer guidance for writing a connector: [docs/developers/connector-development.md](../../docs/developers/connector-development.md),
with the conformance kit in [docs/developers/connector-conformance-kit/](../../docs/developers/connector-conformance-kit/).
Installing the collector: [docs/runbooks/collector-install.md](../../docs/runbooks/collector-install.md).

## Build and test

```bash
npm run build -w packages/connector-runtime   # consumers read dist/
cd packages/connector-runtime
npm run test
npm run test:ci                               # with coverage, as the gate runs it
npm run typecheck
```

## Licence

Apache-2.0. See `LICENSE` and `NOTICE` in this directory. This is one of the open edges of CMDash
(ADR 0011, `docs/decisions/0011-open-edges-commercial-core.md`); the CMDash platform it talks to is
proprietary.
