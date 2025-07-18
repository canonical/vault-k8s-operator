# Release Notes

## What's New:

- Add the `ingress-per-unit` relation allowing the Vault charm to be used behind an ingress. Each unit can be accessed through a unique URL.
- Add the `tracing` relation, allowing to read the Vault charm traces in an OpenTelemetry compatible tracing system.
- Add a `bootstrap-raft` action, allowing to bootstrap the raft storage backend when quorum is lost.

Full Changelog: [Changes compared to 1.15](https://github.com/canonical/vault-k8s-operator/compare/release-1.15...release-1.16)
