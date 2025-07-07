# Vault Charms 1.17 Release Notes

## What's New:

- Both K8s and Machine charms run on Ubuntu@24.04 now as a base.
- The K8s Charm now uses 1.17.x Vault OCI image and the Machine Charm uses the 1.17.x Vault Snap.
- Allow user to configure the log level of the charm. ([#632](https://github.com/canonical/vault-k8s-operator/pull/632))
- Allow the user to configure and enable the ACME engine using the charm. ([#635](https://github.com/canonical/vault-k8s-operator/pull/635))
- Allow the user to run the backup and restore actions on the machine charm without TLS verification. ([#656](https://github.com/canonical/vault-k8s-operator/pull/656))

Full Changelog: [Changes compared to 1.17](https://github.com/canonical/vault-k8s-operator/compare/release-1.16...release-1.17)
