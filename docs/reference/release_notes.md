# Release Notes

## What's New:

- The K8s Charm now uses 1.19.x Vault OCI image and the Machine Charm uses the 1.19.x Vault Snap.
- The Machine Charm now supports a `logrotate_frequency` configuration option to control how often syslog is rotated. Accepted values are `daily` (default), `weekly`, and `monthly`.

Full Changelog: [Changes compared to 1.18](https://github.com/canonical/vault-k8s-operator/compare/release-1.18...main)
