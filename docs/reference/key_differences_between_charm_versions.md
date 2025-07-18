# Key differences between Vault charm version 1.8 and 1.15

Versions 1.8 (and below) and 1.15 (and beyond) are fundamentally different charms. Here is a list of additions, changes and removals made to the Vault charm 1.15, when compared with 1.8.

## Additions

- Act as an intermediate CA (see [How-to: use as an intermediate CA](../how-to/use_as_intermediate_ca.md)
- Auto unseal using a root unsealer Vault (see [How-to: Configure for Auto unseal](../how-to/configure_for_autounseal.md)
- Integration with Canonical Observability Stack (see [How-to: Integrate with COS (k8s)](../how-to/integrate_with_cos_k8s.md) and [How-to: Integrate with COS (machine)](../how-to/integrate_with_cos_machine.md))
- Backup and restore through Juju actions and integration with S3 storage (see [How-to: Create a backup](../how-to/create_backup.md) and [How-to: Restore a backup](../how-to/restore_backup.md))
- Vault UI

## Changes

- TLS Certificates integration:  The charm now implements the provider side of the TLS Certificates Integration [V1](https://github.com/canonical/charm-relation-interfaces/tree/main/interfaces/tls_certificates/v1) instead of [V0](https://github.com/canonical/charm-relation-interfaces/tree/main/interfaces/tls_certificates/v0) . This new version of the interface is more secure and only contains public information (CSR's and Certificates).
- Storage backend: The Vault charm now supports the Raft backend and drops support for other backends. Raft provides High Availability by default (see [Explanation: High Availability](../explanation/ha.md).

## Removals
- Providing the snap channel explicitly: Snap revisions are frozen to the charm revision providing reliable deployments.
- [Loadbalancer](https://charmhub.io/integrations/loadbalancer) integration

## Upgrading from 1.8 to 1.15

Upgrading from 1.8 to 1.15 is not supported, however you can backup your data on 1.8, and restore it on a new deployment of Vault 1.15.
