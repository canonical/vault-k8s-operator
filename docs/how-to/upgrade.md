# Upgrade Vault

## Pre-requisites

- Vault >= 1.15 is deployed
- In the case of upgrading `vault-k8s`, it is recommended to have at least 5 units deployed and active to ensure minimal to no downtime.

## Upgrade Procedure

- Create a backup of your Vault data following [this guide](create_backup.md) (in case anything goes wrong during the upgrade).
- Make sure to save your unseal key(s), as this operation will seal all units.
- If you are upgrading an existing `1.1x` deployment, upgrade directly to `2.0/stable` using the [1.1x to 2.0 upgrade guide](upgrade_1.1x_to_2.0.md).

## Version-specific upgrade guides

All `1.x` tracks are deprecated and existing deployments should migrate to `2.0/stable`. For the version-specific procedure, follow:

- [Upgrade from 1.1x to 2.0](upgrade_1.1x_to_2.0.md)
