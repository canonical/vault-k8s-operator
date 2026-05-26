# Upgrade Vault

## Pre-requisites

- Vault >= 1.15 is deployed
- In the case of upgrading `vault-k8s`, it is recommended to have at least 5 units deployed and active to ensure minimal to no downtime.

## Upgrade Procedure

- Create a backup of your Vault data following [this guide](create_backup.md) (in case anything goes wrong during the upgrade).
- Make sure to save your unseal key(s), as this operation will seal all units.
- Run `juju refresh vault --channel=$VAULT_HIGHER_VERSION`, where VAULT_HIGHER_VERSION is a supported version higher than the one you currently have deployed.

## Version-specific upgrade guides

For major version upgrades, consult the version-specific guides:

- [Upgrade from 1.1x to 2.0](upgrade_1.1x_to_2.0.md)
