# Upgrade Vault

## Pre-requisites

- Vault >= 1.15 is deployed
- In the case of upgrading `vault-k8s`, it is recommended to have at least 5 units deployed and active to ensure minimal to no downtime.

## Upgrade Procedure

- Create a backup of your Vault data following [this guide](https://discourse.charmhub.io/t/how-to-create-a-backup-with-vault/12863) (in case anything goes wrong during the upgrade).
- run `juju refresh vault --channel=$VAULT_HIGHER_VERSION` where VAULT_HIGHER_VERSION is any version higher than the one you have currently deployed.
