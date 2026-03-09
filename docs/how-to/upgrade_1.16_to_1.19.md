# Upgrade from 1.16 to 1.19

This guide covers the upgrade path from Vault charm 1.16 to 1.19. For general upgrade instructions, see the [upgrade guide](upgrade.md).

## Pre-requisites

- Vault 1.16 is deployed and in `active/idle` state.
- In the case of upgrading `vault-k8s`, it is recommended to have at least 5 units deployed and active to ensure minimal to no downtime.
- Access to S3 storage for creating a backup.

## Breaking changes

- The charm base changes from `ubuntu@22.04` to `ubuntu@24.04`. The `juju refresh` command must include the `--base ubuntu@24.04` flag to allow the base change. Without it, Juju will reject the upgrade.
- The `common_name` configuration option has been removed and replaced by `pki_ca_common_name`. If you are using the `vault-pki` relation, you must record the current value before upgrading and re-apply it after the upgrade using the new key. Failing to do so will cause the PKI secrets engine to enter a blocked state.

## Upgrade procedure

### 1. Record current configuration

If you are using the `vault-pki` relation, save your current `common_name` value:

```shell
juju config vault common_name
```

### 2. Create a backup

Create a backup of your Vault data following [this guide](create_backup.md) in case anything goes wrong during the upgrade.

### 3. Save your unseal keys

Make sure to save your unseal key(s), as the upgrade operation will seal all units. You will need these keys to unseal Vault after the upgrade.

### 4. Run the upgrade

```shell
juju refresh vault --channel=1.19/stable --base ubuntu@24.04
```

### 5. Reconfigure PKI

If you were using the `vault-pki` relation, set the new configuration key with the value you saved in step 1:

```shell
juju config vault-k8s pki_ca_common_name=<your-common-name>
```

### 6. Unseal Vault

Unseal all Vault units using your saved unseal keys. See the [unseal guide](unseal_k8s.md) for detailed instructions.

### 7. Verify the upgrade

Wait for all units to settle and verify the deployment is healthy:

```shell
juju status
```

All units should reach `active/idle` state.
