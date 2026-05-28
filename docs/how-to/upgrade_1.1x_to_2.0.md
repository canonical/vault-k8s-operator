# Upgrade from 1.1x to 2.0

This guide covers the upgrade path from any Vault charm 1.1x version (1.15, 1.16, 1.17, 1.18, 1.19) to 2.0. For general upgrade instructions, see the [upgrade guide](upgrade.md).

## Pre-requisites

- Vault 1.1x is deployed and in `active/idle` state.
- In the case of upgrading `vault-k8s`, it is recommended to have at least 5 units deployed and active to ensure minimal to no downtime.
- Access to S3 storage for creating a backup.

## Breaking changes

Vault 2.0 is a major version upgrade of the Vault workload. Review the [HashiCorp Vault 2.0 upgrade guide](https://developer.hashicorp.com/vault/docs/upgrading) for details on upstream changes.

Key points:

- **Vault workload version**: The Vault binary is upgraded to 2.0.x. While HashiCorp maintains backward compatibility for the storage format, this is a major version jump.
- **Charm base change (from 1.16 or earlier)**: If you are upgrading from 1.16 or earlier, the charm base changes from `ubuntu@22.04` to `ubuntu@24.04`. The `juju refresh` command must include the `--base ubuntu@24.04` flag. Without it, Juju will reject the upgrade.
- **No charm base change (from 1.17+)**: If you are upgrading from 1.17 or later, the base is already `ubuntu@24.04`. No `--base` flag is needed.
- **Configuration key rename (from 1.16 or earlier)**: The `common_name` configuration option was renamed to `pki_ca_common_name` in 1.19. If you are upgrading from 1.16 or earlier and using the `vault-pki` relation, you must record the current value before upgrading and re-apply it using the new key after the upgrade.
- **Machine charm snap channel**: For the machine charm, the snap channel changes to `2.0/stable`. This is handled automatically by the charm.

## Upgrade procedure

### 1. Create a backup

Create a backup of your Vault data following [this guide](create_backup.md) in case anything goes wrong during the upgrade.

### 2. Save your unseal keys

Make sure to save your unseal key(s), as the upgrade operation will seal all units. You will need these keys to unseal Vault after the upgrade.

### 3. Record current PKI configuration (from 1.16 or earlier only)

If you are upgrading from 1.16 or earlier and using the `vault-pki` relation, save your current `common_name` value:

```shell
juju config vault common_name
```

### 4. Run the upgrade

If upgrading from **1.17 or later** (base is already `ubuntu@24.04`):

```shell
juju refresh vault --channel=2.0/stable
```

If upgrading from **1.16 or earlier** (base change required):

```shell
juju refresh vault --channel=2.0/stable --base ubuntu@24.04
```

### 5. Reconfigure PKI (from 1.16 or earlier only)

If you were using the `vault-pki` relation and upgraded from 1.16 or earlier, set the new configuration key:

```shell
juju config vault pki_ca_common_name=<your-common-name>
```

### 6. Unseal Vault

Unseal all Vault units using your saved unseal keys. See the unseal guide for your platform:

- [Unseal (Kubernetes)](unseal_k8s.md)
- [Unseal (Machine)](unseal_machine.md)

### 7. Verify the upgrade

Wait for all units to settle and verify the deployment is healthy:

```shell
juju status
```

All units should reach `active/idle` state.

## Rollback

If the upgrade fails, restore from the backup you created in step 1 using the [restore guide](restore_backup.md).
