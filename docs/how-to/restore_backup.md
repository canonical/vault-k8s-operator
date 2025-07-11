# Restore a backup

## Pre-requisites

To restore a Vault Backup, ensure you:
* Have a Vault cluster deployed.
* Your Vault deployment is in *active idle* state.
* Have access to S3 storage where your backup is saved.
* Have [configured the settings for S3 storage](../reference/s3_storage.md).
* Have access to the unseal keys and root-token used by the Vault cluster at the time of creating the backup.

Once the prerequisites are in place you can run the `restore-backup` action on the leader unit to restore the specified backup, providing the following parameters to the action:
- backup-id: Identifier of the backup you are attempting to restore, as saved on the S3 storage.

`juju run vault/leader restore-backup backup-id=<backup-id> `

The restored Vault will be unsealed and it will require to be [unsealed](https://charmhub.io/vault-k8s/docs/h-unseal) an authorised using root token and unseal key that were in use at the time of creating the backup.

## List backups

You can get a list of the identifiers of all the backups that are stored on the configured S3 storage using the `list-backups` action:

`juju run vault/leader list-backups`

## Restore Backups created in different environments
To restore a snapshot that wasn't created using the Vault charm's `create-backup` action, you'll need to manually upload it to the S3 storage accessible by the Vault charm where the `restore-backup` action will run.
1. [Configure the settings for S3 storage](../reference/s3_storage.md).
2.  Connect to your S3 storage
3. Use the same bucket configured in step 1 to store the snapshot
4. Use the ID of the stored snapshot to run the restore backup action
