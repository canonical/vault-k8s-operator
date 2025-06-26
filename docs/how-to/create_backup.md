# Create a backup

## Pre-requisites

To create a Vault Backup, ensure you:
- Have a Vault cluster deployed.
- Your Vault deployment is in *active idle* state.
- Have access to S3 storage.
- Have [configured the settings for S3 storage](../reference/s3_storage.md).
- Have saved your unseal keys and root-token in a secure location of your choice.

**Note**: The unseal keys and root-token used at the time of creating the backup must be saved as they will be required to perform the restore action.

Once the prerequisites are in place you can run the `create-backup` action on the leader unit to create a backup:

`juju run vault/leader create-backup`

The action will create a snapshot of the Vault cluster, save it to the configured S3 storage and return the identifier of the backup.

## List backups
It is possible to list all backups that are saved in the configured S3 storage using the `list-backups` action:
`juju run vault/leader list-backups`
