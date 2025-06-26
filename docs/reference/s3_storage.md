# S3 storage for Backup and Restore

The Vault operator implements the requirer side of the [S3](https://charmhub.io/integrations/s3) interface, enabling it to integrate with any charm that implements the provider side of this interface.

The Vault operator obtains the necessary information to connect to S3 storage through the S3 relation interface.

[S3-integrator](https://charmhub.io/s3-integrator) charm can also be used to integrate Vault with S3 storage if the storage itself does not support the S3 charm relation interface.
