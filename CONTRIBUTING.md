# Contributing

This repository contains the source code for the `vault-k8s` and `vault` charms. You can find the contributing guidelines in each charm's directory if you want to contribute to one of these charms.

## Common code between the Machine and K8s charms

The Vault machine and K8s charms share code. The K8s charm owns the files that are identical on both platforms. From the repository root, copy those files into the machine charm using:

```shell
make vendor-libs
```

This command copies only the identical files from `k8s/lib/vault/` to `machine/lib/vault/`. The `vault_helpers.py` and `vault_managers.py` files have platform-specific behavior, including auto-unseal configuration. Port changes to those files separately.

Run `make check-vendored-libs` to verify that the identical files are in sync. CI runs this check on every pull request.
