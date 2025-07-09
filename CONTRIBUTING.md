# Contributing

This repository contains the source code for the `vault-k8s` and `vault` charms. You can find the contributing guidelines in each charm's directory if you want to contribute to one of these charms.

## Common code between the Machine and K8s charms

Shared code used by both the Vault machine and K8s charms is defined in `vault-package`. This code is vendored into both charms so that `charmcraft pack` can run in each directory without any additional information. Vendored code must be in sync to merge to `main`. Copy any changes from `vault-package` into the charms by running:

```shell
make vendor-shared-code
```

## Documentation

Serve the documentation locally with:

```shell
cd docs
make run
```
