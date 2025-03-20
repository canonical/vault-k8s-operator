# Contributing

This repository contains the source code for the `vault-k8s` and `vault` charms. If you want to contribute to one of these charms, you can find the contributing guidelines in the charm's directory.

## Common code between the Machine and K8s charms

The Vault machine and K8s charms share a lot of common code. This common code is stored in the `lib` directory and then vendored into the `src/lib` directory of each charm. Vendoring is done using:

```shell
tox -e vendor-libs
```

You can run lint and unit tests on the common code using:

```shell
tox -e lint
tox -e unit
```
