# Contributing

This repository contains the source code for the `vault-k8s` and `vault` charms. If you want to contribute to one of these charms, you can find the contributing guidelines in each of the charm's directory.

## Common code between the Machine and K8s charms

The Vault machine and K8s charms share a lot of code. This common code is owned by the k8s charm in its `lib` directory. The common code can be vendored into the machine charm using:

```shell
tox -e vendor-machine-libs
```
