# Contributing

This repository contains the source code for the `vault-k8s` and `vault` charms. You can find the contributing guidelines in each charm's directory if you want to contribute to one of these charms.

## Common code between the Machine and K8s charms

The Vault machine and K8s charms share a lot of code. The K8s charm owns this common code and you can fetch this code into the Machine charm using:

```shell
tox -e vendor-machine-libs
```
