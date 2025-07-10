# Contributing

This repository contains the source code for the `vault-k8s` and `vault` charms. You can find the contributing guidelines in each charm's directory if you want to contribute to one of these charms.

Tool settings for linting, static analysis, and testing are configured in the repo-level `pyproject.toml`. Project-specific settings for `ruff` and `pyright` may be defined in individual `pyproject.toml` files if necessary, but prefer the repo-level `pyproject.toml` where possible.

## Common code between the Machine and K8s charms

Shared code used by both the Vault machine and K8s charms is defined in `vault-package`. This code is vendored into both charms so that `charmcraft pack` can run in each directory without any additional information. Vendored code **must** be in sync to merge to `main`.

Vendored code is syncronised into a charm when running any of its `tox` commands. When editing shared code, it is best practice to run `tox` for both charms to ensure the changes work for both charms. However, you can also manually vendor the shared code by running the following command in the `k8s/` and `machine/` directories:

```shell
make vendor-shared-code
```

## Documentation

Serve the documentation locally with:

```shell
cd docs
make run
```
