# Contributing

This package contains common code shared between the `k8s` and `machine` `vault` charms. Updates to this code must be vendored into both of these charms. To do so, run `make vendor-shared-code` in the `k8s/` and `machine/` directories, or run any of their `tox` commands. Ensure that all changed files and any newly created files are committed to version control.

Unit tests for this package go under `tests/unit`, while tests that integrate with the charms themselves go in the charms' `tests` directories.

This project uses `uv`. You can install it on Ubuntu with:

```shell
sudo snap install --classic astral-uv
```

You can create an environment for development with `uv`:

```shell
uv sync
source .venv/bin/activate
```

## Testing

This project uses `tox` for managing test environments. It can be installed with:

```shell
uv tool install tox --with tox-uv
```

There are some pre-configured environments that can be used for linting
and formatting code when you're preparing contributions to the charm:

```shell
tox run -e format        # update your code according to linting rules
tox run -e lint          # code style
tox run -e static        # static type checking
tox run -e unit          # unit tests
tox                      # runs 'lint', 'static', and 'unit' environments
```
