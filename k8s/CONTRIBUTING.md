# Contributing to the `vault-k8s` charm

To make contributions to this charm, you'll need a working [development setup](https://juju.is/docs/sdk/dev-setup).

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

This project uses `tox` for managing test environments. It can be installed
with:

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
tox                      # runs 'format', 'lint', 'static', and 'unit' environments
```

### Running the integration tests locally

To run the integration tests locally, you will need to have a Juju controller
on `microk8s` active.

First, you need to build the `vault-k8s` charm, as well as the test `vault-kv-requirer` charm. From the project root, run the following commands:

```shell
charmcraft pack
charmcraft pack --project-dir tests/integration/vault_kv_requirer_operator/
```

Then, you can run the integration tests with:

```shell
tox -e integration -- --charm_path ./vault-k8s_ubuntu-22.04-amd64.charm --kv_requirer_charm_path ./vault-kv-requirer_ubuntu-22.04-amd64.charm
```

## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```
