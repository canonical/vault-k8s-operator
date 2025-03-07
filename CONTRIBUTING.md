# Contributing

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

## Library Structure

The library structure of this charm isn't complex, however it does have a few key components that are worth noting, especially for a new contributor:

- `lib/charms` contains the charm libraries used by this charm.
  - `vault_k8s/v0` contains the charm libraries that are owned by this charm_path
    - `juju_facade.py`
      - wraps the Juju ops library to make it easier to use within the context of our charms
      - is an opinionated API that makes writing charms that follow our conventions easier, and should not contain any vault-specific code
      - all Juju interactions should be done through this library
    - `vault_client.py`
      - interacts with the Vault API
      - wraps Vault API calls with an interface that makes it easy to write charms that need to interact with Vault
      - should not contain any business logic
    - `vault_managers.py`
      - manages features implemented by this charm, and all associated business logic
      - managers interact with the Vault API via the `VaultClient` abstraction from `vault_client.py`, Juju via the `JujuFacade` abstraction, and relations via the relation libraries described below.
      - This code is used by both the k8s and machine charms and ensures feature parity.
    - `vault_autounseal.py`, `vault_kv.py`, and `vault_s3.py` are relation libraries that make it easy to implement and interact with the associated relation interfaces
  - The rest of the directories in `lib/` are vendored libraries that are used by this charm.

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
