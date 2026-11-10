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
tox                      # runs 'lint', 'static', and 'unit' without editing files
```

## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

### Running the integration tests locally

Use a Juju controller on LXD. From the `machine/` directory, build the Vault charm. Build the test KV requirer charm when running the full suite or KV tests:

```shell
charmcraft pack
charmcraft pack --project-dir tests/integration/vault_kv_requirer_operator/
```

Run the full suite with:

```shell
tox -e integration -- --charm_path ./vault_ubuntu-22.04-amd64.charm --kv_requirer_charm_path ./vault-kv-requirer_ubuntu-22.04-amd64.charm
```

For a quick deploy, initialize, unseal, and authorize check, run:

```shell
tox -e integration -- -m smoke --charm_path ./vault_ubuntu-22.04-amd64.charm
```

You can also run one feature, such as `-k test_backup`, in place of `-m smoke`. CI runs each feature file independently.

<!-- You may want to include any contribution/style guidelines in this document>
