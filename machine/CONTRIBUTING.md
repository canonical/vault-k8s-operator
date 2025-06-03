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
tox                      # runs 'format', 'lint', 'static', and 'unit' environments
```

You can also run the integration tests locally. This requires a working Juju controller and the `charmcraft` tool installed, as well as building the charm first. The integration tests are run using `tox`. You can run them with:

```shell
tox run -e integration -- --charm_path ./vault_amd64.charm --kv_requirer_charm_path ./vault-kv-requirer_amd64.charm
```

Or, to run a specific test suite:

```shell
tox run -e integration -- --charm_path ./vault_amd64.charm --kv_requirer_charm_path ./vault-kv-requirer_amd64.charm -k test_autounseal.py
```

Or, to run a specific test:

```shell
tox run -e integration -- --charm_path ./vault_amd64.charm --kv_requirer_charm_path ./vault-kv-requirer_amd64.charm -k test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated
```


## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

<!-- You may want to include any contribution/style guidelines in this document>
