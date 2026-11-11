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
tox                      # runs 'lint', 'static', and 'unit' without editing files
```

### Running the integration tests locally

To run the integration tests locally, you will need to have a Juju controller
on `microk8s` active.

First, build the `vault-k8s` charm from the `k8s/` directory. Build the test `vault-kv-requirer` charm when running the full suite or KV tests:

```shell
charmcraft pack
charmcraft pack --project-dir tests/integration/vault_kv_requirer_operator/
```

Then, you can run the integration tests with:

```shell
tox -e integration -- --charm_path ./vault-k8s_ubuntu-22.04-amd64.charm --kv_requirer_charm_path ./vault-kv-requirer_ubuntu-22.04-amd64.charm
```

Run only the deploy, initialize, unseal, and authorize smoke test with:

```shell
tox -e integration -- -m smoke --charm_path ./vault-k8s_ubuntu-22.04-amd64.charm
```

To work on one behavior, replace `-m smoke` with a selector such as `-k test_pki_tls`. The integration files cover core behavior, KV, PKI and TLS, backup, COS, auto-unseal, and in-track upgrades. CI runs each file independently.

## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```
