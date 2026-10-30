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

### Running the integration tests locally

To run the integration tests locally, you will need to have a Juju controller on a machine substrate active (such as lxd).

First, you need to build the `vault` charm, as well as the test `vault-kv-requirer` charm. From the `machine/` directory, run the following commands:

```shell
make copy-test-libs
charmcraft pack
charmcraft pack --project-dir tests/integration/vault_kv_requirer_operator/
```

The integration tests are run using `tox`. You can run them with:

```shell
tox run -e integration -- --charm_path ./vault_amd64.charm --kv_requirer_charm_path ./vault-kv-requirer_amd64.charm -k test_autounseal.py
```

Where the `-k` argument is the test suite you want to run.

Or, to run a specific test:

```shell
tox run -e integration -- --charm_path ./vault_amd64.charm --kv_requirer_charm_path ./vault-kv-requirer_amd64.charm -k test_given_vault_is_deployed_when_integrate_another_vault_then_autounseal_activated
```

At this time, each integration test suite must be run separately.

#### Backup tests

The backup suites require MicroCeph on the test host, with its S3-compatible RGW
endpoint listening on port `7480` and reachable from the LXD containers. Create
an S3 user with access key and secret key `vaultmicrocephtest`, and a bucket named
`vault-microceph-test`.

Follow the "Install MicroCeph and configure RGW for backup tests" step in the
[machine integration workflow](../.github/workflows/machine-integration-test.yaml)
to bootstrap MicroCeph, add loop-backed storage, and create the S3 user and bucket.
Only run the bootstrap and storage setup on a dedicated test host.

The TLS backup suite (`test_backup_tls.py`) also requires `socat`:

```shell
sudo apt-get install --yes socat
```

The TLS suite creates a temporary self-signed certificate and proxies HTTPS on
port `16666` to RGW, verifying the certificate using the configured CA chain.

## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```
