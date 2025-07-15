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

To run the backup tests, you will need to have an S3 compatible storage service running, such as MinIO. You can find instructions to configure LXD to manage the MinIO service at <https://documentation.ubuntu.com/lxd/latest/howto/storage_buckets/#howto-storage-buckets>.

The following is a summary of the steps, and may not be up to date with the latest LXD documentation or your system. Use with care.

```shell
sudo wget --no-clobber https://dl.min.io/server/minio/release/linux-amd64/minio -O /usr/bin/minio && sudo chmod +x /usr/bin/minio
sudo wget --no-clobber https://dl.min.io/client/mc/release/linux-amd64/mc -O /usr/bin/mc && sudo chmod +x /usr/bin/mc
snap set lxd minio.path=/usr/bin
snap restart lxd
lxc config set core.storage_buckets_address :8555
```

It would, however, be best to lock down the storage buckets to only allow access from other LXD containers.

```shell
lxd_bridge_ip=$(lxc network list --format yaml | yq '.[] | select(.name == "lxdbr0") | .config["ipv4.address"]' | cut -d'/' -f1) && echo "LXD bridge IP: ${lxd_bridge_ip}"
lxc config set core.storage_buckets_address ${lxd_bridge_ip}:8555
```

Finally, create the bucket and the access keys for the integration tests:

```shell
lxc storage bucket create default vault-integration-test
lxc storage bucket key create default vault-integration-test vault-integration-test --role admin --access-key vaultintegrationtest --secret-key vaultintegrationtest
```

## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```
