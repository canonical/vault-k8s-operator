from pathlib import Path

import yaml

# There is a dependency here on the `idle_period` we use in `wait_for_idle()`.
# This value should be greater than the `idle_period` used, otherwise the
# `wait_for_idle` function may catch the charm executing the `update-status`
# hook and reset the timer. `idle_period` default is 15s.
JUJU_FAST_INTERVAL = "20s"

# TIMEOUTS
SHORT_TIMEOUT = (
    60 * 2
)  # How long to wait for apps to settle after integrating them, or configuring them. These events should be quick.
DEPLOY_TIMEOUT = 60 * 5  # How long to wait for apps to settle after deploying them

APPLICATION_NAME = "vault-k8s"
AUTOUNSEAL_TOKEN_SECRET_LABEL = "vault-autounseal-token"
LOKI_APPLICATION_NAME = "loki-k8s"
METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
MINIO_APPLICATION_NAME = "minio"
MINIO_S3_ACCESS_KEY = "minio_access_key"
MINIO_S3_SECRET_KEY = "minio_secret_key"
NUM_VAULT_UNITS = 3
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
S3_INTEGRATOR_APPLICATION_NAME = "s3-integrator"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
SELF_SIGNED_CERTIFICATES_CHANNEL = "1/stable"
SELF_SIGNED_CERTIFICATES_REVISION = 263
VAULT_KV_REQUIRER_1_APPLICATION_NAME = "vault-kv-requirer-a"
VAULT_KV_REQUIRER_2_APPLICATION_NAME = "vault-kv-requirer-b"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
VAULT_PKI_REQUIRER_REVISION = 93


VAULT_RESOURCES = {"vault-image": METADATA["resources"]["vault-image"]["upstream-source"]}
