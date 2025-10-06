from pathlib import Path

import yaml

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())

APP_NAME: str = METADATA["name"]
GRAFANA_AGENT_APPLICATION_NAME = "grafana-agent"
HAPROXY_APPLICATION_NAME = "haproxy"
INGRESS_RELATION_NAME = "ingress"
MINIO_APPLICATION_NAME = "minio"
MINIO_S3_ACCESS_KEY = "vaultintegrationtest"
MINIO_S3_SECRET_KEY = "vaultintegrationtest"
NUM_VAULT_UNITS = 3
PEER_RELATION_NAME = "vault-peers"
S3_INTEGRATOR_APPLICATION_NAME = "s3-integrator"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
SELF_SIGNED_CERTIFICATES_REVISION = 317
VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"

VAULT_KV_LIB_DIR = "lib/charms/vault_k8s/v0/vault_kv.py"
VAULT_KV_REQUIRER_CHARM_DIR = "tests/integration/vault_kv_requirer_operator"

MATCHING_COMMON_NAME = "example.com"
UNMATCHING_COMMON_NAME = "unmatching-the-requirer.com"
VAULT_PKI_REQUIRER_REVISION = 93

# There is a dependency here on the `idle_period` we use in `wait_for_idle()`.
# This value should be greater than the `idle_period` used, otherwise the
# `wait_for_idle` function may catch the charm executing the `update-status`
# hook and reset the timer. `idle_period` default is 15s.
JUJU_FAST_INTERVAL = "20s"

# How long to wait for apps to settle after integrating them, or configuring them. These events should be quick.
SHORT_TIMEOUT = 60 * 2
REFRESH_TIMEOUT = 60 * 10
