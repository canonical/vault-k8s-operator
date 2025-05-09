from pathlib import Path

import yaml

APPLICATION_NAME = "vault-k8s"

AUTOUNSEAL_TOKEN_SECRET_LABEL = "vault-autounseal-token"
JUJU_FAST_INTERVAL = "20s"
LOKI_APPLICATION_NAME = "loki-k8s"
METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
MINIO_APPLICATION_NAME = "minio"
MINIO_S3_ACCESS_KEY = "minio_access_key"
MINIO_S3_SECRET_KEY = "minio_secret_key"
NUM_VAULT_UNITS = 3
PROMETHEUS_APPLICATION_NAME = "prometheus-k8s"
S3_INTEGRATOR_APPLICATION_NAME = "s3-integrator"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
SELF_SIGNED_CERTIFICATES_REVISION = 263
VAULT_KV_LIB_DIR = "lib/charms/vault_k8s/v0/vault_kv.py"
VAULT_KV_REQUIRER_1_APPLICATION_NAME = "vault-kv-requirer-a"
VAULT_KV_REQUIRER_2_APPLICATION_NAME = "vault-kv-requirer-b"
VAULT_KV_REQUIRER_CHARM_DIR = "tests/integration/vault_kv_requirer_operator"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
VAULT_PKI_REQUIRER_REVISION = 93

MINIO_CONFIG = {
    "access-key": MINIO_S3_ACCESS_KEY,
    "secret-key": MINIO_S3_SECRET_KEY,
}


VAULT_RESOURCES = {"vault-image": METADATA["resources"]["vault-image"]["upstream-source"]}
