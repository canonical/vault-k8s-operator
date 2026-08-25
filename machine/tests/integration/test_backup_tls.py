import os
import socket
import ssl
import tempfile

import boto3
import jubilant
import pytest
from botocore.config import Config as BotoConfig
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from config import APP_NAME, MINIO_S3_ACCESS_KEY, MINIO_S3_SECRET_KEY
from helpers import (
    VaultInit,
    configure_s3_and_create_backup,
    get_leader_unit_name,
    get_vault_client,
    list_backups,
    restore_backup,
    run_action_on_leader,
)

# Path prefix configured on the s3-integrator.
S3_PATH = "vault"
# The port that the MinIO server listens on.
BUCKET_SERVER_PORT = 8555


@pytest.fixture(scope="module")
def bucket_ca_cert(host_ip: str) -> str:
    """Return the PEM-encoded CA cert of the self-signed LXD bucket server.

    Used to configure the s3-integrator's ``tls-ca-chain`` config value.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host_ip, BUCKET_SERVER_PORT), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host_ip) as ssock:
            der = ssock.getpeercert(binary_form=True)
    assert der, "No certificate presented by the bucket server"
    cert = x509.load_der_x509_certificate(der)
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.mark.abort_on_fail
def test_given_self_signed_tls_endpoint_and_ca_chain_when_create_backup_then_succeeds_with_prefixed_key(
    juju: jubilant.Juju,
    deploy: VaultInit,
    host_ip: str,
    bucket_ca_cert: str,
):
    backup_id = configure_s3_and_create_backup(
        juju,
        root_token=deploy.root_token,
        s3_endpoint=f"https://{host_ip}:{BUCKET_SERVER_PORT}",
        s3_access_key=MINIO_S3_ACCESS_KEY,
        s3_secret_key=MINIO_S3_SECRET_KEY,
        s3_bucket="vault-integration-test",
        s3_region="local",
        kv_secret_value="tls-value",
        s3_path="vault",
        s3_tls_ca_chain=bucket_ca_cert,
        skip_verify=False,
    )
    assert backup_id.startswith(f"{S3_PATH}/vault-backup-"), backup_id


@pytest.mark.abort_on_fail
def test_given_path_set_when_list_backups_then_keys_are_prefixed(
    juju: jubilant.Juju,
    deploy: VaultInit,
):
    backup_ids = list_backups(juju, skip_verify=False)
    assert backup_ids, "Expected at least one backup"
    assert all(bid.startswith(f"{S3_PATH}/") for bid in backup_ids), backup_ids


@pytest.mark.abort_on_fail
def test_given_prefixed_backup_when_restore_backup_then_succeeds(
    juju: jubilant.Juju,
    deploy: VaultInit,
):
    restored_id = restore_backup(
        juju,
        root_token=deploy.root_token,
        kv_secret_value="tls-value",
        skip_verify=False,
    )
    assert restored_id.startswith(f"{S3_PATH}/"), restored_id


@pytest.mark.abort_on_fail
def test_given_legacy_root_level_backup_when_restore_backup_then_falls_back(
    juju: jubilant.Juju,
    deploy: VaultInit,
    host_ip: str,
    bucket_ca_cert: str,
):
    # Take a real raft snapshot via the leader's Vault API; this is the same
    # binary payload the charm's create-backup action uploads to S3.
    leader_name = get_leader_unit_name(juju, APP_NAME)
    vault = get_vault_client(juju, leader_name, deploy.root_token)
    snapshot_bytes = b"".join(vault.client.sys.read_raft_snapshot())

    # Write the CA cert to a temp file so boto3 can verify the self-signed
    # endpoint when uploading the legacy object.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as ca_file:
        ca_file.write(bucket_ca_cert)
        ca_path = ca_file.name
    try:
        session = boto3.session.Session(
            aws_access_key_id=MINIO_S3_ACCESS_KEY,
            aws_secret_access_key=MINIO_S3_SECRET_KEY,
            region_name="local",
        )
        s3 = session.resource(
            "s3",
            endpoint_url=f"https://{host_ip}:{BUCKET_SERVER_PORT}",
            verify=ca_path,
            config=BotoConfig(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )
        legacy_key = "vault-backup-legacy-root-level"
        s3.Bucket("vault-integration-test").put_object(
            Key=legacy_key,
            Body=snapshot_bytes,
        )
    finally:
        os.unlink(ca_path)

    # The legacy key has no path prefix; restore-backup must fall back to it.
    # Use run_action_on_leader directly so we target the legacy key explicitly.
    results = run_action_on_leader(
        juju,
        APP_NAME,
        "restore-backup",
        backup_id=legacy_key,
        skip_verify=False,
    )
    assert results["restored"] == legacy_key, results
