import datetime
import ipaddress
import os
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Iterator

import boto3
import jubilant
import pytest
from botocore.config import Config as BotoConfig
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from config import (
    APP_NAME,
    MICROCEPH_RGW_PORT,
    MICROCEPH_S3_ACCESS_KEY,
    MICROCEPH_S3_BUCKET,
    MICROCEPH_S3_SECRET_KEY,
)
from helpers import (
    VaultInit,
    configure_s3_and_create_backup,
    get_leader_unit_name,
    get_vault_client,
    list_backups,
    restore_backup,
    run_action_on_leader,
)

S3_PATH = "vault"
TLS_PROXY_PORT = 16666


@pytest.fixture(scope="module")
def s3_tls_endpoint_and_ca_cert(host_ip: str) -> Iterator[tuple[str, str]]:
    """Start a TLS proxy for MicroCeph RGW and return its endpoint and CA certificate."""
    cert_dir = tempfile.mkdtemp(prefix="s3-tls-certs-")
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, host_ip)])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now.replace(year=now.year + 1))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host_ip))]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        key_path = os.path.join(cert_dir, "private.key")
        cert_path = os.path.join(cert_dir, "public.crt")
        with open(key_path, "wb") as key_file:
            key_file.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
        ca_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        proc = subprocess.Popen(
            [
                "socat",
                (
                    f"OPENSSL-LISTEN:{TLS_PROXY_PORT},bind={host_ip},reuseaddr,fork,"
                    f"cert={cert_path},key={key_path},verify=0"
                ),
                f"TCP:127.0.0.1:{MICROCEPH_RGW_PORT}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(30):
                if proc.poll() is not None:
                    stderr = proc.stderr.read() if proc.stderr else ""
                    raise RuntimeError(f"TLS proxy exited unexpectedly: {stderr}")
                try:
                    with socket.create_connection((host_ip, TLS_PROXY_PORT), timeout=2):
                        break
                except (ConnectionRefusedError, OSError):
                    time.sleep(1)
            else:
                raise RuntimeError("TLS proxy did not start within 30s")

            yield f"https://{host_ip}:{TLS_PROXY_PORT}", ca_cert_pem
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    finally:
        shutil.rmtree(cert_dir, ignore_errors=True)


@pytest.mark.abort_on_fail
def test_given_vault_integrated_with_s3_when_create_backup_then_action_succeeds(
    juju: jubilant.Juju,
    deploy: VaultInit,
    microceph_endpoint: str,
):
    configure_s3_and_create_backup(
        juju,
        root_token=deploy.root_token,
        s3_endpoint=microceph_endpoint,
        s3_access_key=MICROCEPH_S3_ACCESS_KEY,
        s3_secret_key=MICROCEPH_S3_SECRET_KEY,
        s3_bucket=MICROCEPH_S3_BUCKET,
        s3_region="local",
        kv_secret_value="value",
    )


@pytest.mark.abort_on_fail
def test_given_vault_integrated_with_s3_when_list_backups_then_action_succeeds(
    juju: jubilant.Juju, deploy: VaultInit
):
    list_backups(juju)


@pytest.mark.abort_on_fail
def test_given_vault_integrated_with_s3_when_restore_backup_then_action_succeeds(
    juju: jubilant.Juju,
    deploy: VaultInit,
):
    restore_backup(
        juju,
        root_token=deploy.root_token,
        kv_secret_value="value",
    )


@pytest.mark.abort_on_fail
def test_given_self_signed_tls_endpoint_and_ca_chain_when_create_backup_then_succeeds_with_prefixed_key(
    juju: jubilant.Juju,
    deploy: VaultInit,
    s3_tls_endpoint_and_ca_cert: tuple[str, str],
):
    endpoint, ca_cert = s3_tls_endpoint_and_ca_cert
    backup_id = configure_s3_and_create_backup(
        juju,
        root_token=deploy.root_token,
        s3_endpoint=endpoint,
        s3_access_key=MICROCEPH_S3_ACCESS_KEY,
        s3_secret_key=MICROCEPH_S3_SECRET_KEY,
        s3_bucket=MICROCEPH_S3_BUCKET,
        s3_region="local",
        kv_secret_value="tls-value",
        s3_path=S3_PATH,
        s3_tls_ca_chain=ca_cert,
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
    assert all(backup_id.startswith(f"{S3_PATH}/") for backup_id in backup_ids), backup_ids


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
    s3_tls_endpoint_and_ca_cert: tuple[str, str],
):
    endpoint, ca_cert = s3_tls_endpoint_and_ca_cert

    leader_name = get_leader_unit_name(juju, APP_NAME)
    vault = get_vault_client(juju, leader_name, deploy.root_token)
    snapshot_bytes = vault.client.sys.take_raft_snapshot().content

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as ca_file:
        ca_file.write(ca_cert)
        ca_path = ca_file.name
    try:
        session = boto3.session.Session(
            aws_access_key_id=MICROCEPH_S3_ACCESS_KEY,
            aws_secret_access_key=MICROCEPH_S3_SECRET_KEY,
            region_name="local",
        )
        s3 = session.resource(
            "s3",
            endpoint_url=endpoint,
            verify=ca_path,
            config=BotoConfig(
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )
        legacy_key = "vault-backup-legacy-root-level"
        s3.Bucket(MICROCEPH_S3_BUCKET).put_object(
            Key=legacy_key,
            Body=snapshot_bytes,
        )
    finally:
        os.unlink(ca_path)

    results = run_action_on_leader(
        juju,
        APP_NAME,
        "restore-backup",
        backup_id=legacy_key,
        skip_verify=False,
    )
    assert results["restored"] == legacy_key, results
