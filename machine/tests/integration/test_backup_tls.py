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
# The bucket name used by the test MinIO instance.
S3_BUCKET = "vault-integration-test"
# The port for the test MinIO server (avoid conflicts with LXD bucket server's 8555).
MINIO_PORT = 16666


@pytest.fixture(scope="module")
def minio_endpoint_and_ca_cert(host_ip: str) -> Iterator[tuple[str, str]]:
    """Start a MinIO server with a self-signed TLS cert and return its endpoint + CA cert.

    The cert's SAN includes the lxdbr0 gateway IP so that hostname verification
    passes when Vault units connect to the endpoint from inside LXD containers.
    Yields a ``(endpoint, ca_cert_pem)`` tuple. The MinIO process and temp
    files are cleaned up when the fixture goes out of scope.
    """
    cert_dir = tempfile.mkdtemp(prefix="minio-certs-")
    data_dir = tempfile.mkdtemp(prefix="minio-data-")
    try:
        # Generate a self-signed cert with the lxdbr0 IP as a SAN.
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, host_ip)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow().replace(year=datetime.datetime.utcnow().year + 1)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host_ip))]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        key_path = os.path.join(cert_dir, "private.key")
        cert_path = os.path.join(cert_dir, "public.crt")
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        ca_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        # Find the minio binary.
        # In github ci it's installed to /var/snap/lxd/common/minio/minio.
        # When testing locally, it may be on PATH.
        minio_bin = shutil.which("minio") or "/var/snap/lxd/common/minio/minio"

        # Start MinIO with TLS.
        proc = subprocess.Popen(
            [
                minio_bin,
                "server",
                f"--address={host_ip}:{MINIO_PORT}",
                f"--certs-dir={cert_dir}",
                data_dir,
            ],
            env={
                **os.environ,
                "MINIO_ROOT_USER": MINIO_S3_ACCESS_KEY,
                "MINIO_ROOT_PASSWORD": MINIO_S3_SECRET_KEY,
            },
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            # Wait for MinIO to start listening.
            for _ in range(30):
                try:
                    with socket.create_connection((host_ip, MINIO_PORT), timeout=2):
                        break
                except (ConnectionRefusedError, OSError):
                    time.sleep(1)
            else:
                raise RuntimeError("MinIO did not start within 30s")

            session = boto3.session.Session(
                aws_access_key_id=MINIO_S3_ACCESS_KEY,
                aws_secret_access_key=MINIO_S3_SECRET_KEY,
                region_name="local",
            )
            s3 = session.resource(
                "s3",
                endpoint_url=f"https://{host_ip}:{MINIO_PORT}",
                verify=cert_path,
                config=BotoConfig(
                    request_checksum_calculation="when_required",
                    response_checksum_validation="when_required",
                ),
            )
            s3.create_bucket(Bucket=S3_BUCKET)

            endpoint = f"https://{host_ip}:{MINIO_PORT}"
            yield endpoint, ca_cert_pem
        finally:
            proc.terminate()
            proc.wait(timeout=10)
    finally:
        shutil.rmtree(cert_dir, ignore_errors=True)
        shutil.rmtree(data_dir, ignore_errors=True)


@pytest.mark.abort_on_fail
def test_given_self_signed_tls_endpoint_and_ca_chain_when_create_backup_then_succeeds_with_prefixed_key(
    juju: jubilant.Juju,
    deploy: VaultInit,
    minio_endpoint_and_ca_cert: tuple[str, str],
):
    endpoint, ca_cert = minio_endpoint_and_ca_cert
    backup_id = configure_s3_and_create_backup(
        juju,
        root_token=deploy.root_token,
        s3_endpoint=endpoint,
        s3_access_key=MINIO_S3_ACCESS_KEY,
        s3_secret_key=MINIO_S3_SECRET_KEY,
        s3_bucket=S3_BUCKET,
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
    minio_endpoint_and_ca_cert: tuple[str, str],
):
    endpoint, ca_cert = minio_endpoint_and_ca_cert

    # Take a real raft snapshot via the leader's Vault API.
    leader_name = get_leader_unit_name(juju, APP_NAME)
    vault = get_vault_client(juju, leader_name, deploy.root_token)
    snapshot_bytes = b"".join(vault.client.sys.read_raft_snapshot())

    # Upload the snapshot as a legacy root-level object (no path prefix).
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as ca_file:
        ca_file.write(ca_cert)
        ca_path = ca_file.name
    try:
        session = boto3.session.Session(
            aws_access_key_id=MINIO_S3_ACCESS_KEY,
            aws_secret_access_key=MINIO_S3_SECRET_KEY,
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
        s3.Bucket(S3_BUCKET).put_object(
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
