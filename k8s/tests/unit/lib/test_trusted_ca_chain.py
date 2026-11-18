"""Check TLS trust when the access provider uses an intermediate CA."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from vault.vault_managers import File, TLSManager, TLSMode


def _certificate(
    name: str,
    issuer: x509.Certificate | None = None,
    issuer_key: rsa.RSAPrivateKey | None = None,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=name != "vault", path_length=None), critical=True)
        .sign(issuer_key or key, hashes.SHA256())
    )
    return certificate, key


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def test_intermediate_access_certificate_needs_transferred_root():
    root, root_key = _certificate("root")
    intermediate, intermediate_key = _certificate("intermediate", root, root_key)
    leaf, _ = _certificate("vault", intermediate, intermediate_key)
    certificate_bundle = _pem(leaf) + _pem(intermediate)
    transfer = MagicMock()
    transfer.get_all_certificates.return_value = {_pem(root)}
    manager = cast(
        TLSManager,
        SimpleNamespace(
            trusted_ca_transfer=transfer,
            mode=TLSMode.TLS_INTEGRATION,
            _is_self_signed=TLSManager._is_self_signed,
        ),
    )

    assert TLSManager._get_ca_bundle(manager, _pem(intermediate)).strip() == _pem(root).strip()
    manager.pull_tls_file_from_workload = lambda file: {
        File.CERT: certificate_bundle,
        File.CA: "",
    }[file]
    assert TLSManager.access_certificate_requires_trusted_ca(manager)

    manager.pull_tls_file_from_workload = lambda file: {
        File.CERT: certificate_bundle,
        File.CA: _pem(root),
    }[file]
    assert not TLSManager.access_certificate_requires_trusted_ca(manager)
