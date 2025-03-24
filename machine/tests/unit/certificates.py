# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from datetime import timedelta
from typing import Tuple

from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    PrivateKey,
    ProviderCertificate,
    RequirerCertificateRequest,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)


def generate_example_provider_certificate(
    common_name: str,
    relation_id: int,
    validity: timedelta = timedelta(days=365),
) -> Tuple[ProviderCertificate, PrivateKey]:
    private_key = generate_private_key()
    csr = generate_csr(
        private_key=private_key,
        common_name=common_name,
    )
    ca_private_key = generate_private_key()
    ca_certificate = generate_ca(
        private_key=ca_private_key,
        common_name="ca.com",
        validity=validity,
    )
    certificate = generate_certificate(
        csr=csr,
        ca=ca_certificate,
        ca_private_key=ca_private_key,
        validity=validity,
    )

    provider_certificate = ProviderCertificate(
        relation_id=relation_id,
        certificate_signing_request=csr,
        certificate=certificate,
        ca=ca_certificate,
        chain=[ca_certificate],
        revoked=False,
    )
    return provider_certificate, private_key


def generate_example_requirer_csr(
    common_name: str, relation_id: int
) -> RequirerCertificateRequest:
    private_key = generate_private_key()
    csr = generate_csr(
        private_key=private_key,
        common_name=common_name,
    )
    return RequirerCertificateRequest(
        relation_id=relation_id,
        certificate_signing_request=csr,
        is_ca=False,
    )


def sign_certificate(
    ca_certificate: Certificate,
    ca_private_key: PrivateKey,
    csr: CertificateSigningRequest,
    validity: timedelta = timedelta(days=365),
) -> Certificate:
    return generate_certificate(
        csr=csr,
        ca=ca_certificate,
        ca_private_key=ca_private_key,
        validity=validity,
    )
