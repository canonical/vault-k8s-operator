# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from typing import Tuple

from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    PrivateKey,
    ProviderCertificate,
    RequirerCSR,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)


def generate_example_provider_certificate(
    common_name: str, relation_id: int
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
        validity=365,
    )
    certificate = generate_certificate(
        csr=csr,
        ca=ca_certificate,
        ca_private_key=ca_private_key,
        validity=365,
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


def generate_example_requirer_csr(common_name: str, relation_id: int) -> RequirerCSR:
    private_key = generate_private_key()
    csr = generate_csr(
        private_key=private_key,
        common_name=common_name,
    )
    return RequirerCSR(
        relation_id=relation_id,
        certificate_signing_request=csr,
    )


def sign_certificate(
    ca_certificate: Certificate, ca_private_key: PrivateKey, csr: CertificateSigningRequest
) -> Certificate:
    return generate_certificate(
        csr=csr,
        ca=ca_certificate,
        ca_private_key=ca_private_key,
        validity=365,
    )
