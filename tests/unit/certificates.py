# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import datetime

from charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
    RequirerCSR,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)


def generate_example_provider_certificate(
    common_name: str, relation_id: int
) -> ProviderCertificate:
    private_key = generate_private_key()
    csr = generate_csr(
        private_key=private_key,
        subject=common_name,
    )
    ca_private_key = generate_private_key()
    ca_certificate = generate_ca(
        private_key=ca_private_key,
        subject="ca.com",
        validity=365,
    )
    certificate = generate_certificate(
        csr=csr,
        ca=ca_certificate,
        ca_key=ca_private_key,
        validity=365,
    )

    provider_certificate = ProviderCertificate(
        application_name="vault",
        relation_id=relation_id,
        csr=csr.decode(),
        certificate=certificate.decode(),
        ca=ca_certificate.decode(),
        chain=[ca_certificate.decode()],
        revoked=False,
        expiry_time=datetime.datetime.now(),
    )
    return provider_certificate


def generate_example_requirer_csr(common_name: str, relation_id: int) -> RequirerCSR:
    private_key = generate_private_key()
    csr = generate_csr(
        private_key=private_key,
        subject=common_name,
    )
    return RequirerCSR(
        relation_id=relation_id,
        application_name="tls-requirer",
        unit_name="tls-requirer/0",
        csr=csr.decode(),
        is_ca=False,
    )
