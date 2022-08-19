# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Library for the tls-certificates relation.

This library contains the Requires and Provides classes for handling the tls-certificates
interface.

## Getting Started
From a charm directory, fetch the library using `charmcraft`:

```shell
charmcraft fetch-lib charms.tls_certificates_interface.v1.tls_certificates
```

Add the following libraries to the charm's `requirements.txt` file:
- jsonschema
- cryptography

Add the following section to the charm's `charmcraft.yaml` file:
```yaml
parts:
  charm:
    build-packages:
      - libffi-dev
      - libssl-dev
      - rustc
      - cargo
```

### Provider charm
The provider charm is the charm providing certificates to another charm that requires them. In
this example, the provider charm is storing its private key using a peer relation interface called
`replicas`.

Example:
```python
from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateCreationRequestEvent,
    CertificateRevocationRequestEvent,
    TLSCertificatesProvidesV1,
    generate_private_key,
)
from ops.charm import CharmBase, InstallEvent
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus


def generate_ca(private_key: bytes, subject: str) -> str:
    return "whatever ca content"


def generate_certificate(ca: str, private_key: str, csr: str) -> str:
    return "Whatever certificate"


class ExampleProviderCharm(CharmBase):

    def __init__(self, *args):
        super().__init__(*args)
        self.certificates = TLSCertificatesProvidesV1(self, "certificates")
        self.framework.observe(
            self.certificates.on.certificate_request, self._on_certificate_request
        )
        self.framework.observe(
            self.certificates.on.certificate_revoked, self._on_certificate_revoked
        )
        self.framework.observe(self.on.install, self._on_install)

    def _on_install(self, event: InstallEvent) -> None:
        private_key_password = b"banana"
        private_key = generate_private_key(password=private_key_password)
        ca_certificate = generate_ca(private_key=private_key, subject="whatever")
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        replicas_relation.data[self.app].update(
            {
                "private_key_password": "banana",
                "private_key": private_key,
                "ca_certificate": ca_certificate,
            }
        )
        self.unit.status = ActiveStatus()

    def _on_certificate_request(self, event: CertificateCreationRequestEvent) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        ca_certificate = replicas_relation.data[self.app].get("ca_certificate")
        private_key = replicas_relation.data[self.app].get("private_key")
        certificate = generate_certificate(
            ca=ca_certificate,
            private_key=private_key,
            csr=event.certificate_signing_request,
        )

        self.certificates.set_relation_certificate(
            certificate=certificate,
            certificate_signing_request=event.certificate_signing_request,
            ca=ca_certificate,
            chain=ca_certificate,
            relation_id=event.relation_id,
        )

    def _on_certificate_revoked(self, event: CertificateRevocationRequestEvent) -> None:
        # Do what you want to do with this information
        pass


if __name__ == "__main__":
    main(ExampleProviderCharm)
```

### Requirer charm
The requirer charm is the charm requiring certificates from another charm that provides them. In
this example, the requirer charm is storing its certificates using a peer relation interface called
`replicas`.

Example:
```python

from charms.tls_certificates_interface.v1.tls_certificates import (
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    CertificateRevokedEvent,
    TLSCertificatesRequiresV1,
    generate_csr,
    generate_private_key,
)
from ops.charm import CharmBase, RelationJoinedEvent
from ops.main import main
from ops.model import ActiveStatus, WaitingStatus


class ExampleRequirerCharm(CharmBase):

    def __init__(self, *args):
        super().__init__(*args)
        self.cert_subject = "whatever"
        self.certificates = TLSCertificatesRequiresV1(self, "certificates")
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.on.certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.on.certificates.on.certificate_revoked, self._on_certificate_revoked
        )

    def _on_install(self, event) -> None:
        private_key_password = b"banana"
        private_key = generate_private_key(password=private_key_password)
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        replicas_relation.data[self.app].update(
            {"private_key_password": "banana", "private_key": private_key.decode()}
        )

    def _on_certificates_relation_joined(self, event: RelationJoinedEvent) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        private_key_password = replicas_relation.data[self.app].get("private_key_password")
        private_key = replicas_relation.data[self.app].get("private_key")
        csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject=self.cert_subject,
        )
        replicas_relation.data[self.app].update({"csr": csr.decode()})
        self.certificates.request_certificate_creation(certificate_signing_request=csr)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        replicas_relation.data[self.app].update({"certificate": event.certificate})
        replicas_relation.data[self.app].update({"ca": event.ca})
        replicas_relation.data[self.app].update({"chain": event.chain})
        self.unit.status = ActiveStatus()

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        old_csr = replicas_relation.data[self.app].get("csr")
        private_key_password = replicas_relation.data[self.app].get("private_key_password")
        private_key = replicas_relation.data[self.app].get("private_key")
        new_csr = generate_csr(
            private_key=private_key.encode(),
            private_key_password=private_key_password.encode(),
            subject=self.cert_subject,
        )
        self.certificates.request_certificate_renewal(
            old_certificate_signing_request=old_csr,
            new_certificate_signing_request=new_csr,
        )
        replicas_relation.data[self.app].update({"csr": new_csr.decode()})

    def _on_certificate_revoked(self, event: CertificateRevokedEvent):
        replicas_relation = self.model.get_relation("replicas")
        if not replicas_relation:
            self.unit.status = WaitingStatus("Waiting for peer relation to be created")
            event.defer()
            return
        stored_csr = replicas_relation.data[self.app].get("csr")
        if event.certificate_signing_request == stored_csr:
            private_key_password = replicas_relation.data[self.app].get("private_key_password")
            private_key = replicas_relation.data[self.app].get("private_key")
            new_csr = generate_csr(
                private_key=private_key.encode(),
                private_key_password=private_key_password.encode(),
                subject=self.cert_subject,
            )
            self.certificates.request_certificate_renewal(
                old_certificate_signing_request=stored_csr, new_certificate_signing_request=new_csr
            )
            replicas_relation.data[self.app].update({"csr": new_csr.decode()})


if __name__ == "__main__":
    main(ExampleRequirerCharm)
```
"""  # noqa: D405, D410, D411, D214, D416

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from jsonschema import exceptions, validate  # type: ignore[import]
from ops.charm import CharmBase, CharmEvents, RelationChangedEvent, UpdateStatusEvent
from ops.framework import EventBase, EventSource, Handle, Object

# The unique Charmhub library identifier, never change it
LIBID = "afd8c2bccf834997afce12c2706d2ede"

# Increment this major API version when introducing breaking changes
LIBAPI = 1

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 2

REQUIRER_JSON_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "$id": "https://canonical.github.io/charm-relation-interfaces/tls_certificates/v1/schemas/requirer.json",  # noqa: E501
    "type": "object",
    "title": "`tls_certificates` requirer root schema",
    "description": "The `tls_certificates` root schema comprises the entire requirer databag for this interface.",  # noqa: E501
    "examples": [
        {
            "certificate_signing_requests": [
                {
                    "certificate_signing_request": "-----BEGIN CERTIFICATE REQUEST-----\\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKYmFuYW5hLmNvbTCCASIwDQYJKoZIhvcN\\nAQEBBQADggEPADCCAQoCggEBANWlx9wE6cW7Jkb4DZZDOZoEjk1eDBMJ+8R4pyKp\\nFBeHMl1SQSDt6rAWsrfL3KOGiIHqrRY0B5H6c51L8LDuVrJG0bPmyQ6rsBo3gVke\\nDSivfSLtGvHtp8lwYnIunF8r858uYmblAR0tdXQNmnQvm+6GERvURQ6sxpgZ7iLC\\npPKDoPt+4GKWL10FWf0i82FgxWC2KqRZUtNbgKETQuARLig7etBmCnh20zmynorA\\ncY7vrpTPAaeQpGLNqqYvKV9W6yWVY08V+nqARrFrjk3vSioZSu8ZJUdZ4d9++SGl\\nbH7A6e77YDkX9i/dQ3Pa/iDtWO3tXS2MvgoxX1iSWlGNOHcCAwEAAaAAMA0GCSqG\\nSIb3DQEBCwUAA4IBAQCW1fKcHessy/ZhnIwAtSLznZeZNH8LTVOzkhVd4HA7EJW+\\nKVLBx8DnN7L3V2/uPJfHiOg4Rx7fi7LkJPegl3SCqJZ0N5bQS/KvDTCyLG+9E8Y+\\n7wqCmWiXaH1devimXZvazilu4IC2dSks2D8DPWHgsOdVks9bme8J3KjdNMQudegc\\newWZZ1Dtbd+Rn7cpKU3jURMwm4fRwGxbJ7iT5fkLlPBlyM/yFEik4SmQxFYrZCQg\\n0f3v4kBefTh5yclPy5tEH+8G0LMsbbo3dJ5mPKpAShi0QEKDLd7eR1R/712lYTK4\\ndi4XaEfqERgy68O4rvb4PGlJeRGS7AmL7Ss8wfAq\\n-----END CERTIFICATE REQUEST-----\\n"  # noqa: E501
                },
                {
                    "certificate_signing_request": "-----BEGIN CERTIFICATE REQUEST-----\\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKYmFuYW5hLmNvbTCCASIwDQYJKoZIhvcN\\nAQEBBQADggEPADCCAQoCggEBAMk3raaX803cHvzlBF9LC7KORT46z4VjyU5PIaMb\\nQLIDgYKFYI0n5hf2Ra4FAHvOvEmW7bjNlHORFEmvnpcU5kPMNUyKFMTaC8LGmN8z\\nUBH3aK+0+FRvY4afn9tgj5435WqOG9QdoDJ0TJkjJbJI9M70UOgL711oU7ql6HxU\\n4d2ydFK9xAHrBwziNHgNZ72L95s4gLTXf0fAHYf15mDA9U5yc+YDubCKgTXzVySQ\\nUx73VCJLfC/XkZIh559IrnRv5G9fu6BMLEuBwAz6QAO4+/XidbKWN4r2XSq5qX4n\\n6EPQQWP8/nd4myq1kbg6Q8w68L/0YdfjCmbyf2TuoWeImdUCAwEAAaAAMA0GCSqG\\nSIb3DQEBCwUAA4IBAQBIdwraBvpYo/rl5MH1+1Um6HRg4gOdQPY5WcJy9B9tgzJz\\nittRSlRGTnhyIo6fHgq9KHrmUthNe8mMTDailKFeaqkVNVvk7l0d1/B90Kz6OfmD\\nxN0qjW53oP7y3QB5FFBM8DjqjmUnz5UePKoX4AKkDyrKWxMwGX5RoET8c/y0y9jp\\nvSq3Wh5UpaZdWbe1oVY8CqMVUEVQL2DPjtopxXFz2qACwsXkQZxWmjvZnRiP8nP8\\nbdFaEuh9Q6rZ2QdZDEtrU4AodPU3NaukFr5KlTUQt3w/cl+5//zils6G5zUWJ2pN\\ng7+t9PTvXHRkH+LnwaVnmsBFU2e05qADQbfIn7JA\\n-----END CERTIFICATE REQUEST-----\\n"  # noqa: E501
                },
            ]
        }
    ],
    "properties": {
        "certificate_signing_requests": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"certificate_signing_request": {"type": "string"}},
                "required": ["certificate_signing_request"],
            },
        }
    },
    "required": ["certificate_signing_requests"],
    "additionalProperties": True,
}

PROVIDER_JSON_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "$id": "https://canonical.github.io/charm-relation-interfaces/tls_certificates/v1/schemas/provider.json",  # noqa: E501
    "type": "object",
    "title": "`tls_certificates` provider root schema",
    "description": "The `tls_certificates` root schema comprises the entire provider databag for this interface.",  # noqa: E501
    "example": [
        {
            "certificates": [
                {
                    "ca": "-----BEGIN CERTIFICATE-----\\nMIIDJTCCAg2gAwIBAgIUMsSK+4FGCjW6sL/EXMSxColmKw8wDQYJKoZIhvcNAQEL\\nBQAwIDELMAkGA1UEBhMCVVMxETAPBgNVBAMMCHdoYXRldmVyMB4XDTIyMDcyOTIx\\nMTgyN1oXDTIzMDcyOTIxMTgyN1owIDELMAkGA1UEBhMCVVMxETAPBgNVBAMMCHdo\\nYXRldmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA55N9DkgFWbJ/\\naqcdQhso7n1kFvt6j/fL1tJBvRubkiFMQJnZFtekfalN6FfRtA3jq+nx8o49e+7t\\nLCKT0xQ+wufXfOnxv6/if6HMhHTiCNPOCeztUgQ2+dfNwRhYYgB1P93wkUVjwudK\\n13qHTTZ6NtEF6EzOqhOCe6zxq6wrr422+ZqCvcggeQ5tW9xSd/8O1vNID/0MTKpy\\nET3drDtBfHmiUEIBR3T3tcy6QsIe4Rz/2sDinAcM3j7sG8uY6drh8jY3PWar9til\\nv2l4qDYSU8Qm5856AB1FVZRLRJkLxZYZNgreShAIYgEd0mcyI2EO/UvKxsIcxsXc\\nd45GhGpKkwIDAQABo1cwVTAfBgNVHQ4EGAQWBBRXBrXKh3p/aFdQjUcT/UcvICBL\\nODAhBgNVHSMEGjAYgBYEFFcGtcqHen9oV1CNRxP9Ry8gIEs4MA8GA1UdEwEB/wQF\\nMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGmCEvcoFUrT9e133SHkgF/ZAgzeIziO\\nBjfAdU4fvAVTVfzaPm0yBnGqzcHyacCzbZjKQpaKVgc5e6IaqAQtf6cZJSCiJGhS\\nJYeosWrj3dahLOUAMrXRr8G/Ybcacoqc+osKaRa2p71cC3V6u2VvcHRV7HDFGJU7\\noijbdB+WhqET6Txe67rxZCJG9Ez3EOejBJBl2PJPpy7m1Ml4RR+E8YHNzB0lcBzc\\nEoiJKlDfKSO14E2CPDonnUoWBJWjEvJys3tbvKzsRj2fnLilytPFU0gH3cEjCopi\\nzFoWRdaRuNHYCqlBmso1JFDl8h4fMmglxGNKnKRar0WeGyxb4xXBGpI=\\n-----END CERTIFICATE-----\\n",  # noqa: E501
                    "chain": "-----BEGIN CERTIFICATE-----\\nMIIDJTCCAg2gAwIBAgIUMsSK+4FGCjW6sL/EXMSxColmKw8wDQYJKoZIhvcNAQEL\\nBQAwIDELMAkGA1UEBhMCVVMxETAPBgNVBAMMCHdoYXRldmVyMB4XDTIyMDcyOTIx\\nMTgyN1oXDTIzMDcyOTIxMTgyN1owIDELMAkGA1UEBhMCVVMxETAPBgNVBAMMCHdo\\nYXRldmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA55N9DkgFWbJ/\\naqcdQhso7n1kFvt6j/fL1tJBvRubkiFMQJnZFtekfalN6FfRtA3jq+nx8o49e+7t\\nLCKT0xQ+wufXfOnxv6/if6HMhHTiCNPOCeztUgQ2+dfNwRhYYgB1P93wkUVjwudK\\n13qHTTZ6NtEF6EzOqhOCe6zxq6wrr422+ZqCvcggeQ5tW9xSd/8O1vNID/0MTKpy\\nET3drDtBfHmiUEIBR3T3tcy6QsIe4Rz/2sDinAcM3j7sG8uY6drh8jY3PWar9til\\nv2l4qDYSU8Qm5856AB1FVZRLRJkLxZYZNgreShAIYgEd0mcyI2EO/UvKxsIcxsXc\\nd45GhGpKkwIDAQABo1cwVTAfBgNVHQ4EGAQWBBRXBrXKh3p/aFdQjUcT/UcvICBL\\nODAhBgNVHSMEGjAYgBYEFFcGtcqHen9oV1CNRxP9Ry8gIEs4MA8GA1UdEwEB/wQF\\nMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGmCEvcoFUrT9e133SHkgF/ZAgzeIziO\\nBjfAdU4fvAVTVfzaPm0yBnGqzcHyacCzbZjKQpaKVgc5e6IaqAQtf6cZJSCiJGhS\\nJYeosWrj3dahLOUAMrXRr8G/Ybcacoqc+osKaRa2p71cC3V6u2VvcHRV7HDFGJU7\\noijbdB+WhqET6Txe67rxZCJG9Ez3EOejBJBl2PJPpy7m1Ml4RR+E8YHNzB0lcBzc\\nEoiJKlDfKSO14E2CPDonnUoWBJWjEvJys3tbvKzsRj2fnLilytPFU0gH3cEjCopi\\nzFoWRdaRuNHYCqlBmso1JFDl8h4fMmglxGNKnKRar0WeGyxb4xXBGpI=\\n-----END CERTIFICATE-----\\n",  # noqa: E501
                    "certificate_signing_request": "-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKYmFuYW5hLmNvbTCCASIwDQYJKoZIhvcN\nAQEBBQADggEPADCCAQoCggEBANWlx9wE6cW7Jkb4DZZDOZoEjk1eDBMJ+8R4pyKp\nFBeHMl1SQSDt6rAWsrfL3KOGiIHqrRY0B5H6c51L8LDuVrJG0bPmyQ6rsBo3gVke\nDSivfSLtGvHtp8lwYnIunF8r858uYmblAR0tdXQNmnQvm+6GERvURQ6sxpgZ7iLC\npPKDoPt+4GKWL10FWf0i82FgxWC2KqRZUtNbgKETQuARLig7etBmCnh20zmynorA\ncY7vrpTPAaeQpGLNqqYvKV9W6yWVY08V+nqARrFrjk3vSioZSu8ZJUdZ4d9++SGl\nbH7A6e77YDkX9i/dQ3Pa/iDtWO3tXS2MvgoxX1iSWlGNOHcCAwEAAaAAMA0GCSqG\nSIb3DQEBCwUAA4IBAQCW1fKcHessy/ZhnIwAtSLznZeZNH8LTVOzkhVd4HA7EJW+\nKVLBx8DnN7L3V2/uPJfHiOg4Rx7fi7LkJPegl3SCqJZ0N5bQS/KvDTCyLG+9E8Y+\n7wqCmWiXaH1devimXZvazilu4IC2dSks2D8DPWHgsOdVks9bme8J3KjdNMQudegc\newWZZ1Dtbd+Rn7cpKU3jURMwm4fRwGxbJ7iT5fkLlPBlyM/yFEik4SmQxFYrZCQg\n0f3v4kBefTh5yclPy5tEH+8G0LMsbbo3dJ5mPKpAShi0QEKDLd7eR1R/712lYTK4\ndi4XaEfqERgy68O4rvb4PGlJeRGS7AmL7Ss8wfAq\n-----END CERTIFICATE REQUEST-----\n",  # noqa: E501
                    "certificate": "-----BEGIN CERTIFICATE-----\nMIICvDCCAaQCFFPAOD7utDTsgFrm0vS4We18OcnKMA0GCSqGSIb3DQEBCwUAMCAx\nCzAJBgNVBAYTAlVTMREwDwYDVQQDDAh3aGF0ZXZlcjAeFw0yMjA3MjkyMTE5Mzha\nFw0yMzA3MjkyMTE5MzhaMBUxEzARBgNVBAMMCmJhbmFuYS5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVpcfcBOnFuyZG+A2WQzmaBI5NXgwTCfvE\neKciqRQXhzJdUkEg7eqwFrK3y9yjhoiB6q0WNAeR+nOdS/Cw7layRtGz5skOq7Aa\nN4FZHg0or30i7Rrx7afJcGJyLpxfK/OfLmJm5QEdLXV0DZp0L5vuhhEb1EUOrMaY\nGe4iwqTyg6D7fuBili9dBVn9IvNhYMVgtiqkWVLTW4ChE0LgES4oO3rQZgp4dtM5\nsp6KwHGO766UzwGnkKRizaqmLylfVusllWNPFfp6gEaxa45N70oqGUrvGSVHWeHf\nfvkhpWx+wOnu+2A5F/Yv3UNz2v4g7Vjt7V0tjL4KMV9YklpRjTh3AgMBAAEwDQYJ\nKoZIhvcNAQELBQADggEBAChjRzuba8zjQ7NYBVas89Oy7u++MlS8xWxh++yiUsV6\nWMk3ZemsPtXc1YmXorIQohtxLxzUPm2JhyzFzU/sOLmJQ1E/l+gtZHyRCwsb20fX\nmphuJsMVd7qv/GwEk9PBsk2uDqg4/Wix0Rx5lf95juJP7CPXQJl5FQauf3+LSz0y\nwF/j+4GqvrwsWr9hKOLmPdkyKkR6bHKtzzsxL9PM8GnElk2OpaPMMnzbL/vt2IAt\nxK01ZzPxCQCzVwHo5IJO5NR/fIyFbEPhxzG17QsRDOBR9fl9cOIvDeSO04vyZ+nz\n+kA2c3fNrZFAtpIlOOmFh8Q12rVL4sAjI5mVWnNEgvI=\n-----END CERTIFICATE-----\n",  # noqa: E501
                }
            ]
        }
    ],
    "properties": {
        "certificates": {
            "$id": "#/properties/certificates",
            "type": "array",
            "items": {
                "$id": "#/properties/certificates/items",
                "type": "object",
                "required": ["certificate_signing_request", "certificate", "ca", "chain"],
                "properties": {
                    "certificate_signing_request": {
                        "$id": "#/properties/certificates/items/certificate_signing_request",
                        "type": "string",
                    },
                    "certificate": {
                        "$id": "#/properties/certificates/items/certificate",
                        "type": "string",
                    },
                    "ca": {"$id": "#/properties/certificates/items/ca", "type": "string"},
                    "chain": {"$id": "#/properties/certificates/items/chain", "type": "string"},
                },
            },
        }
    },
    "required": ["certificates"],
}


logger = logging.getLogger(__name__)


class CertificateAvailableEvent(EventBase):
    """Charm Event triggered when a TLS certificate is available."""

    def __init__(
        self,
        handle: Handle,
        certificate: str,
        certificate_signing_request: str,
        ca: str,
        chain: str,
    ):
        super().__init__(handle)
        self.certificate = certificate
        self.certificate_signing_request = certificate_signing_request
        self.ca = ca
        self.chain = chain

    def snapshot(self) -> dict:
        """Returns snapshot."""
        return {
            "certificate": self.certificate,
            "certificate_signing_request": self.certificate_signing_request,
            "ca": self.ca,
            "chain": self.chain,
        }

    def restore(self, snapshot: dict):
        """Restores snapshot."""
        self.certificate = snapshot["certificate"]
        self.certificate_signing_request = snapshot["certificate_signing_request"]
        self.ca = snapshot["ca"]
        self.chain = snapshot["chain"]


class CertificateExpiringEvent(EventBase):
    """Charm Event triggered when a TLS certificate is almost expired."""

    def __init__(self, handle, certificate: str, expiry: datetime):
        """CertificateExpiringEvent.

        Args:
            handle (Handle): Juju framework handle
            certificate (str): TLS Certificate
            expiry (datetime): Datetime object reprensenting the time at which the certificate
                won't be valid anymore.
        """
        super().__init__(handle)
        self.certificate = certificate
        self.expiry = expiry

    def snapshot(self) -> dict:
        """Returns snapshot."""
        return {"certificate": self.certificate, "expiry": self.expiry}

    def restore(self, snapshot: dict):
        """Restores snapshot."""
        self.certificate = snapshot["certificate"]
        self.expiry = snapshot["expiry"]


class CertificateExpiredEvent(EventBase):
    """Charm Event triggered when a TLS certificate is expired."""

    def __init__(self, handle: Handle, certificate: str):
        super().__init__(handle)
        self.certificate = certificate

    def snapshot(self) -> dict:
        """Returns snapshot."""
        return {"certificate": self.certificate}

    def restore(self, snapshot: dict):
        """Restores snapshot."""
        self.certificate = snapshot["certificate"]


class CertificateCreationRequestEvent(EventBase):
    """Charm Event triggered when a TLS certificate is required."""

    def __init__(self, handle: Handle, certificate_signing_request: str, relation_id: int):
        super().__init__(handle)
        self.certificate_signing_request = certificate_signing_request
        self.relation_id = relation_id

    def snapshot(self) -> dict:
        """Returns snapshot."""
        return {
            "certificate_signing_request": self.certificate_signing_request,
            "relation_id": self.relation_id,
        }

    def restore(self, snapshot: dict):
        """Restores snapshot."""
        self.certificate_signing_request = snapshot["certificate_signing_request"]
        self.relation_id = snapshot["relation_id"]


class CertificateRevocationRequestEvent(EventBase):
    """Charm Event triggered when a TLS certificate needs to be revoked."""

    def __init__(
        self,
        handle: Handle,
        certificate: str,
        certificate_signing_request: str,
        ca: str,
        chain: str,
    ):
        super().__init__(handle)
        self.certificate = certificate
        self.certificate_signing_request = certificate_signing_request
        self.ca = ca
        self.chain = chain

    def snapshot(self) -> dict:
        """Returns snapshot."""
        return {
            "certificate": self.certificate,
            "certificate_signing_request": self.certificate_signing_request,
            "ca": self.ca,
            "chain": self.chain,
        }

    def restore(self, snapshot: dict):
        """Restores snapshot."""
        self.certificate = snapshot["certificate"]
        self.certificate_signing_request = snapshot["certificate_signing_request"]
        self.ca = snapshot["ca"]
        self.chain = snapshot["chain"]


class CertificateRevokedEvent(EventBase):
    """Charm Event triggered when a TLS certificate is revoked."""

    def __init__(self, handle, certificate_signing_request: str):
        super().__init__(handle)
        self.certificate_signing_request = certificate_signing_request

    def snapshot(self) -> dict:
        """Returns snapshot."""
        return {"certificate_signing_request": self.certificate_signing_request}

    def restore(self, snapshot):
        """Restores snapshot."""
        self.certificate_signing_request = snapshot["certificate_signing_request"]


def _load_unit_relation_data(raw_relation_data: dict) -> dict:
    """Loads relation data from the relation data bag.

    Json loads all data.

    Args:
        raw_relation_data: Relation data from the databag

    Returns:
        dict: Relation data in dict format.
    """
    certificate_data = dict()
    for key in raw_relation_data:
        try:
            certificate_data[key] = json.loads(raw_relation_data[key])
        except json.decoder.JSONDecodeError:
            certificate_data[key] = raw_relation_data[key]
    return certificate_data


def _get_provider_csrs(raw_provider_unit_relation_data: dict) -> List[str]:
    provider_relation_data = _load_unit_relation_data(raw_provider_unit_relation_data)
    return [
        certificate["certificate_signing_request"]
        for certificate in provider_relation_data.get("certificates", [])
        if certificate.get("certificate_signing_request", None)
    ]


def _get_requirer_csrs(raw_requirer_unit_relation_data: dict) -> List[str]:
    requirer_relation_data = _load_unit_relation_data(raw_requirer_unit_relation_data)
    return [
        certificate_creation_request["certificate_signing_request"]
        for certificate_creation_request in requirer_relation_data.get(
            "certificate_signing_requests", []
        )
        if certificate_creation_request.get("certificate_signing_request", None)
    ]


def generate_ca(
    private_key: bytes,
    subject: str,
    private_key_password: Optional[bytes] = None,
    validity: int = 365,
    country: str = "US",
) -> bytes:
    """Generates a CA Certificate.

    Args:
        private_key (bytes): Private key
        subject (str): Certificate subject
        private_key_password (bytes): Private key password
        validity (int): Certificate validity time (in days)
        country (str): Certificate Issuing country

    Returns:
        bytes: CA Certificate.
    """
    private_key_object = serialization.load_pem_private_key(
        private_key, password=private_key_password
    )
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, subject),
        ]
    )
    subject_identifier_object = x509.SubjectKeyIdentifier.from_public_key(
        private_key_object.public_key()  # type: ignore[arg-type]
    )
    subject_identifier = key_identifier = subject_identifier_object.public_bytes()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key_object.public_key())  # type: ignore[arg-type]
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity))
        .add_extension(x509.SubjectKeyIdentifier(digest=subject_identifier), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key_object, hashes.SHA256())  # type: ignore[arg-type]
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_certificate(
    csr: bytes,
    ca: bytes,
    ca_key: bytes,
    ca_key_password: Optional[bytes] = None,
    validity: int = 365,
    alt_names: list = None,
) -> bytes:
    """Generates a TLS certificate based on a CSR.

    Args:
        csr (bytes): CSR
        ca (bytes): CA Certificate
        ca_key (bytes): CA private key
        ca_key_password: CA private key password
        validity (int): Certificate validity (in days)
        alt_names: Certificate Subject alternative names

    Returns:
        bytes: Certificate
    """
    csr_object = x509.load_pem_x509_csr(csr)
    subject = csr_object.subject
    issuer = x509.load_pem_x509_certificate(ca).issuer
    private_key = serialization.load_pem_private_key(ca_key, password=ca_key_password)

    certificate_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(csr_object.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity))
    )
    if alt_names:
        names = [x509.DNSName(n) for n in alt_names]
        certificate_builder = certificate_builder.add_extension(
            x509.SubjectAlternativeName(names),
            critical=False,
        )
    certificate_builder._version = x509.Version.v1
    cert = certificate_builder.sign(private_key, hashes.SHA256())  # type: ignore[arg-type]
    return cert.public_bytes(serialization.Encoding.PEM)


def generate_pfx_package(
    certificate: bytes,
    private_key: bytes,
    package_password: str,
    private_key_password: Optional[bytes] = None,
) -> bytes:
    """Generates a PFX package to contain the TLS certificate and private key.

    Args:
        certificate (bytes): TLS certificate
        private_key (bytes): Private key
        package_password (str): Password to open the PFX package
        private_key_password (bytes): Private key password

    Returns:
        bytes:
    """
    private_key_object = serialization.load_pem_private_key(
        private_key, password=private_key_password
    )
    certificate_object = x509.load_pem_x509_certificate(certificate)
    name = certificate_object.subject.rfc4514_string()
    pfx_bytes = pkcs12.serialize_key_and_certificates(
        name=name.encode(),
        cert=certificate_object,
        key=private_key_object,  # type: ignore[arg-type]
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(package_password.encode()),
    )
    return pfx_bytes


def generate_private_key(
    password: Optional[bytes] = None,
    key_size: int = 2048,
    public_exponent: int = 65537,
) -> bytes:
    """Generates a private key.

    Args:
        password (bytes): Password for decrypting the private key
        key_size (int): Key size in bytes
        public_exponent: Public exponent.

    Returns:
        bytes: Private Key
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption(),
    )
    return key_bytes


def generate_csr(
    private_key: bytes,
    subject: str,
    add_unique_id_to_subject_name: bool = True,
    email_address: str = None,
    country_name: str = None,
    private_key_password: Optional[bytes] = None,
    sans: Optional[List[str]] = None,
    additional_critical_extensions: Optional[List] = None,
) -> bytes:
    """Generates a CSR using private key and subject.

    Args:
        private_key (bytes): Private key
        subject (str): CSR Subject.
        add_unique_id_to_subject_name (bool): Whether a unique ID must be added to the CSR's
            subject name. Always leave to "True" when the CSR is used to request certificates
            using the tls-certificates relation.
        email_address (str): Email address.
        country_name (str): Country Name.
        private_key_password (bytes): Private key password
        sans (list): List of subject alternative names
        additional_critical_extensions (list): List if critical additional extension objects.
            Object must be a x509 ExtensionType.

    Returns:
        bytes: CSR
    """
    signing_key = serialization.load_pem_private_key(private_key, password=private_key_password)
    subject_name = [x509.NameAttribute(x509.NameOID.COMMON_NAME, subject)]
    if add_unique_id_to_subject_name:
        unique_identifier = uuid.uuid4()
        subject_name.append(
            x509.NameAttribute(x509.NameOID.X500_UNIQUE_IDENTIFIER, str(unique_identifier))
        )
    if email_address:
        subject_name.append(x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, email_address))
    if country_name:
        subject_name.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country_name))
    csr = x509.CertificateSigningRequestBuilder(subject_name=x509.Name(subject_name))
    if sans:
        csr = csr.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san) for san in sans]), critical=False
        )
    if additional_critical_extensions:
        for extension in additional_critical_extensions:
            csr = csr.add_extension(extension, critical=True)
    signed_certificate = csr.sign(signing_key, hashes.SHA256())  # type: ignore[arg-type]
    return signed_certificate.public_bytes(serialization.Encoding.PEM)


class CertificatesProviderCharmEvents(CharmEvents):
    """List of events that the TLS Certificates provider charm can leverage."""

    certificate_creation_request = EventSource(CertificateCreationRequestEvent)
    certificate_revocation_request = EventSource(CertificateRevocationRequestEvent)


class CertificatesRequirerCharmEvents(CharmEvents):
    """List of events that the TLS Certificates requirer charm can leverage."""

    certificate_available = EventSource(CertificateAvailableEvent)
    certificate_expiring = EventSource(CertificateExpiringEvent)
    certificate_expired = EventSource(CertificateExpiredEvent)
    certificate_revoked = EventSource(CertificateRevokedEvent)


class TLSCertificatesProvidesV1(Object):
    """TLS certificates provider class to be instantiated by TLS certificates providers."""

    on = CertificatesProviderCharmEvents()

    def __init__(self, charm: CharmBase, relationship_name: str):
        super().__init__(charm, relationship_name)
        self.framework.observe(
            charm.on[relationship_name].relation_changed, self._on_relation_changed
        )
        self.charm = charm
        self.relationship_name = relationship_name

    @staticmethod
    def _relation_data_is_valid(certificates_data: dict) -> bool:
        """Uses JSON schema validator to validate relation data content.

        Args:
            certificates_data (dict): Certificate data dictionary as retrieved from relation data.

        Returns:
            bool: True/False depending on whether the relation data follows the json schema.
        """
        try:
            validate(instance=certificates_data, schema=REQUIRER_JSON_SCHEMA)
            return True
        except exceptions.ValidationError:
            return False

    def set_relation_certificate(
        self,
        certificate: str,
        certificate_signing_request: str,
        ca: str,
        chain: str,
        relation_id: int,
    ) -> None:
        """Adds certificates to relation data.

        Args:
            certificate (str): Certificate
            certificate_signing_request (str): Certificate signing request
            ca (str): CA Certificate
            chain (str): CA Chain certificate
            relation_id (int): Juju relation ID

        Returns:
            None
        """
        certificates_relation = self.model.get_relation(
            relation_name=self.relationship_name, relation_id=relation_id
        )
        provider_relation_data = certificates_relation.data[self.model.unit]  # type: ignore[union-attr]  # noqa: E501
        loaded_relation_data = _load_unit_relation_data(provider_relation_data)
        new_certificate = {
            "certificate": certificate.strip(),
            "certificate_signing_request": certificate_signing_request.strip(),
            "ca": ca.strip(),
            "chain": chain.strip(),
        }
        if "certificates" not in loaded_relation_data:
            certificates = [new_certificate]
        else:
            certificates = loaded_relation_data["certificates"]
            for cert_dict in certificates:
                if cert_dict["certificate_signing_request"] == certificate_signing_request.strip():
                    certificates.remove(cert_dict)
            loaded_relation_data["certificates"].append(new_certificate)
        provider_relation_data["certificates"] = json.dumps(certificates)

    def remove_certificate(self, certificate: str) -> None:
        """Removes a given certificate from relation data.

        Args:
            certificate (str): TLS Certificate

        Returns:
            None
        """
        relations = self.model.relations
        for certificate_relation in relations[self.relationship_name]:
            provider_relation_data = certificate_relation.data[self.model.unit]
            loaded_relation_data = _load_unit_relation_data(provider_relation_data)
            provided_certificates = loaded_relation_data["certificates"]
            for provided_certificate in provided_certificates:
                if provided_certificate["certificate"] == certificate.strip():
                    provided_certificates.remove(provided_certificate)
            provider_relation_data["certificates"] = json.dumps(provided_certificates)

    def _on_relation_changed(self, event) -> None:
        """Handler triggerred on relation changed event.

        Looks at the relation data and either emits:
        - certificate request event: If the unit relation data contains a CSR for which
            a certificate does not exist in the provider relation data.
        - certificate revocation event: If the provider relation data contains a CSR for which
            a csr does not exist in the requirer relation data.

        Args:
            event: Juju event

        Returns:
            None
        """
        requirer_relation_data = _load_unit_relation_data(event.relation.data[event.unit])
        provider_relation_data = _load_unit_relation_data(event.relation.data[self.model.unit])
        if not self._relation_data_is_valid(requirer_relation_data):
            logger.warning(
                f"Relation data did not pass JSON Schema validation: {requirer_relation_data}"
            )
            return
        provider_csrs = _get_provider_csrs(event.relation.data[self.model.unit])
        requirer_csrs = _get_requirer_csrs(event.relation.data[event.unit])
        for certificate_signing_request in requirer_csrs:
            if certificate_signing_request not in provider_csrs:
                self.on.certificate_creation_request.emit(
                    certificate_signing_request=certificate_signing_request,
                    relation_id=event.relation.id,
                )
        for certificate in provider_relation_data.get("certificates", []):
            if certificate["certificate_signing_request"] not in requirer_csrs:
                self.on.certificate_revocation_request.emit(
                    certificate=certificate["certificate"],
                    certificate_signing_request=certificate["certificate_signing_request"],
                    ca=certificate["ca"],
                    chain=certificate["chain"],
                )
                self.remove_certificate(certificate=certificate["certificate"])


class TLSCertificatesRequiresV1(Object):
    """TLS certificates requirer class to be instantiated by TLS certificates requirers."""

    on = CertificatesRequirerCharmEvents()

    def __init__(
        self,
        charm: CharmBase,
        relationship_name: str,
        expiry_notification_time: int = 168,
    ):
        """Generates/use private key and observes relation changed event.

        Args:
            charm: Charm object
            relationship_name: Juju relation name
            expiry_notification_time (int): Time difference between now and expiry (in hours).
                Used to trigger the CertificateExpiring event. Default: 7 days.
        """
        super().__init__(charm, relationship_name)
        self.relationship_name = relationship_name
        self.charm = charm
        self.expiry_notification_time = expiry_notification_time
        self.framework.observe(
            charm.on[relationship_name].relation_changed, self._on_relation_changed
        )
        self.framework.observe(charm.on.update_status, self._on_update_status)

    def request_certificate_creation(self, certificate_signing_request: bytes) -> None:
        """Request TLS certificate to provider charm.

        Args:
            certificate_signing_request (bytes): Certificate Signing Request

        Returns:
            None
        """
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            message = (
                f"Relation {self.relationship_name} does not exist - "
                f"The certificate request can't be completed"
            )
            logger.error(message)
            raise RuntimeError(message)
        relation_data = _load_unit_relation_data(relation.data[self.model.unit])
        new_certificate_creation_request = {
            "certificate_signing_request": certificate_signing_request.decode().strip()
        }
        if "certificate_signing_requests" in relation_data:
            certificate_creation_request_list = relation_data["certificate_signing_requests"]
            if new_certificate_creation_request in certificate_creation_request_list:
                logger.info("Request was already made - Doing nothing")
                return
            certificate_creation_request_list.append(new_certificate_creation_request)
        else:
            certificate_creation_request_list = [new_certificate_creation_request]
        relation.data[self.model.unit]["certificate_signing_requests"] = json.dumps(
            certificate_creation_request_list
        )
        logger.info("Certificate request sent to provider")

    def request_certificate_revocation(self, certificate_signing_request: bytes) -> None:
        """Removes CSR from relation data.

        The provider of this relation is then expected to remove certificates associated to this
        CSR from the relation data as well and emit a request_certificate_revocation event for the
        provider charm to interpret.

        Args:
            certificate_signing_request (bytes): Certificate Signing Request

        Returns:
            None
        """
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            raise RuntimeError(f"Relation {self.relationship_name} does not exist")
        relation_data = _load_unit_relation_data(relation.data[self.model.unit])
        requirer_relation_csr_list = relation_data.get("certificate_signing_requests")
        if not requirer_relation_csr_list:
            logger.info("No CSR in relation data.")
            return
        for requirer_csr in requirer_relation_csr_list:
            if (
                requirer_csr["certificate_signing_request"]
                == certificate_signing_request.decode().strip()
            ):
                requirer_relation_csr_list.remove(requirer_csr)
        relation.data[self.model.unit]["certificate_signing_requests"] = json.dumps(
            requirer_relation_csr_list
        )
        logger.info("Certificate revocation sent to provider")

    def request_certificate_renewal(
        self, old_certificate_signing_request: bytes, new_certificate_signing_request: bytes
    ) -> None:
        """Renews certificate.

        Removes old CSR from relation data and adds new one.

        Args:
            old_certificate_signing_request: Old CSR
            new_certificate_signing_request: New CSR

        Returns:
            None
        """
        try:
            self.request_certificate_revocation(
                certificate_signing_request=old_certificate_signing_request
            )
        except RuntimeError:
            logger.warning("Certificate revocation failed.")
        self.request_certificate_creation(
            certificate_signing_request=new_certificate_signing_request
        )
        logger.info("Certificate renewal request completed.")

    @staticmethod
    def _relation_data_is_valid(certificates_data: dict) -> bool:
        """Checks whether relation data is valid based on json schema.

        Args:
            certificates_data: Certificate data in dict format.

        Returns:
            bool: Whether relation data is valid.
        """
        try:
            validate(instance=certificates_data, schema=PROVIDER_JSON_SCHEMA)
            return True
        except exceptions.ValidationError:
            return False

    def _on_relation_changed(self, event: RelationChangedEvent) -> None:
        """Handler triggerred on relation changed events.

        Args:
            event: Juju event

        Returns:
            None
        """
        provider_relation_data = _load_unit_relation_data(event.relation.data[event.unit])
        if not self._relation_data_is_valid(provider_relation_data):
            logger.warning(
                f"Relation data did not pass JSON Schema validation: {provider_relation_data}"
            )
            return
        provider_csrs = _get_provider_csrs(event.relation.data[event.unit])
        requirer_csrs = _get_requirer_csrs(event.relation.data[self.model.unit])
        for certificate in provider_relation_data["certificates"]:
            if certificate["certificate_signing_request"] in requirer_csrs:
                self.on.certificate_available.emit(
                    certificate_signing_request=certificate["certificate_signing_request"],
                    certificate=certificate["certificate"],
                    ca=certificate["ca"],
                    chain=certificate["chain"],
                )
        for csr in requirer_csrs:
            if csr not in provider_csrs:
                self.on.certificate_revoked.emit(certificate_signing_request=csr)

    def _on_update_status(self, event: UpdateStatusEvent) -> None:
        """Triggered on update status event.

        Goes through each certificate in the "certificates" relation and checks their expiry date.
        If they are close to expire (<7 days), emits a CertificateExpiringEvent event and if
        they are expired, emits a CertificateExpiredEvent.

        Args:
            event (UpdateStatusEvent): Juju event

        Returns:
            None
        """
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            return
        for unit in relation.units:
            relation_data = _load_unit_relation_data(relation.data[unit])
            if self._relation_data_is_valid(relation_data):
                certificates = relation_data.get("certificates")
                if not certificates:
                    continue
                for certificate_dict in certificates:
                    certificate = certificate_dict["certificate"]
                    certificate_object = x509.load_pem_x509_certificate(data=certificate.encode())
                    time_difference = certificate_object.not_valid_after - datetime.utcnow()
                    if time_difference.total_seconds() < 0:
                        logger.warning("Certificate is expired")
                        self.on.certificate_expired.emit(certificate=certificate)
                        self.request_certificate_revocation(certificate)
                        continue
                    if time_difference.total_seconds() < (self.expiry_notification_time * 60 * 60):
                        logger.info("Certificate almost expired")
                        self.on.certificate_expiring.emit(
                            certificate=certificate, expiry=certificate_object.not_valid_after
                        )
