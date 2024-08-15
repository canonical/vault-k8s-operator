# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charm library for managing TLS certificates (V4) - BETA.

> Warning: This is a beta version of the tls-certificates interface library.
> Use at your own risk.

This library contains the Requires and Provides classes for handling the tls-certificates
interface.

Pre-requisites:
  - Juju >= 3.0

## Getting Started
From a charm directory, fetch the library using `charmcraft`:

```shell
charmcraft fetch-lib charms.tls_certificates_interface.v4.tls_certificates
```

Add the following libraries to the charm's `requirements.txt` file:
- cryptography >= 42.0.0
- pydantic >= 2.0.0

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

### Requirer charm
The requirer charm is the charm requiring certificates from another charm that provides them.

#### Example

In the following example, the requiring charm requests a certificate using attributes
from the Juju configuration options.

```python
from typing import List, Optional, cast

from ops.charm import ActionEvent, CharmBase
from ops.main import main

from lib.charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
    CertificateRequest,
    Mode,
    TLSCertificatesRequiresV4,
)


class DummyTLSCertificatesRequirerCharm(CharmBase):
    def __init__(self, *args):
        super().__init__(*args)
        certificate_requests = self._get_certificate_requests()
        self.certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name="certificates",
            certificate_requests=certificate_requests,
            mode=Mode.UNIT,
            refresh_events=[self.on.config_changed],
        )
        self.framework.observe(
            self.certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self.on.regenerate_private_key_action, self._on_regenerate_private_key_action
        )
        self.framework.observe(self.on.get_certificate_action, self._on_get_certificate_action)

    def _get_certificate_requests(self) -> List[CertificateRequest]:
        if not self._get_config_common_name():
            return []
        return [
            CertificateRequest(
                common_name=self._get_config_common_name(),
                sans_dns=self._get_config_sans_dns(),
                organization=self._get_config_organization_name(),
                organizational_unit=self._get_config_organization_unit_name(),
                email_address=self._get_config_email_address(),
                country_name=self._get_config_country_name(),
                state_or_province_name=self._get_config_state_or_province_name(),
                locality_name=self._get_config_locality_name(),
            )
        ]

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        print("Certificate available")

    def _on_regenerate_private_key_action(self, event: ActionEvent) -> None:
        self.certificates.regenerate_private_key()

    def _on_get_certificate_action(self, event: ActionEvent) -> None:
        certificate, _ = self.certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_requests()[0]
        )
        if not certificate:
            event.fail("Certificate not available")
            return
        event.set_results(
            {
                "certificate": str(certificate.certificate),
                "ca": str(certificate.ca),
                "csr": str(certificate.certificate_signing_request),
            }
        )

    def _get_config_common_name(self) -> str:
        return cast(str, self.model.config.get("common_name"))

    def _get_config_sans_dns(self) -> List[str]:
        config_sans_dns = cast(str, self.model.config.get("sans_dns", ""))
        return config_sans_dns.split(",") if config_sans_dns else []

    def _get_config_organization_name(self) -> Optional[str]:
        return cast(str, self.model.config.get("organization_name"))

    def _get_config_organization_unit_name(self) -> Optional[str]:
        return cast(str, self.model.config.get("organization_unit_name"))

    def _get_config_email_address(self) -> Optional[str]:
        return cast(str, self.model.config.get("email_address"))

    def _get_config_country_name(self) -> Optional[str]:
        return cast(str, self.model.config.get("country_name"))

    def _get_config_state_or_province_name(self) -> Optional[str]:
        return cast(str, self.model.config.get("state_or_province_name"))

    def _get_config_locality_name(self) -> Optional[str]:
        return cast(str, self.model.config.get("locality_name"))


if __name__ == "__main__":
    main(DummyTLSCertificatesRequirerCharm)
```

You can integrate both charms by running:

```bash
juju integrate <tls-certificates provider charm> <tls-certificates requirer charm>
```
"""  # noqa: D214, D405, D411, D416

import copy
import ipaddress
import json
import logging
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import FrozenSet, List, MutableMapping, Optional, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ops import BoundEvent, CharmBase, CharmEvents, SecretExpiredEvent
from ops.framework import EventBase, EventSource, Handle, Object
from ops.jujuversion import JujuVersion
from ops.model import (
    Application,
    ModelError,
    Relation,
    SecretNotFoundError,
    Unit,
)
from pydantic import BaseModel, ConfigDict, ValidationError

# The unique Charmhub library identifier, never change it
LIBID = "afd8c2bccf834997afce12c2706d2ede"

# Increment this major API version when introducing breaking changes
LIBAPI = 4

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 4

PYDEPS = ["cryptography", "pydantic"]

logger = logging.getLogger(__name__)


class TLSCertificatesError(Exception):
    """Base class for custom errors raised by this library."""


class DataValidationError(TLSCertificatesError):
    """Raised when data validation fails."""


class _DatabagModel(BaseModel):
    """Base databag model."""

    model_config = ConfigDict(
        # tolerate additional keys in databag
        extra="ignore",
        # Allow instantiating this class by field name (instead of forcing alias).
        populate_by_name=True,
        # Custom config key: whether to nest the whole datastructure (as json)
        # under a field or spread it out at the toplevel.
        _NEST_UNDER=None,
    )  # type: ignore
    """Pydantic config."""

    @classmethod
    def load(cls, databag: MutableMapping):
        """Load this model from a Juju databag."""
        nest_under = cls.model_config.get("_NEST_UNDER")
        if nest_under:
            return cls.model_validate(json.loads(databag[nest_under]))

        try:
            data = {
                k: json.loads(v)
                for k, v in databag.items()
                # Don't attempt to parse model-external values
                if k in {(f.alias or n) for n, f in cls.model_fields.items()}
            }
        except json.JSONDecodeError as e:
            msg = f"invalid databag contents: expecting json. {databag}"
            logger.error(msg)
            raise DataValidationError(msg) from e

        try:
            return cls.model_validate_json(json.dumps(data))
        except ValidationError as e:
            msg = f"failed to validate databag: {databag}"
            logger.debug(msg, exc_info=True)
            raise DataValidationError(msg) from e

    def dump(self, databag: Optional[MutableMapping] = None, clear: bool = True):
        """Write the contents of this model to Juju databag.

        Args:
            databag: The databag to write to.
            clear: Whether to clear the databag before writing.

        Returns:
            MutableMapping: The databag.
        """
        if clear and databag:
            databag.clear()

        if databag is None:
            databag = {}
        nest_under = self.model_config.get("_NEST_UNDER")
        if nest_under:
            databag[nest_under] = self.model_dump_json(
                by_alias=True,
                # skip keys whose values are default
                exclude_defaults=True,
            )
            return databag

        dct = self.model_dump(mode="json", by_alias=True, exclude_defaults=True)
        databag.update({k: json.dumps(v) for k, v in dct.items()})
        return databag


class _Certificate(BaseModel):
    """Certificate model."""

    ca: str
    certificate_signing_request: str
    certificate: str
    chain: Optional[List[str]] = None
    recommended_expiry_notification_time: Optional[int] = None
    revoked: Optional[bool] = None

    def to_provider_certificate(self, relation_id: int) -> "ProviderCertificate":
        """Convert to a ProviderCertificate."""
        return ProviderCertificate(
            relation_id=relation_id,
            certificate=Certificate.from_string(self.certificate),
            certificate_signing_request=CertificateSigningRequest.from_string(
                self.certificate_signing_request
            ),
            ca=Certificate.from_string(self.ca),
            chain=[Certificate.from_string(certificate) for certificate in self.chain]
            if self.chain
            else [],
            recommended_expiry_notification_time=self.recommended_expiry_notification_time,
            revoked=self.revoked,
        )


class _CertificateSigningRequest(BaseModel):
    """Certificate signing request model."""

    certificate_signing_request: str
    ca: Optional[bool]


class _ProviderApplicationData(_DatabagModel):
    """Provider application data model."""

    certificates: List[_Certificate]


class _RequirerData(_DatabagModel):
    """Requirer data model.

    The same model is used for the unit and application data.
    """

    certificate_signing_requests: List[_CertificateSigningRequest]


class Mode(Enum):
    """Enum representing the mode of the certificate request.

    UNIT (default): Request a certificate for the unit.
        Each unit will have its own private key and certificate.
    APP: Request a certificate for the application.
        The private key and certificate will be shared by all units.
    """

    UNIT = 1
    APP = 2


@dataclass(frozen=True)
class PrivateKey:
    """This class represents a private key."""

    raw: str

    def __str__(self):
        """Return the private key as a string."""
        return self.raw

    @classmethod
    def from_string(cls, private_key: str) -> "PrivateKey":
        """Create a PrivateKey object from a private key."""
        return cls(raw=private_key.strip())


@dataclass(frozen=True)
class Certificate:
    """This class represents a certificate."""

    raw: str
    common_name: str
    sans_dns: Optional[FrozenSet[str]] = None
    sans_ip: Optional[FrozenSet[str]] = None
    sans_oid: Optional[FrozenSet[str]] = None
    email_address: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country_name: Optional[str] = None
    state_or_province_name: Optional[str] = None
    locality_name: Optional[str] = None
    expiry_time: Optional[datetime] = None
    validity_start_time: Optional[datetime] = None

    def __str__(self) -> str:
        """Return the certificate as a string."""
        return self.raw

    @classmethod
    def from_string(cls, certificate: str) -> "Certificate":
        """Create a Certificate object from a certificate."""
        try:
            certificate_object = x509.load_pem_x509_certificate(data=certificate.encode())
        except ValueError as e:
            logger.error("Could not load certificate: %s", e)
            raise TLSCertificatesError("Could not load certificate")

        common_name = certificate_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        country_name = certificate_object.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        state_or_province_name = certificate_object.subject.get_attributes_for_oid(
            NameOID.STATE_OR_PROVINCE_NAME
        )
        locality_name = certificate_object.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
        organization_name = certificate_object.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )
        email_address = certificate_object.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)

        try:
            sans = certificate_object.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            sans_dns = frozenset(
                str(san)
                for san in sans.get_values_for_type(x509.DNSName)
                if isinstance(san, x509.DNSName)
            )
            sans_ip = frozenset(
                str(san)
                for san in sans.get_values_for_type(x509.IPAddress)
                if isinstance(san, x509.IPAddress)
            )
            sans_oid = frozenset(
                str(san)
                for san in sans.get_values_for_type(x509.RegisteredID)
                if isinstance(san, x509.RegisteredID)
            )
        except x509.ExtensionNotFound:
            logger.debug("No SANs found in certificate")
            sans_dns = None
            sans_ip = None
            sans_oid = None
        expiry_time = certificate_object.not_valid_after_utc
        validity_start_time = certificate_object.not_valid_before_utc

        return cls(
            raw=certificate.strip(),
            common_name=str(common_name[0].value),
            country_name=str(country_name[0].value) if country_name else None,
            state_or_province_name=str(state_or_province_name[0].value)
            if state_or_province_name
            else None,
            locality_name=str(locality_name[0].value) if locality_name else None,
            organization=str(organization_name[0].value) if organization_name else None,
            email_address=str(email_address[0].value) if email_address else None,
            sans_dns=sans_dns,
            sans_ip=sans_ip,
            sans_oid=sans_oid,
            expiry_time=expiry_time,
            validity_start_time=validity_start_time,
        )


@dataclass(frozen=True)
class CertificateSigningRequest:
    """This class represents a certificate signing request."""

    raw: str
    common_name: str
    sans_dns: Optional[FrozenSet[str]] = None
    sans_ip: Optional[FrozenSet[str]] = None
    sans_oid: Optional[FrozenSet[str]] = None
    email_address: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country_name: Optional[str] = None
    state_or_province_name: Optional[str] = None
    locality_name: Optional[str] = None
    is_ca: bool = False

    def __eq__(self, other: object) -> bool:
        """Check if two CertificateSigningRequest objects are equal."""
        if not isinstance(other, CertificateSigningRequest):
            return NotImplemented
        return self.raw.strip() == other.raw.strip()

    def __str__(self) -> str:
        """Return the CSR as a string."""
        return self.raw

    def to_certificate_request(self) -> "CertificateRequest":
        """Convert to a CertificateRequest object."""
        return CertificateRequest(
            common_name=self.common_name,
            sans_dns=self.sans_dns,
            sans_ip=self.sans_ip,
            sans_oid=self.sans_oid,
            email_address=self.email_address,
            organization=self.organization,
            organizational_unit=self.organizational_unit,
            country_name=self.country_name,
            state_or_province_name=self.state_or_province_name,
            locality_name=self.locality_name,
            is_ca=self.is_ca,
        )

    @classmethod
    def from_string(cls, csr: str) -> "CertificateSigningRequest":
        """Create a CertificateSigningRequest object from a CSR."""
        try:
            csr_object = x509.load_pem_x509_csr(csr.encode())
        except ValueError as e:
            logger.error("Could not load CSR: %s", e)
            raise TLSCertificatesError("Could not load CSR")
        common_name = csr_object.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        country_name = csr_object.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        state_or_province_name = csr_object.subject.get_attributes_for_oid(
            NameOID.STATE_OR_PROVINCE_NAME
        )
        locality_name = csr_object.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)
        organization_name = csr_object.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        email_address = csr_object.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        try:
            sans = csr_object.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            sans_dns = frozenset(sans.get_values_for_type(x509.DNSName))
            sans_ip = frozenset([str(san) for san in sans.get_values_for_type(x509.IPAddress)])
            sans_oid = frozenset([str(san) for san in sans.get_values_for_type(x509.RegisteredID)])
        except x509.ExtensionNotFound:
            sans = frozenset()
            sans_dns = frozenset()
            sans_ip = frozenset()
            sans_oid = frozenset()
        return cls(
            raw=csr.strip(),
            common_name=str(common_name[0].value),
            country_name=str(country_name[0].value) if country_name else None,
            state_or_province_name=str(state_or_province_name[0].value)
            if state_or_province_name
            else None,
            locality_name=str(locality_name[0].value) if locality_name else None,
            organization=str(organization_name[0].value) if organization_name else None,
            email_address=str(email_address[0].value) if email_address else None,
            sans_dns=sans_dns,
            sans_ip=sans_ip if sans_ip else None,
            sans_oid=sans_oid if sans_oid else None,
        )

    def matches_private_key(self, key: PrivateKey) -> bool:
        """Check if a CSR matches a private key.

        This function only works with RSA keys.

        Args:
            key (PrivateKey): Private key
        Returns:
            bool: True/False depending on whether the CSR matches the private key.
        """
        try:
            csr_object = x509.load_pem_x509_csr(self.raw.encode("utf-8"))
            key_object = serialization.load_pem_private_key(
                data=key.raw.encode("utf-8"), password=None
            )
            key_object_public_key = key_object.public_key()
            csr_object_public_key = csr_object.public_key()
            if not isinstance(key_object_public_key, rsa.RSAPublicKey):
                logger.warning("Key is not an RSA key")
                return False
            if not isinstance(csr_object_public_key, rsa.RSAPublicKey):
                logger.warning("CSR is not an RSA key")
                return False
            if (
                csr_object_public_key.public_numbers().n
                != key_object_public_key.public_numbers().n
            ):
                logger.warning("Public key numbers between CSR and key do not match")
                return False
        except ValueError:
            logger.warning("Could not load certificate or CSR.")
            return False
        return True

    def matches_certificate(self, certificate: Certificate) -> bool:
        """Check if a CSR matches a certificate.

        Args:
            certificate (Certificate): Certificate
        Returns:
            bool: True/False depending on whether the CSR matches the certificate.
        """
        csr_object = x509.load_pem_x509_csr(self.raw.encode("utf-8"))
        cert_object = x509.load_pem_x509_certificate(certificate.raw.encode("utf-8"))
        return csr_object.public_key() == cert_object.public_key()

    def get_sha256_hex(self) -> str:
        """Calculate the hash of the provided data and return the hexadecimal representation."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.raw.encode())
        return digest.finalize().hex()


@dataclass(frozen=True)
class CertificateRequest:
    """This class represents a certificate request.

    This class should be used inside the requirer charm to specify the requested
    attributes for the certificate.
    """

    common_name: str
    sans_dns: Optional[FrozenSet[str]] = None
    sans_ip: Optional[FrozenSet[str]] = None
    sans_oid: Optional[FrozenSet[str]] = None
    email_address: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country_name: Optional[str] = None
    state_or_province_name: Optional[str] = None
    locality_name: Optional[str] = None
    is_ca: bool = False

    def is_valid(self) -> bool:
        """Check whether the certificate request is valid."""
        if not self.common_name:
            return False
        return True

    def generate_csr(  # noqa: C901
        self,
        private_key: PrivateKey,
        add_unique_id_to_subject_name: bool = True,
    ) -> CertificateSigningRequest:
        """Generate a CSR using private key and subject.

        Args:
            private_key (PrivateKey): Private key
            add_unique_id_to_subject_name (bool): Whether a unique ID must be added to the CSR's
                subject name. Always leave to "True" when the CSR is used to request certificates
                using the tls-certificates relation.

        Returns:
            CertificateSigningRequest: CSR
        """
        signing_key = serialization.load_pem_private_key(str(private_key).encode(), password=None)
        subject_name = [x509.NameAttribute(x509.NameOID.COMMON_NAME, self.common_name)]
        if add_unique_id_to_subject_name:
            unique_identifier = uuid.uuid4()
            subject_name.append(
                x509.NameAttribute(x509.NameOID.X500_UNIQUE_IDENTIFIER, str(unique_identifier))
            )
        if self.organization:
            subject_name.append(
                x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, self.organization)
            )
        if self.email_address:
            subject_name.append(x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, self.email_address))
        if self.country_name:
            subject_name.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, self.country_name))
        if self.state_or_province_name:
            subject_name.append(
                x509.NameAttribute(
                    x509.NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province_name
                )
            )
        if self.locality_name:
            subject_name.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, self.locality_name))
        csr = x509.CertificateSigningRequestBuilder(subject_name=x509.Name(subject_name))

        _sans: List[x509.GeneralName] = []
        if self.sans_oid:
            _sans.extend([x509.RegisteredID(x509.ObjectIdentifier(san)) for san in self.sans_oid])
        if self.sans_ip:
            _sans.extend([x509.IPAddress(ipaddress.ip_address(san)) for san in self.sans_ip])
        if self.sans_dns:
            _sans.extend([x509.DNSName(san) for san in self.sans_dns])
        if _sans:
            csr = csr.add_extension(x509.SubjectAlternativeName(set(_sans)), critical=False)
        signed_certificate = csr.sign(signing_key, hashes.SHA256())  # type: ignore[arg-type]
        csr_str = signed_certificate.public_bytes(serialization.Encoding.PEM).decode()
        return CertificateSigningRequest.from_string(csr_str)


@dataclass(frozen=True)
class ProviderCertificate:
    """This class represents a certificate provided by the TLS provider."""

    relation_id: int
    certificate: Certificate
    certificate_signing_request: CertificateSigningRequest
    ca: Certificate
    chain: List[Certificate]
    recommended_expiry_notification_time: Optional[int] = None
    revoked: Optional[bool] = None

    def to_json(self) -> str:
        """Return the object as a JSON string.

        Returns:
            str: JSON representation of the object
        """
        return json.dumps(
            {
                "csr": str(self.certificate_signing_request),
                "certificate": str(self.certificate),
                "ca": str(self.ca),
                "chain": [str(cert) for cert in self.chain],
                "revoked": self.revoked,
            }
        )


@dataclass(frozen=True)
class RequirerCSR:
    """This class represents a certificate signing request requested by the TLS requirer."""

    relation_id: int
    certificate_signing_request: CertificateSigningRequest


class CertificateAvailableEvent(EventBase):
    """Charm Event triggered when a TLS certificate is available."""

    def __init__(
        self,
        handle: Handle,
        certificate: Certificate,
        certificate_signing_request: CertificateSigningRequest,
        ca: Certificate,
        chain: List[Certificate],
    ):
        super().__init__(handle)
        self.certificate = certificate
        self.certificate_signing_request = certificate_signing_request
        self.ca = ca
        self.chain = chain

    def snapshot(self) -> dict:
        """Return snapshot."""
        return {
            "certificate": str(self.certificate),
            "certificate_signing_request": str(self.certificate_signing_request),
            "ca": str(self.ca),
            "chain": json.dumps([str(certificate) for certificate in self.chain]),
        }

    def restore(self, snapshot: dict):
        """Restore snapshot."""
        self.certificate = Certificate.from_string(snapshot["certificate"])
        self.certificate_signing_request = CertificateSigningRequest.from_string(
            snapshot["certificate_signing_request"]
        )
        self.ca = Certificate.from_string(snapshot["ca"])
        chain_strs = json.loads(snapshot["chain"])
        self.chain = [Certificate.from_string(chain_str) for chain_str in chain_strs]

    def chain_as_pem(self) -> str:
        """Return full certificate chain as a PEM string."""
        return "\n\n".join([str(cert) for cert in self.chain])


def _get_closest_future_time(
    expiry_notification_time: datetime, expiry_time: datetime
) -> datetime:
    """Return expiry_notification_time if not in the past, otherwise return expiry_time.

    Args:
        expiry_notification_time (datetime): Notification time of impending expiration
        expiry_time (datetime): Expiration time

    Returns:
        datetime: expiry_notification_time if not in the past, expiry_time otherwise
    """
    return (
        expiry_notification_time
        if datetime.now(timezone.utc) < expiry_notification_time
        else expiry_time
    )


def calculate_expiry_notification_time(
    validity_start_time: datetime,
    expiry_time: datetime,
    provider_recommended_notification_time: Optional[int],
) -> datetime:
    """Calculate a reasonable time to notify the user about the certificate expiry.

    It takes into account the time recommended by the provider.
    Time recommended by the provider is preferred,
    then dynamically calculated time.

    Args:
        validity_start_time: Certificate validity time
        expiry_time: Certificate expiry time
        provider_recommended_notification_time:
            Time in hours prior to expiry to notify the user.
            Recommended by the provider.

    Returns:
        datetime: Time to notify the user about the certificate expiry.
    """
    if provider_recommended_notification_time is not None:
        provider_recommended_notification_time = abs(provider_recommended_notification_time)
        provider_recommendation_time_delta = expiry_time - timedelta(
            hours=provider_recommended_notification_time
        )
        if validity_start_time < provider_recommendation_time_delta:
            return provider_recommendation_time_delta
    calculated_hours = (expiry_time - validity_start_time).total_seconds() / (3600 * 3)
    return expiry_time - timedelta(hours=calculated_hours)


def _generate_private_key(
    key_size: int = 2048,
    public_exponent: int = 65537,
) -> PrivateKey:
    """Generate a private key with the RSA algorithm.

    Args:
        key_size (int): Key size in bytes
        public_exponent: Public exponent.

    Returns:
        str: Private Key
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
    )
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return PrivateKey.from_string(key_bytes.decode())


class CertificatesRequirerCharmEvents(CharmEvents):
    """List of events that the TLS Certificates requirer charm can leverage."""

    certificate_available = EventSource(CertificateAvailableEvent)


class TLSCertificatesRequiresV4(Object):
    """A class to manage the TLS certificates interface for a unit or app."""

    on = CertificatesRequirerCharmEvents()  # type: ignore[reportAssignmentType]

    def __init__(
        self,
        charm: CharmBase,
        relationship_name: str,
        certificate_requests: List[CertificateRequest],
        mode: Mode = Mode.UNIT,
        refresh_events: List[BoundEvent] = [],
    ):
        """Create a new instance of the TLSCertificatesRequiresV4 class.

        Args:
            charm (CharmBase): The charm instance to relate to.
            relationship_name (str): The name of the relation that provides the certificates.
            certificate_requests (List[CertificateRequest]): A list of certificate requests.
            mode (Mode): Whether to use unit or app certificates mode. Default is Mode.UNIT.
            refresh_events (List[BoundEvent]): A list of events to trigger a refresh of
              the certificates.
        """
        super().__init__(charm, relationship_name)
        if not JujuVersion.from_environ().has_secrets:
            logger.warning("This version of the TLS library requires Juju secrets (Juju >= 3.0)")
        if not self._mode_is_valid(mode):
            raise TLSCertificatesError("Invalid mode. Must be Mode.UNIT or Mode.APP")
        for certificate_request in certificate_requests:
            if not certificate_request.is_valid():
                raise TLSCertificatesError("Invalid certificate request")
        self.charm = charm
        self.relationship_name = relationship_name
        self.certificate_requests = certificate_requests
        self.mode = mode
        self.framework.observe(charm.on[relationship_name].relation_created, self._configure)
        self.framework.observe(charm.on[relationship_name].relation_changed, self._configure)
        self.framework.observe(charm.on.secret_expired, self._on_secret_expired)
        for event in refresh_events:
            self.framework.observe(event, self._configure)

    def _configure(self, _: EventBase):
        """Handle TLS Certificates Relation Data.

        This method is called during any TLS relation event.
        It will generate a private key if it doesn't exist yet.
        It will send certificate requests if they haven't been sent yet.
        It will find available certificates and emit events.
        """
        if not self._tls_relation_created():
            logger.debug("TLS relation not created yet.")
            return
        self._generate_private_key()
        self._send_certificate_requests()
        self._find_available_certificates()
        self._cleanup_certificate_requests()

    def _mode_is_valid(self, mode) -> bool:
        return mode in [Mode.UNIT, Mode.APP]

    def _on_secret_expired(self, event: SecretExpiredEvent) -> None:
        """Handle Secret Expired Event.

        Renews certificate requests and removes the expired secret.
        """
        if not event.secret.label or not event.secret.label.startswith(f"{LIBID}-certificate"):
            return
        try:
            csr_str = event.secret.get_content(refresh=True)["csr"]
        except ModelError:
            logger.error("Failed to get CSR from secret - Skipping renewal")
            return
        csr = CertificateSigningRequest.from_string(csr_str)
        self._renew_certificate_request(csr)
        event.secret.remove_all_revisions()

    def _renew_certificate_request(self, csr: CertificateSigningRequest):
        """Remove existing CSR from relation data and create a new one."""
        self._remove_requirer_csr_from_relation_data(csr)
        self._send_certificate_requests()
        logger.info("Renewed certificate request")

    def _remove_requirer_csr_from_relation_data(self, csr: CertificateSigningRequest) -> None:
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return
        if not self.get_csrs_from_requirer_relation_data():
            logger.info("No CSRs in relation data - Doing nothing")
            return
        app_or_unit = self._get_app_or_unit()
        try:
            requirer_relation_data = _RequirerData.load(relation.data[app_or_unit])
        except DataValidationError:
            logger.warning("Invalid relation data - Skipping removal of CSR")
            return
        new_relation_data = copy.deepcopy(requirer_relation_data.certificate_signing_requests)
        for requirer_csr in new_relation_data:
            if requirer_csr.certificate_signing_request.strip() == str(csr).strip():
                new_relation_data.remove(requirer_csr)
        try:
            _RequirerData(certificate_signing_requests=new_relation_data).dump(
                relation.data[app_or_unit]
            )
            logger.info("Removed CSR from relation data")
        except ModelError:
            logger.warning("Failed to update relation data")

    def _get_app_or_unit(self) -> Union[Application, Unit]:
        """Return the unit or app object based on the mode."""
        if self.mode == Mode.UNIT:
            return self.model.unit
        elif self.mode == Mode.APP:
            return self.model.app
        raise TLSCertificatesError("Invalid mode")

    @property
    def private_key(self) -> PrivateKey | None:
        """Return the private key."""
        if not self._private_key_generated():
            return None
        secret = self.charm.model.get_secret(label=self._get_private_key_secret_label())
        private_key = secret.get_content(refresh=True)["private-key"]
        return PrivateKey.from_string(private_key)

    def _generate_private_key(self) -> None:
        if self._private_key_generated():
            return
        private_key = _generate_private_key()
        self.charm.unit.add_secret(
            content={"private-key": str(private_key)},
            label=self._get_private_key_secret_label(),
        )
        logger.info("Private key generated")

    def regenerate_private_key(self) -> None:
        """Regenerate the private key.

        Generate a new private key, remove old certificate requests and send new ones.
        """
        if not self._private_key_generated():
            logger.warning("No private key to regenerate")
            return
        self._regenerate_private_key()
        self._cleanup_certificate_requests()
        self._send_certificate_requests()

    def _regenerate_private_key(self) -> None:
        secret = self.charm.model.get_secret(label=self._get_private_key_secret_label())
        secret.set_content({"private-key": str(_generate_private_key())})

    def _private_key_generated(self) -> bool:
        try:
            self.charm.model.get_secret(label=self._get_private_key_secret_label())
        except (SecretNotFoundError, KeyError):
            return False
        return True

    def _csr_matches_certificate_request(self, csr: CertificateSigningRequest) -> bool:
        for certificate_request in self.certificate_requests:
            if csr.to_certificate_request() == certificate_request:
                return True
        return False

    def _certificate_requested(self, certificate_request: CertificateRequest) -> bool:
        if not self.private_key:
            return False
        csr = self._certificate_requested_for_attributes(certificate_request)
        if not csr:
            return False
        if not csr.matches_private_key(key=self.private_key):
            return False
        return True

    def _certificate_requested_for_attributes(
        self, certificate_request: CertificateRequest
    ) -> Optional[CertificateSigningRequest]:
        for requirer_csr in self.get_csrs_from_requirer_relation_data():
            if requirer_csr.to_certificate_request() == certificate_request:
                return requirer_csr
        return None

    def get_csrs_from_requirer_relation_data(self) -> List[CertificateSigningRequest]:
        """Return list of requirer's CSRs from relation data."""
        if self.mode == Mode.APP and not self.model.unit.is_leader():
            logger.debug("Not a leader unit - Skipping")
            return []
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return []
        app_or_unit = self._get_app_or_unit()
        try:
            requirer_relation_data = _RequirerData.load(relation.data[app_or_unit])
        except DataValidationError:
            logger.warning("Invalid relation data")
            return []
        return [
            CertificateSigningRequest.from_string(csr.certificate_signing_request)
            for csr in requirer_relation_data.certificate_signing_requests
        ]

    def get_provider_certificates(self) -> List[ProviderCertificate]:
        """Return list of certificates from the provider's relation data."""
        return self._load_provider_certificates()

    def _load_provider_certificates(self) -> List[ProviderCertificate]:
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return []
        if not relation.app:
            logger.debug("No remote app in relation: %s", self.relationship_name)
            return []
        try:
            provider_relation_data = _ProviderApplicationData.load(relation.data[relation.app])
        except DataValidationError:
            logger.warning("Invalid relation data")
            return []
        return [
            certificate.to_provider_certificate(relation_id=relation.id)
            for certificate in provider_relation_data.certificates
        ]

    def _request_certificate(self, csr: CertificateSigningRequest, is_ca: bool) -> None:
        """Add CSR to relation data."""
        if self.mode == Mode.APP and not self.model.unit.is_leader():
            logger.debug("Not a leader unit - Skipping")
            return
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            logger.debug("No relation: %s", self.relationship_name)
            return
        new_csr = _CertificateSigningRequest(
            certificate_signing_request=str(csr).strip(), ca=is_ca
        )
        app_or_unit = self._get_app_or_unit()
        try:
            requirer_relation_data = _RequirerData.load(relation.data[app_or_unit])
        except DataValidationError:
            requirer_relation_data = _RequirerData(
                certificate_signing_requests=[],
            )
        new_relation_data = copy.deepcopy(requirer_relation_data.certificate_signing_requests)
        new_relation_data.append(new_csr)
        try:
            _RequirerData(certificate_signing_requests=new_relation_data).dump(
                relation.data[app_or_unit]
            )
            logger.info("Certificate signing request added to relation data.")
        except ModelError:
            logger.warning("Failed to update relation data")

    def _send_certificate_requests(self):
        if not self.private_key:
            logger.debug("Private key not generated yet.")
            return
        for certificate_request in self.certificate_requests:
            if not self._certificate_requested(certificate_request):
                csr = certificate_request.generate_csr(
                    private_key=self.private_key,
                )
                if not csr:
                    logger.warning("Failed to generate CSR")
                    continue
                self._request_certificate(csr=csr, is_ca=certificate_request.is_ca)

    def get_assigned_certificate(
        self, certificate_request: CertificateRequest
    ) -> Tuple[ProviderCertificate | None, PrivateKey | None]:
        """Get the certificate that was assigned to the given certificate request."""
        for requirer_csr in self.get_csrs_from_requirer_relation_data():
            if certificate_request == requirer_csr.to_certificate_request():
                return self._find_certificate_in_relation_data(requirer_csr), self.private_key
        return None, None

    def get_assigned_certificates(self) -> Tuple[List[ProviderCertificate], PrivateKey | None]:
        """Get a list of certificates that were assigned to this or app."""
        assigned_certificates = []
        for requirer_csr in self.get_csrs_from_requirer_relation_data():
            if cert := self._find_certificate_in_relation_data(requirer_csr):
                assigned_certificates.append(cert)
        return assigned_certificates, self.private_key

    def _find_certificate_in_relation_data(
        self, csr: CertificateSigningRequest
    ) -> Optional[ProviderCertificate]:
        """Return the certificate that match the given CSR."""
        for provider_certificate in self.get_provider_certificates():
            if provider_certificate.certificate_signing_request == csr:
                return provider_certificate
        return None

    def _find_available_certificates(self):
        """Find available certificates and emit events.

        This method will find certificates that are available for the requirer's CSRs.
        If a certificate is found, it will be set as a secret and an event will be emitted.
        If a certificate is revoked, the secret will be removed and an event will be emitted.
        """
        requirer_csrs = self.get_csrs_from_requirer_relation_data()
        provider_certificates = self.get_provider_certificates()
        for provider_certificate in provider_certificates:
            if provider_certificate.certificate_signing_request in requirer_csrs:
                secret_label = self._get_csr_secret_label(
                    provider_certificate.certificate_signing_request
                )
                if provider_certificate.revoked:
                    with suppress(SecretNotFoundError):
                        logger.debug(
                            "Removing secret with label %s",
                            secret_label,
                        )
                        secret = self.model.get_secret(label=secret_label)
                        secret.remove_all_revisions()
                else:
                    if not self._csr_matches_certificate_request(
                        provider_certificate.certificate_signing_request
                    ):
                        logger.debug("Certificate requested for different attributes - Skipping")
                        continue
                    try:
                        logger.debug("Setting secret with label %s", secret_label)
                        secret = self.model.get_secret(label=secret_label)
                        secret.set_content(
                            content={
                                "certificate": str(provider_certificate.certificate),
                                "csr": str(provider_certificate.certificate_signing_request),
                            }
                        )
                        secret.set_info(
                            expire=self._get_next_secret_expiry_time(provider_certificate),
                        )
                    except SecretNotFoundError:
                        logger.debug("Creating new secret with label %s", secret_label)
                        secret = self.charm.unit.add_secret(
                            content={
                                "certificate": str(provider_certificate.certificate),
                                "csr": str(provider_certificate.certificate_signing_request),
                            },
                            label=secret_label,
                            expire=self._get_next_secret_expiry_time(provider_certificate),
                        )
                    self.on.certificate_available.emit(
                        certificate_signing_request=provider_certificate.certificate_signing_request,
                        certificate=provider_certificate.certificate,
                        ca=provider_certificate.ca,
                        chain=provider_certificate.chain,
                    )

    def _cleanup_certificate_requests(self):
        """Clean up certificate requests.

        Remove any certificate requests that falls into one of the following categories:
        - The CSR attributes do not match any of the certificate requests defined in
        the charm's certificate_requests attribute.
        - The CSR public key does not match the private key.
        """
        for requirer_csr in self.get_csrs_from_requirer_relation_data():
            if not self._csr_matches_certificate_request(requirer_csr):
                self._remove_requirer_csr_from_relation_data(requirer_csr)
                logger.info(
                    "Removed CSR from relation data because \
                        it did not match any certificate request"
                )
            elif self.private_key and not requirer_csr.matches_private_key(self.private_key):
                self._remove_requirer_csr_from_relation_data(requirer_csr)
                logger.info(
                    "Removed CSR from relation data because \
                        it did not match the private key"
                )

    def _get_next_secret_expiry_time(
        self, provider_certificate: ProviderCertificate
    ) -> Optional[datetime]:
        """Return the expiry time or expiry notification time.

        Extracts the expiry time from the provided certificate, calculates the
        expiry notification time and return the closest of the two, that is in
        the future.

        Args:
            provider_certificate: ProviderCertificate object

        Returns:
            Optional[datetime]: None if the certificate expiry time cannot be read,
                                next expiry time otherwise.
        """
        if not provider_certificate.certificate.expiry_time:
            logger.warning("Certificate has no expiry time")
            return None
        if not provider_certificate.certificate.validity_start_time:
            logger.warning("Certificate has no validity start time")
            return None
        expiry_notification_time = calculate_expiry_notification_time(
            validity_start_time=provider_certificate.certificate.validity_start_time,
            expiry_time=provider_certificate.certificate.expiry_time,
            provider_recommended_notification_time=provider_certificate.recommended_expiry_notification_time,
        )
        if not expiry_notification_time:
            logger.warning("Could not calculate expiry notification time")
            return None
        return _get_closest_future_time(
            expiry_notification_time,
            provider_certificate.certificate.expiry_time,
        )

    def _tls_relation_created(self) -> bool:
        relation = self.model.get_relation(self.relationship_name)
        if not relation:
            return False
        return True

    def _get_private_key_secret_label(self) -> str:
        if self.mode == Mode.UNIT:
            return f"{LIBID}-private-key-{self._get_unit_number()}"
        elif self.mode == Mode.APP:
            return f"{LIBID}-private-key"
        else:
            raise TLSCertificatesError("Invalid mode. Must be Mode.UNIT or Mode.APP.")

    def _get_csr_secret_label(self, csr: CertificateSigningRequest) -> str:
        csr_in_sha256_hex = csr.get_sha256_hex()
        if self.mode == Mode.UNIT:
            return f"{LIBID}-certificate-{self._get_unit_number()}-{csr_in_sha256_hex}"
        elif self.mode == Mode.APP:
            return f"{LIBID}-certificate-{csr_in_sha256_hex}"
        else:
            raise TLSCertificatesError("Invalid mode. Must be Mode.UNIT or Mode.APP.")

    def _get_unit_number(self) -> str:
        return self.model.unit.name.split("/")[1]


class TLSCertificatesProvidesV4(Object):
    """TLS certificates provider class to be instantiated by TLS certificates providers."""

    def __init__(self, charm: CharmBase, relationship_name: str):
        super().__init__(charm, relationship_name)
        self.framework.observe(charm.on[relationship_name].relation_joined, self._configure)
        self.framework.observe(charm.on[relationship_name].relation_changed, self._configure)
        self.framework.observe(charm.on.update_status, self._configure)
        self.charm = charm
        self.relationship_name = relationship_name

    def _configure(self, _: EventBase) -> None:
        """Handle update status and tls relation changed events.

        This is a common hook triggered on a regular basis.

        Revoke certificates for which no csr exists
        """
        if not self.model.unit.is_leader():
            return
        self._remove_certificates_for_which_no_csr_exists()

    def _remove_certificates_for_which_no_csr_exists(self) -> None:
        provider_certificates = self.get_provider_certificates()
        requirer_csrs = [
            request.certificate_signing_request for request in self.get_certificate_requests()
        ]
        for provider_certificate in provider_certificates:
            if provider_certificate.certificate_signing_request not in requirer_csrs:
                tls_relation = self._get_tls_relations(
                    relation_id=provider_certificate.relation_id
                )
                self._remove_provider_certificate(
                    certificate=provider_certificate.certificate,
                    relation=tls_relation[0],
                )

    def _get_tls_relations(self, relation_id: Optional[int] = None) -> List[Relation]:
        return (
            [
                relation
                for relation in self.model.relations[self.relationship_name]
                if relation.id == relation_id
            ]
            if relation_id is not None
            else self.model.relations.get(self.relationship_name, [])
        )

    def get_certificate_requests(self, relation_id: Optional[int] = None) -> List[RequirerCSR]:
        """Load certificate requests from the relation data."""
        relations = self._get_tls_relations(relation_id)
        requirer_csrs: List[RequirerCSR] = []
        for relation in relations:
            for unit in relation.units:
                requirer_csrs.extend(self._load_requirer_databag(relation, unit))
            requirer_csrs.extend(self._load_requirer_databag(relation, relation.app))
        return requirer_csrs

    def _load_requirer_databag(
        self, relation: Relation, unit_or_app: Union[Application, Unit]
    ) -> List[RequirerCSR]:
        try:
            requirer_relation_data = _RequirerData.load(relation.data[unit_or_app])
        except DataValidationError:
            logger.debug("Invalid requirer relation data for %s", unit_or_app.name)
            return []
        return [
            RequirerCSR(
                relation_id=relation.id,
                certificate_signing_request=CertificateSigningRequest.from_string(
                    csr.certificate_signing_request
                ),
            )
            for csr in requirer_relation_data.certificate_signing_requests
        ]

    def _add_provider_certificate(
        self,
        relation: Relation,
        provider_certificate: ProviderCertificate,
    ) -> None:
        new_certificate = _Certificate(
            certificate=str(provider_certificate.certificate),
            certificate_signing_request=str(provider_certificate.certificate_signing_request),
            ca=str(provider_certificate.ca),
            chain=[str(certificate) for certificate in provider_certificate.chain],
            recommended_expiry_notification_time=provider_certificate.recommended_expiry_notification_time,
        )
        provider_certificates = self._load_provider_certificates(relation)
        if new_certificate in provider_certificates:
            logger.info("Certificate already in relation data - Doing nothing")
            return
        provider_certificates.append(new_certificate)
        self._dump_provider_certificates(relation=relation, certificates=provider_certificates)

    def _load_provider_certificates(self, relation: Relation) -> List[_Certificate]:
        try:
            provider_relation_data = _ProviderApplicationData.load(relation.data[self.charm.app])
        except DataValidationError:
            logger.debug("Invalid provider relation data")
            return []
        return copy.deepcopy(provider_relation_data.certificates)

    def _dump_provider_certificates(self, relation: Relation, certificates: List[_Certificate]):
        try:
            _ProviderApplicationData(certificates=certificates).dump(relation.data[self.model.app])
            logger.info("Certificate relation data updated")
        except ModelError:
            logger.warning("Failed to update relation data")

    def _remove_provider_certificate(
        self,
        relation: Relation,
        certificate: Optional[Certificate] = None,
        certificate_signing_request: Optional[CertificateSigningRequest] = None,
    ) -> None:
        """Remove certificate based on certificate or certificate signing request."""
        provider_certificates = self._load_provider_certificates(relation)
        for provider_certificate in provider_certificates:
            if certificate and provider_certificate.certificate == str(certificate):
                provider_certificates.remove(provider_certificate)
            if (
                certificate_signing_request
                and provider_certificate.certificate_signing_request
                == str(certificate_signing_request)
            ):
                provider_certificates.remove(provider_certificate)
        self._dump_provider_certificates(relation=relation, certificates=provider_certificates)

    def revoke_all_certificates(self) -> None:
        """Revoke all certificates of this provider.

        This method is meant to be used when the Root CA has changed.
        """
        if not self.model.unit.is_leader():
            logger.warning("Unit is not a leader - will not set relation data")
            return
        relations = self._get_tls_relations()
        for relation in relations:
            provider_certificates = self._load_provider_certificates(relation)
            for certificate in provider_certificates:
                certificate.revoked = True
            self._dump_provider_certificates(relation=relation, certificates=provider_certificates)

    def set_relation_certificate(
        self,
        provider_certificate: ProviderCertificate,
    ) -> None:
        """Add certificates to relation data.

        Args:
            provider_certificate (ProviderCertificate): ProviderCertificate object

        Returns:
            None
        """
        if not self.model.unit.is_leader():
            logger.warning("Unit is not a leader - will not set relation data")
            return
        certificates_relation = self.model.get_relation(
            relation_name=self.relationship_name, relation_id=provider_certificate.relation_id
        )
        if not certificates_relation:
            raise TLSCertificatesError(f"Relation {self.relationship_name} does not exist")
        self._remove_provider_certificate(
            relation=certificates_relation,
            certificate_signing_request=provider_certificate.certificate_signing_request,
        )
        self._add_provider_certificate(
            relation=certificates_relation,
            provider_certificate=provider_certificate,
        )

    def get_issued_certificates(
        self, relation_id: Optional[int] = None
    ) -> List[ProviderCertificate]:
        """Return a List of issued (non revoked) certificates.

        Returns:
            List: List of ProviderCertificate objects
        """
        if not self.model.unit.is_leader():
            logger.warning("Unit is not a leader - will not read relation data")
            return []
        provider_certificates = self.get_provider_certificates(relation_id=relation_id)
        return [certificate for certificate in provider_certificates if not certificate.revoked]

    def get_provider_certificates(
        self, relation_id: Optional[int] = None
    ) -> List[ProviderCertificate]:
        """Return a List of issued certificates."""
        certificates: List[ProviderCertificate] = []
        relations = self._get_tls_relations(relation_id)
        for relation in relations:
            if not relation.app:
                logger.warning("Relation %s does not have an application", relation.id)
                continue
            for certificate in self._load_provider_certificates(relation):
                certificates.append(certificate.to_provider_certificate(relation_id=relation.id))
        return certificates

    def get_outstanding_certificate_requests(
        self, relation_id: Optional[int] = None
    ) -> List[RequirerCSR]:
        """Return CSR's for which no certificate has been issued.

        Args:
            relation_id (int): Relation id

        Returns:
            list: List of RequirerCSR objects.
        """
        requirer_csrs = self.get_certificate_requests(relation_id=relation_id)
        outstanding_csrs: List[RequirerCSR] = []
        for relation_csr in requirer_csrs:
            if not self._certificate_issued_for_csr(
                csr=relation_csr.certificate_signing_request,
                relation_id=relation_id,
            ):
                outstanding_csrs.append(relation_csr)
        return outstanding_csrs

    def _certificate_issued_for_csr(
        self, csr: CertificateSigningRequest, relation_id: Optional[int]
    ) -> bool:
        """Check whether a certificate has been issued for a given CSR."""
        issued_certificates_per_csr = self.get_issued_certificates(relation_id=relation_id)
        for issued_certificate in issued_certificates_per_csr:
            if issued_certificate.certificate_signing_request == csr:
                return csr.matches_certificate(issued_certificate.certificate)
        return False
