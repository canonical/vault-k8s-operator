from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from charms.vault_k8s.v0.juju_facade import SecretRemovedError
from charms.vault_k8s.v0.vault_autounseal import AutounsealDetails
from charms.vault_k8s.v0.vault_client import AuthMethod, VaultClient
from charms.vault_k8s.v0.vault_client import Certificate as VaultClientCertificate
from charms.vault_k8s.v0.vault_managers import (
    AUTOUNSEAL_POLICY,
    AutounsealProviderManager,
    AutounsealRequirerManager,
    CertificateRequestAttributes,
    PKIManager,
    PrivateKey,
    ProviderCertificate,
    SecretsBackend,
    TLSCertificatesProvidesV4,
    TLSCertificatesRequiresV4,
)

from charm import AUTOUNSEAL_MOUNT_PATH, VaultCharm
from tests.unit.certificates import (
    generate_example_provider_certificate,
    generate_example_requirer_csr,
    sign_certificate,
)

SECONDS_IN_HOUR = 3600


def is_error_logged(caplog: pytest.LogCaptureFixture, error_message: str):
    error_records = [record for record in caplog.records if record.levelname == "ERROR"]
    return any(error_message in record.message for record in error_records)


class TestVaultAutounsealRequirerManager:
    @pytest.mark.parametrize(
        "token, token_valid, expected_token",
        [
            ("initial token", True, "initial token"),  # Token is set and valid
            ("initial token", False, "new token"),  # Token is set but invalid
            (None, False, "new token"),  # Token is not set
        ],
    )
    @patch("charms.vault_k8s.v0.vault_managers.VaultClient")
    @patch("charms.vault_k8s.v0.vault_managers.JujuFacade")
    def test_when_get_vault_configuration_details_called_then_details_are_retrieved_correctly(
        self,
        juju_facade_mock: MagicMock,
        vault_client_mock: MagicMock,
        token: str | None,
        token_valid: bool,
        expected_token: str,
    ):
        juju_facade_instance = juju_facade_mock.return_value
        charm = MagicMock()
        vault_client_instance = vault_client_mock.return_value
        vault_client_instance.token = token

        def authenticate(auth_method: AuthMethod) -> bool:
            if token and vault_client_instance.authenticate.call_count == 1:
                return token_valid
            vault_client_instance.token = "new token"
            return True

        vault_client_instance.authenticate.side_effect = authenticate
        requires = MagicMock()
        autounseal_details = AutounsealDetails(
            "my_address",
            "my_mount_path",
            "my_key_name",
            "my_role_id",
            "my_secret_id",
            "my_ca_certificate",
        )
        ca_cert_path = "/my/test/path"
        if token:
            juju_facade_instance.get_secret_content_values.return_value = (token,)
        if not token:
            juju_facade_instance.get_secret_content_values.side_effect = SecretRemovedError()

        autounseal = AutounsealRequirerManager(charm, requires)
        returned_token = autounseal.get_provider_vault_token(autounseal_details, ca_cert_path)
        assert returned_token == expected_token


class TestAutounsealProviderManager:
    def test_when_create_credentials_then_vault_client_called_and_key_name_and_credentials_are_returned(
        self,
    ):
        charm = MagicMock()
        provides = MagicMock()
        relation_id = 1
        relation = MagicMock()
        relation.id = relation_id
        vault_client = MagicMock(spec=VaultClient)
        expected_key_name = "1"
        expected_approle_name = "charm-autounseal-1"
        expected_policy_name = "charm-autounseal-1"
        vault_client.create_or_update_approle.return_value = "role_id"
        vault_client.generate_role_secret_id.return_value = "secret_id"

        autounseal = AutounsealProviderManager(
            charm, vault_client, provides, "ca_cert", AUTOUNSEAL_MOUNT_PATH
        )

        key_name, role_id, secret_id = autounseal.create_credentials(
            relation, "https://1.2.3.4:8200"
        )

        vault_client.create_or_update_policy.assert_called_once_with(
            expected_policy_name,
            AUTOUNSEAL_POLICY.format(mount=AUTOUNSEAL_MOUNT_PATH, key_name=expected_key_name),
        )
        vault_client.create_or_update_approle.assert_called_once_with(
            expected_approle_name, policies=[expected_policy_name], token_period="60s"
        )
        vault_client.generate_role_secret_id.assert_called_once_with(expected_approle_name)
        assert key_name == str(relation_id)
        assert role_id == "role_id"
        assert secret_id == "secret_id"
        provides.set_autounseal_data.assert_called_once()

    @patch("charms.vault_k8s.v0.vault_managers.JujuFacade")
    def test_given_orphaned_credentials_when_clean_up_credentials_then_credentials_removed_and_keys_marked_deletion_allowed(
        self, juju_facade_mock: MagicMock
    ):
        juju_facade_instance = juju_facade_mock.return_value
        charm = MagicMock()
        provides = MagicMock()
        vault_client_mock = MagicMock()
        vault_client_mock.list.return_value = ["charm-autounseal-123", "charm-autounseal-321"]
        vault_client_mock.read.return_value = {"deletion_allowed": False}
        test_relation = MagicMock()
        test_relation.id = 123
        provides.get_outstanding_requests.return_value = [test_relation]
        juju_facade_instance.get_active_relations.return_value = [test_relation]
        autounseal = AutounsealProviderManager(
            charm, vault_client_mock, provides, "ca_cert", AUTOUNSEAL_MOUNT_PATH
        )

        autounseal.clean_up_credentials()

        vault_client_mock.delete_role.assert_called_once_with("charm-autounseal-321")
        vault_client_mock.delete_policy.assert_called_once_with("charm-autounseal-321")
        vault_client_mock.write.assert_called_with(
            "charm-autounseal/keys/charm-autounseal-321/config", {"deletion_allowed": True}
        )


class TestPKIManager:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.charm = MagicMock(spec=VaultCharm)
        self.vault = MagicMock(spec=VaultClient)
        self.certificate_request_attributes = CertificateRequestAttributes(
            common_name="common_name",
            is_ca=True,
        )
        self.mount_point = "mount_point"
        self.role_name = "role_name"
        self.vault_pki = MagicMock(spec=TLSCertificatesProvidesV4)
        self.tls_certificates_pki = MagicMock(spec=TLSCertificatesRequiresV4)

        self.pki_manager = PKIManager(
            self.charm,
            self.vault,
            self.certificate_request_attributes,
            self.mount_point,
            self.role_name,
            self.vault_pki,
            self.tls_certificates_pki,
        )

    @pytest.fixture
    def one_issuer(self) -> str:
        self.vault.list_pki_issuers.return_value = ["issuer"]
        return "issuer"

    @pytest.fixture
    def issuer_is_default(self, one_issuer: str):
        self.vault.read.return_value = {
            "data": {"default_follows_latest_issuer": True, "default": one_issuer}
        }

    @pytest.fixture
    def issuer_is_not_default(self, one_issuer: str):
        self.vault.read.return_value = {
            "default_follows_latest_issuer": False,
            "default": one_issuer,
        }

    @pytest.fixture
    def assigned_certificate_and_key(self) -> tuple[ProviderCertificate, PrivateKey]:
        provider_certificate, private_key = generate_example_provider_certificate(
            self.certificate_request_attributes.common_name, 1, validity=timedelta(hours=24)
        )
        self.tls_certificates_pki.get_assigned_certificate.return_value = (
            provider_certificate,
            private_key,
        )
        return (provider_certificate, private_key)

    @pytest.fixture
    def no_issuer(self):
        self.vault.list_pki_issuers.return_value = []

    def test_given_no_pki_issuers_when_make_latest_pki_issuer_default_then_vault_no_error_is_raised_but_error_is_logged(
        self, caplog: pytest.LogCaptureFixture, no_issuer: None
    ):
        # Ensure no error is raised
        self.pki_manager.make_latest_pki_issuer_default()

        assert is_error_logged(caplog, "Failed to get the first issuer")

    def test_given_existing_pki_issuers_when_make_latest_pki_issuer_default_then_config_written_to_path(
        self, issuer_is_not_default: None
    ):
        self.pki_manager.make_latest_pki_issuer_default()

        self.vault.write.assert_called_with(
            path=f"{self.mount_point}/config/issuers",
            data={
                "default_follows_latest_issuer": True,
                "default": "issuer",
            },
        )

    def test_given_issuers_config_already_updated_when_make_latest_pki_issuer_default_then_config_not_written(
        self, issuer_is_default: None
    ):
        self.pki_manager.make_latest_pki_issuer_default()
        self.vault.write.assert_not_called()

    def test_given_intermediate_certificate_expires_before_issued_certificates_when_configure_then_certificate_is_renewed(
        self, assigned_certificate_and_key: tuple[ProviderCertificate, PrivateKey]
    ):
        provider_certificate, _ = assigned_certificate_and_key

        self.vault.get_intermediate_ca.return_value = str(provider_certificate.certificate)

        # This is how long certificates issued by PKI will be valid for. We
        # make it 25 hours, because the intermediate (provider) certificate is valid for 24.
        self.vault.get_role_max_ttl.return_value = 25 * SECONDS_IN_HOUR

        self.pki_manager.configure()

        self.vault.enable_secrets_engine.assert_called_once_with(
            SecretsBackend.PKI, self.mount_point
        )
        self.tls_certificates_pki.renew_certificate.assert_called_once_with(provider_certificate)

    def test_given_new_certificate_issued_when_configure_then_certificates_replaced(
        self, assigned_certificate_and_key: tuple[ProviderCertificate, PrivateKey]
    ):
        # Return a different certificate from Vault, to emulate the situation
        # where a new certificate has been issued.
        vault_certificate, _ = generate_example_provider_certificate(
            self.certificate_request_attributes.common_name, 1, validity=timedelta(hours=24)
        )
        self.vault.get_intermediate_ca.return_value = str(vault_certificate.certificate)

        self.pki_manager.configure()

        self.vault.enable_secrets_engine.assert_called_once_with(
            SecretsBackend.PKI, self.mount_point
        )

        self.vault_pki.revoke_all_certificates.assert_called_once()

        # Certificates are issued for half the time the provider certificate is valid for
        self.vault.create_or_update_pki_charm_role.assert_called_once_with(
            allowed_domains=self.certificate_request_attributes.common_name,
            mount=self.mount_point,
            role=self.role_name,
            max_ttl=f"{12 * SECONDS_IN_HOUR}s",
        )

    def test_given_outstanding_requests_when_sync_then_certificates_issued(
        self, assigned_certificate_and_key: tuple[ProviderCertificate, PrivateKey]
    ):
        provider_certificate, private_key = assigned_certificate_and_key

        self.vault.is_pki_role_created.return_value = True
        csr = generate_example_requirer_csr(self.certificate_request_attributes.common_name, 1)
        self.vault_pki.get_outstanding_certificate_requests.return_value = [csr]

        signed_certificate = sign_certificate(
            provider_certificate.certificate, private_key, csr.certificate_signing_request
        )
        cert = VaultClientCertificate(
            certificate=str(signed_certificate),
            ca=str(provider_certificate.certificate),
            chain=[str(cert) for cert in provider_certificate.chain],
        )

        self.vault.sign_pki_certificate_signing_request.return_value = cert
        self.pki_manager.sync()

        # Certificates are issued for half the time the provider certificate is valid for
        self.vault.sign_pki_certificate_signing_request.assert_called_once_with(
            mount=self.mount_point,
            role=self.role_name,
            csr=str(csr.certificate_signing_request),
            common_name=self.certificate_request_attributes.common_name,
            ttl=f"{12 * SECONDS_IN_HOUR}s",
        )

        self.vault_pki.set_relation_certificate.assert_called_once_with(
            provider_certificate=ProviderCertificate(
                relation_id=1,
                certificate=signed_certificate,
                certificate_signing_request=csr.certificate_signing_request,
                ca=provider_certificate.certificate,
                chain=provider_certificate.chain,
            )
        )
