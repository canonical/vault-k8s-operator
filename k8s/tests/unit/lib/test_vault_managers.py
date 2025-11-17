from datetime import timedelta
from unittest.mock import MagicMock, call, patch

import pytest
from charms.data_platform_libs.v0.s3 import S3Requirer
from vault.juju_facade import NoSuchSecretError, SecretRemovedError
from vault.vault_autounseal import AutounsealDetails
from vault.vault_client import AuthMethod, SecretsBackend, VaultClient, VaultClientError
from vault.vault_client import Certificate as VaultClientCertificate
from vault.vault_managers import (
    AUTOUNSEAL_POLICY,
    ACMEManager,
    AutounsealProviderManager,
    AutounsealRequirerManager,
    BackupManager,
    CertificateRequestAttributes,
    KVManager,
    ManagerError,
    PKIManager,
    PrivateKey,
    ProviderCertificate,
    RaftManager,
    TLSCertificatesProvidesV4,
    TLSCertificatesRequiresV4,
    VaultKvProvides,
)
from vault.vault_s3 import S3Error

from charm import AUTOUNSEAL_MOUNT_PATH, VaultCharm
from container import Container
from tests.unit.certificates import (
    generate_example_provider_certificate,
    generate_example_requirer_csr,
    sign_certificate,
)

SECONDS_IN_HOUR = 3600


def is_error_logged(caplog: pytest.LogCaptureFixture, error_message: str):
    error_records = [record for record in caplog.records if record.levelname == "ERROR"]
    return any(error_message in record.message for record in error_records)


class TestAutounsealRequirerManager:
    @pytest.mark.parametrize(
        "token, token_valid, expected_token",
        [
            ("initial token", True, "initial token"),  # Token is set and valid
            ("initial token", False, "new token"),  # Token is set but invalid
            (None, False, "new token"),  # Token is not set
        ],
    )
    @patch("vault.vault_managers.VaultClient")
    @patch("vault.vault_managers.JujuFacade")
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

    @patch("vault.vault_managers.JujuFacade")
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


class TestKVManager:
    @pytest.fixture(autouse=True)
    @patch("vault.vault_managers.JujuFacade")
    def setup(self, juju_facade_mock: MagicMock):
        self.juju_facade = juju_facade_mock.return_value
        self.charm = MagicMock(spec=VaultCharm)
        self.vault_client = MagicMock(spec=VaultClient)
        self.vault_kv = MagicMock(spec=VaultKvProvides)
        self.ca_cert = "some cert"

        self.manager = KVManager(self.charm, self.vault_client, self.vault_kv, self.ca_cert)

    def test_given_role_does_not_exist_when_generate_kv_for_requirer_then_relation_data_is_set(
        self,
    ):
        # Arrange
        relation = MagicMock()
        app_name = "myapp"
        unit_name = "myapp/0"
        mount_suffix = "mymount"
        egress_subnets = ["1.2.3.4/32"]
        nonce = "123123"
        vault_url = "https://vault:8200"

        self.vault_kv.get_credentials.return_value = {
            "nonce": "my-secret-id",
        }
        secret = MagicMock()
        secret.id = "my-secret-id"
        self.juju_facade.set_app_secret_content.return_value = secret
        self.vault_client.create_or_update_approle.return_value = "my-role-id"
        self.vault_client.generate_role_secret_id.return_value = "my-role-secret-id"

        # Simulate the case where role has not been created yet
        self.juju_facade.get_latest_secret_content.side_effect = NoSuchSecretError()

        # Act
        self.manager.generate_credentials_for_requirer(
            relation, app_name, unit_name, mount_suffix, egress_subnets, nonce, vault_url
        )

        # Assert
        self.vault_client.enable_secrets_engine.assert_called_once_with(
            SecretsBackend.KV_V2, "charm-myapp-mymount"
        )
        policy = """# Allows the KV requirer to create, read, update, delete and list secrets
path "charm-myapp-mymount/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/internal/ui/mounts/charm-myapp-mymount" {
  capabilities = ["read"]
}
"""
        self.vault_client.create_or_update_policy.assert_called_once_with(
            "charm-myapp-mymount-myapp-0",
            policy,
        )
        self.vault_client.generate_role_secret_id.assert_called_once_with(
            "charm-myapp-mymount-myapp-0", egress_subnets
        )

        self.vault_client.create_or_update_approle.assert_called_once_with(
            "charm-myapp-mymount-myapp-0",
            policies=["charm-myapp-mymount-myapp-0"],
            cidrs=egress_subnets,
            token_ttl="1h",
            token_max_ttl="1h",
        )
        self.juju_facade.set_app_secret_content.assert_called_once_with(
            content={"role-id": "my-role-id", "role-secret-id": "my-role-secret-id"},
            label="vault-kv-myapp-0",
        )
        self.vault_kv.set_kv_data.assert_called_once_with(
            relation=relation,
            mount="charm-myapp-mymount",
            ca_certificate=self.ca_cert,
            vault_url=vault_url,
            nonce=nonce,
            credentials_juju_secret_id="my-secret-id",
        )

    def test_given_egress_changed_when_generate_kv_for_requirer_then_relation_data_is_set_and_secret_content_updated(
        self,
    ):
        # Arrange
        relation = MagicMock()
        app_name = "myapp"
        unit_name = "myapp/0"
        mount_suffix = "mymount"
        egress_subnets = ["1.2.3.4/32"]
        nonce = "123123"
        vault_url = "https://vault:8200"

        self.vault_kv.get_credentials.return_value = {
            "nonce": "my-secret-id",
        }
        self.juju_facade.get_latest_secret_content.return_value = {
            "role-secret-id": "my-role-secret-id"
        }
        secret = MagicMock()
        secret.id = "my-secret-id"
        self.juju_facade.set_app_secret_content.return_value = secret
        self.vault_client.create_or_update_approle.return_value = "my-role-id"
        self.vault_client.generate_role_secret_id.return_value = "my-role-secret-id"

        # Return a different cidr from vault to emulate a changed egress
        self.vault_client.read_role_secret.return_value = {"cidr_list": ["4.3.2.1/32"]}

        # Act
        self.manager.generate_credentials_for_requirer(
            relation, app_name, unit_name, mount_suffix, egress_subnets, nonce, vault_url
        )

        # Assert
        self.vault_client.enable_secrets_engine.assert_called_once_with(
            SecretsBackend.KV_V2, "charm-myapp-mymount"
        )
        policy = """# Allows the KV requirer to create, read, update, delete and list secrets
path "charm-myapp-mymount/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/internal/ui/mounts/charm-myapp-mymount" {
  capabilities = ["read"]
}
"""
        self.vault_client.create_or_update_policy.assert_called_once_with(
            "charm-myapp-mymount-myapp-0",
            policy,
        )
        self.vault_client.generate_role_secret_id.assert_called_once_with(
            "charm-myapp-mymount-myapp-0", egress_subnets
        )

        self.vault_client.create_or_update_approle.assert_called_once_with(
            "charm-myapp-mymount-myapp-0",
            policies=["charm-myapp-mymount-myapp-0"],
            cidrs=egress_subnets,
            token_ttl="1h",
            token_max_ttl="1h",
        )
        self.juju_facade.set_app_secret_content.assert_called_once_with(
            content={"role-id": "my-role-id", "role-secret-id": "my-role-secret-id"},
            label="vault-kv-myapp-0",
        )
        self.vault_kv.set_kv_data.assert_called_once_with(
            relation=relation,
            mount="charm-myapp-mymount",
            ca_certificate=self.ca_cert,
            vault_url=vault_url,
            nonce=nonce,
            credentials_juju_secret_id="my-secret-id",
        )

    def test_given_role_exists_and_unchanged_when_generate_kv_for_requirer_then_relation_data_not_set(
        self,
    ):
        # Arrange
        relation = MagicMock()
        app_name = "myapp"
        unit_name = "myapp/0"
        mount_suffix = "mymount"
        egress_subnets = ["1.2.3.4/32"]
        nonce = "123123"
        vault_url = "https://vault:8200"

        self.vault_kv.get_credentials.return_value = {
            "nonce": "my-secret-id",
        }
        self.juju_facade.get_latest_secret_content.return_value = {
            "role-secret-id": "my-role-secret-id"
        }
        secret = MagicMock()
        secret.id = "my-secret-id"
        self.juju_facade.set_app_secret_content.return_value = secret
        self.vault_client.create_or_update_approle.return_value = "my-role-id"
        self.vault_client.generate_role_secret_id.return_value = "my-role-secret-id"

        # Return a different cidr from vault to emulate a changed egress
        self.vault_client.read_role_secret.return_value = {"cidr_list": ["1.2.3.4/32"]}

        # Act
        self.manager.generate_credentials_for_requirer(
            relation, app_name, unit_name, mount_suffix, egress_subnets, nonce, vault_url
        )

        # Assert
        self.vault_client.create_or_update_policy.assert_not_called()
        self.vault_client.create_or_update_approle.assert_not_called()
        self.vault_client.generate_role_secret_id.assert_not_called()
        self.juju_facade.set_app_secret_content.assert_not_called()


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
            chain=[str(provider_certificate.certificate)]
            + [str(cert) for cert in provider_certificate.chain],
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
                chain=[signed_certificate, provider_certificate.certificate]
                + list(provider_certificate.chain),
            )
        )


class TestACMEManager:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.charm = MagicMock(spec=VaultCharm)
        self.vault = MagicMock(spec=VaultClient)
        self.mount_point = "acme-charm"
        self.tls_certificates_acme = MagicMock(spec=TLSCertificatesRequiresV4)
        self.certificate_request_attributes = CertificateRequestAttributes(
            common_name="common_name",
            is_ca=True,
        )
        self.role_name = "acme-charm-role"
        self.vault_address = "https://vault:8200"
        self.acme_manager = ACMEManager(
            self.charm,
            self.vault,
            self.mount_point,
            self.tls_certificates_acme,
            self.certificate_request_attributes,
            self.role_name,
            self.vault_address,
        )

    @pytest.fixture
    def one_issuer(self) -> str:
        self.vault.list_pki_issuers.return_value = ["issuer"]
        return "issuer"

    @pytest.fixture
    def no_issuer(self):
        self.vault.list_pki_issuers.return_value = []

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
        self.tls_certificates_acme.get_assigned_certificate.return_value = (
            provider_certificate,
            private_key,
        )
        return (provider_certificate, private_key)

    def test_given_no_acme_issuers_when_make_latest_acme_issuer_default_then_no_vault_error_is_raised_but_error_is_logged(
        self, caplog: pytest.LogCaptureFixture, no_issuer: None
    ):
        # Ensure no error is raised
        self.acme_manager.make_latest_acme_issuer_default()

        assert is_error_logged(caplog, "Failed to get the first issuer")

    def test_given_existing_acme_issuers_when_make_latest_acme_issuer_default_then_config_written_to_path(
        self, issuer_is_not_default: None
    ):
        self.acme_manager.make_latest_acme_issuer_default()

        self.vault.write.assert_called_with(
            path=f"{self.mount_point}/config/issuers",
            data={
                "default_follows_latest_issuer": True,
                "default": "issuer",
            },
        )

    def test_given_issuers_config_already_updated_when_make_latest_acme_issuer_default_then_config_not_written(
        self, issuer_is_default: None
    ):
        self.acme_manager.make_latest_acme_issuer_default()
        self.vault.write.assert_not_called()

    def test_given_intermediate_certificate_expires_before_issued_certificates_when_configure_then_certificate_is_renewed(
        self, assigned_certificate_and_key: tuple[ProviderCertificate, PrivateKey]
    ):
        provider_certificate, _ = assigned_certificate_and_key

        self.vault.get_intermediate_ca.return_value = str(provider_certificate.certificate)

        # This is how long certificates issued by ACME will be valid for. We
        # make it 25 hours, because the intermediate (provider) certificate is valid for 24.
        self.vault.get_role_max_ttl.return_value = 25 * SECONDS_IN_HOUR

        self.acme_manager.configure()

        self.vault.enable_secrets_engine.assert_called_once_with(
            SecretsBackend.PKI, self.mount_point
        )
        self.tls_certificates_acme.renew_certificate.assert_called_once_with(provider_certificate)

    def test_given_new_certificate_issued_when_configure_then_certificates_replaced(
        self, assigned_certificate_and_key: tuple[ProviderCertificate, PrivateKey]
    ):
        # Return a different certificate from Vault, to emulate the situation
        # where a new certificate has been issued.
        vault_certificate, private_key = generate_example_provider_certificate(
            self.certificate_request_attributes.common_name, 1, validity=timedelta(hours=24)
        )
        self.vault.get_intermediate_ca.return_value = str(vault_certificate.certificate)

        self.acme_manager.configure()

        self.vault.enable_secrets_engine.assert_called_once_with(
            SecretsBackend.PKI, self.mount_point
        )

        self.vault.import_ca_certificate_and_key.assert_called_once_with(
            certificate=str(assigned_certificate_and_key[0].certificate),
            private_key=str(assigned_certificate_and_key[1]),
            mount=self.mount_point,
        )

    def test_given_intermediate_certificate_when_configure_then_role_created(
        self, assigned_certificate_and_key: tuple[ProviderCertificate, PrivateKey]
    ):
        vault_certificate, _ = generate_example_provider_certificate(
            self.certificate_request_attributes.common_name, 1, validity=timedelta(hours=24)
        )
        self.vault.get_intermediate_ca.return_value = str(vault_certificate.certificate)

        self.acme_manager.configure()

        self.vault.enable_secrets_engine.assert_called_once_with(
            SecretsBackend.PKI, self.mount_point
        )

        validity = (
            assigned_certificate_and_key[0].certificate.expiry_time
            - assigned_certificate_and_key[0].certificate.validity_start_time
        )
        validity_in_seconds = validity.total_seconds()
        # This is how the manager currently calculates the max_ttl.
        max_ttl = int(validity_in_seconds / 2)
        self.vault.create_or_update_acme_role.assert_called_once_with(
            mount=self.mount_point,
            role=self.role_name,
            max_ttl=f"{max_ttl}s",
        )

    def test_given_intermediate_certificate_when_configure_then_backend_configured(
        self, assigned_certificate_and_key: tuple[ProviderCertificate, PrivateKey]
    ):
        vault_certificate, _ = generate_example_provider_certificate(
            self.certificate_request_attributes.common_name, 1, validity=timedelta(hours=24)
        )
        self.vault.get_intermediate_ca.return_value = str(vault_certificate.certificate)

        self.acme_manager.configure()

        expected_write_calls = [
            call.write(
                path=f"{self.mount_point}/config/cluster",
                data={"path": f"{self.vault_address}/v1/{self.mount_point}"},
            ),
            call.write(path=f"{self.mount_point}/config/acme", data={"enabled": True}),
        ]
        self.vault.write.assert_has_calls(expected_write_calls, any_order=True)

        self.vault.allow_acme_headers.assert_called_once_with(mount=self.mount_point)

        self.vault.set_urls.assert_called_once_with(
            mount=self.mount_point,
            issuing_certificates=[f"{self.vault_address}/v1/pki/ca"],
            crl_distribution_points=[f"{self.vault_address}/v1/pki/crl"],
        )


class TestBackupManager:
    @pytest.fixture(autouse=True)
    @patch("vault.vault_managers.JujuFacade")
    def setup(self, juju_facade_mock: MagicMock, monkeypatch: pytest.MonkeyPatch):
        """Configure the test environment for the happy path.

        Individual tests can then mock error scenarios by changing the mocks.
        """
        self.juju_facade = juju_facade_mock.return_value
        self.juju_facade.is_leader = True
        self.juju_facade.relation_exists.return_value = True
        self.s3_class = MagicMock()
        monkeypatch.setattr("vault.vault_managers.S3", self.s3_class)
        self.s3 = self.s3_class.return_value
        self.s3.get_object_key_list.return_value = [
            "vault-backup-my-model-1",
            "vault-backup-my-model-2",
        ]
        self.s3.get_content.return_value = "snapshot content"

        self.charm = MagicMock(spec=VaultCharm)
        self.charm.model.name = "my-model"
        self.vault_client = MagicMock(spec=VaultClient)
        self.s3_requirer = MagicMock(spec=S3Requirer)
        self.s3_requirer.get_s3_connection_info.return_value = {
            "bucket": "my-bucket",
            "access-key": "my-access-key",
            "secret-key": "my-secret-key",
            "endpoint": "my-endpoint",
            "region": "my-region",
        }

        self.manager = BackupManager(self.charm, self.s3_requirer, "s3-relation")

    def test_given_non_leader_when_create_backup_then_error_raised(self):
        self.juju_facade.is_leader = False
        with pytest.raises(ManagerError) as e:
            self.manager.create_backup(self.vault_client)
        assert str(e.value) == "Only leader unit can perform backup operations"

    def test_given_s3_relation_not_created_when_create_backup_then_error_raised(self):
        self.juju_facade.relation_exists.return_value = False
        with pytest.raises(ManagerError) as e:
            self.manager.create_backup(self.vault_client)
        assert str(e.value) == "S3 relation not created"

    @pytest.mark.parametrize(
        "missing_key, expected_error_message",
        [
            ("bucket", "S3 parameters missing (bucket)"),
            ("access-key", "S3 parameters missing (access-key)"),
            ("secret-key", "S3 parameters missing (secret-key)"),
            ("endpoint", "S3 parameters missing (endpoint)"),
        ],
    )
    def test_given_missing_s3_parameter_when_create_backup_then_error_raised(
        self, missing_key: str, expected_error_message: str
    ):
        del self.s3_requirer.get_s3_connection_info.return_value[missing_key]
        with pytest.raises(ManagerError) as e:
            self.manager.create_backup(self.vault_client)
        assert str(e.value) == expected_error_message

    def test_given_s3_error_when_create_backup_then_error_raised(self):
        self.s3_class.side_effect = S3Error()  # throw an error when creating the S3 object
        with pytest.raises(ManagerError) as e:
            self.manager.create_backup(self.vault_client)
        assert str(e.value) == "Failed to create S3 session"

    def test_given_bucket_creation_returns_none_when_create_backup_then_error_raised(self):
        self.s3.create_bucket.return_value = None
        with pytest.raises(ManagerError) as e:
            self.manager.create_backup(self.vault_client)
        assert str(e.value) == "Failed to create S3 bucket"

    def test_given_failed_to_upload_backup_when_create_backup_then_error_raised(self):
        self.s3.create_bucket.return_value = True
        self.s3.upload_content.return_value = False
        with pytest.raises(ManagerError) as e:
            self.manager.create_backup(self.vault_client)
        assert str(e.value) == "Failed to upload backup to S3 bucket"

    def test_given_s3_available_when_create_backup_then_backup_created(self):
        key = self.manager.create_backup(self.vault_client)

        self.vault_client.create_snapshot.assert_called_once()
        self.s3.upload_content.assert_called_once()

        assert key.startswith("vault-backup-my-model-")

    @pytest.mark.parametrize("skip_verify", [True, False])
    def test_when_create_backup_then_skip_verify_is_passed(self, skip_verify: bool) -> None:
        self.manager.create_backup(self.vault_client, skip_verify=skip_verify)
        assert self.s3_class.call_args.kwargs["skip_verify"] is skip_verify

    @pytest.mark.parametrize("skip_verify", [True, False])
    def test_list_backups_skip_verify(self, skip_verify: bool) -> None:
        self.manager.list_backups(skip_verify=skip_verify)
        assert self.s3_class.call_args.kwargs["skip_verify"] is skip_verify

    @pytest.mark.parametrize("skip_verify", [True, False])
    def test_restore_backup_skip_verify(self, skip_verify: bool) -> None:
        self.manager.restore_backup(
            self.vault_client, "vault-backup-my-model-1", skip_verify=skip_verify
        )
        assert self.s3_class.call_args.kwargs["skip_verify"] is skip_verify

    # List backups
    def test_given_non_leader_when_list_backups_then_error_raised(self):
        self.juju_facade.is_leader = False
        with pytest.raises(ManagerError) as e:
            self.manager.list_backups()
        assert str(e.value) == "Only leader unit can perform backup operations"

    def test_given_s3_relation_not_created_when_list_backups_then_error_raised(self):
        self.juju_facade.is_leader = True
        self.juju_facade.relation_exists.return_value = False
        with pytest.raises(ManagerError) as e:
            self.manager.list_backups()
        assert str(e.value) == "S3 relation not created"

    @pytest.mark.parametrize(
        "missing_key, expected_error_message",
        [
            ("bucket", "S3 parameters missing (bucket)"),
            ("access-key", "S3 parameters missing (access-key)"),
            ("secret-key", "S3 parameters missing (secret-key)"),
            ("endpoint", "S3 parameters missing (endpoint)"),
        ],
    )
    def test_given_missing_s3_parameter_when_list_backups_then_error_raised(
        self, missing_key: str, expected_error_message: str
    ):
        self.juju_facade.is_leader = True
        self.juju_facade.relation_exists.return_value = True
        del self.s3_requirer.get_s3_connection_info.return_value[missing_key]
        with pytest.raises(ManagerError) as e:
            self.manager.list_backups()
        assert str(e.value) == expected_error_message

    def test_given_s3_error_when_list_backups_then_error_raised(self):
        self.s3_class.side_effect = S3Error()  # throw an error when creating the S3 object
        with pytest.raises(ManagerError) as e:
            self.manager.list_backups()
        assert str(e.value) == "Failed to create S3 session"

    def test_given_s3_error_during_get_object_key_when_list_backups_then_error_raised(self):
        self.s3.get_object_key_list.side_effect = S3Error("some error message")
        with pytest.raises(ManagerError) as e:
            self.manager.list_backups()
        assert str(e.value) == "Failed to list backups in S3 bucket: some error message"

    def test_given_s3_available_when_list_backups_then_backups_listed(self):
        backups = self.manager.list_backups()
        assert backups == ["vault-backup-my-model-1", "vault-backup-my-model-2"]

    # Restore backup
    def test_given_non_leader_when_restore_backup_then_error_raised(self):
        self.juju_facade.is_leader = False
        with pytest.raises(ManagerError) as e:
            self.manager.restore_backup(self.vault_client, "vault-backup-my-model-1")
        assert str(e.value) == "Only leader unit can perform backup operations"

    def test_given_s3_relation_not_created_when_restore_backup_then_error_raised(self):
        self.juju_facade.is_leader = True
        self.juju_facade.relation_exists.return_value = False
        with pytest.raises(ManagerError) as e:
            self.manager.restore_backup(self.vault_client, "vault-backup-my-model-1")
        assert str(e.value) == "S3 relation not created"

    @pytest.mark.parametrize(
        "missing_key, expected_error_message",
        [
            ("bucket", "S3 parameters missing (bucket)"),
            ("access-key", "S3 parameters missing (access-key)"),
            ("secret-key", "S3 parameters missing (secret-key)"),
            ("endpoint", "S3 parameters missing (endpoint)"),
        ],
    )
    def test_given_missing_s3_parameter_when_restore_backup_then_error_raised(
        self, missing_key: str, expected_error_message: str
    ):
        self.juju_facade.is_leader = True
        self.juju_facade.relation_exists.return_value = True
        del self.s3_requirer.get_s3_connection_info.return_value[missing_key]
        with pytest.raises(ManagerError) as e:
            self.manager.restore_backup(self.vault_client, "vault-backup-my-model-1")
        assert str(e.value) == expected_error_message

    def test_given_s3_error_when_restore_backup_then_error_raised(self):
        self.s3_class.side_effect = S3Error()  # throw an error when creating the S3 object
        with pytest.raises(ManagerError) as e:
            self.manager.restore_backup(self.vault_client, "vault-backup-my-model-1")
        assert str(e.value) == "Failed to create S3 session"

    def test_given_s3_error_during_download_when_restore_backup_then_error_raised(self):
        self.s3.get_content.side_effect = S3Error("some error message")
        with pytest.raises(ManagerError) as e:
            self.manager.restore_backup(self.vault_client, "vault-backup-my-model-1")
        assert str(e.value) == "Failed to retrieve snapshot from S3: some error message"

    def test_given_s3_content_not_found_when_restore_backup_then_error_raised(self):
        self.s3.get_content.return_value = None
        with pytest.raises(ManagerError) as e:
            self.manager.restore_backup(self.vault_client, "vault-backup-my-model-1")
        assert "Snapshot not found in S3 bucket" in str(e.value)

    def test_given_vault_client_fails_to_restore_snapshot_when_restore_backup_then_error_raised(
        self,
    ):
        self.vault_client.restore_snapshot.side_effect = VaultClientError("some error message")
        with pytest.raises(ManagerError) as e:
            self.manager.restore_backup(self.vault_client, "vault-backup-my-model-1")
        assert str(e.value) == "Failed to restore snapshot: some error message"

    def test_given_s3_content_and_vault_client_available_when_restore_backup_then_backup_restored(
        self,
    ):
        self.manager.restore_backup(self.vault_client, "vault-backup-my-model-1")
        self.vault_client.restore_snapshot.assert_called_once_with(snapshot="snapshot content")


class TestRaftManager:
    @pytest.fixture(autouse=True)
    @patch("vault.vault_managers.JujuFacade")
    def setup(self, juju_facade_mock: MagicMock, monkeypatch: pytest.MonkeyPatch):
        self.juju_facade = juju_facade_mock.return_value
        self.juju_facade.is_leader = True
        self.juju_facade.planned_units_for_app = 1
        self.charm = MagicMock(spec=VaultCharm)
        self.workload = MagicMock(spec=Container)
        self.manager = RaftManager(self.charm, self.workload, "vault", "/vault/raft")

    def test_given_non_leader_when_bootstrap_then_error_raised(self):
        self.juju_facade.is_leader = False
        with pytest.raises(ManagerError) as e:
            self.manager.bootstrap("my-node", "my-address")
        assert str(e.value) == "Only the leader unit can bootstrap a Vault cluster"

    def test_given_many_units_when_bootstrap_then_error_raised(self):
        self.juju_facade.planned_units_for_app = 2
        with pytest.raises(ManagerError) as e:
            self.manager.bootstrap("my-node", "my-address")
        assert str(e.value) == "Bootstrapping a Vault cluster requires exactly one unit"

    def test_given_one_unit_and_leader_when_bootstrap_then_peers_json_created(self):
        self.manager.bootstrap("my-node", "my-address")
        self.workload.stop.assert_called_once_with("vault")
        self.workload.push.assert_called_once_with(
            "/vault/raft/raft/peers.json",
            '[{"id": "my-node", "address": "my-address"}]',
        )
        self.workload.restart.assert_called_once_with("vault")
