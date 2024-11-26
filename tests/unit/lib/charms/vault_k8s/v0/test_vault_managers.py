from unittest.mock import MagicMock, patch

import pytest
from charms.vault_k8s.v0.juju_facade import SecretRemovedError
from charms.vault_k8s.v0.vault_autounseal import AutounsealDetails
from charms.vault_k8s.v0.vault_client import VaultClient
from charms.vault_k8s.v0.vault_managers import (
    VaultAutounsealProviderManager,
    VaultAutounsealRequirerManager,
    VaultTLSManager,
)


class TestVaultAutounsealRequirerManager:
    @pytest.mark.parametrize(
        "token, token_valid, expected_token",
        [
            ("initial token", True, "initial token"),  # Token is set and valid
            ("initial token", False, "new token"),  # Token is set but invalid
            (None, None, "new token"),  # Token is not set
        ],
    )
    @patch("charms.vault_k8s.v0.vault_managers.VaultClient")
    @patch("charms.vault_k8s.v0.vault_managers.JujuFacade")
    def test_when_vault_configuration_details_called_then_details_are_retrieved_correctly(
        self,
        juju_facade_mock,
        vault_client_mock,
        token,
        token_valid,
        expected_token,
    ):
        juju_facade_instance = juju_facade_mock.return_value
        charm = MagicMock()
        tls_manager = MagicMock(spec=VaultTLSManager)
        tls_manager.get_tls_file_path_in_workload.return_value = "/my/test/path"
        vault_client_instance = vault_client_mock.return_value
        vault_client_instance.token = token

        def authenticate(auth_method):
            if token and vault_client_instance.authenticate.call_count == 1:
                return token_valid
            vault_client_instance.token = "new token"
            return True

        vault_client_instance.authenticate.side_effect = authenticate
        requires = MagicMock()
        requires.get_details.return_value = AutounsealDetails(
            "my_address",
            "my_mount_path",
            "my_key_name",
            "my_role_id",
            "my_secret_id",
            "my_ca_certificate",
        )
        relation_id = 1
        relation = MagicMock()
        relation.id = relation_id
        if token:
            juju_facade_instance.get_secret_content_values.return_value = (token,)
        if not token:
            juju_facade_instance.get_secret_content_values.side_effect = SecretRemovedError()

        autounseal = VaultAutounsealRequirerManager(charm, tls_manager, requires)
        details = autounseal.vault_configuration_details()

        assert details is not None
        assert details.address == "my_address"
        assert details.mount_path == "my_mount_path"
        assert details.key_name == "my_key_name"
        assert details.token == expected_token
        assert details.ca_cert_path == "/my/test/path"


class TestVaultAutounsealProviderManager:
    def test_create_credentials(self):
        charm = MagicMock()
        provides = MagicMock()
        relation_id = 1
        relation = MagicMock()
        relation.id = relation_id
        vault_client = MagicMock(spec=VaultClient)
        vault_client.create_or_update_approle.return_value = "role_id"
        vault_client.generate_role_secret_id.return_value = "secret_id"

        autounseal = VaultAutounsealProviderManager(charm, vault_client, provides, "ca_cert")

        key_name, role_id, secret_id = autounseal.create_credentials(relation)

        assert key_name == str(relation_id)
        assert role_id == "role_id"
        assert secret_id == "secret_id"
        provides.set_autounseal_data.assert_called_once()

    @patch("charms.vault_k8s.v0.vault_managers.JujuFacade")
    def test_sync(self, juju_facade_mock):
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
        autounseal = VaultAutounsealProviderManager(charm, vault_client_mock, provides, "ca_cert")

        autounseal.sync()

        vault_client_mock.ensure_secrets_engine.assert_called_once()
        provides.get_outstanding_requests.assert_called_once()
        vault_client_mock.create_or_update_approle.assert_called_once_with(
            "charm-autounseal-123",
            policies=["charm-autounseal-123"],
            token_period="60s",
        )
        vault_client_mock.generate_role_secret_id.assert_called_once_with("charm-autounseal-123")
        provides.set_autounseal_data.assert_called()
        vault_client_mock.delete_role.assert_called_once_with("charm-autounseal-321")
        vault_client_mock.delete_policy.assert_called_once_with("charm-autounseal-321")
        vault_client_mock.write.assert_called_with(
            "charm-autounseal/keys/charm-autounseal-321/config", {"deletion_allowed": True}
        )

    @patch("charms.vault_k8s.v0.vault_client.VaultClient")
    @patch("charms.vault_k8s.v0.vault_managers.JujuFacade")
    def test_get_address(self, juju_facade_mock, vault_client_mock):
        juju_facade_instance = juju_facade_mock.return_value
        juju_facade_instance.get_ingress_address.return_value = "1.2.3.4"
        charm = MagicMock()
        provides = MagicMock()
        relation = MagicMock()
        autounseal = VaultAutounsealProviderManager(charm, vault_client_mock, provides, "ca_cert")

        address = autounseal.get_address(relation)

        assert address == "https://1.2.3.4:8200"
