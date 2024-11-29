from unittest.mock import MagicMock, patch

import pytest
from charms.vault_k8s.v0.juju_facade import SecretRemovedError
from charms.vault_k8s.v0.vault_autounseal import AutounsealDetails
from charms.vault_k8s.v0.vault_client import VaultClient
from charms.vault_k8s.v0.vault_managers import (
    AUTOUNSEAL_POLICY,
    VaultAutounsealProviderManager,
    VaultAutounsealRequirerManager,
)

from charm import AUTOUNSEAL_MOUNT_PATH


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
    def test_when_get_vault_configuration_details_called_then_details_are_retrieved_correctly(
        self,
        juju_facade_mock,
        vault_client_mock,
        token,
        token_valid,
        expected_token,
    ):
        juju_facade_instance = juju_facade_mock.return_value
        charm = MagicMock()
        vault_client_instance = vault_client_mock.return_value
        vault_client_instance.token = token

        def authenticate(auth_method):
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

        autounseal = VaultAutounsealRequirerManager(charm, requires)
        returned_token = autounseal.get_provider_vault_token(autounseal_details, ca_cert_path)
        assert returned_token == expected_token


class TestVaultAutounsealProviderManager:
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

        autounseal = VaultAutounsealProviderManager(
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
        self, juju_facade_mock
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
        autounseal = VaultAutounsealProviderManager(
            charm, vault_client_mock, provides, "ca_cert", AUTOUNSEAL_MOUNT_PATH
        )

        autounseal.clean_up_credentials()

        vault_client_mock.delete_role.assert_called_once_with("charm-autounseal-321")
        vault_client_mock.delete_policy.assert_called_once_with("charm-autounseal-321")
        vault_client_mock.write.assert_called_with(
            "charm-autounseal/keys/charm-autounseal-321/config", {"deletion_allowed": True}
        )
