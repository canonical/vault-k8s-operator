from unittest.mock import MagicMock, patch

import pytest
from charms.vault_k8s.v0.juju_facade import SecretRemovedError
from charms.vault_k8s.v0.vault_autounseal import AutounsealDetails
from charms.vault_k8s.v0.vault_client import AuthMethod, SecretsBackend, VaultClient
from charms.vault_k8s.v0.vault_managers import (
    AUTOUNSEAL_POLICY,
    AutounsealProviderManager,
    AutounsealRequirerManager,
    KVManager,
    VaultKvProvides,
)

from charm import AUTOUNSEAL_MOUNT_PATH, VaultCharm


class TestAutounsealRequirerManager:
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


class TestKVManager:
    @pytest.fixture(autouse=True)
    @patch("charms.vault_k8s.v0.vault_managers.JujuFacade")
    def setup(self, juju_facade_mock: MagicMock):
        self.juju_facade = juju_facade_mock.return_value
        self.charm = MagicMock(spec=VaultCharm)
        self.vault_client = MagicMock(spec=VaultClient)
        self.vault_kv = MagicMock(spec=VaultKvProvides)
        self.ca_cert = "some cert"

        self.manager = KVManager(self.charm, self.vault_client, self.vault_kv, self.ca_cert)

    def test_when_generate_kv_for_requirer_then_relation_data_is_set(self):
        relation = MagicMock()
        app_name = "myapp"
        unit_name = "myunit"
        mount_suffix = "mount"
        egress_subnets = ["1.2.3.4/32"]
        nonce = "123123"
        vault_url = "https://vault:8200"

        self.vault_kv.get_credentials.return_value = {
            "nonce": "my-secret-id",
        }
        self.juju_facade.get_latest_secret_content.return_value = {
            "role-secret-id": "charm-myapp-mount-juju-secret-id"
        }
        secret = MagicMock()
        secret.id = "my-secret-id"
        self.juju_facade.set_app_secret_content.return_value = secret

        self.manager.generate_kv_for_requirer(
            relation, app_name, unit_name, mount_suffix, egress_subnets, nonce, vault_url
        )

        self.vault_client.enable_secrets_engine.assert_called_once_with(
            SecretsBackend.KV_V2, "charm-myapp-mount"
        )
        self.vault_client.create_or_update_policy_from_file.assert_called_once_with(
            "charm-myapp-mount-myunit", "src/templates/kv_mount.hcl", mount="charm-myapp-mount"
        )
        self.vault_client.generate_role_secret_id.assert_called_once_with(
            "charm-myapp-mount-myunit", egress_subnets
        )

        self.vault_client.create_or_update_approle.assert_called_once_with(
            "charm-myapp-mount-myunit",
            policies=["charm-myapp-mount-myunit"],
            cidrs=egress_subnets,
            token_ttl="1h",
            token_max_ttl="1h",
        )
        self.vault_kv.set_kv_data.assert_called_once_with(
            relation=relation,
            mount="charm-myapp-mount",
            ca_certificate=self.ca_cert,
            vault_url=vault_url,
            nonce=nonce,
            credentials_juju_secret_id="my-secret-id",
        )

    def test_when_egress_address_changed_then_secret_content_is_updated(self):
        pass
