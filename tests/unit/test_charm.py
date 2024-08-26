# # !/usr/bin/env python3
# # Copyright 2023 Canonical Ltd.
# # See LICENSE file for licensing details.

# from unittest.mock import MagicMock, Mock, patch

# import hcl
# from charms.vault_k8s.v0.vault_autounseal import (
#     AutounsealDetails,
# )
# from charms.vault_k8s.v0.vault_client import (
#     AppRole,
#     SecretsBackend,
# )
# from ops import pebble

# from charm import (
#     AUTOUNSEAL_MOUNT_PATH,
# )

# VAULT_KV_LIB_PATH = "charms.vault_k8s.v0.vault_kv"
# VAULT_AUTOUNSEAL_LIB_PATH = "charms.vault_k8s.v0.vault_autounseal"
# VAULT_KV_RELATION_NAME = "vault-kv"
# VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"


# class TestCharm:
#     # Test configure

#     @patch("ops.model.Container.restart", new=Mock)
#     def test_given_all_prerequisites_when_configure_then_configure_completes(self):
#         self.harness.set_leader(is_leader=True)
#         self.harness.add_storage(storage_name="config", attach=True)
#         self._set_peer_relation()
#         self._set_approle_secret(
#             role_id="whatever role id",
#             secret_id="whatever secret id",
#         )
#         self.harness.set_can_connect(container=self.container_name, val=True)
#         self.mock_vault.configure_mock(
#             **{
#                 "is_api_available.return_value": True,
#                 "is_initialized.return_value": True,
#                 "is_sealed.return_value": False,
#             },
#         )

#         self.harness.charm.on.config_changed.emit()

#         self.mock_vault.is_raft_cluster_healthy.assert_called_once()

#     def test_given_node_not_in_raft_when_on_remove_then_node_is_not_removed_from_raft(
#         self,
#     ):
#         self.mock_vault.configure_mock(
#             **{
#                 "is_api_available.return_value": True,
#                 "is_node_in_raft_peers.return_value": False,
#             },
#         )

#         self.harness.set_can_connect(container=self.container_name, val=True)
#         self._set_peer_relation()
#         self._set_approle_secret(
#             role_id="root token content",
#             secret_id="whatever secret id",
#         )

#         self.harness.charm.on.remove.emit()

#         self.mock_vault.remove_raft_node.assert_not_called()

#     @patch(
#         "ops.model.Container.get_service",
#         return_value=Mock(spec=pebble.ServiceInfo, **{"is_running.return_value": True}),
#     )
#     @patch("ops.model.Container.stop")
#     def test_given_service_is_running_when_on_remove_then_service_is_stopped(
#         self,
#         patch_stop_service,
#         patch_get_service,
#     ):
#         self.mock_vault.configure_mock(
#             **{
#                 "is_api_available.return_value": True,
#                 "is_node_in_raft_peers.return_value": False,
#             },
#         )

#         self.harness.set_can_connect(container=self.container_name, val=True)
#         self._set_peer_relation()
#         self._set_approle_secret(
#             role_id="root token content",
#             secret_id="whatever secret id",
#         )

#         self.harness.charm.on.remove.emit()

#         patch_stop_service.assert_called_with("vault")

#     # Test Vault KV
#     @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_unit_credentials")
#     @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_ca_certificate")
#     @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_mount")
#     @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_vault_url")
#     def test_given_unit_not_leader_when_new_vault_kv_client_attached_then_event_kv_relation_data_not_set(
#         self,
#         patch_set_vault_url,
#         patch_set_mount,
#         patch_set_ca_certificate,
#         patch_audit_device_enabled,
#     ):
#         self.harness.set_leader(is_leader=False)
#         self.harness.set_can_connect(container=self.container_name, val=True)
#         vault_kv_relation_name = "vault-kv"
#         vault_kv_relation_id = self.harness.add_relation(
#             relation_name=vault_kv_relation_name, remote_app="vault-kv-remote"
#         )
#         self.harness.add_relation_unit(
#             relation_id=vault_kv_relation_id, remote_unit_name="vault-kv-remote/0"
#         )
#         event = Mock()
#         event.relation_id = vault_kv_relation_id
#         self.harness.charm._on_new_vault_kv_client_attached(event)
#         patch_set_vault_url.assert_not_called()
#         patch_set_mount.assert_not_called()
#         patch_set_ca_certificate.assert_not_called()
#         patch_audit_device_enabled.assert_not_called()

#     def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_approle_auth_is_enabled(
#         self,
#     ):
#         self.mock_vault.configure_mock(
#             **{
#                 "configure_approle.return_value": "12345678",
#                 "generate_role_secret_id.return_value": "11111111",
#             },
#         )
#         self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"
#         self.harness.set_leader(is_leader=True)
#         self.harness.add_relation(relation_name="vault-peers", remote_app="vault")
#         self.harness.set_can_connect(container=self.container_name, val=True)
#         self._set_approle_secret(
#             role_id="role id",
#             secret_id="secret id",
#         )
#         rel_id, _ = self.setup_vault_kv_relation()
#         event = Mock()
#         event.relation_name = VAULT_KV_RELATION_NAME
#         event.relation_id = rel_id
#         event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
#         event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
#         event.mount_suffix = "suffix"
#         event.egress_subnets = ["2.2.2.0/24"]
#         event.nonce = "123123"
#         self.harness.charm._on_new_vault_kv_client_attached(event)
#         self.mock_vault.enable_secrets_engine.assert_called_once_with(
#             SecretsBackend.KV_V2, "charm-vault-kv-requirer-suffix"
#         )

#     @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_ca_certificate")
#     @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_mount")
#     @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_vault_url")
#     def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_kv_relation_data_is_set(
#         self,
#         set_vault_url,
#         set_mount,
#         set_ca_certificate,
#     ):
#         self.mock_vault.configure_mock(
#             **{
#                 "configure_approle.return_value": "12345678",
#                 "generate_role_secret_id.return_value": "11111111",
#             },
#         )
#         self._set_peer_relation()
#         self.harness.set_leader(is_leader=True)
#         self.harness.set_can_connect(container=self.container_name, val=True)
#         self._set_approle_secret(
#             role_id="root token content",
#             secret_id="whatever secret id",
#         )
#         rel_id, _ = self.setup_vault_kv_relation()
#         event = Mock()
#         event.relation_name = VAULT_KV_RELATION_NAME
#         event.relation_id = rel_id
#         event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
#         event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
#         event.mount_suffix = "suffix"
#         event.egress_subnets = ["2.2.2.0/24"]
#         event.nonce = "123123"
#         self.harness.charm._on_new_vault_kv_client_attached(event)
#         set_vault_url.assert_called()
#         set_mount.assert_called()
#         set_ca_certificate.assert_called()

#     def test_given_prerequisites_are_met_when_related_kv_client_unit_egress_is_updated_then_secret_content_is_updated(
#         self,
#     ):
#         self.mock_vault.configure_mock(
#             **{
#                 "configure_approle.return_value": "12345678",
#                 "generate_role_secret_id.return_value": "11111111",
#             },
#         )

#         self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"

#         self.harness.set_can_connect(container=self.container_name, val=True)
#         self._set_peer_relation()
#         self._set_approle_secret(
#             role_id="root token content",
#             secret_id="whatever secret id",
#         )
#         rel_id, egress_subnets = self.setup_vault_kv_relation()
#         self.mock_vault.read_role_secret.return_value = {"cidr_list": egress_subnets}

#         mount_suffix = "whatever-suffix"
#         self.harness.update_relation_data(
#             rel_id, VAULT_KV_REQUIRER_APPLICATION_NAME, {"mount_suffix": mount_suffix}
#         )
#         unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"

#         with patch("ops.Secret.set_content") as set_content:
#             self.harness.update_relation_data(
#                 rel_id, unit_name, {"egress_subnet": "10.20.20.240/32"}
#             )
#             assert set_content.call_count == 1

#     def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_kv_mount_is_configured(
#         self,
#     ):
#         self.mock_vault.configure_mock(
#             **{
#                 "configure_approle.return_value": "12345678",
#                 "generate_role_secret_id.return_value": "11111111",
#             },
#         )
#         self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"

#         self.harness.add_relation(relation_name="vault-peers", remote_app="vault")
#         self.harness.set_leader(is_leader=True)
#         self.harness.set_can_connect(container=self.container_name, val=True)
#         event = Mock()
#         event.params = {"relation_name": "relation", "relation_id": "99"}
#         self._set_approle_secret(
#             role_id="root token content",
#             secret_id="whatever secret id",
#         )
#         rel_id, _ = self.setup_vault_kv_relation()
#         event = Mock()
#         event.relation_name = VAULT_KV_RELATION_NAME
#         event.relation_id = rel_id
#         event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
#         event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
#         event.mount_suffix = "suffix"
#         event.egress_subnets = ["2.2.2.0/24"]
#         event.nonce = "123123"
#         self.harness.charm._on_new_vault_kv_client_attached(event)
#         self.mock_vault.enable_secrets_engine.assert_called_with(
#             SecretsBackend.KV_V2, "charm-vault-kv-requirer-suffix"
#         )

#     @patch("ops.model.Secret.remove_all_revisions")
#     def test_given_vault_kv_client_when_client_detached_then_kv_secret_is_removed(
#         self,
#         patch_remove_secret,
#     ):
#         self.mock_vault.configure_mock(
#             **{
#                 "configure_approle.return_value": "12345678",
#                 "generate_role_secret_id.return_value": "11111111",
#             },
#         )
#         self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"

#         self.harness.add_relation(relation_name="vault-peers", remote_app="vault")
#         self.harness.set_leader(is_leader=True)
#         self.harness.set_can_connect(container=self.container_name, val=True)
#         event = Mock()
#         event.params = {"relation_name": "relation", "relation_id": "99"}
#         self._set_approle_secret(
#             role_id="root token content",
#             secret_id="whatever secret id",
#         )
#         rel_id, _ = self.setup_vault_kv_relation()
#         event = Mock()
#         event.relation_name = VAULT_KV_RELATION_NAME
#         event.relation_id = rel_id
#         event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
#         event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
#         event.mount_suffix = "suffix"
#         event.egress_subnets = ["2.2.2.0/24"]
#         event.nonce = "123123"
#         self.harness.charm._on_new_vault_kv_client_attached(event)
#         kv_client_detached_event = Mock()
#         kv_client_detached_event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
#         self.harness.charm._on_vault_kv_client_detached(kv_client_detached_event)
#         patch_remove_secret.assert_called()
