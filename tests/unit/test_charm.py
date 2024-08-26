#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# import io
# import json
# import unittest
# from datetime import datetime, timezone
# from unittest.mock import MagicMock, Mock, PropertyMock, call, patch

# import hcl  # type: ignore[import-untyped]
# import requests
# from botocore.response import StreamingBody
# from charms.tls_certificates_interface.v3.tls_certificates import (
#     ProviderCertificate,
# )
# from charms.vault_k8s.v0.vault_autounseal import (
#     AutounsealDetails,
# )
# from charms.vault_k8s.v0.vault_client import (
#     AppRole,
#     AuditDeviceType,
#     Certificate,
#     SecretsBackend,
#     Token,
#     Vault,
# )
# from charms.vault_k8s.v0.vault_s3 import S3Error
# from charms.vault_k8s.v0.vault_tls import (
#     CA_CERTIFICATE_JUJU_SECRET_LABEL,
#     VaultCertsError,
#     VaultTLSManager,
# )
# from ops import pebble, testing
# from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

# from charm import (
#     AUTOUNSEAL_MOUNT_PATH,
#     CHARM_POLICY_NAME,
#     CHARM_POLICY_PATH,
#     PKI_RELATION_NAME,
#     S3_RELATION_NAME,
#     TLS_CERTIFICATES_PKI_RELATION_NAME,
#     VAULT_CHARM_APPROLE_SECRET_LABEL,
#     VaultCharm,
#     config_file_content_matches,
# )
# import scenario
# import pytest


# S3_RELATION_LIB_PATH = "charms.data_platform_libs.v0.s3"
# S3_LIB_PATH = "charms.vault_k8s.v0.vault_s3"
# VAULT_KV_LIB_PATH = "charms.vault_k8s.v0.vault_kv"
# TLS_CERTIFICATES_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"
# VAULT_AUTOUNSEAL_LIB_PATH = "charms.vault_k8s.v0.vault_autounseal"
# VAULT_KV_RELATION_NAME = "vault-kv"
# VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"
# PKI_MOUNT = "charm-pki"
# PKI_ROLE_NAME = "charm"
# APPROLE_ROLE_NAME = "charm"


# class TestCharm:

# # Test configure

# @patch("ops.model.Container.restart", new=Mock)
# def test_given_all_prerequisites_when_configure_then_configure_completes(self):
#     self.harness.set_leader(is_leader=True)
#     self.harness.add_storage(storage_name="config", attach=True)
#     self._set_peer_relation()
#     self._set_approle_secret(
#         role_id="whatever role id",
#         secret_id="whatever secret id",
#     )
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self.mock_vault.configure_mock(
#         **{
#             "is_api_available.return_value": True,
#             "is_initialized.return_value": True,
#             "is_sealed.return_value": False,
#         },
#     )

#     self.harness.charm.on.config_changed.emit()

#     self.mock_vault.is_raft_cluster_healthy.assert_called_once()


# def test_given_node_not_in_raft_when_on_remove_then_node_is_not_removed_from_raft(
#     self,
# ):
#     self.mock_vault.configure_mock(
#         **{
#             "is_api_available.return_value": True,
#             "is_node_in_raft_peers.return_value": False,
#         },
#     )

#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self._set_peer_relation()
#     self._set_approle_secret(
#         role_id="root token content",
#         secret_id="whatever secret id",
#     )

#     self.harness.charm.on.remove.emit()

#     self.mock_vault.remove_raft_node.assert_not_called()

# @patch(
#     "ops.model.Container.get_service",
#     return_value=Mock(spec=pebble.ServiceInfo, **{"is_running.return_value": True}),
# )
# @patch("ops.model.Container.stop")
# def test_given_service_is_running_when_on_remove_then_service_is_stopped(
#     self,
#     patch_stop_service,
#     patch_get_service,
# ):
#     self.mock_vault.configure_mock(
#         **{
#             "is_api_available.return_value": True,
#             "is_node_in_raft_peers.return_value": False,
#         },
#     )

#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self._set_peer_relation()
#     self._set_approle_secret(
#         role_id="root token content",
#         secret_id="whatever secret id",
#     )

#     self.harness.charm.on.remove.emit()

#     patch_stop_service.assert_called_with("vault")

# # Test Vault KV
# @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_unit_credentials")
# @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_ca_certificate")
# @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_mount")
# @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_vault_url")
# def test_given_unit_not_leader_when_new_vault_kv_client_attached_then_event_kv_relation_data_not_set(
#     self,
#     patch_set_vault_url,
#     patch_set_mount,
#     patch_set_ca_certificate,
#     patch_audit_device_enabled,
# ):
#     self.harness.set_leader(is_leader=False)
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     vault_kv_relation_name = "vault-kv"
#     vault_kv_relation_id = self.harness.add_relation(
#         relation_name=vault_kv_relation_name, remote_app="vault-kv-remote"
#     )
#     self.harness.add_relation_unit(
#         relation_id=vault_kv_relation_id, remote_unit_name="vault-kv-remote/0"
#     )
#     event = Mock()
#     event.relation_id = vault_kv_relation_id
#     self.harness.charm._on_new_vault_kv_client_attached(event)
#     patch_set_vault_url.assert_not_called()
#     patch_set_mount.assert_not_called()
#     patch_set_ca_certificate.assert_not_called()
#     patch_audit_device_enabled.assert_not_called()

# def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_approle_auth_is_enabled(
#     self,
# ):
#     self.mock_vault.configure_mock(
#         **{
#             "configure_approle.return_value": "12345678",
#             "generate_role_secret_id.return_value": "11111111",
#         },
#     )
#     self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"
#     self.harness.set_leader(is_leader=True)
#     self.harness.add_relation(relation_name="vault-peers", remote_app="vault")
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self._set_approle_secret(
#         role_id="role id",
#         secret_id="secret id",
#     )
#     rel_id, _ = self.setup_vault_kv_relation()
#     event = Mock()
#     event.relation_name = VAULT_KV_RELATION_NAME
#     event.relation_id = rel_id
#     event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
#     event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
#     event.mount_suffix = "suffix"
#     event.egress_subnets = ["2.2.2.0/24"]
#     event.nonce = "123123"
#     self.harness.charm._on_new_vault_kv_client_attached(event)
#     self.mock_vault.enable_secrets_engine.assert_called_once_with(
#         SecretsBackend.KV_V2, "charm-vault-kv-requirer-suffix"
#     )

# @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_ca_certificate")
# @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_mount")
# @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_vault_url")
# def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_kv_relation_data_is_set(
#     self,
#     set_vault_url,
#     set_mount,
#     set_ca_certificate,
# ):
#     self.mock_vault.configure_mock(
#         **{
#             "configure_approle.return_value": "12345678",
#             "generate_role_secret_id.return_value": "11111111",
#         },
#     )
#     self._set_peer_relation()
#     self.harness.set_leader(is_leader=True)
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self._set_approle_secret(
#         role_id="root token content",
#         secret_id="whatever secret id",
#     )
#     rel_id, _ = self.setup_vault_kv_relation()
#     event = Mock()
#     event.relation_name = VAULT_KV_RELATION_NAME
#     event.relation_id = rel_id
#     event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
#     event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
#     event.mount_suffix = "suffix"
#     event.egress_subnets = ["2.2.2.0/24"]
#     event.nonce = "123123"
#     self.harness.charm._on_new_vault_kv_client_attached(event)
#     set_vault_url.assert_called()
#     set_mount.assert_called()
#     set_ca_certificate.assert_called()

# def test_given_prerequisites_are_met_when_related_kv_client_unit_egress_is_updated_then_secret_content_is_updated(
#     self,
# ):
#     self.mock_vault.configure_mock(
#         **{
#             "configure_approle.return_value": "12345678",
#             "generate_role_secret_id.return_value": "11111111",
#         },
#     )

#     self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"

#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self._set_peer_relation()
#     self._set_approle_secret(
#         role_id="root token content",
#         secret_id="whatever secret id",
#     )
#     rel_id, egress_subnets = self.setup_vault_kv_relation()
#     self.mock_vault.read_role_secret.return_value = {"cidr_list": egress_subnets}

#     mount_suffix = "whatever-suffix"
#     self.harness.update_relation_data(
#         rel_id, VAULT_KV_REQUIRER_APPLICATION_NAME, {"mount_suffix": mount_suffix}
#     )
#     unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"

#     with patch("ops.Secret.set_content") as set_content:
#         self.harness.update_relation_data(
#             rel_id, unit_name, {"egress_subnet": "10.20.20.240/32"}
#         )
#         assert set_content.call_count == 1

# def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_kv_mount_is_configured(
#     self,
# ):
#     self.mock_vault.configure_mock(
#         **{
#             "configure_approle.return_value": "12345678",
#             "generate_role_secret_id.return_value": "11111111",
#         },
#     )
#     self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"

#     self.harness.add_relation(relation_name="vault-peers", remote_app="vault")
#     self.harness.set_leader(is_leader=True)
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     event = Mock()
#     event.params = {"relation_name": "relation", "relation_id": "99"}
#     self._set_approle_secret(
#         role_id="root token content",
#         secret_id="whatever secret id",
#     )
#     rel_id, _ = self.setup_vault_kv_relation()
#     event = Mock()
#     event.relation_name = VAULT_KV_RELATION_NAME
#     event.relation_id = rel_id
#     event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
#     event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
#     event.mount_suffix = "suffix"
#     event.egress_subnets = ["2.2.2.0/24"]
#     event.nonce = "123123"
#     self.harness.charm._on_new_vault_kv_client_attached(event)
#     self.mock_vault.enable_secrets_engine.assert_called_with(
#         SecretsBackend.KV_V2, "charm-vault-kv-requirer-suffix"
#     )

# @patch("ops.model.Secret.remove_all_revisions")
# def test_given_vault_kv_client_when_client_detached_then_kv_secret_is_removed(
#     self,
#     patch_remove_secret,
# ):
#     self.mock_vault.configure_mock(
#         **{
#             "configure_approle.return_value": "12345678",
#             "generate_role_secret_id.return_value": "11111111",
#         },
#     )
#     self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "test cert"

#     self.harness.add_relation(relation_name="vault-peers", remote_app="vault")
#     self.harness.set_leader(is_leader=True)
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     event = Mock()
#     event.params = {"relation_name": "relation", "relation_id": "99"}
#     self._set_approle_secret(
#         role_id="root token content",
#         secret_id="whatever secret id",
#     )
#     rel_id, _ = self.setup_vault_kv_relation()
#     event = Mock()
#     event.relation_name = VAULT_KV_RELATION_NAME
#     event.relation_id = rel_id
#     event.app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
#     event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
#     event.mount_suffix = "suffix"
#     event.egress_subnets = ["2.2.2.0/24"]
#     event.nonce = "123123"
#     self.harness.charm._on_new_vault_kv_client_attached(event)
#     kv_client_detached_event = Mock()
#     kv_client_detached_event.unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"
#     self.harness.charm._on_vault_kv_client_detached(kv_client_detached_event)
#     patch_remove_secret.assert_called()

# # Test Auto unseal

# @patch("ops.testing._TestingPebbleClient.restart_services", new=MagicMock)
# @patch(f"{VAULT_AUTOUNSEAL_LIB_PATH}.VaultAutounsealRequires.get_details")
# def test_given_autounseal_details_available_when_autounseal_details_ready_then_transit_stanza_generated(
#     self,
#     mock_get_details,
# ):
#     # Given
#     address = "some address"
#     key_name = "some key"
#     role_id = "role_id"
#     secret_id = "secret_id"
#     ca_cert = "ca_cert"
#     mock_get_details.return_value = AutounsealDetails(
#         address, AUTOUNSEAL_MOUNT_PATH, key_name, role_id, secret_id, ca_cert
#     )
#     relation_id = self.harness.add_relation(
#         relation_name="vault-autounseal-requires", remote_app="autounseal-provider"
#     )
#     self.harness.set_can_connect(self.container_name, True)
#     self.harness.add_storage(storage_name="config", attach=True)
#     self._set_peer_relation()
#     self.harness.update_relation_data(
#         app_or_unit=self.app_name,
#         relation_id=relation_id,
#         key_values={},
#     )
#     self.mock_vault.token = "some token"

#     # When
#     self.harness.charm.vault_autounseal_requires.on.vault_autounseal_details_ready.emit(
#         address, AUTOUNSEAL_MOUNT_PATH, key_name, role_id, secret_id, ca_cert
#     )

#     # Then
#     root = self.harness.get_filesystem_root(self.container_name)
#     pushed_content_hcl = hcl.loads((root / "vault/config/vault.hcl").read_text())
#     assert pushed_content_hcl["seal"]["transit"]["address"] == address
#     assert pushed_content_hcl["seal"]["transit"]["mount_path"] == AUTOUNSEAL_MOUNT_PATH
#     assert pushed_content_hcl["seal"]["transit"]["token"] == "some token"
#     assert pushed_content_hcl["seal"]["transit"]["key_name"] == "some key"
#     self.mock_vault.authenticate.assert_called_with(AppRole(role_id, secret_id))
#     self.mock_vault_tls_manager.push_autounseal_ca_cert.assert_called_with(ca_cert)

# @patch(f"{VAULT_AUTOUNSEAL_LIB_PATH}.VaultAutounsealProvides.set_autounseal_data")
# def test_when_autounseal_initialize_then_credentials_are_set(self, mock_set_autounseal_data):
#     # Given
#     self.mock_vault.configure_mock(
#         **{
#             "is_initialized.return_value": True,
#             "is_api_available.return_value": True,
#             "is_sealed.return_value": False,
#             "create_autounseal_credentials.return_value": (
#                 "key name",
#                 "autounseal role id",
#                 "autounseal secret id",
#             ),
#         },
#     )
#     self.harness.set_leader()
#     self.harness.set_can_connect(self.container_name, True)
#     self.harness.add_storage(storage_name="config", attach=True)
#     self._set_peer_relation()
#     self._set_approle_secret("role id", "secret id")
#     self.mock_vault_tls_manager.pull_tls_file_from_workload.return_value = "ca cert"
#     # Set the default network
#     self.harness.add_network("10.0.0.10")
#     # # When
#     relation_id = self.harness.add_relation(
#         relation_name="vault-autounseal-provides", remote_app="autounseal-requirer"
#     )

#     # Then
#     relation = self.harness.model.get_relation("vault-autounseal-provides", relation_id)
#     mock_set_autounseal_data.assert_called_once_with(
#         relation,
#         "https://10.0.0.10:8200",
#         AUTOUNSEAL_MOUNT_PATH,
#         "key name",
#         "autounseal role id",
#         "autounseal secret id",
#         "ca cert",
#     )

# def test_when_autounseal_destroy_then_credentials_are_removed(self):
#     # Given
#     self.mock_vault.configure_mock(
#         **{
#             "is_initialized.return_value": True,
#             "is_api_available.return_value": True,
#         },
#     )
#     self._set_approle_secret("role id", "secret id")
#     self.harness.set_leader()
#     self.harness.set_can_connect(self.container_name, True)
#     with self.harness.hooks_disabled():
#         relation_id = self.harness.add_relation(
#             relation_name="vault-autounseal-provides", remote_app="autounseal-requirer"
#         )
#         relation = self.harness.model.get_relation("vault-autounseal-provides", relation_id)

#     # When
#     self.harness.charm.vault_autounseal_provides.on.vault_autounseal_requirer_relation_broken.emit(
#         relation
#     )

#     # Then
#     self.mock_vault.destroy_autounseal_credentials.assert_called_once_with(
#         relation_id, AUTOUNSEAL_MOUNT_PATH
#     )
