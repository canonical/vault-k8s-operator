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


# def read_file(path: str) -> str:
#     """Read a file and returns as a string.

#     Args:
#         path (str): path to the file.

#     Returns:
#         str: content of the file.
#     """
#     with open(path, "r") as f:
#         content = f.read()
#     return content


# class MockNetwork:
#     def __init__(self, bind_address: str, ingress_address: str):
#         self.bind_address = bind_address
#         self.ingress_address = ingress_address


# class MockBinding:
#     def __init__(self, bind_address: str, ingress_address: str):
#         self.network = MockNetwork(bind_address=bind_address, ingress_address=ingress_address)


# class TestConfigFileContentMatches(unittest.TestCase):
#     def test_given_identical_vault_config_when_config_file_content_matches_returns_true(self):
#         existing_content = read_file("tests/unit/config.hcl")
#         new_content = read_file("tests/unit/config.hcl")

#         matches = config_file_content_matches(
#             existing_content=existing_content, new_content=new_content
#         )

#         self.assertTrue(matches)

#     def test_given_different_vault_config_when_config_file_content_matches_returns_false(self):
#         existing_content = read_file("tests/unit/config.hcl")
#         new_content = read_file("tests/unit/config_with_raft_peers.hcl")

#         matches = config_file_content_matches(
#             existing_content=existing_content, new_content=new_content
#         )

#         self.assertFalse(matches)

#     def test_given_equivalent_vault_config_when_config_file_content_matches_returns_true(self):
#         existing_content = read_file("tests/unit/config_with_raft_peers.hcl")
#         new_content = read_file("tests/unit/config_with_raft_peers_equivalent.hcl")

#         matches = config_file_content_matches(
#             existing_content=existing_content, new_content=new_content
#         )

#         self.assertTrue(matches)


# class TestCharm:
#     patcher_vault_tls_manager = patch("charm.VaultTLSManager", autospec=VaultTLSManager)
#     patcher_vault = patch("charm.Vault", autospec=Vault)

#     @pytest.fixture(autouse=True)
#     def setup(self):
#         self.mock_vault_tls_manager = TestCharm.patcher_vault_tls_manager.start().return_value
#         self.mock_vault = TestCharm.patcher_vault.start().return_value

#     @pytest.fixture(autouse=True)
#     def context(self):
#         self.ctx = scenario.Context(
#             charm_type=VaultCharm,
#         )

# self.model_name = "whatever"
# self.harness = testing.Harness(VaultCharm)
# self.addCleanup(self.harness.cleanup)
# self.harness.set_model_name(name=self.model_name)
# self.harness.begin()
# self.container_name = "vault"
# self.app_name = "vault-k8s"

# def tearDown(self):
#     TestCharm.patcher_vault_tls_manager.stop()
#     TestCharm.patcher_vault.stop()
#     # TestCharm.patcher_vault_autounseal_requires.stop()

# def get_valid_s3_params(self):
#     """Return a valid S3 parameters for mocking."""
#     return {
#         "bucket": "BUCKET",
#         "access-key": "whatever access key",
#         "secret-key": "whatever secret key",
#         "endpoint": "http://ENDPOINT",
#         "region": "REGION",
#     }

# def _set_peer_relation(self) -> int:
#     """Set the peer relation and return the relation id."""
#     return self.harness.add_relation(relation_name="vault-peers", remote_app=self.app_name)

# def _set_root_token_secret(self, token: str = "some token") -> str:
#     """Set the root token secret."""
#     content = {
#         "token": token,
#     }
#     original_leader_state = self.harness.charm.unit.is_leader()
#     with self.harness.hooks_disabled():
#         self.harness.set_leader(is_leader=True)
#         secret_id = self.harness.add_user_secret(content=content)
#         self.harness.grant_secret(secret_id, self.app_name)
#         self.harness.set_leader(original_leader_state)
#     return secret_id

# def _set_approle_secret(self, role_id: str, secret_id: str) -> None:
#     """Set the approle secret."""
#     content = {
#         "role-id": role_id,
#         "secret-id": secret_id,
#     }
#     original_leader_state = self.harness.charm.unit.is_leader()
#     with self.harness.hooks_disabled():
#         self.harness.set_leader(is_leader=True)
#         secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
#         secret = self.harness.model.get_secret(id=secret_id)
#         secret.set_info(label=VAULT_CHARM_APPROLE_SECRET_LABEL)
#         self.harness.set_leader(original_leader_state)

# def _set_ca_certificate_secret(self, private_key: str, certificate: str) -> None:
#     """Set the certificate secret."""
#     content = {
#         "certificate": certificate,
#         "privatekey": private_key,
#     }
#     original_leader_state = self.harness.charm.unit.is_leader()
#     with self.harness.hooks_disabled():
#         self.harness.set_leader(is_leader=True)
#         secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
#         secret = self.harness.model.get_secret(id=secret_id)
#         secret.set_info(label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
#         self.harness.set_leader(original_leader_state)

# def setup_vault_kv_relation(self) -> tuple:
#     app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
#     unit_name = app_name + "/0"
#     relation_name = VAULT_KV_RELATION_NAME

#     host_ip = "10.20.20.1"
#     self.harness.add_network(host_ip, endpoint="vault-kv")
#     self.harness.set_leader()
#     rel_id = self.harness.add_relation(relation_name, app_name)
#     unit_name = app_name + "/0"
#     egress_subnets = ["10.20.20.20/32"]
#     self.harness.add_relation_unit(rel_id, unit_name)
#     self.harness.update_relation_data(
#         rel_id, unit_name, {"egress_subnet": ",".join(egress_subnets), "nonce": "0"}
#     )

#     return (rel_id, egress_subnets)


# # Test configure
# @patch("ops.model.Container.restart", new=Mock)
# @patch("socket.getfqdn")
# def test_given_peer_relation_created_when_configure_then_config_file_is_pushed(
#     self,
#     patch_socket_getfqdn,
# ):
#     self.harness.set_leader(is_leader=True)
#     patch_socket_getfqdn.return_value = "myhostname"
#     root = self.harness.get_filesystem_root(self.container_name)
#     self.harness.add_storage(storage_name="config", attach=True)
#     self._set_peer_relation()
#     self._set_approle_secret(
#         role_id="whatever role id",
#         secret_id="whatever secret id",
#     )
#     self.harness.set_can_connect(container=self.container_name, val=True)

#     self.harness.charm.on.config_changed.emit()

#     pushed_content_hcl = hcl.loads((root / "vault/config/vault.hcl").read_text())
#     expected_content_hcl = hcl.loads(read_file("tests/unit/config.hcl"))
#     self.assertEqual(pushed_content_hcl, expected_content_hcl)

# @patch("ops.model.Container.restart", new=Mock)
# def test_given_peer_relation_created_when_configure_then_pebble_plan_is_set(
#     self,
# ):
#     self.harness.set_leader(is_leader=True)
#     self.harness.add_storage(storage_name="config", attach=True)
#     self._set_peer_relation()
#     self._set_approle_secret(
#         role_id="whatever role id",
#         secret_id="whatever secret id",
#     )
#     self.harness.set_can_connect(container=self.container_name, val=True)

#     self.harness.charm.on.config_changed.emit()

#     expected_plan = {
#         "services": {
#             "vault": {
#                 "override": "replace",
#                 "summary": "vault",
#                 "command": "vault server -config=/vault/config/vault.hcl",
#                 "startup": "enabled",
#             }
#         },
#     }
#     self.assertEqual(
#         self.harness.get_container_pebble_plan("vault").to_dict(),
#         expected_plan,
#     )

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

# # Test PKI
# @patch("charm.get_common_name_from_certificate", new=Mock)
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation")
# def test_given_vault_is_available_when_tls_certificates_pki_relation_joined_then_certificate_request_is_made(
#     self,
#     patch_request_certificate_creation,
# ):
#     self.harness.add_storage(storage_name="config", attach=True)
#     csr = "some csr content"
#     self.harness.update_config({"common_name": "vault"})
#     self.mock_vault.configure_mock(
#         **{
#             "is_initialized.return_value": True,
#             "is_api_available.return_value": True,
#             "is_sealed.return_value": False,
#             "get_intermediate_ca.return_value": "vault",
#             "generate_pki_intermediate_ca_csr.return_value": csr,
#         },
#     )
#     self.harness.set_leader(is_leader=True)
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self._set_peer_relation()
#     self._set_approle_secret(
#         role_id="root token content",
#         secret_id="whatever secret id",
#     )

#     relation_id = self.harness.add_relation(
#         relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
#     )
#     self.harness.add_relation_unit(relation_id, "tls-provider/0")

#     self.mock_vault.enable_secrets_engine.assert_called_with(SecretsBackend.PKI, PKI_MOUNT)
#     self.mock_vault.generate_pki_intermediate_ca_csr.assert_called_with(
#         mount=PKI_MOUNT, common_name="vault"
#     )
#     patch_request_certificate_creation.assert_called_with(
#         certificate_signing_request=csr.encode(), is_ca=True
#     )

# @patch("ops.model.Container.restart", new=Mock)
# @patch("charm.get_common_name_from_certificate", new=Mock)
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation")
# def test_given_vault_pki_configured_when_common_name_is_changed_then_new_certificate_request_is_made(
#     self,
#     patch_request_certificate_creation,
# ):
#     csr = "some csr content"
#     self.harness.update_config({"common_name": "vault"})
#     self.mock_vault.configure_mock(
#         **{
#             "is_initialized.return_value": True,
#             "is_api_available.return_value": True,
#             "get_intermediate_ca.return_value": "vault",
#             "generate_pki_intermediate_ca_csr.return_value": csr,
#             "is_sealed.return_value": False,
#         },
#     )
#     self.harness.set_leader(is_leader=True)
#     self.harness.add_storage(storage_name="config", attach=True)
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self._set_peer_relation()
#     self._set_approle_secret(
#         role_id="root token content",
#         secret_id="whatever secret id",
#     )

#     relation_id = self.harness.add_relation(
#         relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
#     )
#     self.harness.add_relation_unit(relation_id, "tls-provider/0")

#     self.mock_vault.enable_secrets_engine.assert_called_with(SecretsBackend.PKI, PKI_MOUNT)
#     self.mock_vault.generate_pki_intermediate_ca_csr.assert_called_with(
#         mount=PKI_MOUNT, common_name="vault"
#     )
#     patch_request_certificate_creation.assert_called_with(
#         certificate_signing_request=csr.encode(), is_ca=True
#     )
#     self.harness.update_config({"common_name": "new_common_name"})
#     self.mock_vault.generate_pki_intermediate_ca_csr.assert_called_with(
#         mount=PKI_MOUNT, common_name="new_common_name"
#     )
#     patch_request_certificate_creation.assert_called_with(
#         certificate_signing_request=csr.encode(), is_ca=True
#     )

# @patch("charm.get_common_name_from_csr", new=Mock)
# @patch("charm.get_common_name_from_certificate", new=Mock(return_value="vault"))
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation")
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_requirer_csrs")
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_provider_certificates")
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
# def test_given_vault_is_available_when_pki_certificate_is_available_then_certificate_added_to_vault_pki_and_latest_issuer_set_to_default(
#     self,
#     patch_get_assigned_certificates: MagicMock,
#     patch_get_provider_certificates: MagicMock,
#     patch_get_requirer_csrs: MagicMock,
#     patch_request_certificate_creation: MagicMock,
# ):
#     csr = "some csr content"
#     self.mock_vault.configure_mock(
#         **{
#             "is_initialized.return_value": True,
#             "is_sealed.return_value": False,
#             "is_api_available.return_value": True,
#             "is_pki_role_created.return_value": False,
#             "get_intermediate_ca.return_value": "vault",
#             "is_common_name_allowed_in_pki_role.return_value": False,
#             "generate_pki_intermediate_ca_csr.return_value": csr,
#         },
#     )
#     certificate = "some certificate"
#     ca = "some ca"
#     chain = [ca]
#     self.harness.update_config({"common_name": "vault"})
#     self.harness.set_leader(is_leader=True)
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self._set_peer_relation()
#     self._set_approle_secret(
#         role_id="root token content",
#         secret_id="whatever secret id",
#     )
#     relation_id = self.harness.add_relation(
#         relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
#     )
#     provider_certificate = ProviderCertificate(
#         relation_id=relation_id,
#         application_name="tls-provider",
#         csr=csr,
#         certificate=certificate,
#         ca=ca,
#         chain=chain,
#         revoked=False,
#         expiry_time=datetime.now(timezone.utc),
#     )
#     patch_get_assigned_certificates.return_value = [provider_certificate]
#     patch_get_provider_certificates.return_value = [provider_certificate]
#     patch_get_requirer_csrs.return_value = [Mock(csr=csr)]
#     self.harness.add_storage("config", attach=True)

#     # Reset mock counts, in case they were called during setup
#     self.mock_vault.reset_mock()
#     # When
#     self.harness.update_relation_data(
#         relation_id,
#         "tls-provider",
#         {
#             "certificates": json.dumps(
#                 [
#                     {
#                         "certificate_signing_request": "csr",
#                         "certificate": certificate,
#                         "ca": "ca",
#                         "chain": ["chain"],
#                     }
#                 ]
#             )
#         },
#     )

#     # Then
#     self.mock_vault.set_pki_intermediate_ca_certificate.assert_called_with(
#         certificate=certificate,
#         mount=PKI_MOUNT,
#     )
#     self.mock_vault.create_or_update_pki_charm_role.assert_called_with(
#         allowed_domains="vault", mount=PKI_MOUNT, role=PKI_ROLE_NAME
#     )
#     self.mock_vault.make_latest_pki_issuer_default.assert_called_with(mount=PKI_MOUNT)

# @patch("ops.model.Container.restart", new=Mock)
# @patch("charm.get_common_name_from_csr", new=Mock)
# @patch("charm.get_common_name_from_certificate")
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation")
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_requirer_csrs")
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_provider_certificates")
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
# def test_given_vault_pki_configured_when_common_name_is_changed_then_new_certificate_added_to_vault_pki(
#     self,
#     patch_get_assigned_certificates,
#     patch_get_provider_certificates,
#     patch_get_requirer_csrs,
#     patch_request_certificate_creation,
#     patch_get_common_name_from_certificate,
# ):
#     csr = "some csr content"
#     self.mock_vault.configure_mock(
#         **{
#             "is_initialized.return_value": True,
#             "is_sealed.return_value": False,
#             "is_api_available.return_value": True,
#             "is_pki_role_created.return_value": False,
#             "get_intermediate_ca.return_value": "vault",
#             "is_common_name_allowed_in_pki_role.return_value": False,
#             "generate_pki_intermediate_ca_csr.return_value": csr,
#         },
#     )
#     certificate = "some certificate"
#     ca = "some ca"
#     chain = [ca]
#     self.harness.update_config({"common_name": "vault"})
#     self.harness.set_leader(is_leader=True)
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self._set_peer_relation()
#     self._set_approle_secret(
#         role_id="root token content",
#         secret_id="whatever secret id",
#     )
#     relation_id = self.harness.add_relation(
#         relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
#     )
#     provider_certificate = ProviderCertificate(
#         relation_id=relation_id,
#         application_name="tls-provider",
#         csr=csr,
#         certificate=certificate,
#         ca=ca,
#         chain=chain,
#         revoked=False,
#         expiry_time=datetime.now(timezone.utc),
#     )
#     patch_get_assigned_certificates.return_value = [provider_certificate]
#     patch_get_provider_certificates.return_value = [provider_certificate]
#     patch_get_requirer_csrs.return_value = [Mock(csr=csr)]
#     self.harness.add_storage("config", attach=True)
#     patch_get_common_name_from_certificate.return_value = "new_common_name"

#     # Reset mock counts, in case they were called during setup
#     self.mock_vault.reset_mock()

#     # When
#     self.harness.update_config({"common_name": "new_common_name"})

#     # Then
#     self.mock_vault.set_pki_intermediate_ca_certificate.assert_called_with(
#         certificate=certificate,
#         mount=PKI_MOUNT,
#     )
#     self.mock_vault.create_or_update_pki_charm_role.assert_called_with(
#         allowed_domains="new_common_name", mount=PKI_MOUNT, role=PKI_ROLE_NAME
#     )

# @patch(
#     f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation",
#     new=Mock(),
# )
# @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate")
# @patch("charm.get_common_name_from_certificate")
# @patch("charm.get_common_name_from_csr")
# def test_given_vault_available_when_vault_pki_certificate_creation_request_then_certificate_is_provided(
#     self,
#     patch_get_common_name_from_csr,
#     patch_get_common_name_from_certificate,
#     patch_set_relation_certificate,
# ):
#     # Given
#     csr = "some csr content"
#     certificate = "some certificate"
#     ca = "some ca"
#     chain = [ca]
#     self.mock_vault.configure_mock(
#         **{
#             "is_initialized.return_value": True,
#             "is_sealed.return_value": False,
#             "is_api_available.return_value": True,
#             "is_pki_role_created.return_value": True,
#             "sign_pki_certificate_signing_request.return_value": Certificate(
#                 certificate=certificate,
#                 ca=ca,
#                 chain=chain,
#             ),
#         },
#     )
#     common_name = "vault"
#     # TODO: Use real certificates so we don't need to mock this out
#     patch_get_common_name_from_csr.return_value = common_name
#     patch_get_common_name_from_certificate.return_value = common_name
#     self.harness.update_config({"common_name": common_name})
#     self.harness.set_leader(is_leader=True)
#     self.harness.add_storage(storage_name="config", attach=True)
#     self.harness.set_can_connect(container=self.container_name, val=True)
#     self._set_peer_relation()
#     self._set_approle_secret(role_id="root token content", secret_id="whatever secret id")
#     self.harness.add_relation(
#         relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME,
#         remote_app="tls-provider",
#     )

#     # When
#     # TODO: Mock the lib so we don't need to deal with the databag
#     relation_id = self.harness.add_relation(
#         relation_name=PKI_RELATION_NAME,
#         remote_app="vault-cert-requirer",
#         unit_data={
#             "certificate_signing_requests": json.dumps([{"certificate_signing_request": csr}])
#         },
#     )

#     # Then
#     self.mock_vault.sign_pki_certificate_signing_request.assert_called_with(
#         mount=PKI_MOUNT,
#         csr=csr,
#         role=PKI_ROLE_NAME,
#         common_name=common_name,
#     )

#     patch_set_relation_certificate.assert_called_with(
#         relation_id=relation_id,
#         certificate_signing_request=csr,
#         certificate=certificate,
#         ca=ca,
#         chain=chain,
#     )

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
