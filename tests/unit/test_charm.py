#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import io
import json
import unittest
from typing import List
from unittest.mock import MagicMock, Mock, PropertyMock, call, patch

import hcl  # type: ignore[import-untyped]
import requests
from botocore.exceptions import BotoCoreError, ClientError, ConnectTimeoutError
from botocore.response import StreamingBody
from charm import (
    PKI_CSR_SECRET_LABEL,
    S3_RELATION_NAME,
    VAULT_INITIALIZATION_SECRET_LABEL,
    VaultCharm,
    config_file_content_matches,
)
from charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    CertificateCreationRequestEvent,
    ProviderCertificate,
)
from charms.vault_k8s.v0.vault_client import Certificate, Vault
from charms.vault_k8s.v0.vault_tls import CA_CERTIFICATE_JUJU_SECRET_LABEL
from ops import testing
from ops.model import ActiveStatus, WaitingStatus

S3_LIB_PATH = "charms.data_platform_libs.v0.s3"
VAULT_KV_LIB_PATH = "charms.vault_k8s.v0.vault_kv"
TLS_CERTIFICATES_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"
VAULT_KV_RELATION_NAME = "vault-kv"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
VAULT_KV_REQUIRER_APPLICATION_NAME = "vault-kv-requirer"


def read_file(path: str) -> str:
    """Read a file and returns as a string.

    Args:
        path (str): path to the file.

    Returns:
        str: content of the file.
    """
    with open(path, "r") as f:
        content = f.read()
    return content


class MockNetwork:
    def __init__(self, bind_address: str, ingress_address: str):
        self.bind_address = bind_address
        self.ingress_address = ingress_address


class MockBinding:
    def __init__(self, bind_address: str, ingress_address: str):
        self.network = MockNetwork(bind_address=bind_address, ingress_address=ingress_address)


class TestConfigFileContentMatches(unittest.TestCase):
    def test_given_identical_vault_config_when_config_file_content_matches_returns_true(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        self.assertTrue(matches)

    def test_given_different_vault_config_when_config_file_content_matches_returns_false(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config_with_raft_peers.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        self.assertFalse(matches)

    def test_given_equivalent_vault_config_when_config_file_content_matches_returns_true(self):
        existing_content = read_file("tests/unit/config_with_raft_peers.hcl")
        new_content = read_file("tests/unit/config_with_raft_peers_equivalent.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        self.assertTrue(matches)


class TestCharm(unittest.TestCase):
    @patch(
        "charm.KubernetesServicePatch",
        lambda charm, ports: None,
    )
    def setUp(self):
        self.model_name = "whatever"
        self.harness = testing.Harness(VaultCharm)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_model_name(name=self.model_name)
        self.harness.begin()
        self.container_name = "vault"
        self.app_name = "vault-k8s"

    def get_valid_s3_params(self):
        """Return a valid S3 parameters for mocking."""
        return {
            "bucket": "BUCKET",
            "access-key": "whatever access key",
            "secret-key": "whatever secret key",
            "endpoint": "http://ENDPOINT",
            "region": "REGION",
        }

    def _set_peer_relation(self) -> int:
        """Set the peer relation and return the relation id."""
        return self.harness.add_relation(relation_name="vault-peers", remote_app=self.app_name)

    def _set_initialization_secret_in_peer_relation(
        self, relation_id: int, root_token: str, unseal_keys: List[str]
    ) -> None:
        """Set the initialization secret in the peer relation."""
        content = {
            "roottoken": root_token,
            "unsealkeys": json.dumps(unseal_keys),
        }
        original_leader_state = self.harness.charm.unit.is_leader()
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
            secret = self.harness.model.get_secret(id=secret_id)
            secret.set_info(label=VAULT_INITIALIZATION_SECRET_LABEL)
            self.harness.set_leader(original_leader_state)
        key_values = {"vault-initialization-secret-id": secret_id}
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    def _set_csr_secret_in_peer_relation(self, relation_id: int, csr: str) -> None:
        """Set the csr secret in the peer relation."""
        content = {
            "csr": csr,
        }
        original_leader_state = self.harness.charm.unit.is_leader()
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
            secret = self.harness.model.get_secret(id=secret_id)
            secret.set_info(label=PKI_CSR_SECRET_LABEL)
            self.harness.set_leader(original_leader_state)
        key_values = {"vault-pki-csr-secret-id": secret_id}
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    def _set_ca_certificate_secret(self, private_key: str, certificate: str) -> None:
        """Set the certificate secret."""
        content = {
            "certificate": certificate,
            "privatekey": private_key,
        }
        original_leader_state = self.harness.charm.unit.is_leader()
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
            secret = self.harness.model.get_secret(id=secret_id)
            secret.set_info(label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
            self.harness.set_leader(original_leader_state)

    def _set_other_node_api_address_in_peer_relation(self, relation_id: int, unit_name: str):
        """Set the other node api address in the peer relation."""
        key_values = {"node_api_address": "http://5.2.1.9:8200"}
        self.harness.update_relation_data(
            app_or_unit=unit_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    def _set_tls_access_certificate_relation(self):
        """Set the peer relation and return the relation id."""
        return self.harness.add_relation(
            relation_name="tls-certificates-access", remote_app="some-tls-provider"
        )

    def setup_vault_kv_relation(self) -> tuple:
        app_name = VAULT_KV_REQUIRER_APPLICATION_NAME
        unit_name = app_name + "/0"
        relation_name = VAULT_KV_RELATION_NAME

        host_ip = "10.20.20.1"
        self.harness.add_network(host_ip, endpoint="vault-kv")
        self.harness.set_leader()
        rel_id = self.harness.add_relation(relation_name, app_name)
        unit_name = app_name + "/0"
        egress_subnet = "10.20.20.20/32"
        self.harness.add_relation_unit(rel_id, unit_name)
        self.harness.update_relation_data(
            rel_id, unit_name, {"egress_subnet": egress_subnet, "nonce": "0"}
        )

        return (rel_id, egress_subnet)

    @patch("ops.model.Container.remove_path")
    def test_given_can_connect_when_install_then_existing_data_is_removed(self, patch_remove_path):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.install.emit()

        patch_remove_path.assert_has_calls(
            calls=[
                call(path="/vault/raft/vault.db", recursive=False),
                call(path="/vault/raft/raft/raft.db", recursive=False),
            ]
        )

    def test_given_cant_connect_when_evaluate_status_then_status_is_waiting(self):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting to be able to connect to vault unit"),
        )

    def test_given_peer_relation_not_created_when_evaluate_status_then_status_is_waiting(self):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for peer relation"),
        )

    def test_given_bind_address_not_available_when_evaluate_status_then_status_is_waiting(self):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for bind and ingress addresses to be available"),
        )

    @patch("ops.model.Model.get_binding")
    def test_given_not_leader_and_init_secret_not_set_when_evaluate_status_then_status_is_waiting(
        self, patch_get_binding
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=False)
        peer_relation_id = self._set_peer_relation()
        other_unit_name = f"{self.app_name}/1"
        self.harness.add_relation_unit(
            relation_id=peer_relation_id, remote_unit_name=other_unit_name
        )
        self._set_other_node_api_address_in_peer_relation(
            relation_id=peer_relation_id, unit_name=other_unit_name
        )
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for initialization secret"),
        )

    @patch("charm.Vault", autospec=True)
    @patch("socket.getfqdn")
    @patch("ops.model.Model.get_binding")
    def test_given_peer_relation_created_when_configure_then_config_file_is_pushed(
        self,
        patch_get_binding,
        patch_socket_getfqdn,
        mock_vault_class,
    ):
        self.harness.set_leader(is_leader=True)
        patch_socket_getfqdn.return_value = "myhostname"
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=relation_id,
            root_token="whatever root token",
            unseal_keys=["whatever unseal key"],
        )
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="1.1.1.1"
        )
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.config_changed.emit()

        pushed_content_hcl = hcl.loads((root / "vault/config/vault.hcl").read_text())
        expected_content_hcl = hcl.loads(read_file("tests/unit/config.hcl"))
        self.assertEqual(pushed_content_hcl, expected_content_hcl)

    @patch("charm.Vault", autospec=True)
    @patch("ops.model.Model.get_binding")
    def test_given_peer_relation_created_when_configure_then_pebble_plan_is_set(
        self,
        patch_get_binding,
        mock_vault_class,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=relation_id,
            root_token="whatever root token",
            unseal_keys=["whatever unseal key"],
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="1.1.1.1"
        )

        self.harness.charm.on.config_changed.emit()

        expected_plan = {
            "services": {
                "vault": {
                    "override": "replace",
                    "summary": "vault",
                    "command": "vault server -config=/vault/config/vault.hcl",
                    "startup": "enabled",
                }
            },
        }
        self.assertEqual(
            self.harness.get_container_pebble_plan("vault").to_dict(),
            expected_plan,
        )

    @patch("charm.VaultCharm._ingress_address", new=PropertyMock(return_value="1.1.1.1"))
    @patch("charm.Vault", autospec=True)
    @patch("ops.model.Model.get_binding")
    def test_given_api_not_available_when_evaluate_status_then_status_is_waiting(
        self,
        patch_get_binding,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": False,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="1.1.1.1"
        )

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for vault to be available"),
        )

    @patch("charm.Vault", autospec=True)
    @patch("ops.model.Model.get_binding")
    def test_given_vault_not_initialized_when_configure_then_vault_initialized(
        self,
        patch_get_binding,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
                "initialize.return_value": ("root token", ["unseal key 1"]),
            },
        )
        mock_vault_class.return_value = mock_vault
        self._set_peer_relation()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="1.1.1.1"
        )

        self.harness.charm.on.config_changed.emit()

        mock_vault.initialize.assert_called_once()
        init_secret = self.harness.model.get_secret(
            label=VAULT_INITIALIZATION_SECRET_LABEL
        ).get_content()
        self.assertEqual(
            init_secret,
            {"roottoken": "root token", "unsealkeys": '["unseal key 1"]'},
        )

    @patch("charm.Vault", autospec=True)
    @patch("ops.model.Model.get_binding")
    def test_given_api_available_when_evaluate_status_then_status_is_active(
        self,
        patch_get_binding,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
                "initialize.return_value": ("root token", ["unseal key 1"]),
            },
        )
        mock_vault_class.return_value = mock_vault

        self._set_peer_relation()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "vault/certs/ca.pem").write_text("some ca")
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="1.1.1.1"
        )

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            ActiveStatus(),
        )

    @patch("charm.Vault", autospec=True)
    @patch("ops.model.Model.get_binding")
    def test_given_audit_device_not_enabled_when_configure_then_audit_device_is_enabled(
        self,
        patch_get_binding,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
                "is_active.return_value": True,
                "audit_device_enabled.return_value": False,
                "initialize.return_value": ("root token", ["unseal key 1"]),
            },
        )
        mock_vault_class.return_value = mock_vault
        self._set_peer_relation()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="1.1.1.1"
        )

        self.harness.charm.on.config_changed.emit()

        mock_vault.enable_audit_device.assert_called_with(device_type="file", path="stdout")

    def test_given_can_connect_when_on_remove_then_raft_storage_path_is_deleted(self):
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.add_storage(storage_name="vault-raft", attach=True)
        (root / "vault/raft/raft").mkdir(parents=True)
        (root / "vault/raft/vault.db").write_text("whatever vault content")
        (root / "vault/raft/raft/raft.db").write_text("whatever raft content")

        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.remove.emit()

        self.assertFalse((root / "vault/raft/vault.db").exists())
        self.assertFalse((root / "vault/raft/raft/raft.db").exists())

    @patch("ops.model.Model.get_binding")
    @patch("charm.Vault", autospec=True)
    def test_given_node_in_raft_when_on_remove_then_node_is_removed_from_raft(
        self,
        mock_vault_class,
        patch_get_binding,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_node_in_raft_peers.return_value": True,
                "get_num_raft_peers.return_value": 2,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_storage(storage_name="certs", attach=True)
        bind_address = "1.2.3.4"
        ingress_address = "10.1.0.1"
        patch_get_binding.return_value = MockBinding(
            bind_address=bind_address, ingress_address=ingress_address
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        self.harness.charm.on.remove.emit()

        mock_vault.remove_raft_node.assert_called_with(
            node_id=f"{self.model_name}-{self.app_name}/0"
        )

    @patch("charm.Vault", autospec=True)
    def test_given_node_not_in_raft_when_on_remove_then_node_is_not_removed_from_raft(
        self,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_node_in_raft_peers.return_value": False,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        self.harness.charm.on.remove.emit()

        mock_vault.remove_raft_node.assert_not_called()

    @patch("charm.Vault", autospec=True)
    @patch("ops.model.Container.get_service", new=Mock)
    @patch("ops.model.Container.stop")
    def test_given_service_is_running_when_on_remove_then_service_is_stopped(
        self,
        patch_stop_service,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_node_in_raft_peers.return_value": False,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        self.harness.charm.on.remove.emit()

        patch_stop_service.assert_called_with("vault")

    def test_given_s3_relation_not_created_when_create_backup_action_then_action_fails(self):
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="S3 relation not created. Failed to perform backup.")

    def test_given_unit_not_leader_when_create_backup_action_then_action_fails(self):
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="Only leader unit can perform backup operations.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_missing_s3_parameters_when_create_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {}
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_once()
        call_args = event.fail.call_args[1]["message"]
        self.assertIn("S3 parameters missing.", call_args)

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_s3_session_not_created_when_create_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {
            "bucket": "whatever bucket",
            "access-key": "whatever access key",
            "secret-key": "whatever secret key",
            "endpoint": "whatever endpoint",
        }
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="Failed to create S3 session.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.create_bucket")
    def test_given_bucket_creation_raises_an_exception_when_create_backup_action_then_action_fails(
        self,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_create_bucket.return_value = False
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="Failed to create S3 bucket.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.create_bucket")
    def test_given_bucket_creation_raises_connect_timeout_error_when_create_backup_action_then_action_fails(
        self,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_create_bucket.side_effect = ConnectTimeoutError(endpoint_url="http://example.com")
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="Timeout trying to connect to S3 endpoint.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.create_bucket")
    @patch("charm.Vault", autospec=True)
    def test_given_vault_is_not_initialized_when_create_backup_action_then_action_fails(
        self,
        mock_vault_class,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": False,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_storage(storage_name="certs", attach=True)
        patch_create_bucket.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="Failed to create raft snapshot.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.create_bucket")
    @patch("charm.Vault", autospec=True)
    def test_given_vault_api_not_available_when_create_backup_action_then_action_fails(
        self,
        mock_vault_class,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": False,
                "is_initialized.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        patch_create_bucket.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="Failed to create raft snapshot.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.create_bucket")
    @patch("charm.Vault", autospec=True)
    def test_given_vault_initialization_secret_not_available_create_backup_action_then_action_fails(
        self,
        mock_vault_class,
        patch_create_bucket,
        patch_get_s3_connection_info,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        patch_create_bucket.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="Failed to create raft snapshot.")

    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.create_bucket")
    def test_given_snapshot_creation_fails_when_create_backup_action_then_action_fails(
        self,
        patch_create_bucket,
        patch_get_s3_connection_info,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        patch_create_bucket.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="Failed to create raft snapshot.")

    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.create_bucket")
    @patch("s3_session.S3.upload_content")
    def test_given_s3_content_upload_fails_when_create_backup_action_then_action_fails(
        self,
        patch_upload_content,
        patch_create_bucket,
        patch_get_s3_connection_info,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        patch_create_bucket.return_value = True
        patch_upload_content.return_value = False
        peer_relation_id = self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="Failed to upload backup to S3 bucket.")

    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.create_bucket")
    @patch("s3_session.S3.upload_content")
    def test_given_s3_content_upload_raises_connect_timeout_error_when_create_backup_action_then_action_fails(
        self,
        patch_upload_content,
        patch_create_bucket,
        patch_get_s3_connection_info,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        patch_create_bucket.return_value = True
        patch_upload_content.side_effect = ConnectTimeoutError(endpoint_url="http://example.com")
        peer_relation_id = self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.fail.assert_called_with(message="Timeout trying to connect to S3 endpoint.")

    @patch("s3_session.S3.create_bucket")
    @patch("s3_session.S3.upload_content")
    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_content_uploaded_to_s3_when_create_backup_action_then_action_succeeds(
        self,
        patch_get_s3_connection_info,
        mock_vault_class,
        patch_upload_content,
        patch_create_bucket,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_api_available.return_value": True,
                "is_initialized.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        patch_upload_content.return_value = True
        patch_create_bucket.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        event = Mock()
        self.harness.charm._on_create_backup_action(event)
        event.set_results.assert_called()

    def test_given_s3_relation_not_created_when_list_backups_action_then_action_fails(self):
        self.harness.set_leader(is_leader=True)
        event = Mock()
        self.harness.charm._on_list_backups_action(event)
        event.fail.assert_called_with(message="S3 relation not created. Failed to list backups.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_unit_not_leader_when_list_backups_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        event = Mock()
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_list_backups_action(event)
        event.fail.assert_called_with(message="Only leader unit can list backups.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_missing_s3_parameters_when_list_backups_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {}
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_list_backups_action(event)
        event.fail.assert_called_once()
        call_args = event.fail.call_args[1]["message"]
        self.assertIn("S3 parameters missing.", call_args)

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_s3_session_not_created_when_list_backups_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {
            "bucket": "whatever bucket",
            "access-key": "whatever access key",
            "secret-key": "whatever secret key",
            "endpoint": "whatever endpoint",
        }
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_list_backups_action(event)
        event.fail.assert_called_with(message="Failed to create S3 session.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.get_object_key_list")
    def test_given_get_object_list_raises_an_exception_when_list_backups_action_then_action_fails(
        self,
        patch_get_object_key_list,
        patch_get_s3_connection_info,
    ):
        patch_get_object_key_list.side_effect = ClientError(
            operation_name="Error",
            error_response={"Error": {"Message": "Random bucket related error message"}},
        )

        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_list_backups_action(event)
        event.fail.assert_called_with(message="Failed to list backups.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.get_object_key_list")
    def test_given_get_object_list_raises_connect_timeout_error_when_list_backups_action_then_action_fails(
        self,
        patch_get_object_key_list,
        patch_get_s3_connection_info,
    ):
        patch_get_object_key_list.side_effect = ConnectTimeoutError(
            endpoint_url="http://example.com"
        )

        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_list_backups_action(event)
        event.fail.assert_called_with(message="Timeout trying to connect to S3 endpoint.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.get_object_key_list")
    def test_given_backups_in_s3_when_list_backups_action_then_action_succeeds_with_backup_list(
        self,
        patch_get_object_key_list,
        patch_get_s3_connection_info,
    ):
        patch_get_object_key_list.return_value = ["backup1", "backup2"]
        expected_backup_list = ["backup1", "backup2"]
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_list_backups_action(event)
        event.set_results.assert_called_with({"backup-ids": json.dumps(expected_backup_list)})

    def test_given_s3_relation_not_created_when_restore_backup_action_then_action_fails(self):
        self.harness.set_leader(is_leader=True)
        event = Mock()
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_with(message="S3 relation not created. Failed to restore backup.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_unit_not_leader_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        event = Mock()
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_with(message="Only leader unit can restore backups.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_missing_s3_parameters_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {}
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_once()
        call_args = event.fail.call_args[1]["message"]
        self.assertIn("S3 parameters missing.", call_args)

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_s3_session_not_created_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
    ):
        patch_get_s3_connection_info.return_value = {
            "bucket": "whatever bucket",
            "access-key": "whatever access key",
            "secret-key": "whatever secret key",
            "endpoint": "whatever endpoint",
        }
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_with(message="Failed to create S3 session.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.get_content")
    def test_given_get_content_raises_clienterror_when_restore_backup_action_then_action_fails(
        self,
        patch_get_content,
        patch_get_s3_connection_info,
    ):
        patch_get_content.side_effect = ClientError(
            operation_name="Error",
            error_response={"Error": {"Message": "Random bucket related error message"}},
        )

        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_with(message="Failed to retrieve snapshot from S3 storage.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.get_content")
    def test_given_get_content_raises_botocoreerror_when_restore_backup_action_then_action_fails(
        self,
        patch_get_content,
        patch_get_s3_connection_info,
    ):
        patch_get_content.side_effect = BotoCoreError()

        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_with(message="Failed to retrieve snapshot from S3 storage.")

    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    @patch("s3_session.S3.get_content")
    def test_given_get_content_raises_connect_timeout_error_when_restore_backup_action_then_action_fails(
        self,
        patch_get_content,
        patch_get_s3_connection_info,
    ):
        patch_get_content.side_effect = ConnectTimeoutError(endpoint_url="http://example.com")
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        event = Mock()
        self.harness.set_leader(is_leader=True)
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_with(message="Timeout trying to connect to S3 endpoint.")

    @patch("s3_session.S3.get_content")
    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_not_initialized_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        mock_vault_class,
        patch_get_content,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": False,
            },
        )
        mock_vault_class.return_value = mock_vault
        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self.harness.add_storage(storage_name="certs", attach=True)
        event = Mock()
        event.params = {
            "backup-id": "whatever backup id",
            "root-token": "whatever root token",
            "unseal-keys": ["whatever unseal keys"],
        }
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_with(message="Failed to restore vault.")

    @patch("s3_session.S3.get_content")
    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_api_not_available_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        mock_vault_class,
        patch_get_content,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": False,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self.harness.add_storage(storage_name="certs", attach=True)
        event = Mock()
        event.params = {
            "backup-id": "whatever backup id",
            "root-token": "whatever root token",
            "unseal-keys": ["whatever unseal keys"],
        }
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_with(message="Failed to restore vault.")

    @patch("s3_session.S3.get_content")
    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_initialization_secret_not_available_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        mock_vault_class,
        patch_get_content,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self.harness.add_storage(storage_name="certs", attach=True)
        event = Mock()
        event.params = {
            "backup-id": "whatever backup id",
            "root-token": "whatever root token",
            "unseal-keys": ["whatever unseal keys"],
        }
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_with(message="Failed to restore vault.")

    @patch("s3_session.S3.get_content")
    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_restoring_snapshot_fails_when_restore_backup_action_then_action_fails(
        self,
        patch_get_s3_connection_info,
        mock_vault_class,
        patch_get_content,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "restore_snapshot.return_value": MagicMock(
                    status_code=500, spec=requests.Response
                ),
                "is_api_available.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        event = Mock()
        event.params = {
            "backup-id": "whatever backup id",
            "root-token": "whatever root token",
            "unseal-keys": ["whatever unseal keys"],
        }
        self.harness.charm._on_restore_backup_action(event)
        event.fail.assert_called_with(message="Failed to restore vault.")

    @patch("s3_session.S3.get_content")
    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_snapshot_is_restored_when_restore_backup_action_then_action_succeeds(
        self,
        patch_get_s3_connection_info,
        mock_vault_class,
        patch_get_content,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "restore_snapshot.return_value": MagicMock(
                    status_code=200, spec=requests.Response
                ),
                "is_api_available.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        event = Mock()
        event.params = {
            "backup-id": "whatever backup id",
            "root-token": "whatever root token",
            "unseal-keys": ["whatever unseal keys"],
        }

        self.harness.charm._on_restore_backup_action(event)
        event.set_results.assert_called_with({"restored": "whatever backup id"})

    @patch("s3_session.S3.get_content")
    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_restore_snapshot_fails_when_restore_backup_action_then_initialization_secret_is_unchanged(
        self,
        patch_get_s3_connection_info,
        mock_vault_class,
        patch_get_content,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "restore_snapshot.return_value": MagicMock(
                    status_code=500, spec=requests.Response
                ),
                "is_api_available.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="original token content",
            unseal_keys=["original_unseal_keys"],
        )
        event = Mock()
        event.params = {
            "backup-id": "whatever backup id",
            "root-token": "backup root token",
            "unseal-keys": ["backup_unseal_keys"],
        }
        self.harness.charm._on_restore_backup_action(event)
        init_secret = self.harness.model.get_secret(
            label=VAULT_INITIALIZATION_SECRET_LABEL
        ).get_content(refresh=True)
        self.assertEqual(
            init_secret,
            {"roottoken": "original token content", "unsealkeys": '["original_unseal_keys"]'},
        )

    @patch("s3_session.S3.get_content")
    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_snapshot_is_restored_when_restore_backup_action_then_initialization_secret_is_updated(
        self,
        patch_get_s3_connection_info,
        mock_vault_class,
        patch_get_content,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "restore_snapshot.return_value": MagicMock(
                    status_code=200, spec=requests.Response
                ),
                "is_api_available.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="original token content",
            unseal_keys=["original_unseal_keys"],
        )
        event = Mock()
        event.params = {
            "backup-id": "whatever backup id",
            "root-token": "backup root token",
            "unseal-keys": ["backup_unseal_keys"],
        }

        self.harness.charm._on_restore_backup_action(event)

        init_secret = self.harness.model.get_secret(
            label=VAULT_INITIALIZATION_SECRET_LABEL
        ).get_content(refresh=True)
        self.assertEqual(
            init_secret,
            {"roottoken": "backup root token", "unsealkeys": '["backup_unseal_keys"]'},
        )

    @patch("s3_session.S3.get_content")
    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_snapshot_is_restored_when_restore_backup_action_then_vault_is_unsealed_with_new_keys(
        self,
        patch_get_s3_connection_info,
        mock_vault_class,
        patch_get_content,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "restore_snapshot.return_value": MagicMock(
                    status_code=200, spec=requests.Response
                ),
                "is_api_available.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="original token content",
            unseal_keys=["original_unseal_keys"],
        )
        event = Mock()
        event.params = {
            "backup-id": "whatever backup id",
            "root-token": "backup root token",
            "unseal-keys": ["backup_unseal_keys"],
        }

        self.harness.charm._on_restore_backup_action(event)

        mock_vault.unseal.assert_called_with(unseal_keys=["backup_unseal_keys"])

    @patch("s3_session.S3.get_content")
    @patch("charm.Vault", autospec=True)
    @patch(f"{S3_LIB_PATH}.S3Requirer.get_s3_connection_info")
    def test_given_vault_snapshot_is_restored_when_restore_backup_action_then_new_vault_root_token_is_set(
        self,
        patch_get_s3_connection_info,
        mock_vault_class,
        patch_get_content,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "restore_snapshot.return_value": MagicMock(
                    status_code=200, spec=requests.Response
                ),
                "is_api_available.return_value": True,
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_relation(relation_name=S3_RELATION_NAME, remote_app="s3-integrator")
        self.harness.set_leader(is_leader=True)
        patch_get_s3_connection_info.return_value = self.get_valid_s3_params()
        patch_get_content.return_value = StreamingBody(
            io.BytesIO(b"whatever content"), content_length=len(b"whatever content")
        )
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="original token content",
            unseal_keys=["original_unseal_keys"],
        )
        event = Mock()
        event.params = {
            "backup-id": "whatever backup id",
            "root-token": "backup root token",
            "unseal-keys": ["backup_unseal_keys"],
        }

        self.harness.charm._on_restore_backup_action(event)

        mock_vault.set_token.assert_called_with(token="backup root token")

    @patch("charm.Vault", autospec=True)
    def test_given_unit_not_leader_when_set_unseal_keys_action_then_action_fails(
        self, mock_vault_class
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        event = Mock()
        self.harness.charm._on_set_unseal_keys_action(event)
        event.fail.assert_called_with(message="Only leader unit can set unseal keys.")

    @patch("charm.Vault", autospec=True)
    def test_given_vault_not_initialized_when_set_unseal_keys_action_then_action_fails(
        self,
        mock_vault_class,
    ):
        mock_vault = MagicMock(spec=Vault, **{"is_initialized.return_value": False})
        mock_vault_class.return_value = mock_vault

        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_leader(is_leader=True)
        event = Mock()
        self.harness.charm._on_set_unseal_keys_action(event)
        event.fail.assert_called_with(
            message="Cannot set unseal keys, vault is not initialized yet."
        )

    @patch("charm.Vault", autospec=True)
    def test_given_provided_unseal_keys_match_current_when_set_unseal_keys_action_then_action_fails(
        self,
        mock_vault_class,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_key1", "unseal_key2"],
        )
        self.harness.set_leader(is_leader=True)
        event = Mock()
        event.params = {"unseal-keys": ["unseal_key2", "unseal_key1"]}
        self.harness.charm._on_set_unseal_keys_action(event)
        event.fail.assert_called_with(message="Provided unseal keys are already set.")

    @patch("charm.Vault", autospec=True)
    def test_given_new_unseal_keys_and_unit_is_leader_and_vault_is_initialized_when_set_unseal_keys_action_then_unseal_keys_are_set_in_secret(  # noqa: E501
        self,
        mock_vault_class,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_key1", "unseal_key2"],
        )
        self.harness.set_leader(is_leader=True)
        event = Mock()
        event.params = {"unseal-keys": ["new unseal key1", "new unseal key2"]}
        self.harness.charm._on_set_unseal_keys_action(event)
        init_secret = self.harness.model.get_secret(
            label=VAULT_INITIALIZATION_SECRET_LABEL
        ).get_content(refresh=True)
        self.assertEqual(
            init_secret,
            {
                "roottoken": "root token content",
                "unsealkeys": '["new unseal key1", "new unseal key2"]',
            },
        )

    @patch("charm.Vault", autospec=True)
    def test_given_new_unseal_keys_and_unit_is_leader_and_vault_is_initialized_when_set_unseal_keys_action_then_vault_is_unsealed(  # noqa: E501
        self,
        mock_vault_class,
    ):
        mock_vault = MagicMock(spec=Vault)
        mock_vault_class.return_value = mock_vault
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_key1", "unseal_key2"],
        )
        self.harness.set_leader(is_leader=True)
        event = Mock()
        event.params = {"unseal-keys": ["new unseal key1", "new unseal key2"]}
        self.harness.charm._on_set_unseal_keys_action(event)
        mock_vault.unseal.assert_called_with(unseal_keys=["new unseal key1", "new unseal key2"])

    @patch("charm.Vault", autospec=True)
    def test_given_new_unseal_keys_and_unit_is_leader_and_vault_is_initialized_when_set_unseal_keys_action_then_action_succeeds(  # noqa: E501
        self,
        mock_vault_class,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_key1", "unseal_key2"],
        )
        self.harness.set_leader(is_leader=True)
        event = Mock()
        event.params = {"unseal-keys": ["new unseal key1", "new unseal key2"]}
        self.harness.charm._on_set_unseal_keys_action(event)
        event.set_results.assert_called_with(
            {"unseal-keys": ["new unseal key1", "new unseal key2"]}
        )

    @patch("charm.Vault", autospec=True)
    def test_given_unit_not_leader_when_set_root_token_action_then_action_fails(
        self, mock_vault_class
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        event = Mock()
        self.harness.charm._on_set_root_token_action(event)
        event.fail.assert_called_with(message="Only leader unit can set the root token.")

    @patch("charm.Vault", autospec=True)
    def test_given_vault_not_initialized_when_set_root_token_action_then_action_fails(
        self,
        mock_vault_class,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_leader(is_leader=True)
        event = Mock()
        self.harness.charm._on_set_root_token_action(event)
        event.fail.assert_called_with(
            message="Cannot set root token, vault is not initialized yet."
        )

    @patch("charm.Vault", autospec=True)
    def test_given_provided_root_token_matches_current_when_set_root_token_action_then_action_fails(
        self,
        mock_vault_class,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_key1", "unseal_key2"],
        )
        self.harness.set_leader(is_leader=True)
        event = Mock()
        event.params = {"root-token": "root token content"}
        self.harness.charm._on_set_root_token_action(event)
        event.fail.assert_called_with(message="Provided root token is already set.")

    @patch("charm.Vault", autospec=True)
    def test_given_new_root_token_and_unit_is_leader_and_vault_is_initialized_when_set_root_token_action_then_root_token_is_set_in_secret(  # noqa: E501
        self,
        mock_vault_class,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_key1", "unseal_key2"],
        )
        self.harness.set_leader(is_leader=True)
        event = Mock()
        event.params = {"root-token": "new root token content"}
        self.harness.charm._on_set_root_token_action(event)
        init_secret = self.harness.model.get_secret(
            label=VAULT_INITIALIZATION_SECRET_LABEL
        ).get_content(refresh=True)
        self.assertEqual(
            init_secret,
            {
                "roottoken": "new root token content",
                "unsealkeys": '["unseal_key1", "unseal_key2"]',
            },
        )

    @patch("charm.Vault", autospec=True)
    def test_given_new_root_token_and_unit_is_leader_and_vault_is_initialized_when_set_root_token_action_then_vault_root_token_is_set(  # noqa: E501
        self,
        mock_vault_class,
    ):
        mock_vault = MagicMock(spec=Vault)
        mock_vault_class.return_value = mock_vault

        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_key1", "unseal_key2"],
        )
        self.harness.set_leader(is_leader=True)
        event = Mock()
        event.params = {"root-token": "new root token content"}
        self.harness.charm._on_set_root_token_action(event)
        mock_vault.set_token.assert_called_with(token="new root token content")

    @patch("charm.Vault", autospec=True)
    def test_given_new_root_token_and_unit_is_leader_and_vault_is_initialized_when_set_root_token_action_then_action_succeeds(  # noqa: E501
        self,
        mock_vault_class,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_key1", "unseal_key2"],
        )
        self.harness.set_leader(is_leader=True)
        event = Mock()
        event.params = {"root-token": "new root token content"}
        self.harness.charm._on_set_root_token_action(event)
        event.set_results.assert_called_with({"root-token": "new root token content"})

    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_unit_credentials")
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_ca_certificate")
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_mount")
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_vault_url")
    def test_given_unit_not_leader_when_new_vault_kv_client_attached_then_event_kv_relation_data_not_set(
        self,
        patch_set_vault_url,
        patch_set_mount,
        patch_set_ca_certificate,
        patch_audit_device_enabled,
    ):
        self.harness.set_leader(is_leader=False)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        vault_kv_relation_name = "vault-kv"
        vault_kv_relation_id = self.harness.add_relation(
            relation_name=vault_kv_relation_name, remote_app="vault-kv-remote"
        )
        self.harness.add_relation_unit(
            relation_id=vault_kv_relation_id, remote_unit_name="vault-kv-remote/0"
        )
        event = Mock()
        self.harness.charm._on_new_vault_kv_client_attached(event)
        patch_set_vault_url.assert_not_called()
        patch_set_mount.assert_not_called()
        patch_set_ca_certificate.assert_not_called()
        patch_audit_device_enabled.assert_not_called()

    def test_given_peer_relation_not_created_when_new_vault_kv_client_attached_then_event_is_deferred(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        event = Mock()
        self.harness.charm._on_new_vault_kv_client_attached(event)
        event.defer.assert_called_with()

    @patch("charm.Vault", autospec=True)
    def test_given_vault_not_initialized_when_new_vault_kv_client_attached_then_event_is_deferred(
        self,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": False,
            },
        )
        mock_vault_class.return_value = mock_vault
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        event = Mock()
        self.harness.add_relation(relation_name="vault-peers", remote_app="vault")
        self.harness.charm._on_new_vault_kv_client_attached(event)
        event.defer.assert_called_with()

    @patch("charm.Vault", autospec=True)
    def test_given_initialization_secret_not_set_in_peer_relation_when_new_vault_kv_client_attached_then_event_is_deferred(
        self,
        mock_vault_class,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        event = Mock()
        self.harness.add_relation(relation_name="vault-peers", remote_app="vault")
        self._set_ca_certificate_secret(
            certificate="whatever certificate",
            private_key="whatever private key",
        )
        self.harness.charm._on_new_vault_kv_client_attached(event)
        event.defer.assert_called_with()

    @patch("charm.Vault", autospec=True)
    def test_given_ca_certificate_secret_not_set_in_peer_relation_when_new_vault_kv_client_attached_then_event_is_deferred(
        self,
        mock_vault_class,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        event = Mock()
        peer_relation_id = self.harness.add_relation(
            relation_name="vault-peers", remote_app="vault"
        )
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        self.harness.charm._on_new_vault_kv_client_attached(event)
        event.defer.assert_called_with()

    @patch("charm.Vault", autospec=True)
    @patch("ops.model.Model.get_binding")
    def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_approle_auth_is_enabled(
        self,
        patch_get_binding,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "configure_approle.return_value": "12345678",
                "generate_role_secret_id.return_value": "11111111",
            },
        )
        mock_vault_class.return_value = mock_vault
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )
        peer_relation_id = self.harness.add_relation(
            relation_name="vault-peers", remote_app="vault"
        )
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "vault/certs/ca.pem").write_text("some ca")
        self.harness.set_can_connect(container=self.container_name, val=True)
        event = Mock()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        rel_id, _ = self.setup_vault_kv_relation()
        event = Mock()
        event.relation_name = VAULT_KV_RELATION_NAME
        event.relation_id = rel_id
        event.mount_suffix = "suffix"
        self.harness.charm._on_new_vault_kv_client_attached(event)
        mock_vault.enable_approle_auth.assert_called_once()

    @patch("charm.Vault", autospec=True)
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_ca_certificate")
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_mount")
    @patch(f"{VAULT_KV_LIB_PATH}.VaultKvProvides.set_vault_url")
    @patch("ops.model.Model.get_binding")
    def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_kv_relation_data_is_set(
        self,
        patch_get_binding,
        set_vault_url,
        set_mount,
        set_ca_certificate,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "configure_approle.return_value": "12345678",
                "generate_role_secret_id.return_value": "11111111",
            },
        )
        mock_vault_class.return_value = mock_vault
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )
        peer_relation_id = self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "vault/certs/ca.pem").write_text("some ca")
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        rel_id, _ = self.setup_vault_kv_relation()
        event = Mock()
        event.relation_name = VAULT_KV_RELATION_NAME
        event.relation_id = rel_id
        event.mount_suffix = "suffix"
        self.harness.charm._on_new_vault_kv_client_attached(event)
        self.harness.get_relation_data(rel_id, self.app_name)
        set_vault_url.assert_called()
        set_mount.assert_called()
        set_ca_certificate.assert_called()

    @patch("charm.Vault", autospec=True)
    def test_given_prerequisites_are_met_when_related_kv_client_unit_egress_is_updated_then_secret_content_is_updated(
        self,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "configure_approle.return_value": "12345678",
                "generate_role_secret_id.return_value": "11111111",
            },
        )
        mock_vault_class.return_value = mock_vault

        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "vault/certs/ca.pem").write_text("some ca")
        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        rel_id, egress_subnet = self.setup_vault_kv_relation()
        mock_vault.read_role_secret.return_value = {"cidr_list": [egress_subnet]}

        mount_suffix = "whatever-suffix"
        self.harness.update_relation_data(
            rel_id, VAULT_KV_REQUIRER_APPLICATION_NAME, {"mount_suffix": mount_suffix}
        )
        unit_name = f"{VAULT_KV_REQUIRER_APPLICATION_NAME}/0"

        with patch("ops.Secret.set_content") as set_content:
            self.harness.update_relation_data(
                rel_id, unit_name, {"egress_subnet": "10.20.20.240/32"}
            )
            assert set_content.call_count == 1

    @patch("charm.Vault", autospec=True)
    @patch("ops.model.Model.get_binding")
    def test_given_prerequisites_are_met_when_new_vault_kv_client_attached_then_kv_mount_is_configured(
        self,
        patch_get_binding,
        mock_vault_class,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_secret_engine_enabled.return_value": False,
                "configure_approle.return_value": "12345678",
                "generate_role_secret_id.return_value": "11111111",
            },
        )
        mock_vault_class.return_value = mock_vault

        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )
        peer_relation_id = self.harness.add_relation(
            relation_name="vault-peers", remote_app="vault"
        )
        self.harness.set_leader(is_leader=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "vault/certs/ca.pem").write_text("some ca")
        self.harness.set_can_connect(container=self.container_name, val=True)
        event = Mock()
        event.params = {"relation_name": "relation", "relation_id": "99"}
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        rel_id, _ = self.setup_vault_kv_relation()
        event = Mock()
        event.relation_name = VAULT_KV_RELATION_NAME
        event.relation_id = rel_id
        event.mount_suffix = "suffix"
        self.harness.charm._on_new_vault_kv_client_attached(event)
        mock_vault.enable_kv_engine.assert_called_once()

    @patch("charm.get_common_name_from_certificate", new=Mock)
    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.request_certificate_creation")
    @patch("charm.Vault", autospec=True)
    def test_given_vault_is_available_when_tls_certificates_pki_relation_joined_then_certificate_request_is_made(
        self,
        mock_vault_class,
        patch_request_certificate_creation,
    ):
        csr = "some csr content"
        self.harness.update_config({"common_name": "vault"})
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "get_intermediate_ca.return_value": "vault",
                "generate_pki_intermediate_ca_csr.return_value": csr,
                "is_secret_engine_enabled.return_value": False,
            },
        )
        mock_vault_class.return_value = mock_vault
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "vault/certs/ca.pem").write_text("some ca")
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        relation_id = self.harness.add_relation(
            relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
        )
        self.harness.add_relation_unit(relation_id, "tls-provider/0")

        mock_vault.enable_pki_engine.assert_called_with(path="charm-pki")
        mock_vault.generate_pki_intermediate_ca_csr.assert_called_with(
            mount="charm-pki", common_name="vault"
        )
        patch_request_certificate_creation.assert_called_with(
            certificate_signing_request=csr.encode(), is_ca=True
        )

    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesRequiresV3.get_assigned_certificates")
    @patch("charm.Vault", autospec=True)
    def test_given_vault_is_available_when_pki_certificate_is_available_then_certificate_added_to_vault_pki(
        self,
        mock_vault_class,
        patch_get_assigned_certificates,
    ):
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "is_intermediate_ca_set.return_value": False,
                "is_pki_role_created.return_value": False,
            },
        )
        mock_vault_class.return_value = mock_vault

        csr = "some csr content"
        certificate = "some certificate"
        ca = "some ca"
        chain = [ca]
        self.harness.update_config({"common_name": "vault"})
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "vault/certs/ca.pem").write_text("some ca")
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        self._set_csr_secret_in_peer_relation(relation_id=peer_relation_id, csr="some csr content")
        event = CertificateAvailableEvent(
            handle=Mock(),
            certificate=certificate,
            certificate_signing_request=csr,
            ca=ca,
            chain=chain,
        )
        relation_id = self.harness.add_relation(
            relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
        )

        patch_get_assigned_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                application_name="tls-provider",
                csr=csr,
                certificate=certificate,
                ca=ca,
                chain=chain,
                revoked=False,
            )
        ]

        self.harness.charm._on_tls_certificate_pki_certificate_available(event=event)

        mock_vault.set_pki_intermediate_ca_certificate.assert_called_with(
            certificate=certificate,
            mount="charm-pki",
        )
        mock_vault.create_pki_charm_role.assert_called_with(
            allowed_domains="vault", mount="charm-pki", role="charm"
        )

    @patch(f"{TLS_CERTIFICATES_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate")
    @patch("charm.get_common_name_from_csr")
    @patch("charm.Vault", autospec=True)
    def test_given_vault_available_when_vault_pki_certificate_creation_request_then_certificate_is_provided(
        self,
        mock_vault_class,
        patch_get_common_name_from_csr,
        patch_set_relation_certificate,
    ):
        csr = "some csr content"
        certificate = "some certificate"
        ca = "some ca"
        chain = [ca]
        mock_vault = MagicMock(
            spec=Vault,
            **{
                "is_initialized.return_value": True,
                "is_api_available.return_value": True,
                "is_pki_role_created.return_value": True,
                "sign_pki_certificate_signing_request.return_value": Certificate(
                    certificate=certificate,
                    ca=ca,
                    chain=chain,
                ),
            },
        )
        relation_id = self.harness.add_relation(
            relation_name=TLS_CERTIFICATES_PKI_RELATION_NAME, remote_app="tls-provider"
        )
        mock_vault_class.return_value = mock_vault
        common_name = "vault"
        relation_id = 99
        patch_get_common_name_from_csr.return_value = common_name
        self.harness.update_config({"common_name": common_name})
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "vault/certs/ca.pem").write_text(ca)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        event = CertificateCreationRequestEvent(
            handle=Mock(),
            certificate_signing_request=csr,
            relation_id=relation_id,
            is_ca=False,
        )

        self.harness.charm._on_vault_pki_certificate_creation_request(event=event)

        mock_vault.sign_pki_certificate_signing_request.assert_called_with(
            mount="charm-pki",
            csr=csr,
            role="charm",
            common_name=common_name,
        )

        patch_set_relation_certificate.assert_called_with(
            relation_id=relation_id,
            certificate_signing_request=csr,
            certificate=certificate,
            ca=ca,
            chain=chain,
        )
