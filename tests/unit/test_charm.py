#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from typing import List
from unittest.mock import Mock, call, patch

import hcl  # type: ignore[import-untyped]
from ops import testing
from ops.model import WaitingStatus

from charm import (
    CA_CERTIFICATE_JUJU_SECRET_LABEL,
    VAULT_INITIALIZATION_SECRET_LABEL,
    VaultCharm,
    config_file_content_matches,
)

TLS_CERTIFICATES_LIB_PATH = "charms.tls_certificates_interface.v2.tls_certificates"


def read_file(path: str) -> str:
    """Reads a file and returns as a string.

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
        secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
        secret = self.harness.model.get_secret(id=secret_id)
        secret.set_info(label=VAULT_INITIALIZATION_SECRET_LABEL)
        key_values = {"vault-initialization-secret-id": secret_id}
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    def _set_ca_certificate_secret_in_peer_relation(
        self, relation_id: int, private_key: str, certificate: str
    ) -> None:
        """Set the certificate secret in the peer relation."""
        content = {
            "certificate": certificate,
            "privatekey": private_key,
        }
        secret_id = self.harness.add_model_secret(owner=self.app_name, content=content)
        secret = self.harness.model.get_secret(id=secret_id)
        secret.set_info(label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
        key_values = {"vault-ca-certificates-secret-id": secret_id}
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    def _set_other_node_api_address_in_peer_relation(self, relation_id: int, unit_name: str):
        """Set the other node api address in the peer relation."""
        key_values = {"node_api_address": "http://5.2.1.9:8200"}
        self.harness.update_relation_data(
            app_or_unit=unit_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    @patch("ops.model.Container.remove_path")
    def test_given_can_connect_when_install_then_existing_data_is_removed(self, patch_remove_path):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.install.emit()

        patch_remove_path.assert_has_calls(
            calls=[call(path="/vault/raft/vault.db"), call(path="/vault/raft/raft/raft.db")]
        )

    def test_given_cant_connect_when_install_then_status_is_waiting(self):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm.on.install.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting to be able to connect to vault unit"),
        )

    def test_given_cant_connect_when_configure_then_status_is_waiting(self):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting to be able to connect to vault unit"),
        )

    def test_given_peer_relation_not_created_when_configure_then_status_is_waiting(self):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for peer relation"),
        )

    def test_given_bind_address_not_available_when_configure_then_status_is_waiting(self):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for bind and ingress addresses to be available"),
        )

    @patch("ops.model.Model.get_binding")
    def test_given_not_leader_and_peer_addresses_not_available_when_configure_then_status_is_waiting(
        self, patch_get_binding
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=False)
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for other units to provide their addresses"),
        )

    @patch("vault.Vault.enable_audit_device", new=Mock)
    @patch("vault.Vault.is_active", new=Mock)
    @patch("vault.Vault.audit_device_enabled", new=Mock)
    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.is_sealed", new=Mock)
    @patch("vault.Vault.is_initialized", new=Mock)
    @patch("vault.Vault.is_api_available", new=Mock)
    @patch("ops.model.Container.push", new=Mock)
    @patch("charm.generate_vault_unit_certificate")
    @patch("charm.generate_vault_ca_certificate")
    @patch("ops.model.Model.get_binding")
    def test_given_unit_is_leader_and_ca_certificate_not_generated_when_configure_then_ca_certificate_is_generated(
        self,
        patch_get_binding,
        patch_generate_ca_certificate,
        patch_generate_unit_certificate,
    ):
        ca_private_key = "ca private key content"
        ca_certificate = "ca certificate content"
        patch_generate_ca_certificate.return_value = ca_private_key, ca_certificate
        patch_generate_unit_certificate.return_value = "unit private key", "unit certificate"
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=relation_id,
            root_token="whatever root token",
            unseal_keys=["whatever unseal key"],
        )
        self.harness.set_leader(is_leader=True)
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )

        self.harness.charm.on.config_changed.emit()

        patch_generate_ca_certificate.assert_called()
        secret = self.harness.model.get_secret(
            label=CA_CERTIFICATE_JUJU_SECRET_LABEL
        ).get_content()
        self.assertEqual(secret, {"privatekey": ca_private_key, "certificate": ca_certificate})

    @patch("vault.Vault.enable_audit_device", new=Mock)
    @patch("vault.Vault.is_active", new=Mock)
    @patch("vault.Vault.audit_device_enabled", new=Mock)
    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.is_sealed", new=Mock)
    @patch("vault.Vault.is_initialized", new=Mock)
    @patch("vault.Vault.is_api_available", new=Mock)
    @patch("ops.model.Container.exists")
    @patch("charm.generate_vault_unit_certificate")
    @patch("ops.model.Model.get_binding")
    def test_given_ca_certificate_not_pushed_to_workload_when_configure_then_ca_certificate_pushed(
        self, patch_get_binding, patch_generate_unit_certificate, patch_exists
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

        patch_exists.return_value = False
        ca_private_key = "ca private key content"
        ca_certificate = "ca certificate content"
        patch_generate_unit_certificate.return_value = "unit private key", "unit certificate"
        relation_id = self._set_peer_relation()
        self._set_ca_certificate_secret_in_peer_relation(
            certificate=ca_certificate, private_key=ca_private_key, relation_id=relation_id
        )
        self._set_initialization_secret_in_peer_relation(
            relation_id=relation_id,
            root_token="whatever root token",
            unseal_keys=["whatever unseal key"],
        )
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.1.2", ingress_address="10.1.0.1"
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)

        self.harness.charm.on.config_changed.emit()

        self.assertEqual((root / "vault/certs/ca.pem").read_text(), ca_certificate)

    @patch("vault.Vault.enable_audit_device", new=Mock)
    @patch("vault.Vault.is_active", new=Mock)
    @patch("vault.Vault.audit_device_enabled", new=Mock)
    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.is_sealed", new=Mock)
    @patch("socket.getfqdn")
    @patch("vault.Vault.is_initialized", new=Mock)
    @patch("vault.Vault.is_api_available", new=Mock)
    @patch("ops.model.Container.exists")
    @patch("charm.generate_vault_unit_certificate")
    @patch("ops.model.Model.get_binding")
    def test_given_unit_certificate_not_stored_when_configure_then_unit_certificate_is_generated(
        self,
        patch_get_binding,
        patch_generate_unit_certificate,
        patch_exists,
        patch_socket_getfqdn,
    ):
        fqdn = "banana"
        patch_socket_getfqdn.return_value = fqdn
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        patch_exists.return_value = False
        ingress_address = "10.1.0.1"
        bind_address = "1.2.1.2"
        ca_certificate = "ca certificate content"
        ca_private_key = "ca private key content"
        unit_private_key = "unit private key content"
        unit_certificate = "unit certificate content"
        patch_generate_unit_certificate.return_value = unit_private_key, unit_certificate
        relation_id = self._set_peer_relation()
        self._set_ca_certificate_secret_in_peer_relation(
            certificate=ca_certificate,
            private_key="ca private key content",
            relation_id=relation_id,
        )
        self._set_initialization_secret_in_peer_relation(
            relation_id=relation_id,
            root_token="whatever root token",
            unseal_keys=["whatever unseal key"],
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        patch_get_binding.return_value = MockBinding(
            bind_address=bind_address, ingress_address=ingress_address
        )

        self.harness.charm.on.config_changed.emit()

        patch_generate_unit_certificate.assert_called_with(
            subject=ingress_address,
            sans_ip=[bind_address, ingress_address],
            sans_dns=[fqdn],
            ca_certificate=ca_certificate.encode(),
            ca_private_key=ca_private_key.encode(),
        )
        self.assertEqual((root / "vault/certs/cert.pem").read_text(), unit_certificate)

    @patch("vault.Vault.enable_audit_device", new=Mock)
    @patch("vault.Vault.is_active", new=Mock)
    @patch("vault.Vault.audit_device_enabled", new=Mock)
    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.is_sealed", new=Mock)
    @patch("vault.Vault.is_initialized", new=Mock)
    @patch("vault.Vault.is_api_available", new=Mock)
    @patch("charm.generate_vault_unit_certificate")
    @patch("charm.generate_vault_ca_certificate")
    @patch("ops.model.Model.get_binding")
    def test_given_peer_relation_created_when_configure_then_config_file_is_pushed(
        self,
        patch_get_binding,
        patch_generate_ca_certificate,
        patch_generate_unit_certificate,
    ):
        patch_generate_ca_certificate.return_value = "ca private key", "ca certificate"
        patch_generate_unit_certificate.return_value = "unit private key", "unit certificate"
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
        self.harness.set_leader(is_leader=True)

        self.harness.charm.on.config_changed.emit()

        pushed_content_hcl = hcl.loads((root / "vault/config/vault.hcl").read_text())
        expected_content_hcl = hcl.loads(read_file("tests/unit/config.hcl"))
        self.assertEqual(pushed_content_hcl, expected_content_hcl)

    @patch("vault.Vault.enable_audit_device", new=Mock)
    @patch("vault.Vault.is_active", new=Mock)
    @patch("vault.Vault.audit_device_enabled", new=Mock)
    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.is_sealed", new=Mock)
    @patch("vault.Vault.is_initialized", new=Mock)
    @patch("vault.Vault.is_api_available", new=Mock)
    @patch("charm.generate_vault_unit_certificate")
    @patch("charm.generate_vault_ca_certificate")
    @patch("ops.model.Model.get_binding")
    def test_given_peer_relation_created_when_configure_then_pebble_plan_is_set(
        self,
        patch_get_binding,
        patch_generate_ca_certificate,
        patch_generate_unit_certificate,
    ):
        patch_generate_ca_certificate.return_value = "ca private key", "ca certificate"
        patch_generate_unit_certificate.return_value = "unit private key", "unit certificate"
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=relation_id,
            root_token="whatever root token",
            unseal_keys=["whatever unseal key"],
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
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

    @patch("vault.Vault.is_initialized", new=Mock)
    @patch("vault.Vault.is_api_available")
    @patch("charm.generate_vault_unit_certificate")
    @patch("charm.generate_vault_ca_certificate")
    @patch("ops.model.Model.get_binding")
    def test_given_api_not_available_when_configure_then_status_is_waiting(
        self,
        patch_get_binding,
        patch_generate_ca_certificate,
        patch_generate_unit_certificate,
        patch_is_api_available,
    ):
        patch_is_api_available.return_value = False
        patch_generate_ca_certificate.return_value = "ca private key", "ca certificate"
        patch_generate_unit_certificate.return_value = "unit private key", "unit certificate"
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        self._set_peer_relation()
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="1.1.1.1"
        )

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for vault to be available"),
        )

    @patch("vault.Vault.enable_audit_device", new=Mock)
    @patch("vault.Vault.is_active", new=Mock)
    @patch("vault.Vault.audit_device_enabled", new=Mock)
    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.is_sealed", new=Mock)
    @patch("vault.Vault.initialize")
    @patch("vault.Vault.is_initialized")
    @patch("vault.Vault.is_api_available")
    @patch("charm.generate_vault_unit_certificate")
    @patch("charm.generate_vault_ca_certificate")
    @patch("ops.model.Model.get_binding")
    def test_given_vault_not_initialized_when_configure_then_vault_initialized(
        self,
        patch_get_binding,
        patch_generate_ca_certificate,
        patch_generate_unit_certificate,
        patch_is_api_available,
        patch_is_initialized,
        patch_initialize,
    ):
        patch_is_api_available.return_value = True
        patch_is_initialized.return_value = False
        patch_initialize.return_value = "root token", ["unseal key 1"]
        patch_generate_ca_certificate.return_value = "ca private key", "ca certificate"
        patch_generate_unit_certificate.return_value = "unit private key", "unit certificate"
        self._set_peer_relation()
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.set_leader(is_leader=True)
        patch_get_binding.return_value = MockBinding(
            bind_address="1.2.3.4", ingress_address="1.1.1.1"
        )

        self.harness.charm.on.config_changed.emit()

        patch_initialize.assert_called_once()
        init_secret = self.harness.model.get_secret(
            label=VAULT_INITIALIZATION_SECRET_LABEL
        ).get_content()
        self.assertEqual(
            init_secret,
            {"roottoken": "root token", "unsealkeys": '["unseal key 1"]'},
        )

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
    @patch("vault.Vault.get_num_raft_peers")
    @patch("vault.Vault.is_api_available")
    @patch("vault.Vault.is_node_in_raft_peers")
    @patch("vault.Vault.remove_raft_node")
    def test_given_node_in_raft_when_on_remove_then_node_is_removed_from_raft(
        self,
        patch_remove_raft_node,
        patch_is_node_in_raft_peers,
        patch_is_api_available,
        patch_get_num_raft_peers,
        patch_get_binding,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        patch_get_num_raft_peers.return_value = 2
        bind_address = "1.2.3.4"
        ingress_address = "10.1.0.1"
        patch_get_binding.return_value = MockBinding(
            bind_address=bind_address, ingress_address=ingress_address
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_is_api_available.return_value = True
        patch_is_node_in_raft_peers.return_value = True
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        self.harness.charm.on.remove.emit()

        patch_remove_raft_node.assert_called_with(node_id=f"{self.model_name}-{self.app_name}/0")

    @patch("vault.Vault.is_api_available")
    @patch("vault.Vault.is_node_in_raft_peers")
    @patch("vault.Vault.remove_raft_node")
    def test_given_node_not_in_raft_when_on_remove_then_node_is_not_removed_from_raft(
        self,
        patch_remove_raft_node,
        patch_is_node_in_raft_peers,
        patch_is_api_available,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_is_api_available.return_value = True
        patch_is_node_in_raft_peers.return_value = False
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        self.harness.charm.on.remove.emit()

        patch_remove_raft_node.assert_not_called()

    @patch("vault.Vault.is_api_available")
    @patch("vault.Vault.is_node_in_raft_peers")
    @patch("vault.Vault.remove_raft_node", new=Mock)
    @patch("ops.model.Container.get_service", new=Mock)
    @patch("ops.model.Container.stop")
    def test_given_service_is_running_when_on_remove_then_service_is_stopped(
        self,
        patch_stop_service,
        patch_is_node_in_raft_peers,
        patch_is_api_available,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_is_api_available.return_value = True
        patch_is_node_in_raft_peers.return_value = False
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )

        self.harness.charm.on.remove.emit()

        patch_stop_service.assert_called_with("vault")

    def setup_vault_kv_relation(self, nb_units: int = 1) -> tuple:
        app_name = "consumer"
        unit_name = app_name + "/0"
        relation_name = "vault-kv"

        host_ip = "10.20.20.1"
        self.harness.add_network(host_ip, endpoint="vault-kv")
        self.harness.set_leader()
        rel_id = self.harness.add_relation(relation_name, app_name)
        units = {}
        for unit_id in range(nb_units):
            unit_name = app_name + "/" + str(unit_id)
            egress_subnet = f"10.20.20.{20 + unit_id}/32"
            self.harness.add_relation_unit(rel_id, unit_name)
            self.harness.update_relation_data(
                rel_id, unit_name, {"egress_subnet": egress_subnet, "nonce": str(unit_id)}
            )
            units[unit_name] = egress_subnet

        return (
            app_name,
            host_ip,
            relation_name,
            rel_id,
            units,
        )

    @patch("charms.vault_k8s.v0.vault_kv.VaultKvProvides.set_unit_credentials")
    @patch("charms.vault_k8s.v0.vault_kv.VaultKvProvides.set_ca_certificate")
    @patch("charms.vault_k8s.v0.vault_kv.VaultKvProvides.set_mount")
    @patch("charms.vault_k8s.v0.vault_kv.VaultKvProvides.set_vault_url")
    @patch("vault.Vault.generate_role_secret_id")
    @patch("vault.Vault.configure_approle")
    @patch("vault.Vault.configure_kv_policy")
    @patch("vault.Vault.configure_kv_mount")
    @patch("vault.Vault.enable_approle_auth")
    @patch("vault.Vault.is_api_available")
    def test_given_unit_is_leader_when_secret_kv_is_complete_then_provider_side_is_filled(
        self,
        _,
        enable_approle_auth,
        __,
        ___,
        configure_approle,
        generate_role_secret_id,
        set_vault_url,
        set_mount,
        set_ca_certificate,
        set_unit_credentials,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        self._set_ca_certificate_secret_in_peer_relation(
            relation_id=peer_relation_id,
            certificate="ca certificate content",
            private_key="private key content",
        )
        (
            app_name,
            _,
            _,
            rel_id,
            _,
        ) = self.setup_vault_kv_relation(nb_units=3)

        configure_approle.return_value = "12345678"
        generate_role_secret_id.return_value = "11111111"

        mount_suffix = "dummy"
        self.harness.update_relation_data(rel_id, app_name, {"mount_suffix": mount_suffix})

        enable_approle_auth.assert_called()
        set_vault_url.assert_called()
        set_mount.assert_called()
        set_ca_certificate.assert_called()
        set_unit_credentials.assert_called()

    @patch("charms.vault_k8s.v0.vault_kv.VaultKvProvides.set_unit_credentials")
    @patch("charms.vault_k8s.v0.vault_kv.VaultKvProvides.set_ca_certificate")
    @patch("charms.vault_k8s.v0.vault_kv.VaultKvProvides.set_vault_url")
    @patch("charms.vault_k8s.v0.vault_kv.VaultKvProvides.set_mount")
    @patch("vault.Vault.generate_role_secret_id")
    @patch("vault.Vault.configure_approle")
    @patch("vault.Vault.configure_kv_policy")
    @patch("vault.Vault.configure_kv_mount")
    @patch("vault.Vault.enable_approle_auth")
    @patch("vault.Vault.is_api_available")
    def test_given_unit_is_not_leader_when_secret_kv_is_complete_then_no_data_is_updated(
        self,
        _,
        enable_approle_auth,
        __,
        ___,
        configure_approle,
        generate_role_secret_id,
        set_mount,
        set_vault_url,
        set_ca_certificate,
        set_unit_credentials,
    ):
        (
            app_name,
            _,
            _,
            rel_id,
            _,
        ) = self.setup_vault_kv_relation(nb_units=3)
        self.harness.set_leader(False)

        configure_approle.return_value = "12345678"
        generate_role_secret_id.return_value = "11111111"

        mount_suffix = "dummy"
        self.harness.update_relation_data(rel_id, app_name, {"mount_suffix": mount_suffix})

        enable_approle_auth.assert_not_called()
        set_mount.assert_not_called()
        set_vault_url.assert_not_called()
        set_ca_certificate.assert_not_called()
        set_unit_credentials.assert_not_called()

    @patch("vault.Vault.read_role_secret")
    @patch("vault.Vault.generate_role_secret_id")
    @patch("vault.Vault.configure_approle")
    @patch("vault.Vault.configure_kv_policy")
    @patch("vault.Vault.configure_kv_mount")
    @patch("vault.Vault.is_api_available")
    @patch("vault.Vault.enable_approle_auth")
    def test_given_unit_is_leader_when_related_unit_egress_is_updated_then_secret_content_is_updated(  # noqa: E501
        self,
        _,
        __,
        ___,
        ____,
        configure_approle,
        generate_role_secret_id,
        read_role_secret,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal_keys"],
        )
        self._set_ca_certificate_secret_in_peer_relation(
            relation_id=peer_relation_id,
            certificate="ca certificate content",
            private_key="private key content",
        )
        (
            app_name,
            _,
            _,
            rel_id,
            units,
        ) = self.setup_vault_kv_relation(nb_units=3)

        configure_approle.return_value = "12345678"
        generate_role_secret_id.return_value = "11111111"

        mount_suffix = "dummy"
        self.harness.update_relation_data(rel_id, app_name, {"mount_suffix": mount_suffix})
        # choose an unit to update
        unit = next(iter(units.keys()))

        # Mock read to actually return a comparable cidr_list
        def mock_read_role_secret(role_name, _):
            unit_name = "/".join(role_name.split("-")[-2:])
            return {"cidr_list": [units[unit_name]]}

        read_role_secret.side_effect = mock_read_role_secret
        # get current role secret id from unit's secret
        with patch("ops.Secret.set_content") as set_content:
            self.harness.update_relation_data(rel_id, unit, {"egress_subnet": "10.20.20.240/32"})
            assert set_content.call_count == 1

    def test_given_ca_cert_exists_when_certificate_transfer_relation_joins_then_ca_cert_is_advertised(
        self,
    ):
        ca_certificate = "certificate content"
        ca_private_key = "private key content"
        relation_id = self._set_peer_relation()
        self._set_ca_certificate_secret_in_peer_relation(
            certificate=ca_certificate,
            private_key=ca_private_key,
            relation_id=relation_id,
        )
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        app = "traefik"
        certificate_transfer_rel_id = self.harness.add_relation(
            relation_name="send-ca-cert", remote_app=app
        )

        self.harness.add_relation_unit(
            relation_id=certificate_transfer_rel_id, remote_unit_name=f"{app}/0"
        )

        data = self.harness.get_relation_data(certificate_transfer_rel_id, self.harness.charm.unit)
        ca_from_rel_data = data["ca"]
        self.assertEqual(ca_certificate, ca_from_rel_data)

    @patch("charm.generate_vault_unit_certificate", new=Mock)
    def test_given_ca_cert_is_not_stored_when_certificate_transfer_relation_joins_then_ca_cert_is_not_advertised(
        self,
    ):
        self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        app = "traefik"
        certificate_transfer_rel_id = self.harness.add_relation(
            relation_name="send-ca-cert", remote_app=app
        )

        self.harness.add_relation_unit(
            relation_id=certificate_transfer_rel_id, remote_unit_name=f"{app}/0"
        )

        relation_data = self.harness.get_relation_data(
            certificate_transfer_rel_id, self.harness.charm.unit
        )

        self.assertNotIn("ca", relation_data)
