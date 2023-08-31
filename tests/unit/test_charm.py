#!/usr/bin/env python3
# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import unittest
from typing import List
from unittest.mock import Mock, patch

from ops import testing
from ops.model import ActiveStatus, ModelError, WaitingStatus

from charm import VaultCharm


class MockNetwork:
    def __init__(self, bind_address: str):
        self.bind_address = bind_address


class MockBinding:
    def __init__(self, bind_address: str):
        self.network = MockNetwork(bind_address=bind_address)


class TestCharm(unittest.TestCase):
    @patch(
        "charm.KubernetesServicePatch",
        lambda charm, ports: None,
    )
    def setUp(self):
        self.harness = testing.Harness(VaultCharm)
        self.addCleanup(self.harness.cleanup)
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
        key_values = {"vault-initialization-secret-id": secret_id}
        self.harness.update_relation_data(
            app_or_unit=self.app_name,
            relation_id=relation_id,
            key_values=key_values,
        )

    def test_given_cant_connect_to_workload_when_install_then_status_is_waiting(self):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm.on.install.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting to be able to connect to vault unit"),
        )

    def test_given_peer_relation_not_created_when_install_then_status_is_waiting(self):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.install.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for peer relation to be created"),
        )

    @patch("ops.model.Model.get_binding")
    def test_given_bind_address_not_available_when_install_then_status_is_waiting(
        self, patch_get_binding
    ):
        self._set_peer_relation()
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_get_binding.side_effect = ModelError()

        self.harness.charm.on.install.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for bind address to be available"),
        )

    @patch("vault.Vault.unseal")
    @patch("vault.Vault.set_token")
    @patch("vault.Vault.initialize")
    @patch("vault.Vault.wait_for_api_available")
    @patch("ops.model.Model.get_binding")
    def test_given_binding_address_when_install_then_vault_is_initialized(
        self,
        patch_get_binding,
        patch_vault_wait_for_api_available,
        patch_vault_initialize,
        patch_vault_set_token,
        patch_vault_unseal,
    ):
        root_token = "root token content"
        unseal_keys = ["unseal key 1"]
        bind_address = "1.2.1.2"
        patch_get_binding.return_value = MockBinding(bind_address=bind_address)
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_vault_initialize.return_value = root_token, unseal_keys
        self._set_peer_relation()
        self.harness.charm.on.install.emit()

        patch_vault_wait_for_api_available.assert_called_once()
        patch_vault_initialize.assert_called_once()
        patch_vault_set_token.assert_called_once_with(token=root_token)
        patch_vault_unseal.assert_called_once_with(unseal_keys=unseal_keys)

    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.set_token", new=Mock)
    @patch("vault.Vault.initialize")
    @patch("vault.Vault.wait_for_api_available", new=Mock)
    @patch("ops.model.Model.get_binding")
    def test_given_binding_address_when_install_then_pebble_is_planned(
        self, patch_get_binding, patch_vault_initialize
    ):
        bind_address = "1.2.1.2"
        patch_get_binding.return_value = MockBinding(bind_address=bind_address)
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_vault_initialize.return_value = "root token content", "unseal key content"
        self._set_peer_relation()

        expected_plan = {
            "services": {
                "vault": {
                    "override": "replace",
                    "summary": "vault",
                    "command": "/usr/local/bin/docker-entrypoint.sh server",
                    "startup": "enabled",
                    "environment": {
                        "VAULT_LOCAL_CONFIG": '{"backend": {"file": {"path": "/srv"}}, '
                        '"listener": {"tcp": {'
                        '"tls_disable": true, "address": "[::]:8200"}}, '
                        '"default_lease_ttl": "168h", "max_lease_ttl": "720h", '
                        '"disable_mlock": true, '
                        f'"cluster_addr": "http://{bind_address}:8201", '
                        f'"api_addr": "http://{bind_address}:8200"'
                        "}",
                        "VAULT_API_ADDR": "http://[::]:8200",
                    },
                }
            },
        }
        self.harness.charm.on.install.emit()

        updated_plan = self.harness.get_container_pebble_plan("vault").to_dict()
        self.assertEqual(updated_plan, expected_plan)

    @patch("vault.Vault.unseal", new=Mock)
    @patch("vault.Vault.set_token", new=Mock)
    @patch("vault.Vault.initialize")
    @patch("vault.Vault.wait_for_api_available", new=Mock)
    @patch("ops.model.Model.get_binding")
    def test_given_binding_address_when_install_then_status_is_active(
        self, patch_get_binding, patch_vault_initialize
    ):
        patch_get_binding.return_value = MockBinding(bind_address="1.2.1.2")
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_vault_initialize.return_value = "root token content", "unseal key content"
        self._set_peer_relation()

        self.harness.charm.on.install.emit()

        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())

    def test_given_cant_connect_to_workload_when_config_changed_then_status_is_waiting(self):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting to be able to connect to vault unit"),
        )

    def test_given_peer_relation_not_created_when_config_changed_then_status_is_waiting(self):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for peer relation"),
        )

    def test_given_initialization_secret_not_stored_when_config_changed_then_status_is_waiting(
        self,
    ):
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._set_peer_relation()

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(
            self.harness.charm.unit.status,
            WaitingStatus("Waiting for vault initialization secret"),
        )

    @patch("ops.model.Model.get_binding")
    @patch("vault.Vault.is_sealed")
    @patch("vault.Vault.wait_for_api_available", new=Mock)
    @patch("ops.model.Container.exec", new=Mock)
    def test_given_initialization_secret_is_stored_when_config_changed_then_pebble_plan_is_applied(
        self, patch_vault_is_sealed, patch_get_binding
    ):
        bind_address = "1.2.3.4"
        patch_vault_is_sealed.return_value = False
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal key content"],
        )
        patch_get_binding.return_value = MockBinding(bind_address=bind_address)

        self.harness.charm.on.config_changed.emit()

        expected_plan = {
            "services": {
                "vault": {
                    "override": "replace",
                    "summary": "vault",
                    "command": "/usr/local/bin/docker-entrypoint.sh server",
                    "startup": "enabled",
                    "environment": {
                        "VAULT_LOCAL_CONFIG": '{"backend": {"file": {"path": "/srv"}}, '
                        '"listener": {"tcp": {'
                        '"tls_disable": true, "address": "[::]:8200"}}, '
                        '"default_lease_ttl": "168h", "max_lease_ttl": "720h", '
                        '"disable_mlock": true, '
                        f'"cluster_addr": "http://{bind_address}:8201", '
                        f'"api_addr": "http://{bind_address}:8200"'
                        "}",
                        "VAULT_API_ADDR": "http://[::]:8200",
                    },
                }
            },
        }
        self.assertEqual(
            self.harness.get_container_pebble_plan("vault").to_dict(),
            expected_plan,
        )

    @patch("ops.model.Model.get_binding")
    @patch("vault.Vault.is_sealed")
    @patch("vault.Vault.wait_for_api_available", new=Mock)
    @patch("ops.model.Container.exec", new=Mock)
    def test_given_initialization_secret_is_stored_when_config_changed_then_status_is_active(
        self, patch_vault_is_sealed, patch_get_binding
    ):
        patch_vault_is_sealed.return_value = False
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=["unseal key content"],
        )
        patch_get_binding.return_value = MockBinding(bind_address="1.2.3.4")

        self.harness.charm.on.config_changed.emit()

        self.assertEqual(self.harness.charm.unit.status, ActiveStatus())

    @patch("ops.model.Model.get_binding")
    @patch("vault.Vault.unseal")
    @patch("vault.Vault.is_sealed")
    @patch("vault.Vault.wait_for_api_available", new=Mock)
    @patch("ops.model.Container.exec", new=Mock)
    def test_given_vault_is_sealed_when_config_changed_then_vault_is_unsealed(
        self, patch_vault_is_sealed, patch_vault_unseal, patch_get_binding
    ):
        unseal_keys = ["unseal key content"]
        patch_vault_is_sealed.return_value = True
        self.harness.set_leader(is_leader=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        peer_relation_id = self._set_peer_relation()
        self._set_initialization_secret_in_peer_relation(
            relation_id=peer_relation_id,
            root_token="root token content",
            unseal_keys=unseal_keys,
        )
        patch_get_binding.return_value = MockBinding(bind_address="1.2.3.4")

        self.harness.charm.on.config_changed.emit()

        patch_vault_unseal.assert_called_once_with(unseal_keys=unseal_keys)
