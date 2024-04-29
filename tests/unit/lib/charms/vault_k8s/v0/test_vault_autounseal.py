#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import textwrap
import unittest
from unittest.mock import MagicMock, patch

from charms.vault_k8s.v0.vault_autounseal import (
    VaultAutounsealDestroy,
    VaultAutounsealDetailsReadyEvent,
    VaultAutounsealInitialize,
    VaultAutounsealProvides,
    VaultAutounsealRequires,
)
from ops import Relation, testing
from ops.charm import CharmBase

AUTOUNSEAL_PROVIDES_RELATION_NAME = "vault-autounseal-provides"
AUTOUNSEAL_REQUIRES_RELATION_NAME = "vault-autounseal-requires"


class VaultAutounsealProviderCharm(CharmBase):
    metadata_yaml = textwrap.dedent(
        """
        name: vault-autounseal-provider
        containers:
          vault:
            resource: vault-image
        provides:
          vault-autounseal-provides:
            interface: vault-autounseal
            limit: 2
        """
    )

    def __init__(self, *args):
        super().__init__(*args)
        self.interface = VaultAutounsealProvides(self, AUTOUNSEAL_PROVIDES_RELATION_NAME)
        self.framework.observe(
            self.interface.on.vault_autounseal_initialize, self._on_vault_autounseal_initialize
        )
        self.framework.observe(
            self.interface.on.vault_autounseal_destroy, self._on_vault_autounseal_initialize
        )

    def _on_vault_autounseal_initialize(self, event: VaultAutounsealInitialize):
        pass

    def _on_vault_autounseal_destroy(self, event: VaultAutounsealDestroy):
        pass


class VaultAutounsealRequirerCharm(CharmBase):
    metadata_yaml = textwrap.dedent(
        """
        name: vault-autounseal-requirer
        containers:
          vault:
            resource: vault-image
        requires:
          vault-autounseal-requires:
            interface: vault-autounseal
        """
    )

    def __init__(self, *args):
        super().__init__(*args)
        self.interface = VaultAutounsealRequires(self, AUTOUNSEAL_REQUIRES_RELATION_NAME)
        self.framework.observe(
            self.interface.on.vault_autounseal_details_ready, self._on_details_ready
        )

    def _on_details_ready(self, event: VaultAutounsealDetailsReadyEvent):
        pass


class TestVaultAutounsealProvides(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(
            VaultAutounsealProviderCharm, meta=VaultAutounsealProviderCharm.metadata_yaml
        )
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def setup_relation(
        self, leader: bool = True, remote_app: str = "vault-autounseal-requires"
    ) -> tuple[str, str, Relation]:
        """Set up a relation between the charm and a remote app with 1 unit."""
        remote_unit = f"{remote_app}/0"
        rel_name = AUTOUNSEAL_PROVIDES_RELATION_NAME
        self.harness.set_leader(leader)
        rel_id = self.harness.add_relation(rel_name, remote_app)
        relation = self.harness.model.get_relation(rel_name, rel_id)
        assert relation
        self.harness.add_relation_unit(rel_id, remote_unit)
        return remote_app, remote_unit, relation

    @patch(
        "ops.model.Application.add_secret",
    )
    def test_given_unit_is_leader_when_set_autounseal_data_then_relation_data_is_updated(
        self, mock_add_secret: MagicMock
    ):
        remote_app, remote_unit, relation = self.setup_relation()
        vault_address = "https://vault.example.com"
        approle_id = "some approle id"
        approle_secret_id = "some approle secret id"
        ca_certificate = "my ca certificate"

        mock_add_secret.return_value = MagicMock(**{"id": "some secret id"})

        self.harness.charm.interface.set_autounseal_data(
            relation, vault_address, approle_id, approle_secret_id, ca_certificate
        )
        mock_add_secret.assert_called_once()
        assert self.harness.get_relation_data(relation.id, self.harness.charm.app.name) == {
            "address": vault_address,
            "credentials_secret_id": "some secret id",
            "ca_certificate": ca_certificate,
        }

    def test_given_unit_is_not_leader_when_set_autounseal_data_then_relation_data_not_updated(
        self,
    ):
        remote_app, remote_unit, relation = self.setup_relation(leader=False)
        vault_address = "https://vault.example.com"
        approle_id = "some approle id"
        approle_secret_id = "some approle secret id"
        ca_certificate = "my ca certificate"

        self.harness.charm.interface.set_autounseal_data(
            relation, vault_address, approle_id, approle_secret_id, ca_certificate
        )
        assert self.harness.get_relation_data(relation.id, self.harness.charm.app.name) == {}

    def test_given_no_request_when_get_outstanding_requests_then_empty_list_is_returned(self):
        kv_requests = self.harness.charm.interface.get_outstanding_requests()

        assert len(kv_requests) == 0

    def test_given_1_outstanding_request_when_get_outstanding_requests_then_request_is_returned(
        self,
    ):
        remote_app, remote_unit, relation = self.setup_relation()

        self.harness.update_relation_data(
            relation.id,
            remote_app,
            key_values={
                # "credentials_secret_id": secret_id,  # Missing!
                "address": "https://vault.example.com",
                "ca_certificate": "some ca certificate",
            },
        )

        outstanding_requests = self.harness.charm.interface.get_outstanding_requests()

        assert len(outstanding_requests) == 1
        assert [relation.id for relation in outstanding_requests] == [relation.id]

    def test_given_1_outstanding_and_1_satisfied_request_when_get_outstanding_requests_then_outstanding_request_is_returned(
        self,
    ):
        remote_app_1, _, relation_1 = self.setup_relation(remote_app="vault-autounseal-requires-1")
        remote_app_2, _, relation_2 = self.setup_relation(remote_app="vault-autounseal-requires-2")

        secret_id = self.harness.add_model_secret(
            self.harness.charm.app, {"role-id": "some role", "secret-id": "some secret"}
        )

        self.harness.update_relation_data(
            relation_1.id,
            remote_app_1,
            key_values={
                "credentials_secret_id": secret_id,
                "address": "https://vault.example.com",
                "ca_certificate": "some ca certificate",
            },
        )
        self.harness.update_relation_data(
            relation_2.id,
            remote_app_2,
            key_values={
                # "credentials_secret_id": secret_id,  # Missing!
                "address": "https://vault.example.com",
                "ca_certificate": "some ca certificate",
            },
        )

        kv_requests = self.harness.charm.interface.get_outstanding_requests()

        assert len(kv_requests) == 1
        assert kv_requests[0].id == relation_2.id

    def test_given_satisfied_request_when_get_outstanding_kv_requests_then_request_is_not_returned(
        self,
    ):
        remote_app, remote_unit, relation = self.setup_relation()

        secret_id = self.harness.add_model_secret(
            self.harness.charm.app, {"role-id": "some role", "secret-id": "some secret"}
        )
        self.harness.update_relation_data(
            relation.id,
            remote_app,
            key_values={
                "credentials_secret_id": secret_id,
                "address": "https://vault.example.com",
                "ca_certificate": "some ca certificate",
            },
        )

        outstanding_requests = self.harness.charm.interface.get_outstanding_requests()

        assert len(outstanding_requests) == 0

    def test_given_no_request_when_get_requests_then_empty_list_is_returned(self):
        kv_requests = self.harness.charm.interface.get_outstanding_requests()

        assert len(kv_requests) == 0

    def test_given_2_requests_when_get_requests_then_requests_are_returned(self):
        remote_app_1, _, relation_1 = self.setup_relation(remote_app="vault-autounseal-requires-1")
        remote_app_2, _, relation_2 = self.setup_relation(remote_app="vault-autounseal-requires-2")

        self.harness.update_relation_data(
            relation_1.id,
            remote_app_1,
            key_values={
                # "credentials_secret_id": secret_id,  # Missing!
                "address": "https://vault.example.com",
                "ca_certificate": "some ca certificate",
            },
        )
        self.harness.update_relation_data(
            relation_2.id,
            remote_app_2,
            key_values={
                # "credentials_secret_id": secret_id,  # Missing!
                "address": "https://vault.example.com",
                "ca_certificate": "some ca certificate",
            },
        )

        requests = self.harness.charm.interface.get_outstanding_requests()

        assert len(requests) == 2
        assert {relation.id for relation in requests} == {relation_1.id, relation_2.id}


class TestVaultAutounsealRequires(unittest.TestCase):
    def setUp(self):
        self.harness = testing.Harness(
            VaultAutounsealRequirerCharm, meta=VaultAutounsealRequirerCharm.metadata_yaml
        )
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def setup_relation(self, leader: bool = True) -> tuple:
        """Set up a relation between the charm and a remote app with 1 unit."""
        remote_app = "vault-autounseal-provider"
        remote_unit = f"{remote_app}/0"
        rel_name = AUTOUNSEAL_REQUIRES_RELATION_NAME
        self.harness.set_leader(leader)
        rel_id = self.harness.add_relation(rel_name, remote_app)
        relation = self.harness.model.get_relation(rel_name, rel_id)
        assert relation
        self.harness.add_relation_unit(rel_id, remote_unit)
        return remote_app, remote_unit, relation

    @patch("test_vault_autounseal.VaultAutounsealRequirerCharm._on_details_ready")
    def test_given_unit_joined_when_all_data_present_then_vault_auto_unseal_details_ready_event_is_fired(
        self, _on_details_ready
    ):
        remote_app, remote_unit, relation = self.setup_relation()
        vault_url = "https://vault.example.com"
        credentials_secret_id = self.harness.add_model_secret(
            self.harness.charm.app, {"role-id": "some role id", "secret-id": "some secret"}
        )
        ca_certificate = "some ca certificate"
        self.harness.update_relation_data(
            relation.id,
            remote_app,
            {
                "address": vault_url,
                "credentials_secret_id": credentials_secret_id,
                "ca_certificate": ca_certificate,
            },
        )

        args, _ = _on_details_ready.call_args
        event = args[0]

        assert isinstance(event, VaultAutounsealDetailsReadyEvent)
        assert event.address == vault_url
        assert event.role_id == "some role id"
        assert event.secret_id == "some secret"
        assert event.ca_certificate == ca_certificate

    @patch("test_vault_autounseal.VaultAutounsealRequirerCharm._on_details_ready")
    def test_given_unit_joined_when_data_missing_then_vault_auto_unseal_details_ready_event_not_fired(
        self, _on_details_ready
    ):
        remote_app, remote_unit, relation = self.setup_relation()
        vault_url = "https://vault.example.com"
        credentials_secret_id = "some secret id"
        self.harness.update_relation_data(
            relation.id,
            remote_app,
            {
                "address": vault_url,
                "credentials_secret_id": credentials_secret_id,
                # "ca_certificate": Missing!
            },
        )

        _on_details_ready.assert_not_called()

    def test_given_address_in_relation_data_when_get_vault_url_then_returns_address(self):
        remote_app, remote_unit, relation = self.setup_relation()
        self.harness.update_relation_data(
            relation.id, remote_app, {"address": "https://vault.example.com"}
        )

        address = self.harness.charm.interface.get_vault_url()
        assert address == "https://vault.example.com"

    def test_given_secret_exists_and_stored_in_relation_when_get_credentials_then_returns_credentials(
        self,
    ):
        remote_app, remote_unit, relation = self.setup_relation()
        secret_id = self.harness.add_model_secret(
            self.harness.charm.app, {"role-id": "some role id", "secret-id": "some secret id"}
        )
        self.harness.update_relation_data(
            relation.id, remote_app, {"credentials_secret_id": secret_id}
        )

        credentials = self.harness.charm.interface.get_credentials()
        assert credentials == ("some role id", "some secret id")

    def test_given_ca_certificate_in_relation_data_when_get_ca_certificate_then_returns_ca_certificate(
        self,
    ):
        remote_app, remote_unit, relation = self.setup_relation()
        self.harness.update_relation_data(
            relation.id, remote_app, {"ca_certificate": "some ca certificate"}
        )

        ca_certificate = self.harness.charm.interface.get_ca_certificate()
        assert ca_certificate == "some ca certificate"
