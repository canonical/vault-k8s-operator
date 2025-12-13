#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from datetime import timedelta
from io import StringIO
from unittest.mock import MagicMock, patch

import hcl
import ops.testing as testing
import pytest
from charms.operator_libs_linux.v2.snap import Snap
from vault.vault_autounseal import AutounsealDetails
from vault.vault_client import AppRole

from certificates import generate_example_provider_certificate
from fixtures import VaultCharmFixtures


class MockRelation:
    """Mock class for Relation used in Autounseal tests.

    We shouldn't need this mock. If we replace the output return of `get_relations_without_credentials`
    to be a list of relation ID's instead of a list of relation objects, we can remove this mock.
    """

    def __init__(self, id: int):
        self.id = id


class MockNetwork:
    """Mock class for Relation used in Autounseal tests.

    We shouldn't need this mock. If we replace the output return of `get_relations_without_credentials`
    to be a list of relation ID's instead of a list of relation objects, we can remove this mock.
    """

    def __init__(self, bind_address: str, ingress_address: str):
        self.bind_address = bind_address
        self.ingress_address = ingress_address
        self.ingress_addresses = [ingress_address]


class MockBinding:
    """Mock class for Relation used in Autounseal tests.

    We shouldn't need this mock. If we replace the output return of `get_relations_without_credentials`
    to be a list of relation ID's instead of a list of relation objects, we can remove this mock.
    """

    def __init__(self, bind_address: str, ingress_address: str):
        self.network = MockNetwork(bind_address=bind_address, ingress_address=ingress_address)


class TestCharmConfigure(VaultCharmFixtures):
    def test_given_leader_when_configure_then_config_file_is_pushed(self):
        self.mock_socket_fqdn.return_value = "myhostname"
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        model_name = "whatever"

        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            leader=True,
            relations=[peer_relation],
            model=testing.Model(name=model_name),
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.1.2")])],
                )
            },
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        with open("tests/unit/config.hcl", "r") as f:
            expected_config = f.read()

        vault_hcl_call = None
        for call in self.mock_machine.push.call_args_list:
            if call.kwargs["path"] == "/var/snap/vault/common/vault.hcl":
                vault_hcl_call = call
                break

        assert vault_hcl_call is not None, "vault.hcl was not pushed"
        pushed_content_hcl = hcl.loads(vault_hcl_call.kwargs["source"])
        assert pushed_content_hcl == hcl.loads(expected_config)

    def test_given_leader_when_configure_then_vault_service_is_started(self):
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        vault_snap = MagicMock(spec=Snap)
        snap_cache = {"vault": vault_snap}
        self.mock_snap_cache.return_value = snap_cache
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            leader=True,
            relations=[peer_relation],
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.1.2")])],
                )
            },
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        vault_snap.start.assert_called_with(services=["vaultd"])

    # PKI

    def test_given_certificate_available_when_configure_then_pki_secrets_engine_is_configured(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "authenticate.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_active_or_standby.return_value": True,
                "get_intermediate_ca.return_value": "",
                "is_common_name_allowed_in_pki_role.return_value": False,
            },
        )
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        pki_relation = testing.Relation(
            endpoint="tls-certificates-pki",
            interface="tls-certificates",
        )
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            leader=True,
            secrets=[approle_secret],
            relations=[peer_relation, pki_relation],
            config={"pki_ca_common_name": "myhostname.com"},
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.1.2")])],
                )
            },
        )
        provider_certificate, private_key = generate_example_provider_certificate(
            common_name="myhostname.com",
            relation_id=pki_relation.id,
            validity=timedelta(hours=24),
        )
        self.mock_get_requirer_assigned_certificate.return_value = (
            provider_certificate,
            private_key,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_pki_manager.configure.assert_called_once()

    @pytest.mark.parametrize(
        "config_key, config_value",
        [
            ("pki_allowed_domains", "This should have been a comma separated list"),
            ("pki_ca_sans_dns", "This should have been a comma separated list"),
        ],
    )
    def test_given_pki_config_is_invalid_when_configure_then_pki_secrets_engine_is_not_configured(
        self, config_key: str, config_value: str
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "authenticate.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_active_or_standby.return_value": True,
                "get_intermediate_ca.return_value": "",
                "is_common_name_allowed_in_pki_role.return_value": False,
            },
        )
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        pki_relation = testing.Relation(
            endpoint="tls-certificates-pki",
            interface="tls-certificates",
        )
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            leader=True,
            secrets=[approle_secret],
            relations=[peer_relation, pki_relation],
            config={
                "pki_ca_common_name": "myhostname.com",
                config_key: config_value,
            },
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.1.2")])],
                )
            },
        )
        provider_certificate, private_key = generate_example_provider_certificate(
            common_name="myhostname.com",
            relation_id=pki_relation.id,
            validity=timedelta(hours=24),
        )
        self.mock_get_requirer_assigned_certificate.return_value = (
            provider_certificate,
            private_key,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_pki_manager.configure.assert_not_called()

    # ACME
    def test_given_certificate_available_when_configure_then_acme_server_is_configured(
        self,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "authenticate.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_active_or_standby.return_value": True,
                "get_intermediate_ca.return_value": "",
                "is_common_name_allowed_in_pki_role.return_value": False,
            },
        )
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        acme_relation = testing.Relation(
            endpoint="tls-certificates-acme",
            interface="tls-certificates",
        )
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            leader=True,
            secrets=[approle_secret],
            relations=[peer_relation, acme_relation],
            config={"acme_ca_common_name": "myhostname.com"},
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.1.2")])],
                )
            },
        )
        provider_certificate, private_key = generate_example_provider_certificate(
            common_name="myhostname.com",
            relation_id=acme_relation.id,
            validity=timedelta(hours=24),
        )
        self.mock_get_requirer_assigned_certificate.return_value = (
            provider_certificate,
            private_key,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_acme_manager.configure.assert_called_once()

    @pytest.mark.parametrize(
        "config_key, config_value",
        [
            ("acme_allowed_domains", "This should have been a comma separated list"),
            ("acme_ca_sans_dns", "This should have been a comma separated list"),
        ],
    )
    def test_given_acme_config_is_invalid_when_configure_then_acme_server_is_not_configured(
        self,
        config_key: str,
        config_value: str,
    ):
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "authenticate.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_active_or_standby.return_value": True,
                "get_intermediate_ca.return_value": "",
                "is_common_name_allowed_in_pki_role.return_value": False,
            },
        )
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        acme_relation = testing.Relation(
            endpoint="tls-certificates-acme",
            interface="tls-certificates",
        )
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            leader=True,
            secrets=[approle_secret],
            relations=[peer_relation, acme_relation],
            config={
                "acme_ca_common_name": "myhostname.com",
                config_key: config_value,
            },
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.1.2")])],
                )
            },
        )
        provider_certificate, private_key = generate_example_provider_certificate(
            common_name="myhostname.com",
            relation_id=acme_relation.id,
            validity=timedelta(hours=24),
        )
        self.mock_get_requirer_assigned_certificate.return_value = (
            provider_certificate,
            private_key,
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_acme_manager.configure.assert_not_called()

    # Test Auto unseal

    @patch("ops.model.Model.get_binding")
    def test_given_autounseal_details_available_when_configure_then_transit_stanza_generated(
        self, mock_get_binding: MagicMock
    ):
        key_name = "my key"
        approle_id = "my approle id"
        approle_secret_id = "my approle secret id"
        self.mock_vault.configure_mock(
            **{
                "token": "some token",
                "is_api_available.return_value": True,
                "authenticate.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_active_or_standby.return_value": True,
                "is_common_name_allowed_in_pki_role.return_value": False,
            },
        )
        self.mock_vault_autounseal_provider_manager.configure_mock(
            **{
                "create_credentials.return_value": (key_name, approle_id, approle_secret_id),
            }
        )
        self.mock_autounseal_requires_get_details.return_value = AutounsealDetails(
            "1.2.3.4",
            "charm-autounseal",
            key_name,
            approle_id,
            approle_secret_id,
            "ca cert",
        )
        self.mock_vault_autounseal_requirer_manager.get_provider_vault_token.return_value = (
            "some token"
        )
        self.mock_tls.configure_mock(
            **{
                "pull_tls_file_from_workload.return_value": "my ca",
            },
        )
        self.mock_autounseal_requires_get_details.return_value = AutounsealDetails(
            "1.2.3.4", "charm-autounseal", "key name", "role id", "secret id", "ca cert"
        )
        self.mock_machine.pull.return_value = StringIO("")
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        vault_autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
            remote_app_name="vault-autounseal-requirer",
        )
        mock_get_binding.return_value = MockBinding(
            bind_address="myhostname",
            ingress_address="myhostname",
        )
        relation = MockRelation(id=vault_autounseal_relation.id)
        self.mock_autounseal_provides_get_relations_without_credentials.return_value = [relation]
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            leader=True,
            secrets=[approle_secret],
            relations=[peer_relation, vault_autounseal_relation],
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("myhostname")])],
                    ingress_addresses=["myhostname"],
                )
            },
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        calls = [
            call
            for call in self.mock_machine.push.call_args_list
            if call.kwargs["path"] == "/var/snap/vault/common/vault.hcl"
        ]
        assert len(calls) == 1
        _, kwargs = calls[0]
        actual_config = kwargs["source"]
        actual_config_hcl = hcl.loads(actual_config)
        assert actual_config_hcl["seal"]["transit"]["address"] == "1.2.3.4"
        assert actual_config_hcl["seal"]["transit"]["mount_path"] == "charm-autounseal"
        assert actual_config_hcl["seal"]["transit"]["key_name"] == "key name"
        self.mock_vault.authenticate.assert_called_with(AppRole("role id", "secret id"))
        self.mock_tls.push_autounseal_ca_cert.assert_called_with("ca cert")

    @patch("ops.model.Model.get_binding")
    def test_given_outstanding_autounseal_requests_when_configure_then_credentials_are_set(
        self, mock_get_binding: MagicMock
    ):
        key_name = "my key"
        approle_id = "my approle id"
        approle_secret_id = "my approle secret id"
        self.mock_vault.configure_mock(
            **{
                "is_api_available.return_value": True,
                "authenticate.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "is_active_or_standby.return_value": True,
                "is_common_name_allowed_in_pki_role.return_value": False,
            },
        )
        self.mock_vault_autounseal_provider_manager.configure_mock(
            **{
                "create_credentials.return_value": (key_name, approle_id, approle_secret_id),
            }
        )
        self.mock_autounseal_requires_get_details.return_value = AutounsealDetails(
            "1.2.3.4",
            "charm-autounseal",
            "key name",
            "role id",
            "secret id",
            "ca cert",
        )
        self.mock_vault_autounseal_requirer_manager.get_provider_vault_token.return_value = (
            "some token"
        )
        self.mock_tls.configure_mock(
            **{
                "pull_tls_file_from_workload.return_value": "my ca",
            },
        )
        self.mock_autounseal_requires_get_details.return_value = None
        self.mock_machine.pull.return_value = StringIO("")
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        vault_autounseal_relation = testing.Relation(
            endpoint="vault-autounseal-provides",
            interface="vault-autounseal",
            remote_app_name="vault-autounseal-requirer",
        )
        mock_get_binding.return_value = MockBinding(
            bind_address="myhostname",
            ingress_address="myhostname",
        )
        relation = MockRelation(id=vault_autounseal_relation.id)
        self.mock_autounseal_provides_get_relations_without_credentials.return_value = [relation]
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            leader=True,
            secrets=[approle_secret],
            relations=[peer_relation, vault_autounseal_relation],
            networks={
                testing.Network(
                    "vault-peers",
                    bind_addresses=[testing.BindAddress([testing.Address("1.2.1.2")])],
                )
            },
        )

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        self.mock_vault_autounseal_provider_manager.create_credentials.assert_called_with(
            relation,
            "https://myhostname:8200",
        )

    # KV

    def test_given_kv_request_when_configure_then_generate_credentials_for_requirer(
        self,
    ):
        self.mock_machine.pull.return_value = StringIO("")
        self.mock_vault.configure_mock(
            **{
                "token": "some token",
                "is_api_available.return_value": True,
                "authenticate.return_value": True,
                "is_initialized.return_value": True,
                "is_sealed.return_value": False,
                "generate_role_secret_id.return_value": "kv role secret id",
                "create_or_update_approle.return_value": "kv role id",
            },
        )
        self.mock_autounseal_requires_get_details.return_value = None
        peer_relation = testing.PeerRelation(
            endpoint="vault-peers",
        )
        kv_relation = testing.Relation(
            endpoint="vault-kv",
            interface="vault-kv",
            remote_app_name="vault-kv",
            remote_app_data={
                "mount_suffix": "remote-suffix",
            },
            remote_units_data={
                0: {
                    "nonce": "123123",
                    "egress_subnet": "2.2.2.0/24",
                },
            },
        )
        approle_secret = testing.Secret(
            label="vault-approle-auth-details",
            tracked_content={"role-id": "role id", "secret-id": "secret id"},
        )
        state_in = testing.State(
            unit_status=testing.ActiveStatus(),
            leader=True,
            relations=[peer_relation, kv_relation],
            secrets=[approle_secret],
        )
        self.mock_kv_provides_get_credentials.return_value = {}

        self.ctx.run(self.ctx.on.config_changed(), state_in)

        kwargs = self.mock_kv_manager.generate_credentials_for_requirer.call_args_list[0].kwargs
        assert kwargs["relation"].id == kv_relation.id
        assert kwargs["app_name"] == "vault-kv"
        assert kwargs["unit_name"] == "vault-kv/0"
        assert kwargs["mount_suffix"] == "remote-suffix"
        assert kwargs["egress_subnets"] == ["2.2.2.0/24"]
        assert kwargs["nonce"] == "123123"
        assert kwargs["vault_url"] == "https://192.0.2.0:8200"
