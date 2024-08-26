#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import tempfile

import hcl
import scenario
from charms.vault_k8s.v0.vault_autounseal import (
    AutounsealDetails,
)
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    Certificate,
    SecretsBackend,
)
from ops.pebble import Layer

from tests.unit.certificates import (
    generate_example_provider_certificate,
    generate_example_requirer_csr,
)
from tests.unit.fixtures import MockBinding, VaultCharmFixtures


class MockRelation:
    def __init__(self, id: int):
        self.id = id


class TestCharmConfigure(VaultCharmFixtures):
    def test_given_leader_when_configure_then_config_file_is_pushed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_socket_fqdn.return_value = "myhostname"
            self.mock_autounseal_requires_get_details.return_value = None
            model_name = "whatever"
            vault_raft_mount = scenario.Mount(
                location="/vault/raft",
                src=temp_dir,
            )
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-raft": vault_raft_mount,
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                relations=[peer_relation],
                model=scenario.Model(name=model_name),
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            with open(f"{temp_dir}/vault.hcl", "r") as f:
                actual_config = f.read()

            with open("tests/unit/config.hcl", "r") as f:
                expected_config = f.read()
            actual_content_hcl = hcl.loads(actual_config)
            expected_content_hcl = hcl.loads(expected_config)
            assert actual_content_hcl == expected_content_hcl

    def test_given_leader_when_configure_then_pebble_layer_is_planned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                relations=[peer_relation],
            )

            state_out = self.ctx.run(container.pebble_ready_event, state_in)

            assert state_out.containers[0].layers == {
                "vault": Layer(
                    {
                        "summary": "vault layer",
                        "description": "pebble config layer for vault",
                        "services": {
                            "vault": {
                                "summary": "vault",
                                "startup": "enabled",
                                "override": "replace",
                                "command": "vault server -config=/vault/config/vault.hcl",
                            }
                        },
                    }
                )
            }

    # PKI

    def test_given_vault_active_when_configure_then_pki_secrets_engine_is_configured(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_vault.configure_mock(
                **{
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "is_active_or_standby.return_value": True,
                    "generate_pki_intermediate_ca_csr.return_value": "my csr",
                },
            )
            self.mock_pki_requirer_get_assigned_certificates.return_value = []
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            pki_relation = scenario.Relation(
                endpoint="tls-certificates-pki",
                interface="tls-certificates",
            )
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, pki_relation],
                config={"common_name": "myhostname.com"},
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            self.mock_vault.enable_secrets_engine.assert_called_once_with(
                SecretsBackend.PKI, "charm-pki"
            )
            self.mock_vault.generate_pki_intermediate_ca_csr.assert_called_once_with(
                mount="charm-pki",
                common_name="myhostname.com",
            )
            self.mock_pki_requirer_request_certificate_creation.assert_called_once_with(
                certificate_signing_request="my csr".encode(),
                is_ca=True,
            )

    def test_given_vault_is_available_when_pki_certificate_is_available_then_certificate_added_to_vault_pki_and_latest_issuer_set_to_default(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_vault.configure_mock(
                **{
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "is_active_or_standby.return_value": True,
                    "generate_pki_intermediate_ca_csr.return_value": "my csr",
                    "is_common_name_allowed_in_pki_role.return_value": False,
                },
            )
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            pki_relation = scenario.Relation(
                endpoint="tls-certificates-pki",
                interface="tls-certificates",
            )
            provider_certificate = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=pki_relation.relation_id,
            )
            self.mock_pki_requirer_get_assigned_certificates.return_value = [provider_certificate]
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, pki_relation],
                config={"common_name": "myhostname.com"},
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            self.mock_vault.set_pki_intermediate_ca_certificate.assert_called_once_with(
                certificate=provider_certificate.certificate,
                mount="charm-pki",
            )
            self.mock_vault.make_latest_pki_issuer_default.assert_called_once_with(
                mount="charm-pki",
            )
            self.mock_vault.create_or_update_pki_charm_role.assert_called_once_with(
                allowed_domains="myhostname.com",
                mount="charm-pki",
                role="charm",
            )

    def test_given_vault_available_when_vault_pki_certificate_creation_request_then_certificate_is_provided(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_vault.configure_mock(
                **{
                    "is_api_available.return_value": True,
                    "authenticate.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "is_active_or_standby.return_value": True,
                    "generate_pki_intermediate_ca_csr.return_value": "my csr",
                    "is_common_name_allowed_in_pki_role.return_value": False,
                    "sign_pki_certificate_signing_request.return_value": Certificate(
                        certificate="my certificate",
                        ca="my ca",
                        chain=["my ca"],
                    ),
                },
            )
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            pki_relation_provider = scenario.Relation(
                endpoint="tls-certificates-pki",
                interface="tls-certificates",
                remote_app_name="tls-provider",
            )
            pki_relation_requirer = scenario.Relation(
                endpoint="vault-pki",
                interface="tls-certificates",
                remote_app_name="tls-requirer",
            )
            provider_certificate = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=pki_relation_provider.relation_id,
            )
            requirer_csr = generate_example_requirer_csr(
                common_name="subdomain.myhostname.com",
                relation_id=pki_relation_requirer.relation_id,
            )
            self.mock_pki_requirer_get_assigned_certificates.return_value = [provider_certificate]

            self.mock_pki_provider_get_outstanding_certificate_requests.return_value = [
                requirer_csr
            ]
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, pki_relation_provider, pki_relation_requirer],
                config={"common_name": "myhostname.com"},
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            self.mock_vault.sign_pki_certificate_signing_request.assert_called_once_with(
                mount="charm-pki",
                role="charm",
                csr=requirer_csr.csr,
                common_name="subdomain.myhostname.com",
            )
            self.mock_pki_provider_set_relation_certificate.assert_called_once_with(
                relation_id=pki_relation_requirer.relation_id,
                certificate="my certificate",
                ca="my ca",
                certificate_signing_request=requirer_csr.csr,
                chain=["my ca"],
            )

    # Test Auto unseal

    def test_given_autounseal_details_available_when_autounseal_details_ready_then_transit_stanza_generated(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
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
                    "generate_pki_intermediate_ca_csr.return_value": "my csr",
                    "is_common_name_allowed_in_pki_role.return_value": False,
                    "create_autounseal_credentials.return_value": (
                        key_name,
                        approle_id,
                        approle_secret_id,
                    ),
                },
            )
            self.mock_tls.configure_mock(
                **{
                    "pull_tls_file_from_workload.return_value": "my ca",
                },
            )
            self.mock_autounseal_requires_get_details.return_value = AutounsealDetails(
                "1.2.3.4", "charm-autounseal", "key name", "role id", "secret id", "ca cert"
            )
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            pki_relation_provider = scenario.Relation(
                endpoint="tls-certificates-pki",
                interface="tls-certificates",
                remote_app_name="tls-provider",
            )
            vault_autounseal_relation = scenario.Relation(
                endpoint="vault-autounseal-provides",
                interface="vault-autounseal",
                remote_app_name="vault-autounseal-requirer",
            )
            provider_certificate = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=pki_relation_provider.relation_id,
            )
            self.mock_get_binding.return_value = MockBinding(
                bind_address="myhostname",
                ingress_address="myhostname",
            )
            self.mock_pki_requirer_get_assigned_certificates.return_value = [provider_certificate]
            relation = MockRelation(id=vault_autounseal_relation.relation_id)
            self.mock_autounseal_provides_get_outstanding_requests.return_value = [relation]
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, pki_relation_provider, vault_autounseal_relation],
                config={"common_name": "myhostname.com"},
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            with open(f"{temp_dir}/vault.hcl", "r") as f:
                actual_config = f.read()
            actual_config_hcl = hcl.loads(actual_config)
            assert actual_config_hcl["seal"]["transit"]["address"] == "1.2.3.4"
            assert actual_config_hcl["seal"]["transit"]["mount_path"] == "charm-autounseal"
            assert actual_config_hcl["seal"]["transit"]["token"] == "some token"
            assert actual_config_hcl["seal"]["transit"]["key_name"] == "key name"
            self.mock_vault.authenticate.assert_called_with(AppRole("role id", "secret id"))
            self.mock_tls.push_autounseal_ca_cert.assert_called_with("ca cert")

    def test_given_outstanding_autounseal_requests_when_autounseal_initialize_then_credentials_are_set(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
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
                    "generate_pki_intermediate_ca_csr.return_value": "my csr",
                    "is_common_name_allowed_in_pki_role.return_value": False,
                    "create_autounseal_credentials.return_value": (
                        key_name,
                        approle_id,
                        approle_secret_id,
                    ),
                },
            )
            self.mock_tls.configure_mock(
                **{
                    "pull_tls_file_from_workload.return_value": "my ca",
                },
            )
            self.mock_autounseal_requires_get_details.return_value = None
            vault_config_mount = scenario.Mount(
                location="/vault/config",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={
                    "vault-config": vault_config_mount,
                },
            )
            peer_relation = scenario.PeerRelation(
                endpoint="vault-peers",
            )
            pki_relation_provider = scenario.Relation(
                endpoint="tls-certificates-pki",
                interface="tls-certificates",
                remote_app_name="tls-provider",
            )
            vault_autounseal_relation = scenario.Relation(
                endpoint="vault-autounseal-provides",
                interface="vault-autounseal",
                remote_app_name="vault-autounseal-requirer",
            )
            provider_certificate = generate_example_provider_certificate(
                common_name="myhostname.com",
                relation_id=pki_relation_provider.relation_id,
            )
            self.mock_get_binding.return_value = MockBinding(
                bind_address="myhostname",
                ingress_address="myhostname",
            )
            self.mock_pki_requirer_get_assigned_certificates.return_value = [provider_certificate]
            relation = MockRelation(id=vault_autounseal_relation.relation_id)
            self.mock_autounseal_provides_get_outstanding_requests.return_value = [relation]
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            state_in = scenario.State(
                containers=[container],
                leader=True,
                secrets=[approle_secret],
                relations=[peer_relation, pki_relation_provider, vault_autounseal_relation],
                config={"common_name": "myhostname.com"},
            )

            self.ctx.run(container.pebble_ready_event, state_in)

            self.mock_autounseal_provides_set_data.assert_called_with(
                relation,
                "https://myhostname:8200",
                "charm-autounseal",
                key_name,
                approle_id,
                approle_secret_id,
                "my ca",
            )
