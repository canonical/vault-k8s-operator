#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import tempfile

import hcl
import scenario

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmConfigure(VaultCharmFixtures):
    def test_given_leader_when_configure_then_config_file_is_pushed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_socket_fqdn.return_value = "myhostname"
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
