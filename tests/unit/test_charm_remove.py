#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import os
import tempfile

import scenario
from ops.pebble import Layer, ServiceStatus

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmRemove(VaultCharmFixtures):
    def test_given_can_connect_when_remove_then_data_is_deleted(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.mock_vault.configure_mock(
                **{
                    "is_api_available.return_value": True,
                    "is_initialized.return_value": True,
                    "is_sealed.return_value": False,
                    "is_node_in_raft_peers.return_value": True,
                    "get_num_raft_peers.return_value": 4,
                },
            )
            model_name = "model-name"
            approle_secret = scenario.Secret(
                id="0",
                label="vault-approle-auth-details",
                contents={0: {"role-id": "role id", "secret-id": "secret id"}},
            )
            vault_raft_mount = scenario.Mount(
                location="/vault/raft",
                src=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={"vault-raft": vault_raft_mount},
            )
            state_in = scenario.State(
                containers=[container],
                secrets=[approle_secret],
                model=scenario.Model(name=model_name),
            )
            with open(f"{temp_dir}/vault.db", "w") as f:
                f.write("data")
            os.mkdir(f"{temp_dir}/raft")
            with open(f"{temp_dir}/raft/raft.db", "w") as f:
                f.write("data")

            self.ctx.run("remove", state_in)
            assert not os.path.exists(f"{temp_dir}/vault.db")
            assert not os.path.exists(f"{temp_dir}/raft/raft.db")

    def test_given_service_is_running_when_remove_then_service_is_stopped(self):
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            contents={0: {"role-id": "role id", "secret-id": "secret id"}},
        )
        container = scenario.Container(
            name="vault",
            can_connect=True,
            layers={"vault": Layer({"services": {"vault": {}}})},
            service_status={"vault": ServiceStatus.ACTIVE},
        )
        state_in = scenario.State(
            containers=[container],
            secrets=[approle_secret],
        )

        state_out = self.ctx.run("remove", state_in)

        assert state_out.containers[0].service_status["vault"] == ServiceStatus.INACTIVE
