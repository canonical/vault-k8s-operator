#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import os
import tempfile

import scenario

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmInstall(VaultCharmFixtures):
    def test_given_existing_data_exists_when_install_then_existing_data_is_removed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            vault_raft_mount = scenario.Mount(
                location="/vault/raft",
                source=temp_dir,
            )
            container = scenario.Container(
                name="vault",
                can_connect=True,
                mounts={"vault-raft": vault_raft_mount},
            )
            state_in = scenario.State(containers=[container])
            with open(f"{temp_dir}/vault.db", "w") as f:
                f.write("data")
            os.mkdir(f"{temp_dir}/raft")
            with open(f"{temp_dir}/raft/raft.db", "w") as f:
                f.write("data")

            self.ctx.run(self.ctx.on.install(), state_in)

            assert not os.path.exists(f"{temp_dir}/vault.db")
            assert not os.path.exists(f"{temp_dir}/raft/raft.db")
