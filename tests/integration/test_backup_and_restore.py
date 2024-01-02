#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import json
from pathlib import Path
from typing import List

import pytest
import yaml
from juju.application import Application
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APPLICATION_NAME = "vault-k8s"
MINIO_APPLICATION_NAME = "minio"
S3_INTEGRATOR_APPLICATION_NAME = "s3-integrator"

MINIO_S3_ACCESS_KEY = "minio_access_key"
MINIO_S3_SECRET_KEY = "minio_secret_key"
MINIO_CONFIG = {
    "access-key": MINIO_S3_ACCESS_KEY,
    "secret-key": MINIO_S3_SECRET_KEY,
}

NUM_VAULT_UNITS = 5


async def get_leader_unit(model, application_name: str) -> Unit:
    """Returns the leader unit for the given application."""
    for unit in model.units.values():
        if unit.application == application_name and await unit.is_leader_from_status():
            return unit
    raise RuntimeError(f"Leader unit for `{application_name}` not found.")


class TestBackupAndRestore:
    @staticmethod
    async def deploy_charm(ops_test: OpsTest, charm: Path) -> None:
        """Deploys charm.

        Args:
            ops_test: Ops test Framework.
            charm: Charm path.
        """
        assert ops_test.model
        resources = {
            "vault-image": METADATA["resources"]["vault-image"]["upstream-source"],
        }
        await ops_test.model.deploy(
            charm,
            resources=resources,
            application_name=APPLICATION_NAME,
            trust=True,
            series="jammy",
            num_units=NUM_VAULT_UNITS,
        )

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def build_and_deploy(self, ops_test: OpsTest):
        """Builds and deploys vault-k8s charm.

        Args:
            ops_test: Ops test Framework.
        """
        ops_test.destructive_mode = False
        charm = await ops_test.build_charm(".")
        assert charm is not None
        await self.deploy_charm(ops_test, charm)

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def deploy_s3_integrator(self, ops_test: OpsTest) -> None:
        """Deploys S3 Integrator.

        Args:
            ops_test: Ops test Framework.
        """
        assert ops_test.model
        await ops_test.model.deploy(
            "s3-integrator",
            application_name=S3_INTEGRATOR_APPLICATION_NAME,
            trust=True,
        )

    @pytest.mark.abort_on_fail
    @pytest.fixture(scope="module")
    async def deploy_minio(self, ops_test: OpsTest) -> None:
        """Deploys minio-operator.

        Args:
            ops_test: Ops test Framework.
        """
        assert ops_test.model
        await ops_test.model.deploy(
            "minio", application_name=MINIO_APPLICATION_NAME, trust=True, config=MINIO_CONFIG
        )

    async def run_s3_integrator_sync_credentials_action(
        self,
        ops_test: OpsTest,
        access_key: str,
        secret_key: str,
    ) -> dict:
        """Runs `sync-s3-credentials` action on the `s3-integrator` leader unit.

        Args:
            ops_test (OpsTest): OpsTest

        Returns:
            dict: Action output
        """
        assert ops_test.model
        leader_unit = await get_leader_unit(ops_test.model, S3_INTEGRATOR_APPLICATION_NAME)
        sync_credentials_action = await leader_unit.run_action(
            action_name="sync-s3-credentials",
            **{
                "access-key": access_key,
                "secret-key": secret_key,
            },
        )
        return await ops_test.model.get_action_output(
            action_uuid=sync_credentials_action.entity_id, wait=120
        )

    async def run_create_backup_action(
        self,
        ops_test: OpsTest,
    ) -> dict:
        """Runs `create-backup` action on the `vault-k8s` leader unit.

        Args:
            ops_test (OpsTest): OpsTest

        Returns:
            dict: Action output
        """
        assert ops_test.model
        leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
        create_backup_action = await leader_unit.run_action(
            action_name="create-backup",
        )
        return await ops_test.model.get_action_output(
            action_uuid=create_backup_action.entity_id, wait=120
        )

    async def run_list_backups_action(
        self,
        ops_test: OpsTest,
    ) -> dict:
        """Runs `list-backups` action on the `vault-k8s` leader unit.

        Args:
            ops_test (OpsTest): OpsTest

        Returns:
            dict: Action output
        """
        assert ops_test.model
        leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
        list_backups_action = await leader_unit.run_action(
            action_name="list-backups",
        )
        return await ops_test.model.get_action_output(
            action_uuid=list_backups_action.entity_id, wait=120
        )

    async def run_restore_backup_action(
        self,
        ops_test: OpsTest,
        backup_id: str,
        root_token: str,
        unseal_keys: List[str],
    ) -> dict:
        """Runs `restore-backup` action on the `vault-k8s` leader unit.

        Args:
            ops_test (OpsTest): OpsTest

        Returns:
            dict: Action output
        """
        assert ops_test.model
        leader_unit = await get_leader_unit(ops_test.model, APPLICATION_NAME)
        restore_backup_action = await leader_unit.run_action(
            action_name="restore-backup",
            **{
                "backup-id": backup_id,
                "unseal-keys": unseal_keys,
                "root-token": root_token,
            },
        )
        restore_backup_action_output = await ops_test.model.get_action_output(
            action_uuid=restore_backup_action.entity_id, wait=120
        )
        return restore_backup_action_output

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_and_related_to_s3_integrator_when_create_backup_action_then_backup_is_created(
        self,
        ops_test: OpsTest,
        build_and_deploy,
        deploy_s3_integrator,
        deploy_minio,
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[MINIO_APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=1,
        )
        status = await ops_test.model.get_status()
        minio_ip = (
            status.applications[MINIO_APPLICATION_NAME]
            .units[f"{MINIO_APPLICATION_NAME}/0"]
            .address
        )
        endpoint = f"http://{minio_ip}:9000"
        s3_integrator = ops_test.model.applications[S3_INTEGRATOR_APPLICATION_NAME]
        await self.run_s3_integrator_sync_credentials_action(
            ops_test,
            secret_key=MINIO_S3_SECRET_KEY,
            access_key=MINIO_S3_ACCESS_KEY,
        )
        s3_config = {
            "endpoint": endpoint,
            "bucket": "test-bucket",
            "region": "local",
        }
        await s3_integrator.set_config(s3_config)
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.integrate(
            relation1=APPLICATION_NAME,
            relation2=S3_INTEGRATOR_APPLICATION_NAME,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        vault = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(vault, Application)
        create_backup_action_output = await self.run_create_backup_action(ops_test)
        assert create_backup_action_output["backup-id"]

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_and_backup_created_when_list_backups_action_then_backups_are_listed(
        self,
        ops_test: OpsTest,
        build_and_deploy,
        deploy_s3_integrator,
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        vault = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(vault, Application)
        list_backups_action_output = await self.run_list_backups_action(ops_test)
        assert list_backups_action_output["backup-ids"]

    @pytest.mark.abort_on_fail
    async def test_given_application_is_deployed_and_backup_created_when_restore_backup_action_then_backup_is_restored(
        self,
        ops_test: OpsTest,
        build_and_deploy,
        deploy_s3_integrator,
    ):
        assert ops_test.model
        await ops_test.model.wait_for_idle(
            apps=[S3_INTEGRATOR_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[APPLICATION_NAME],
            status="active",
            timeout=1000,
            wait_for_exact_units=NUM_VAULT_UNITS,
        )
        vault = ops_test.model.applications[APPLICATION_NAME]
        assert isinstance(vault, Application)
        list_backups_action_output = await self.run_list_backups_action(ops_test)
        backup_id = json.loads(list_backups_action_output["backup-ids"])[0]
        # In this test we are not using the correct unsealed keys and root token.
        restore_backup_action_output = await self.run_restore_backup_action(
            ops_test,
            backup_id=backup_id,
            root_token="RandomRootToken",
            unseal_keys=["RandomUnsealKey"],
        )
        assert restore_backup_action_output["restored"] == backup_id
