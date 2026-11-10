#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Exercise backup and restore against MicroCeph's S3 gateway."""

import json
from asyncio import Task

import pytest
from pytest_operator.plugin import OpsTest

from tests.integration.helpers import get_app, has_relation
from tests.integration.integration_support import (
    APP_NAME,
    NUM_VAULT_UNITS,
    S3_INTEGRATOR_APPLICATION_NAME,
    get_leader_vault_client,
    run_create_backup_action,
    run_list_backups_action,
    run_restore_backup_action,
    run_s3_integrator_sync_credentials_action,
)


@pytest.mark.abort_on_fail
async def test_backup_and_restore_with_microceph(
    ops_test: OpsTest, vault_authorized: Task, s3_integrator_idle: Task
):
    """Verify that a snapshot restores Vault data through a real S3 gateway."""
    assert ops_test.model
    root_token, _ = await vault_authorized
    await s3_integrator_idle

    return_code, host_ip, stderr = await ops_test.juju(
        "exec", "--unit", f"{APP_NAME}/leader", "ip route | grep 'default via' | awk '{print $3}'"
    )
    assert return_code == 0, stderr
    endpoint = f"http://{host_ip.strip()}:7480"

    await run_s3_integrator_sync_credentials_action(
        ops_test, access_key="vaultmicrocephtest", secret_key="vaultmicrocephtest"
    )
    s3_integrator = get_app(ops_test.model, S3_INTEGRATOR_APPLICATION_NAME)
    await s3_integrator.set_config(
        {"endpoint": endpoint, "bucket": "vault-microceph-test", "region": "local"}
    )
    await ops_test.model.wait_for_idle(
        apps=[S3_INTEGRATOR_APPLICATION_NAME], status="active", timeout=1000
    )
    vault_app = get_app(ops_test.model)
    if not has_relation(vault_app, "s3-parameters"):
        await ops_test.model.integrate(
            relation1=APP_NAME, relation2=S3_INTEGRATOR_APPLICATION_NAME
        )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, wait_for_exact_units=NUM_VAULT_UNITS
    )

    vault = await get_leader_vault_client(ops_test, APP_NAME)
    vault.client.token = root_token
    vault.client.sys.enable_secrets_engine(backend_type="kv", path="backport-test")
    vault.client.write("backport-test/secret", value="before-backup")

    created = await run_create_backup_action(ops_test)
    backup_id = created["backup-id"]
    listed = json.loads((await run_list_backups_action(ops_test))["backup-ids"])
    assert backup_id in listed

    vault.client.delete("backport-test/secret")
    assert vault.client.read("backport-test/secret") is None
    restored = await run_restore_backup_action(ops_test, backup_id)
    assert restored["restored"] == backup_id
    assert vault.client.read("backport-test/secret")["data"]["value"] == "before-backup"
