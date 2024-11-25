#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

from contextlib import nullcontext as does_not_raise
from unittest.mock import MagicMock, patch

import pytest
import requests
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    AuditDeviceType,
    SecretsBackend,
    Token,
    VaultClient,
    VaultClientError,
)
from hvac.exceptions import Forbidden, InternalServerError, InvalidPath

TEST_PATH = "./tests/unit/lib/charms/vault_k8s/v0"


@patch("hvac.api.auth_methods.token.Token.lookup_self")
def test_given_token_as_auth_details_when_authenticate_then_token_is_set(_):
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    vault.authenticate(Token("some token"))

    assert vault._client.token == "some token"


@patch("hvac.api.auth_methods.token.Token.lookup_self")
def test_given_valid_token_as_auth_details_when_authenticate_then_authentication_succeeds(
    patch_lookup,
):
    patch_lookup.return_value = {"data": "random data"}
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    assert vault.authenticate(Token("some token"))


@patch("hvac.api.auth_methods.token.Token.lookup_self")
def test_given_invalid_token_as_auth_details_when_authenticate_then_authentication_fails(
    patch_lookup,
):
    patch_lookup.side_effect = Forbidden()
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    vault.authenticate(Token("some token"))
    assert not vault.authenticate(Token("some token"))


@patch("hvac.api.auth_methods.token.Token.lookup_self")
@patch("hvac.api.auth_methods.approle.AppRole.login")
def test_given_approle_as_auth_details_when_authenticate_then_approle_login_is_called(
    patch_approle_login, _
):
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    vault.authenticate(AppRole(role_id="some role id", secret_id="some secret id"))

    patch_approle_login.assert_called_with(
        role_id="some role id", secret_id="some secret id", use_token=True
    )


@patch("hvac.api.system_backend.health.Health.read_health_status")
def test_given_connection_error_when_is_api_available_then_return_false(patch_health_status):
    patch_health_status.side_effect = requests.exceptions.ConnectionError()
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")

    assert not vault.is_api_available()


@patch("hvac.api.system_backend.health.Health.read_health_status")
def test_given_api_returns_when_is_api_available_then_return_true(patch_health_status):
    patch_health_status.return_value = requests.Response()
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")

    assert vault.is_api_available()


@patch("hvac.api.system_backend.raft.Raft.read_raft_config")
def test_given_node_in_peer_list_when_is_node_in_raft_peers_then_returns_true(patch_health_status):
    node_id = "whatever node id"
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    patch_health_status.return_value = {"data": {"config": {"servers": [{"node_id": node_id}]}}}

    assert vault.is_node_in_raft_peers(node_id=node_id)


@patch("hvac.api.system_backend.raft.Raft.read_raft_config")
def test_given_node_not_in_peer_list_when_is_node_in_raft_peers_then_returns_false(
    patch_health_status,
):
    node_id = "whatever node id"
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    patch_health_status.return_value = {
        "data": {"config": {"servers": [{"node_id": "not our node"}]}}
    }

    assert not vault.is_node_in_raft_peers(node_id=node_id)


@patch("hvac.api.system_backend.raft.Raft.read_raft_config")
def test_given_1_node_in_raft_cluster_when_get_num_raft_peers_then_returns_1(patch_health_status):
    patch_health_status.return_value = {
        "data": {
            "config": {
                "servers": [
                    {"node_id": "node 1"},
                    {"node_id": "node 2"},
                    {"node_id": "node 3"},
                ]
            }
        }
    }

    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")

    vault.get_num_raft_peers()

    assert vault.get_num_raft_peers() == 3


@patch("hvac.api.system_backend.auth.Auth.enable_auth_method")
def test_given_approle_not_in_auth_methods_when_enable_approle_auth_then_approle_is_added_to_auth_methods(
    patch_enable_auth_method,
):
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")

    vault.enable_approle_auth_method()

    patch_enable_auth_method.assert_called_once()


@patch("hvac.api.system_backend.audit.Audit.enable_audit_device")
def test_given_audit_device_is_not_yet_enabled_when_enable_audit_device_then_device_is_enabled(
    patch_enable_audit_device,
):
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
    patch_enable_audit_device.assert_called_once_with(
        device_type="file", options={"file_path": "stdout"}
    )


@patch("hvac.api.system_backend.audit.Audit.enable_audit_device")
def test_given_audit_device_is_enabled_when_enable_audit_device_then_nothing_happens(
    patch_enable_audit_device,
):
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
    patch_enable_audit_device.assert_called_once_with(
        device_type="file", options={"file_path": "stdout"}
    )


@patch("hvac.api.system_backend.policy.Policy.create_or_update_policy")
def test_given_policy_with_mount_when_configure_policy_then_policy_is_formatted_properly(
    patch_create_policy,
):
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    vault.configure_policy(
        "test-policy", policy_path=f"{TEST_PATH}/kv_with_mount.hcl", mount="example"
    )
    with open(f"{TEST_PATH}/kv_mounted.hcl", "r") as f:
        policy = f.read()
        patch_create_policy.assert_called_with(
            name="test-policy",
            policy=policy,
        )


@patch("hvac.api.system_backend.policy.Policy.create_or_update_policy")
def test_given_policy_without_mount_when_configure_policy_then_policy_created_correctly(
    patch_create_policy,
):
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    vault.configure_policy("test-policy", policy_path=f"{TEST_PATH}/kv_mounted.hcl")
    with open(f"{TEST_PATH}/kv_mounted.hcl", "r") as f:
        policy = f.read()
        patch_create_policy.assert_called_with(
            name="test-policy",
            policy=policy,
        )


@patch("hvac.api.auth_methods.approle.AppRole.read_role_id")
@patch("hvac.api.auth_methods.approle.AppRole.create_or_update_approle")
def test_given_approle_with_valid_params_when_configure_approle_then_approle_created(
    patch_create_approle, patch_read_role_id
):
    patch_read_role_id.return_value = {"data": {"role_id": "1234"}}
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    assert "1234" == vault.create_or_update_approle(
        "test-approle",
        policies=["root", "default"],
        cidrs=["192.168.1.0/24"],
        token_max_ttl="1h",
        token_ttl="1h",
    )

    patch_create_approle.assert_called_with(
        "test-approle",
        bind_secret_id="true",
        token_ttl="1h",
        token_max_ttl="1h",
        token_policies=["root", "default"],
        token_bound_cidrs=["192.168.1.0/24"],
        token_period=None,
    )
    patch_read_role_id.assert_called_once()


@patch("hvac.api.system_backend.mount.Mount.enable_secrets_engine")
def test_given_secrets_engine_with_valid_params_when_enable_secrets_engine_then_secrets_engine_enabled(
    patch_enable_secrets_engine,
):
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    vault.ensure_secrets_engine(SecretsBackend.KV_V2, "some/path")

    patch_enable_secrets_engine.assert_called_with(
        backend_type=SecretsBackend.KV_V2.value,
        description=f"Charm created '{SecretsBackend.KV_V2.value}' backend",
        path="some/path",
    )


@patch("hvac.api.system_backend.mount.Mount.disable_secrets_engine")
def test_when_disable_secrets_engine_then_secrets_engine_disabled(
    mock_disable_secrets_engine: MagicMock,
):
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    vault.disable_secrets_engine("some/path")

    mock_disable_secrets_engine.assert_called_with("some/path")


@patch("hvac.api.system_backend.health.Health.read_health_status")
def test_given_health_status_returns_200_when_is_active_then_return_true(patch_health_status):
    response = requests.Response()
    response.status_code = 200
    patch_health_status.return_value = response
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    assert vault.is_active_or_standby()


@patch("hvac.api.system_backend.health.Health.read_health_status")
def test_given_health_status_returns_standby_when_is_active_then_return_false(patch_health_status):
    response = requests.Response()
    response.status_code = 429
    patch_health_status.return_value = response
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    assert vault.is_active_or_standby()
    assert not vault.is_active()


@patch("hvac.api.system_backend.health.Health.read_health_status")
def test_given_health_status_returns_5xx_when_is_active_then_return_false(patch_health_status):
    response = requests.Response()
    response.status_code = 501
    patch_health_status.return_value = response
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    assert not vault.is_active_or_standby()


@patch("hvac.api.system_backend.health.Health.read_health_status")
def test_given_connection_error_when_is_active_then_return_false(patch_health_status):
    patch_health_status.side_effect = requests.exceptions.ConnectionError()
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    assert not vault.is_active_or_standby()


@patch("hvac.api.secrets_engines.pki.Pki.list_issuers")
def test_given_no_pki_issuers_when_make_latest_pki_issuer_default_then_vault_client_error_is_raised(
    patch_read_pki_issuers,
):
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    patch_read_pki_issuers.side_effect = InvalidPath()
    with pytest.raises(VaultClientError):
        vault.make_latest_pki_issuer_default(mount="test")


@patch("hvac.api.secrets_engines.pki.Pki.list_issuers")
@patch("hvac.Client.write_data")
@patch("hvac.Client.read")
def test_given_existing_pki_issuers_when_make_latest_pki_issuer_default_then_config_written_to_path(
    patch_read,
    patch_write,
    patch_read_pki_issuers,
):
    patch_read.return_value = {
        "data": {"default_follows_latest_issuer": False, "default": "whatever issuer"}
    }
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    patch_read_pki_issuers.return_value = {"data": {"keys": ["issuer"]}}
    mount = "test"
    vault.make_latest_pki_issuer_default(mount=mount)
    patch_write.assert_called_with(
        path=f"{mount}/config/issuers",
        data={
            "default_follows_latest_issuer": True,
            "default": "issuer",
        },
    )


@patch("hvac.api.secrets_engines.pki.Pki.list_issuers")
@patch("hvac.Client.write_data")
@patch("hvac.Client.read")
def test_given_issuers_config_already_updated_when_make_latest_pki_issuer_default_then_config_not_written(
    patch_read,
    patch_write,
    patch_read_pki_issuers,
):
    patch_read.return_value = {
        "data": {"default_follows_latest_issuer": True, "default": "whatever issuer"}
    }
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    patch_read_pki_issuers.return_value = {"data": {"keys": ["issuer"]}}
    mount = "test"
    vault.make_latest_pki_issuer_default(mount=mount)
    patch_write.assert_not_called()


@pytest.mark.parametrize(
    "exception_raised, expectation",
    [
        (InternalServerError(), does_not_raise()),
        (requests.exceptions.ConnectionError(), does_not_raise()),
        (ValueError(), pytest.raises(ValueError)),
        (TypeError(), pytest.raises(TypeError)),
    ],
)
def test_when_remove_raft_node_is_called_and_exception_raised_then_exception_is_surpressed_or_bubbled_up(
    exception_raised, expectation, monkeypatch
):
    monkeypatch.setattr(
        "hvac.api.system_backend.raft.Raft.remove_raft_node",
        MagicMock(side_effect=exception_raised),
    )
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    with expectation:
        vault.remove_raft_node("node_id")


@pytest.mark.parametrize(
    "exception_raised, expectation",
    [
        (InternalServerError(), does_not_raise()),
        (requests.exceptions.ConnectionError(), does_not_raise()),
        (ValueError(), pytest.raises(ValueError)),
        (TypeError(), pytest.raises(TypeError)),
    ],
)
def test_when_is_node_in_raft_peers_called_and_exception_raised_then_exception_is_surpressed_or_bubbled_up(
    exception_raised, expectation, monkeypatch
):
    monkeypatch.setattr(
        "hvac.api.system_backend.raft.Raft.read_raft_config",
        MagicMock(side_effect=exception_raised),
    )
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    with expectation:
        vault.is_node_in_raft_peers("node_id")


@pytest.mark.parametrize(
    "exception_raised, expectation",
    [
        (InternalServerError(), does_not_raise()),
        (requests.exceptions.ConnectionError(), does_not_raise()),
        (ValueError(), pytest.raises(ValueError)),
        (TypeError(), pytest.raises(TypeError)),
    ],
)
def test_when_get_num_raft_peers_called_andexception_raised_then_exception_is_surpressed_or_bubbled_up(
    exception_raised, expectation, monkeypatch
):
    monkeypatch.setattr(
        "hvac.api.system_backend.raft.Raft.read_raft_config",
        MagicMock(side_effect=exception_raised),
    )
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    with expectation:
        vault.get_num_raft_peers()


@patch("hvac.Client.read")
def test_read(patch_read):
    patch_read.return_value = {"data": {"key": "value"}}
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    result = vault.read("some/path")
    assert result == {"key": "value"}
    patch_read.assert_called_once_with("some/path")


@patch("hvac.Client.list")
def test_list(patch_list):
    patch_list.return_value = {"data": {"keys": ["key1", "key2"]}}
    vault = VaultClient(url="http://whatever-url", ca_cert_path="whatever path")
    result = vault.list("some/path")
    assert result == ["key1", "key2"]
    patch_list.assert_called_once_with("some/path")
