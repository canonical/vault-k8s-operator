#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from unittest.mock import MagicMock, create_autospec

import pytest
from requests.exceptions import ConnectionError

from vault.vault_client import VaultClient, VaultClientError
from vault.vault_helpers import (
    ConfigAction,
    allowed_domains_config_is_valid,
    config_file_content_matches,
    get_config_action,
    sans_dns_config_is_valid,
)


def read_file(path: str) -> str:
    """Read a file and returns as a string."""
    with open(path, "r") as f:
        content = f.read()
    return content


class TestJujuConfigValidity:
    def test_given_one_domain_when_sans_dns_config_is_valid_returns_true(self):
        assert sans_dns_config_is_valid("example.com")

    def test_given_multiple_domains_when_sans_dns_config_is_valid_returns_true(self):
        assert sans_dns_config_is_valid("example.com,example.org")

    def test_given_empty_when_sans_dns_config_is_valid_returns_true(self):
        assert sans_dns_config_is_valid("")

    def test_given_invalid_string_when_sans_dns_config_is_valid_returns_false(self):
        assert not sans_dns_config_is_valid("This should have been a comma separated list")

    def test_given_valid_string_when_allowed_domains_config_is_valid_returns_true(self):
        assert allowed_domains_config_is_valid("example.com,example.org")

    def test_given_empty_when_allowed_domains_config_is_valid_returns_true(self):
        assert allowed_domains_config_is_valid("")

    def test_given_invalid_string_when_allowed_domains_config_is_valid_returns_false(self):
        assert not allowed_domains_config_is_valid("This should have been a comma separated list")


class TestConfigFileContentMatches:
    def test_given_identical_vault_config_when_config_file_content_matches_returns_true(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        assert matches

    def test_given_different_vault_config_when_config_file_content_matches_returns_false(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config_with_raft_peers.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        assert not matches

    def test_given_equivalent_vault_config_when_config_file_content_matches_returns_true(self):
        existing_content = read_file("tests/unit/config_with_raft_peers.hcl")
        new_content = read_file("tests/unit/config_with_raft_peers_equivalent.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        assert matches


def vault_config(
    peers: tuple[str, ...] = (),
    log_level: str = "info",
    default_lease_ttl: str = "168h",
    transit_address: str | None = None,
) -> str:
    """Return a Vault config file with the given settings."""
    retry_joins = "".join(
        f"""
  retry_join {{
    leader_api_addr = "{peer}"
    leader_ca_cert_file = "/vault/certs/ca.pem"
  }}"""
        for peer in peers
    )
    seal = (
        f"""
seal "transit" {{
  address = "{transit_address}"
}}"""
        if transit_address
        else ""
    )
    return f"""
storage "raft" {{
  path = "/vault/raft"
  node_id = "model-vault/0"{retry_joins}
}}
log_level = "{log_level}"
default_lease_ttl = "{default_lease_ttl}"
api_addr = "https://vault-0:8200"{seal}
"""


class TestGetConfigAction:
    @pytest.fixture
    def vault(self) -> MagicMock:
        vault = create_autospec(VaultClient, instance=True)
        vault.is_api_available.return_value = True
        vault.is_initialized.return_value = False
        return vault

    def test_given_equivalent_config_when_get_config_action_then_none(self, vault: MagicMock):
        existing = vault_config(peers=("https://vault-1:8200", "https://vault-2:8200"))
        new = vault_config(peers=("https://vault-2:8200", "https://vault-1:8200"))

        assert get_config_action(existing, new, vault) is ConfigAction.NONE
        vault.is_initialized.assert_not_called()

    def test_given_log_level_changed_when_get_config_action_then_reload(self, vault: MagicMock):
        action = get_config_action(vault_config(), vault_config(log_level="debug"), vault)

        assert action is ConfigAction.RELOAD
        vault.is_initialized.assert_not_called()

    @pytest.mark.parametrize(
        "new",
        [
            pytest.param(vault_config(default_lease_ttl="24h"), id="lease-ttl"),
            pytest.param(vault_config(transit_address="https://unsealer:8200"), id="transit"),
            pytest.param(
                vault_config(default_lease_ttl="24h", log_level="debug"), id="restart-and-reload"
            ),
        ],
    )
    def test_given_setting_read_at_startup_changed_when_get_config_action_then_restart(
        self, vault: MagicMock, new: str
    ):
        assert get_config_action(vault_config(), new, vault) is ConfigAction.RESTART
        vault.is_initialized.assert_not_called()

    def test_given_no_existing_config_when_get_config_action_then_restart(self, vault: MagicMock):
        assert get_config_action("", vault_config(), vault) is ConfigAction.RESTART

    def test_given_peers_changed_and_vault_uninitialized_when_get_config_action_then_restart(
        self, vault: MagicMock
    ):
        existing = vault_config(peers=("https://vault-0:8200",))
        new = vault_config(peers=("https://vault-0:8200", "https://vault-2:8200"))

        assert get_config_action(existing, new, vault) is ConfigAction.RESTART

    @pytest.mark.parametrize(
        "log_level,expected",
        [("info", ConfigAction.NONE), ("debug", ConfigAction.RELOAD)],
    )
    def test_given_peers_changed_and_vault_initialized_when_get_config_action_then_retry_join_ignored(  # noqa: E501
        self, vault: MagicMock, log_level: str, expected: ConfigAction
    ):
        vault.is_initialized.return_value = True
        existing = vault_config(peers=("https://vault-0:8200",))
        new = vault_config(peers=("https://vault-2:8200",), log_level=log_level)

        assert get_config_action(existing, new, vault) is expected

    @pytest.mark.parametrize("unavailable", ["no-client", "api", "init-status"])
    def test_given_peers_changed_and_vault_state_unknown_when_get_config_action_then_raises(
        self, vault: MagicMock, unavailable: str
    ):
        vault.is_api_available.return_value = unavailable != "api"
        if unavailable == "init-status":
            vault.is_initialized.side_effect = ConnectionError("connection refused")
        existing = vault_config(peers=("https://vault-0:8200",))
        new = vault_config(peers=("https://vault-2:8200",))

        with pytest.raises(VaultClientError):
            get_config_action(existing, new, None if unavailable == "no-client" else vault)
