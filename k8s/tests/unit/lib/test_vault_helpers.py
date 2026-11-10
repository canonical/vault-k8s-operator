#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from unittest.mock import MagicMock

from vault.vault_client import VaultClient
from vault.vault_helpers import (
    ConfigAction,
    config_file_content_matches,
    get_config_action,
    seal_type_has_changed,
)


def read_file(path: str) -> str:
    """Read a file and returns as a string."""
    with open(path, "r") as f:
        content = f.read()
    return content


class TestSealTypeHasChanged:
    def test_given_identical_vault_config_when_seal_type_has_changed_returns_false(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config.hcl")
        assert not seal_type_has_changed(existing_content, new_content)

    def test_given_different_seal_type_config_when_seal_type_has_changed_returns_true(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/lib/config_with_transit_stanza.hcl")
        assert seal_type_has_changed(existing_content, new_content)


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
        new_content = read_file("tests/unit/lib/config_with_raft_peers.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        assert not matches

    def test_given_equivalent_vault_config_when_config_file_content_matches_returns_true(self):
        existing_content = read_file("tests/unit/lib/config_with_raft_peers.hcl")
        new_content = read_file("tests/unit/lib/config_with_raft_peers_equivalent.hcl")

        matches = config_file_content_matches(
            existing_content=existing_content, new_content=new_content
        )

        assert matches


def test_retry_join_change_restarts_only_before_vault_has_joined():
    """A joined node ignores retry_join, while an unjoined node must reread it."""
    existing = read_file("tests/unit/lib/config_with_raft_peers.hcl")
    changed = existing.replace("http://127.0.0.1:8200", "http://127.0.0.3:8200")
    vault = MagicMock(spec=VaultClient)
    vault.is_api_available.return_value = True

    vault.is_initialized.return_value = False
    assert get_config_action(existing, changed, vault) is ConfigAction.RESTART

    vault.is_initialized.return_value = True
    assert get_config_action(existing, changed, vault) is ConfigAction.NONE


def test_changed_vault_setting_requires_restart_after_join():
    existing = read_file("tests/unit/config.hcl")
    changed = existing.replace('default_lease_ttl = "168h"', 'default_lease_ttl = "24h"')
    vault = MagicMock(spec=VaultClient)

    assert get_config_action(existing, changed, vault) is ConfigAction.RESTART
    vault.is_api_available.assert_not_called()
