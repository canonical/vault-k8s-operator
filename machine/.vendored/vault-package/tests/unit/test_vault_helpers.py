#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


from vault.vault_helpers import (
    allowed_domains_config_is_valid,
    config_file_content_matches,
    sans_dns_config_is_valid,
    seal_type_has_changed,
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


class TestSealTypeHasChanged:
    def test_given_identical_vault_config_when_seal_type_has_changed_returns_false(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config.hcl")
        assert not seal_type_has_changed(existing_content, new_content)

    def test_given_different_seal_type_config_when_seal_type_has_changed_returns_true(self):
        existing_content = read_file("tests/unit/config.hcl")
        new_content = read_file("tests/unit/config_with_transit_stanza.hcl")
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
