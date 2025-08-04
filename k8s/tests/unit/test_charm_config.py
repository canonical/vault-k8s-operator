from pathlib import Path

import ops.testing as testing
import yaml
from ops.testing import Context, State

from charm import VaultCharm
from fixtures import VaultCharmFixtures


class TestCharmConfig(VaultCharmFixtures):
    config = {
        "cpu": "1",
        "memory": "1Gi",
        "default_lease_ttl": "168h",
        "max_lease_ttl": "720h",
        "log_level": "info",
        "access_sans_dns": "example.com",
        "access_country_name": "US",
        "access_state_or_province_name": "CA",
        "access_locality_name": "San Francisco",
        "access_organization": "Example Inc",
        "access_organizational_unit": "IT",
        "access_email_address": "info@example.com",
        "pki_ca_common_name": "example.com",
        "pki_ca_sans_dns": "example.com",
        "pki_ca_country_name": "US",
        "pki_ca_state_or_province_name": "CA",
        "pki_ca_locality_name": "San Francisco",
        "pki_ca_organization": "Example Inc",
        "pki_ca_organizational_unit": "IT",
        "pki_ca_email_address": "info@example.com",
        "pki_allowed_domains": "example.com",
        "pki_allow_subdomains": False,
        "pki_allow_wildcard_certificates": True,
        "pki_allow_any_name": False,
        "pki_allow_ip_sans": False,
        "pki_organization": "Example Inc",
        "pki_organizational_unit": "IT",
        "pki_country": "US",
        "pki_province": "CA",
        "pki_locality": "San Francisco",
        "acme_ca_common_name": "example.com",
        "acme_ca_sans_dns": "example.com",
        "acme_ca_country_name": "US",
        "acme_ca_state_or_province_name": "CA",
        "acme_ca_locality_name": "San Francisco",
        "acme_ca_organization": "Example Inc",
        "acme_ca_organizational_unit": "IT",
        "acme_ca_email_address": "info@example.com",
        "acme_allowed_domains": "example.com",
        "acme_allow_subdomains": False,
        "acme_allow_wildcard_certificates": True,
        "acme_allow_any_name": False,
        "acme_allow_ip_sans": False,
        "acme_organization": "Example Inc",
        "acme_organizational_unit": "IT",
        "acme_country": "US",
        "acme_province": "CA",
        "acme_locality": "San Francisco",
    }

    def test_given_config_with_defaults_then_default_config_values_are_correct(self):
        """This test checks the default config values."""
        ctx = Context(VaultCharm)
        with ctx(
            ctx.on.start(), State(containers=[testing.Container(name="vault", can_connect=True)])
        ) as manager:
            manager.run()
            assert manager.charm.model.config.get("default_lease_ttl") == "168h"
            assert manager.charm.model.config.get("max_lease_ttl") == "720h"
            assert manager.charm.model.config.get("log_level") == "info"
            assert not manager.charm.model.config.get("pki_allow_subdomains")
            assert manager.charm.model.config.get("pki_allow_wildcard_certificates")
            assert not manager.charm.model.config.get("pki_allow_any_name")
            assert not manager.charm.model.config.get("pki_allow_ip_sans")
            assert not manager.charm.model.config.get("acme_allow_subdomains")
            assert manager.charm.model.config.get("acme_allow_wildcard_certificates")
            assert not manager.charm.model.config.get("acme_allow_any_name")
            assert not manager.charm.model.config.get("acme_allow_ip_sans")

    def test_given_config_when_start_then_config_keys_are_complete_and_types_are_correct(self):
        """This test checks the config keys and their types.

        This is supposed to fail if a key is removed or the type is changed.
        """
        ctx = Context(VaultCharm)
        state_in = testing.State(
            config=self.config,
            containers=[testing.Container(name="vault", can_connect=True)],
        )
        with ctx(ctx.on.start(), state_in) as manager:
            manager.run()

    def test_given_config_when_start_then_no_extra_config_keys(self):
        """Ensure no keys were added to the config file without being added to the test."""
        charmcraft_data = yaml.safe_load(Path("./charmcraft.yaml").read_text())
        config_options = charmcraft_data.get("config", {}).get("options", {})
        expected_keys = set(config_options.keys())
        diff = expected_keys.difference(set(self.config.keys()))
        if diff:
            raise AssertionError(f"Charmcraft.yaml contains config keys missing from test: {diff}")
