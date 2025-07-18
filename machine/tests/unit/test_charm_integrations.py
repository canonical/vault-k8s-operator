import ops.testing as testing
from ops.testing import Context

from charm import VaultOperatorCharm


class TestCharmIntegrations:
    integration_endpoints = [
        "vault-autounseal-requires",
        "tls-certificates-access",
        "tls-certificates-pki",
        "tls-certificates-acme",
        "s3-parameters",
        "ingress",
        "vault-autounseal-provides",
        "vault-kv",
        "vault-pki",
        "cos-agent",
        "send-ca-cert",
    ]

    def test_given_integrations_when_start_then_integrations_are_complete(self):
        """Ensure no integrations were removed from the charmcraft.yaml."""
        ctx = Context(VaultOperatorCharm)
        relations = []
        for integration in self.integration_endpoints:
            relation = testing.Relation(
                endpoint=integration,
            )
            relations.append(relation)
        state_in = testing.State(
            relations=relations,
        )
        with ctx(ctx.on.start(), state_in) as manager:
            manager.run()

    def test_given_integrations_when_start_then_no_extra_integrations(self):
        """Ensure no integrations were added to the charmcraft.yaml without being added to the test."""
        ctx = Context(VaultOperatorCharm)
        with ctx(ctx.on.start(), testing.State()) as manager:
            missing_relations = set(manager.charm.meta.relations.keys()).difference(
                set(self.integration_endpoints)
            ) - {"vault-peers"}
            if missing_relations:
                raise AssertionError(
                    f"Charmcraft.yaml contains integrations missing from test: {missing_relations}"
                )
            manager.run()
