# Charm Policies

When running the [authorize-charm](https://charmhub.io/vault-k8s/actions) Juju action, the charm creates a Vault policy to ensure it can only access what it needs for day-to-day operations.

These rules are defined in the [charm_policy.hcl](https://github.com/canonical/vault-k8s-operator/blob/main/k8s/src/templates/charm_policy.hcl) file.

Paths starting with the `charm—` prefix should only be accessed by the charm; it is strongly discouraged for users to create resources under these paths.
