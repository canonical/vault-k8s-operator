# Relation-based secret engines

The Vault charm offers some of the Vault's functionality through charm relation interfaces.

## Key-Value

The Vault charm is a provider of the [vault-kv](https://charmhub.io/integrations/vault-kv) charm relation interface, allowing requirer to request key-value type secrets.

## PKI

The Vault charm is a provider of the [tls-certificates v1](https://charmhub.io/integrations/tls-certificates) charm relation interface, allowing requirer to request TLS Certificates.  Charms that implement the requirer side of the integration, using the [tls-certificates charm library](https://github.com/canonical/tls-certificates-interface), can request and receive certificates. For more information about TLS in the Juju ecosystem, [read this topic](https://charmhub.io/topics/security-with-x-509-certificates).
