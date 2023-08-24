# vault

This charm deploys [Vault][vault-upstream], a tool for securely managing
secrets used in modern computing (e.g. passwords, certificates, API keys).

In addition to deploying and initializing Vault, this charm provides a relation
for other charms to request that Vault's Certificate Authority (CA) sign a certificate 
for the related charm, enabling the related charm to manage its own TLS keys locally.

> **Note**: This charm does not support high-availability / scaling .

## Usage

### Deploy

Deploy the charm:
```bash
juju deploy vault-k8s --trust
```

## Interact with Vault

Install the Vault client:

```bash
sudo snap install vault
```

Retrieve the Vault root token from the unit:

```bash
juju run vault-k8s/0 get-root-token
```

Set the vault token for use in the client:

```bash
export VAULT_TOKEN="<root-token>"
```

Identify the vault unit by setting the `VAULT_ADDR` environment variable based on the IP address of the unit.

```bash
export VAULT_ADDR="http://10.1.182.39:8200"
```

You can now run vault commands against the vault unit.

```bash
vault status
```

<!-- LINKS -->

[vault-upstream]: https://www.vaultproject.io/docs/what-is-vault/
