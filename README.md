# vault

This charm deploys [Vault][vault-upstream], a tool for securely managing
secrets used in modern computing (e.g. passwords, certificates, API keys).

In addition to deploying and initializing Vault, this charm supports high availability mode using
the Raft backend.

## Usage

### Deploy

Deploy the charm:
```bash
juju deploy vault-k8s -n 5 --trust
```

We recommend deploying Vault with an odd number of units.

### Retrieve Vault's Root token

Retrieve the Juju secrets list:

```bash
user@ubuntu:~$ juju secrets
ID                    Owner      Rotation  Revision  Last updated
cjma4gdp3des7ac9uedg  vault-k8s  never            1  11 seconds ago
```

Read the secret content:

```bash
user@ubuntu:~$ juju show-secret cjma4gdp3des7ac9uedg --reveal
cjma4gdp3des7ac9uedg:
  revision: 1
  owner: vault-k8s
  created: 2023-08-28T13:33:54Z
  updated: 2023-08-28T13:33:54Z
  content:
    roottoken: hvs.Z3CuzSQno3XMuUgUcm1CmjQK
    unsealkeys: '["11bd448ccfec24db29ed5c14fdfe3d169589f5c5c6b57870e31d738aec623856"]'
```

### Interact with Vault

Install the Vault client:

```bash
sudo snap install vault
```

Set the vault token for use in the client:

```bash
export VAULT_TOKEN=hvs.Z3CuzSQno3XMuUgUcm1CmjQK
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
