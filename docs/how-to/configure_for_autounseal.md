# Configure a Vault for auto-unseal 

**WARNING: There is currently no way to remove the auto-unseal configuration once it has been set on Vault Charms. Removing the integration may put Vault Charms in a bad state which requires manual intervention.**


## Prerequisites

1. A Vault Charm instance you wish to use as the *unsealer*. Deployed, initialized, unsealed, and authorized. See [Tutorial: Getting started with Vault-K8s](../tutorial/getting_started_k8s.md) or [Getting Started: Vault (Machine)](../tutorial/getting_started_machine.md) if you're not there yet.
2. A second Vault Charm instance you wish to use as the *autounsealed* Vault. This instance may already be initialized, unsealed, and authorized, or you may initialize it as part of this process.

## 1. Integrate the Vault instances

Integrate the *autounsealed* Vault instance with the *unsealer* Vault instance.

```bash
juju integrate vault-unsealer:vault-autounseal-provides vault-autounsealed:vault-autounseal-requires
```

## 2. Configure the Vault CLI to interact with the *autounsealed* Vault.

```bash
export VAULT_ADDR="..."
export VAULT_TOKEN="..."
```

Now, either follow 2a for an initialized *autounsealed* Vault instance, or 2b for an uninitialized *autounsealed* Vault instance.

### 2a. Migrate the *autounsealed* Vault instance to auto-unseal

In this step, the Vault instance being migrated needs to be unsealed with the existing *manual unseal keys*, and migrate its data to auto-unseal. To do this, unseal the Vault instance with the `-migrate` flag.

```bash
vault operator unseal -migrate ${token}
```

### 2b. If not already initialized, initialize and authorize the *autounsealed* Vault instance

Configure your CLI to interact with the *autounsealed* Vault instance. See the getting started guide for more information on how to do this. In short, you will need to set the `VAULT_ADDR` environment variable to the address of the *autounsealed* Vault instance, and retrieve and set the appropriate CA certificate.

```bash
vault operator init
```

Use the root token to create a temporary token, and authorize the Vault charm with it.

```console
$ vault token create -ttl=10m
Key                  Value
---                  -----
token                hvs.mmMXCLNZ2X7OcqCM38WYDnoX
token_accessor       eXzWoD1ajA5YtNgfopj1DP1r
token_duration       10m
token_renewable      true
token_policies       ["root"]
identity_policies    []
policies             ["root"]
```

Create a secret that contains the token above
```console
$ juju add-secret approle_authorization_token token="hvs.mmMXCLNZ2X7OcqCM38WYDnoX"
secret:cqgj49fmp25c7796r0pg
```

Grant the secret to the *autounsealed* vault, and provide the ID of the secret to the `authorize-charm` action.
```bash
juju grant-secret approle_authorization_token vault-autounsealed
juju run vault-autounsealed/leader authorize-charm secret-id=cqgj49fmp25c7796r0pg
```
