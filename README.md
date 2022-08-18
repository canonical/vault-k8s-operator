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

### TLS Certificates
To use Vault to sign certificates for another charm:

```bash
juju deploy <your charm>
juju add-relation vault-k8s <your charm>
```

The requirer charm should use the `tls-certificates` relation and leverage the tls-certificates 
[library](https://charmhub.io/tls-certificates-interface/).


## Post-deployment tasks

Once the application is deployed the following tasks **must** be performed:

* Vault initialisation
* Unsealing of Vault

Vault itself will be needed as a client to perform these tasks.

### Vault client

Vault is needed as a client in order to manage the Vault deployment. Install it
on the host where the Juju client resides:

```bash
sudo snap install vault
```

### Initialise Vault

Identify the vault unit by setting the ``VAULT_ADDR`` environment variable
based on the IP address of the unit. This can be discovered from `kubectl get services`
output (column 'EXTERNAL-IP'). Here we'll use '10.0.0.126':

```bash
export VAULT_ADDR="http://10.0.0.126:8200"
```

Initialise Vault by specifying the number of unseal keys that should get
generated as well as the number of unseal keys that are needed in order to
complete the unseal process. Below we will specify five and three,
respectively:

```bash
vault operator init -key-shares=5 -key-threshold=3
```


Sample output:

    Unseal Key 1: XONSc5Ku8HJu+ix/zbzWhMvDTiPpwWX0W1X/e/J1Xixv
    Unseal Key 2: J/fQCPvDeMFJT3WprfPy17gwvyPxcvf+GV751fTHUoN/
    Unseal Key 3: +bRfX5HMISegsODqNZxvNcupQp/kYQuhsQ2XA+GamjY4
    Unseal Key 4: FMRTPJwzykgXFQOl2XTupw2lfgLOXbbIep9wgi9jQ2ls
    Unseal Key 5: 7rrxiIVQQWbDTJPMsqrZDKftD6JxJi6vFOlyC0KSabDB

    Initial Root Token: s.ezlJjFw8ZDZO6KbkAkm605Qv

    Vault initialized with 5 key shares and a key threshold of 3. Please securely
    distribute the key shares printed above. When the Vault is re-sealed,
    restarted, or stopped, you must supply at least 3 of these keys to unseal it
    before it can start servicing requests.

    Vault does not store the generated master key. Without at least 3 key to
    reconstruct the master key, Vault will remain permanently sealed!

    It is possible to generate new unseal keys, provided you have a quorum of
    existing unseal keys shares. See "vault operator rekey" for more information.

Besides displaying the five unseal keys the output also includes an "initial
root token". This token is used to access the Vault API.

> **Warning**: It is not possible to unseal Vault without the unseal keys, nor
  is it possible to manage Vault without the initial root token. **Store this
  information in a safe place immediately**.

### Unseal Vault

Unseal the vault unit using the requisite number of unique keys (three in this
example):
```bash
vault operator unseal XONSc5Ku8HJu+ix/zbzWhMvDTiPpwWX0W1X/e/J1Xixv
vault operator unseal FMRTPJwzykgXFQOl2XTupw2lfgLOXbbIep9wgi9jQ2ls
vault operator unseal 7rrxiIVQQWbDTJPMsqrZDKftD6JxJi6vFOlyC0KSabDB
```

> **Note**: Maintenance work on the cloud may require vault units to be paused
  and later resumed. A resumed vault unit will be sealed and will therefore
  require unsealing.

Proceed to the next step once all units have been unsealed.

### Authorise the vault charm

The vault charm must be authorised to access the Vault deployment in order to
create storage backends (for secrets) and roles (to allow other applications to
access Vault for encryption key storage).

Generate a root token with a limited lifetime (10 minutes here) using the
initial root token:

```bash
export VAULT_TOKEN=s.ezlJjFw8ZDZO6KbkAkm605Qv
vault token create -ttl=10m
```

Sample output:

    Key                  Value
    ---                  -----
    token                s.QMhaOED3UGQ4MeH3fmGOpNED
    token_accessor       nApB972Dp2lnTTIF5VXQqnnb
    token_duration       10m
    token_renewable      true
    token_policies       ["root"]
    identity_policies    []
    policies             ["root"]

This temporary token ('token') is then used to authorise the charm:

```bash
juju run-action --wait vault-k8s/leader authorise-charm token=s.QMhaOED3UGQ4MeH3fmGOpNED
```

After the action completes execution, the vault unit(s) will become active and
any pending requests for secrets storage will be processed for consuming
applications.

Now that the post-deployment steps have been completed you will most likely
want to add a CA certificate to Vault. See [Managing TLS
certificates][cdg-vault-certs-add] in the [OpenStack Charms Deployment
Guide][cdg] for details.

### Automation

Vault initialization and unsealing can be done using Vault's Python API client:

```python
import hvac

# Setup
vault = hvac.Client(url="http://10.0.0.126:8200")

# Initialise
initialize_response = vault.sys.initialize(secret_shares=1, secret_threshold=1)

# Unseal
vault.sys.submit_unseal_key(initialize_response["keys"][0])

# Generate token for charm
token_response = vault.auth.token.create(ttl="10m")
token = token_response["auth"]["client_token"]
```

<!-- LINKS -->

[vault-upstream]: https://www.vaultproject.io/docs/what-is-vault/
