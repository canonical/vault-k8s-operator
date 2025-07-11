# Getting Started (Kubernetes)

In this tutorial, we will deploy Vault on Kubernetes and use it to store a very important secret.

## Pre-requisites
A Ubuntu 22.04 machine with the following requirements:

* A `x86_64` CPU
* 8GB of RAM
* 20GB of free disk space

## 1. Install MicroK8s

```shell
sudo snap install microk8s --channel=1.29-strict/stable
```

Enable the storage and dns addons:

```
sudo microk8s enable hostpath-storage
sudo microk8s enable dns
```

## 2. Bootstrap a Juju controller

From your terminal, install Juju:

```
sudo snap install juju --channel=3.6/stable
```

Bootstrap a Juju controller:

```
juju bootstrap microk8s
```

## 3. Deploy Vault

Create a Juju model named `demo`:

```shell
juju add-model demo
```

Deploy the Vault K8s operator:

```shell
juju deploy vault-k8s vault --channel=1.17/stable
```

Deploying Vault will take several minutes, wait for the unit to be in the `blocked/idle` state, awaiting initialisation.

```shell
$ juju status
Model  Controller          Cloud/Region        Version  SLA          Timestamp
demo   microk8s-localhost  microk8s/localhost  3.4.0    unsupported  12:31:45-04:00

App    Version  Status   Scale  Charm      Channel      Rev  Address         Exposed  Message
vault           blocked      1  vault-k8s  1.17/stable  380  10.152.183.183  no       Please initialize Vault or integrate with an auto-unseal provider

Unit      Workload  Agent  Address     Ports  Message
vault/0*  blocked   idle   10.1.0.237         Please initialize Vault or integrate with an auto-unseal provider
```

## 4. Set up the Vault CLI

To communicate with Vault via CLI, we need to install the Vault CLI client and set the following environment variables:
* `VAULT_ADDR`
* `VAULT_TOKEN`
* `VAULT_CAPATH`

Install the [Vault client](https://snapcraft.io/vault) and [yq](https://snapcraft.io/yq):

```shell
sudo snap install vault
sudo snap install yq
```

Set the `VAULT_ADDR` environment variable:
 
```shell
export VAULT_ADDR=https://$(juju status vault/leader --format=yaml | yq '.applications.vault.address'):8200; echo $VAULT_ADDR
```

Extract and store Vault's CA certificate to a `vault.pem` file:

```shell
cert_juju_secret_id=$(juju secrets --format=yaml | yq 'to_entries | .[] | select(.value.label == "self-signed-vault-ca-certificate") | .key'); echo $cert_juju_secret_id
juju show-secret ${cert_juju_secret_id} --reveal --format=yaml | yq '.[].content.certificate' > vault.pem
```

This will put the CA certificate in a file called `vault.pem`. Now, you can point the `vault` client to this file by setting the `VAULT_CAPATH` variable.

```shell
export VAULT_CAPATH=$(pwd)/vault.pem; echo $VAULT_CAPATH
```

Validate that Vault is accessible and up and running:

```shell
vault status
```

You should expect the following output.

```shell
$ vault status
Key                Value
---                -----
Seal Type          shamir
Initialized        false
Sealed             true
Total Shares       0
Threshold          0
Unseal Progress    0/0
Unseal Nonce       n/a
Version            1.17.6
Build Date         n/a
Storage Type       raft
HA Enabled         true
```

## 5. Initialise and unseal Vault

Initialise Vault: 

```shell
$ vault operator init -key-shares=1 -key-threshold=1
Unseal Key 1: NXw7vSzWOnNuNF2v5aEkQcQy/TdTuryYS9Qz3hxDS38=

Initial Root Token: hvs.0d26h3eSnlZzpUoVu49Sj64V

Vault initialized with 1 key shares and a key threshold of 1. Please securely
distribute the key shares printed above. When the Vault is re-sealed,
restarted, or stopped, you must supply at least 1 of these keys to unseal it
before it can start servicing requests.

Vault does not store the generated root key. Without at least 1 keys to
reconstruct the root key, Vault will remain permanently sealed!

It is possible to generate new unseal keys, provided you have a quorum of
existing unseal keys shares. See "vault operator rekey" for more information.
```

Set the `VAULT_TOKEN` variable using the root token:
```
export VAULT_TOKEN=hvs.0d26h3eSnlZzpUoVu49Sj64V
```

Unseal Vault using the unseal key:

```shell
vault operator unseal NXw7vSzWOnNuNF2v5aEkQcQy/TdTuryYS9Qz3hxDS38=
```

## 6. Authorise the Vault charm

Create a token:

```
$vault token create -ttl=10m
Key                  Value
---                  -----
token                hvs.M9vfjsKfv1zOgU6QTuFJblwP
token_accessor       ctfCqC3MX8vGH9G7Z3URgWsR
token_duration       10m
token_renewable      true
token_policies       ["root"]
identity_policies    []
policies             ["root"]
```
Add the token as a juju user secret

```shell
juju add-secret one-time-token token=hvs.0d26h3eSnlZzpUoVu49Sj64V
```

Grant this secret to the charm

```shell
juju grant-secret one-time-token vault
```

Authorise the charm to interact with Vault using the token value from the secret: 

```shell
juju run vault/leader authorize-charm secret-id="cq3rldnmp25c7bvnhim0"
```

You may now remove the secret

```shell
juju remove-secret one-time-token
```

## 7. Create a key-value type secret

Enable the `kv` secret engine:

```
vault secrets enable -version=2 kv
```

Create a secret under the `kv/mypasswords` path with these attributes:

* key: `bob`
* value: `1jioaf123901jdeja`

```shell
vault kv put kv/mypasswords bob=1jioaf123901jdeja
```

Good job, you created your first secret!

You can now retrieve it:

```shell
vault kv get kv/mypasswords
```

And delete it:

```shell
vault kv delete kv/mypasswords
```

## 8. Destroy the environment

Destroy the Juju controller and its models:

```shell
juju kill-controller microk8s-localhost
```

Uninstall all the installed packages:

```shell
sudo snap remove juju --purge
sudo snap remove yq --purge
sudo snap remove vault --purge
```
