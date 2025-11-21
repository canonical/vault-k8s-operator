# Scale (K8s)

The Vault charm uses the [raft](https://developer.hashicorp.com/vault/docs/configuration/storage/raft) backend to scale. This guide walks you through scaling Vault.

## Pre-requisites

- Vault is initialised and unsealed
- The Vault charm is authorised

## 1. Validate that Vault is an active state

Run `juju status`:
```
Model  Controller          Cloud/Region        Version  SLA          Timestamp
demo   microk8s-localhost  microk8s/localhost  3.4.0    unsupported  12:52:32-04:00

App    Version  Status   Scale  Charm      Channel    Rev  Address         Exposed  Message
vault           waiting      1  vault-k8s  1.18/edge  198  10.152.183.208  no       installing agent

Unit      Workload  Agent  Address      Ports  Message
vault/0*  active    idle   10.1.182.38
```

## 2. Scale Vault to 3 units

Add 2 more units:

```
juju add-unit vault -n 2
```

The new units will be sealed:

```
Model  Controller          Cloud/Region        Version  SLA          Timestamp
demo   microk8s-localhost  microk8s/localhost  3.4.0    unsupported  12:54:51-04:00

App    Version  Status   Scale  Charm      Channel    Rev  Address         Exposed  Message
vault           waiting      3  vault-k8s  1.18/edge  198  10.152.183.208  no       installing agent

Unit      Workload  Agent  Address      Ports  Message
vault/0*  active    idle   10.1.182.38         
vault/1   blocked   idle   10.1.182.51         Please unseal Vault
vault/2   blocked   idle   10.1.182.34         Please unseal Vault
```

Set the `VAULT_ADDR` variable to the `vault/1` unit:
```
export VAULT_ADDR=https://$(juju status vault/1 --format=yaml |  yq -r '.applications.vault.units.vault/1.address'):8200; echo $VAULT_ADDR
```

Set the `VAULT_SKIP_VERIFY` to true:

```
export VAULT_SKIP_VERIFY=true
```

Unseal the the `vault/1` unit using the same unseal keys as received during the initialization of the Vault leader:

```
vault operator unseal EJoB62t286mjUpSQYZg3mOla3lz/bbElVL5OLnj+rpE=
```

And complete the same operations for the `vault/2` unit:

```
export VAULT_ADDR=https://$(juju status vault/2 --format=yaml |  yq -r '.applications.vault.units.vault/2.address'):8200; echo $VAULT_ADDR
vault operator unseal EJoB62t286mjUpSQYZg3mOla3lz/bbElVL5OLnj+rpE=
```

## 3. Validate that all units are part of the cluster

All units should go to the `Active/Idle` Juju status:

```
$ juju status
Model  Controller          Cloud/Region        Version  SLA          Timestamp
demo   microk8s-localhost  microk8s/localhost  3.4.0    unsupported  12:57:52-04:00

App    Version  Status  Scale  Charm      Channel    Rev  Address         Exposed  Message
vault           active      3  vault-k8s  1.18/edge  198  10.152.183.208  no       

Unit      Workload  Agent  Address      Ports  Message
vault/0*  active    idle   10.1.182.38         
vault/1   active    idle   10.1.182.51         
vault/2   active    idle   10.1.182.34 
```

And they should all be part of the raft cluster:

```
$ vault operator raft list-peers
Node            Address                                                State       Voter
----            -------                                                -----       -----
demo-vault/0    vault-0.vault-endpoints.demo.svc.cluster.local:8201    leader      true
demo-vault/1    vault-1.vault-endpoints.demo.svc.cluster.local:8201    follower    true
demo-vault/2    vault-2.vault-endpoints.demo.svc.cluster.local:8201    follower    true
```
