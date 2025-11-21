# Unseal a sealed unit (K8s)

In the circumstance that a Vault unit restarts, you will have to manually unseal it. This guide walks you through the necessary steps:

Starting from a cluster where one unit is sealed:
```
$ juju status
Model  Controller          Cloud/Region        Version  SLA          Timestamp
demo   microk8s-localhost  microk8s/localhost  3.4.0    unsupported  13:02:12-04:00

App    Version  Status   Scale  Charm      Channel    Rev  Address         Exposed  Message
vault           waiting      3  vault-k8s  1.18/edge  198  10.152.183.208  no       installing agent

Unit      Workload  Agent  Address      Ports  Message
vault/0*  active    idle   10.1.182.38         
vault/1   active    idle   10.1.182.51         
vault/2   blocked   idle   10.1.182.15         Please unseal Vault
```

Set the `VAULT_ADDR` variable to the sealed unit:

```
export VAULT_ADDR=https://$(juju status vault/2 --format=yaml |  yq -r '.applications.vault.units.vault/2.address'):8200; echo $VAULT_ADDR
```

Unseal the the unit using the same unseal keys as received during the initialization of the Vault leader:

```
vault operator unseal -tls-skip-verify EJoB62t286mjUpSQYZg3mOla3lz/bbElVL5OLnj+rpE=
```

The units will go back to the active/idle state:

```
$ juju status
Model  Controller          Cloud/Region        Version  SLA          Timestamp
demo   microk8s-localhost  microk8s/localhost  3.4.0    unsupported  13:03:26-04:00

App    Version  Status  Scale  Charm      Channel    Rev  Address         Exposed  Message
vault           active      3  vault-k8s  1.18/edge  198  10.152.183.208  no       

Unit      Workload  Agent  Address      Ports  Message
vault/0*  active    idle   10.1.182.38         
vault/1   active    idle   10.1.182.51         
vault/2   active    idle   10.1.182.15
```
