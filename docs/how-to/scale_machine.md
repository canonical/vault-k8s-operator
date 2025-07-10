# Scale (Machine)

The Vault charm uses the [raft](https://developer.hashicorp.com/vault/docs/configuration/storage/raft) backend to scale. This guide walks you through scaling Vault.

## Pre-requisites

- Vault is initialised and unseal
- The Vault charm is authorised

## 1. Validate that Vault is an active state

Run `juju status`:
```
Model  Controller           Cloud/Region         Version  SLA          Timestamp
demo   localhost-localhost  localhost/localhost  3.4.0    unsupported  12:11:19-04:00

App    Version  Status  Scale  Charm  Channel      Rev  Exposed  Message
vault           active      1  vault  1.17/stable  257  no       

Unit      Workload  Agent  Machine  Public address  Ports  Message
vault/0*  active    idle   0        10.191.126.116         

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.191.126.116  juju-b8368f-0  ubuntu@22.04      Running
```

## 2. Scale Vault to 3 units

Add 2 more units:

```
juju add-unit vault -n 2
```

The new units will be sealed:

```
Model  Controller           Cloud/Region         Version  SLA          Timestamp
demo   localhost-localhost  localhost/localhost  3.4.0    unsupported  12:19:14-04:00

App    Version  Status   Scale  Charm  Channel      Rev  Exposed  Message
vault           blocked      3  vault  1.17/stable  257  no       Waiting for Vault to be unsealed

Unit      Workload  Agent  Machine  Public address  Ports  Message
vault/0*  active    idle   0        10.191.126.116         
vault/1   blocked   idle   1        10.191.126.151         Waiting for Vault to be unsealed
vault/2   blocked   idle   2        10.191.126.90          Waiting for Vault to be unsealed

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.191.126.116  juju-b8368f-0  ubuntu@22.04      Running
1        started  10.191.126.151  juju-b8368f-1  ubuntu@22.04      Running
2        started  10.191.126.90   juju-b8368f-2  ubuntu@22.04      Running

```

Set the `VAULT_ADDR` variable to the `vault/1` unit:
```
export VAULT_ADDR=https://$(juju status vault/1 --format=yaml | awk '/public-address/ { print $2 }'):8200; echo $VAULT_ADDR
```
Unseal the the `vault/1` unit using the same unseal keys as received during the initialization of the Vault leader:

```
vault operator unseal EJoB62t286mjUpSQYZg3mOla3lz/bbElVL5OLnj+rpE=
```

And complete the same operations for the `vault/2` unit:

```
export VAULT_ADDR=https://$(juju status vault/2 --format=yaml | awk '/public-address/ { print $2 }'):8200; echo $VAULT_ADDR
vault operator unseal EJoB62t286mjUpSQYZg3mOla3lz/bbElVL5OLnj+rpE=
```

## 3. Validate that all units are part of the cluster

All units should go to the `Active/Idle` Juju status:

```
$ juju status
Model  Controller           Cloud/Region         Version  SLA          Timestamp
demo   localhost-localhost  localhost/localhost  3.4.0    unsupported  12:24:32-04:00

App    Version  Status  Scale  Charm  Channel      Rev  Exposed  Message
vault           active      3  vault  1.17/stable  257  no       

Unit      Workload  Agent  Machine  Public address  Ports  Message
vault/0*  active    idle   0        10.191.126.116         
vault/1   active    idle   1        10.191.126.151         
vault/2   active    idle   2        10.191.126.90          

Machine  State    Address         Inst id        Base          AZ  Message
0        started  10.191.126.116  juju-b8368f-0  ubuntu@22.04      Running
1        started  10.191.126.151  juju-b8368f-1  ubuntu@22.04      Running
2        started  10.191.126.90   juju-b8368f-2  ubuntu@22.04      Running

```

And they should all be part of the raft cluster:

```
$ vault operator raft list-peers
Node            Address                State       Voter
----            -------                -----       -----
demo-vault/0    10.191.126.116:8201    leader      true
demo-vault/1    10.191.126.151:8201    follower    true
demo-vault/2    10.191.126.90:8201     follower    true
```
