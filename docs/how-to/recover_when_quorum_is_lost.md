# Recover a Vault Cluster When Raft Quorum is Lost

## Prerequisites

1. A Vault cluster that has lost quorum

## 1. Scale the Cluster Down to One Node

On the machine charm, this means removing all but one unit. Ideally, keep the unit that is the leader, but otherwise choose any healthy unit that is in the blocked "Waiting for vault to finish raft leader election" state.

```shell
juju remove-unit vault/1 vault/2 vault/3 vault/4
```

You may need to use a combination of `--force` and `--no-wait` to remove units if they are in a bad state.

On the Kubernetes charm, you can scale the deployment down using the scale-application command.

```shell
juju scale-application vault-k8s 1
```

## 2. Run the `bootstrap-raft` Action

Next, run the `bootstrap-raft` action on the remaining unit. This will re-bootstrap the cluster with a single node.

```shell
juju run vault/leader bootstrap-raft
```

This should update the status of the unit to "Please unseal Vault".

## 3. Unseal Vault

If necessary, follow the instructions on how to unseal Vault in the Unseal a sealed unit guide.

## 4. Scale the Cluster Back Up

Once the single unit is unsealed, you can scale the cluster back up to the desired number of units (and unseal if necessary)

On the Machine charm:

```shell
juju add-unit vault -n 4
```

Or, on the Kubernetes charm:

```shell
juju scale-application vault-k8s 5
```
