# High Availability

## Starting Vault with Multiple Units

Vault's Raft backend configuration is automatically generated and loaded onto all vault workloads in vault units. This configuration tells vault to search for other Vault units in the same application, and attempt to join their cluster. 

In order for this to happen, there needs to be at least 1 vault unit that's initialized and unsealed, and the joining unit and the active vault unit needs to share a root CA in their loaded certificates. 

On first deployment, if you decide to deploy ,for example, 3 units, you will notice that they will all be awaiting initialization. After you initialize 1 unit, the other 2 will still be reporting that they need to be initialized. In this case, avoid initializing more than 1 vault unit. Once you unseal the unit you've already initialized, the other vault units will be able to join the cluster, replicate the Raft database, and automatically move to the unsealing stage.

There is no need for the active vault unit that you choose to initialize to match the juju leader unit. All vault units will automatically redirect any incoming requests to the leader unit (with one rare exception that's handled by the charm).

## Connecting to Vault

After all units are unsealed, vault units will send symmetrical responses. If you're on K8s, you will have no issue simply using the application IP to allow the load balancer to decide which vault unit to serve.
