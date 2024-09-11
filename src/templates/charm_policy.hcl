# Allow management of secrets on secret engines starting with charm- prefix
# Allows reading, writing, updating, deleting and listing secrets
# Wildcard path is required as the charm won't know the rest of the path for the kv mount at the time of policy creation
# KV mount path with charm prefix is provided by the KV requirer
path "charm-*"{
  capabilities = [ "create", "read", "update", "list", "delete"]
}

# Allow discovery of all policies
path "sys/policy/" {
  capabilities = ["list"]
}

# Required for managing policies with charm- prefix
# Allows creating, reading, updating and deleting policies
# The wildcard path is required as the charm won't know the full path of the policy at the time of policy creation in the case of vault-kv
path "sys/policy/charm-*" {
  capabilities = ["create", "read", "update", "delete"]
}

# Allow discovery of secrets backends

# Allow management of approle's with charm- prefix
# Allows creating, reading, updating, deleting and listing approle's
# The wildcard path is required as the charm won't know the full path of the approle at the time of approle creation in the case of vault-kv
path "auth/approle/role/charm-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow discovery of approles
path "auth/approle/role/" {
  capabilities = ["list"]
}

# Allow charm- prefixes secrets backends to be mounted and managed
# Allows enabling, reading, updating, deleting and listing secret engines
# The wildcard path is required as the charm won't know the full path of the secret engine at the time of secret engine creation in the case of vault-kv
path "sys/mounts/charm-*" {
  capabilities = ["create", "read", "update", "list", "delete"]
}

path "sys/mounts/" {
  capabilities = ["list"]
}

# Allow reading the health of the raft backend
path "sys/storage/raft/autopilot/state" {
  capabilities = ["read"]
}
# Allow reading raft peers
path "sys/storage/raft/configuration" {
  capabilities = ["read"]
}

# Allow removing nodes from the raft backend
# This is required for the charm to prune dead nodes from the raft backend
path "sys/storage/raft/remove-peer" {
  capabilities = ["update"]
}

# Allow taking snapshots of Vault
path "sys/storage/raft/snapshot" {
  capabilities = ["read"]
}

# Allows the charm to restore a snapshot
path "sys/storage/raft/snapshot-force" {
  capabilities = ["update"]
}
