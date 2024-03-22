# Allow management of policies starting with charm- prefix
path "sys/policy/charm-*" {
  capabilities = ["create", "read", "update", "delete"]
}
# Allow operations under the charm prefix
path "charm-*" {
  capabilities = [ "create", "read", "update", "delete", "list", "sudo" ]
}

# Allow discovery of all policies
path "sys/policy/" {
  capabilities = ["list"]
}

# Allow management of approle's with charm- prefix
path "auth/approle/role/charm-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow discovery of approles
path "auth/approle/role" {
  capabilities = ["read"]
}
path "auth/approle/role/" {
  capabilities = ["list"]
}

# Allow charm- prefixes secrets backends to be mounted and managed
path "sys/mounts/charm-*" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}

# Allow charm- prefixes pki backends to be used
path "charm-pki-*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Allow discovery of secrets backends
path "sys/mounts" {
  capabilities = ["read"]
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
path "sys/storage/raft/remove-peer" {
  capabilities = ["update"]
}

# Allow taking and restoring snapshots of Vault
path "sys/storage/raft/snapshot" {
  capabilities = ["create", "read"]
}