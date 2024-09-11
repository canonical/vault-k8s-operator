# Allows the KV requirer to manage the KV secret engine on the given mount
# Allows the KV requirer to create, read, update, delete and list secrets
path "{mount}/*" {{
  capabilities = ["create", "read", "update", "delete", "list"]
}}
path "sys/internal/ui/mounts/{mount}" {{
  capabilities = ["read"]
}}
