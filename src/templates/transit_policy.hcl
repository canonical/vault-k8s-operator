path "charm-transit/*" {{
  capabilities = ["create", "read", "update", "delete", "list"]
}}

path "sys/mounts" {{
  capabilities = ["create", "read", "update", "delete", "list"]
}}
path "sys/internal/ui/mounts/{mount}" {{
  capabilities = ["read"]
}}
