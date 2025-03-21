path "{mount}/*" {{
  capabilities = ["create", "read", "update", "delete", "list"]
}}
path "sys/internal/ui/mounts/{mount}" {{
  capabilities = ["read"]
}}
