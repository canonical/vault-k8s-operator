path "example/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "sys/internal/ui/mounts/example" {
  capabilities = ["read"]
}
