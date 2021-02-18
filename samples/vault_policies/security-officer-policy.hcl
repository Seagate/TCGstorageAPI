# Read system health check
path "sys/capabilities"
{
    capabilities = ["update"]
}

# Read system health check
path "sys/tools/*"
{
  capabilities = ["update"]
}

# Enable and manage the key/value secrets engine at `secret/` path

# List, create, update, and delete key/value secrets
path "SeagateSecure/*"
{
  capabilities = ["create", "read", "update", "delete", "list"]
}