### System Administrator
# Drive Replacement and Drive Decommissioning
# - Unlock (bandmaster)
# - Decommission
# - Move drive
# - Check FIPS
# - Firmware update under FIPS

# Read system health check
path "sys/capabilities"
{
    capabilities = ["update"]
}

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

path "SeagateSecure/+/SID"
{
  capabilities = ["deny"]
}