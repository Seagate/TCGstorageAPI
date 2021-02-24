# System Administrator

# Allow user to check its own capabilities
path "sys/capabilities"
{
    capabilities = ["update"]
}

# Allow use of Vault's Random Number Generator
path "sys/tools/*"
{
  capabilities = ["update"]
}

# Can only access Locking SP
path "SeagateSecure/*"
{
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Access to AdminSP (SID) is explicitly blocked
path "SeagateSecure/+/SID"
{
  capabilities = ["deny"]
}