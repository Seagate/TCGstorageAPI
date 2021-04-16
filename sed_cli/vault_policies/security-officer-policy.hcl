# Security Officer

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

# Can access AdminSP and LockingSP
path "SeagateSecure/*"
{
  capabilities = ["create", "read", "update", "delete", "list"]
}