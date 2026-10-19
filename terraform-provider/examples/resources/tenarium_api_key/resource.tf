# A tenant key for the customer's CI. Changing any argument rotates the key.
resource "tenarium_api_key" "ci" {
  tenant_id  = tenarium_tenant.acme.id
  name       = "ci"
  roles      = ["admin"]
  expires_in = "2160h" # 90 days
}

# A platform-wide key (no tenant_id).
resource "tenarium_api_key" "billing_sync" {
  name  = "billing sync"
  roles = ["admin"]
}

output "ci_api_key" {
  value     = tenarium_api_key.ci.key
  sensitive = true
}
