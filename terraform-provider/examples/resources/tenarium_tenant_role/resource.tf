resource "tenarium_tenant_role" "support" {
  tenant_id   = tenarium_tenant.acme.id
  name        = "support"
  description = "Read-only access for the support team"
  actions     = ["members:read", "usage:read", "webhooks:read"]
}
