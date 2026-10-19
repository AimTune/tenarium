# Invites alice if she has no account yet.
resource "tenarium_member" "alice" {
  tenant_id = tenarium_tenant.acme.id
  email     = "alice@acme.example"
  name      = "Alice"
  role      = "admin"
}

resource "tenarium_member" "bot" {
  tenant_id = tenarium_tenant.acme.id
  user_id   = "0190f3a2-0000-7000-8000-000000000001"
  role      = tenarium_tenant_role.support.name
}
