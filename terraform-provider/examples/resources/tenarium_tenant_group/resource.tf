resource "tenarium_tenant_group" "oncall" {
  tenant_id   = tenarium_tenant.acme.id
  name        = "On-call"
  description = "Engineers paged at night"
  roles       = [tenarium_tenant_role.support.name]

  # Omit members to leave membership to SCIM or the UI.
  members = [tenarium_member.alice.id]
}
