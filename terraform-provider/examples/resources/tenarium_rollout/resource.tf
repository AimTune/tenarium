# Turn new-editor on for 10% of the EU tenants on the pro plan that carry
# beta = "yes", always for acme and never for globex.
resource "tenarium_rollout" "new_editor" {
  feature    = "new-editor"
  percentage = 10
  plans      = [tenarium_plan.pro.id]
  regions    = ["eu"]
  labels     = { beta = "yes" }
  include    = [tenarium_tenant.acme.id]
  exclude    = [tenarium_tenant.globex.id]
  enabled    = true # false is the kill switch
}
