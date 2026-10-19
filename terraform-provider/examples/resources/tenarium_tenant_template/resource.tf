resource "tenarium_tenant_template" "startup" {
  id          = "startup"
  name        = "Startup"
  description = "Defaults for self-serve startups"
  plan        = tenarium_plan.pro.id
  add_ons     = [tenarium_plan.extra_seats.id]
  region      = "eu"
  labels      = { segment = "startup" }
  settings    = jsonencode({ onboarding = { checklist = true } })
  features    = { beta = true }
  limits      = { members = 10 }

  branding = {
    primary_color = "#1a2b3c"
  }

  # Custom roles created in every new tenant.
  roles = [{
    name        = "billing"
    description = "Manages billing contacts"
    actions     = ["tenants:read", "usage:read"]
  }]
}
