resource "tenarium_plan" "pro" {
  id          = "pro"
  name        = "Pro"
  description = "For growing teams"
  features = {
    sso   = true
    audit = true
  }
  limits = {
    members   = 50
    api_calls = 100000
  }

  # Changes apply to new subscribers only: tenants already on the plan are
  # pinned to its previous revision on every update.
  grandfather_on_update = true
}

# An add-on: a plan stacked on another one with tenarium_tenant.add_ons.
resource "tenarium_plan" "extra_seats" {
  id     = "extra-seats"
  name   = "10 extra seats"
  limits = { members = 10 }
}
