resource "tenarium_tenant" "acme" {
  slug   = "acme"
  name   = "Acme Inc."
  plan   = tenarium_plan.pro.id
  region = "eu" # changing it later moves the tenant

  # Add-on plans stacked on the plan.
  add_ons = [tenarium_plan.extra_seats.id]

  labels = {
    tier = "gold"
  }

  # Any JSON object; formatting and key order do not cause diffs.
  settings = jsonencode({
    theme  = { color = "#0050ff" }
    locale = "en"
  })

  # Overrides on top of the plan.
  features = { beta = true }
  limits   = { members = 100 }

  # Monthly billing cycles start on the 15th.
  billing_anchor = "2026-01-15T00:00:00Z"

  branding = {
    display_name  = "Acme"
    logo_url      = "https://acme.example/logo.svg"
    primary_color = "#0050ff"
    support_email = "support@acme.example"
  }

  deletion_protection = true
}

# A workspace nested under the organization.
resource "tenarium_tenant" "acme_dev" {
  slug      = "acme-dev"
  name      = "Acme (dev)"
  parent_id = tenarium_tenant.acme.id

  # Skip the server's deletion grace period on destroy.
  force_delete = true
}

# A tenant preset by a template: plan, region, labels, branding and custom
# roles come from the template unless configured here.
resource "tenarium_tenant" "globex" {
  slug     = "globex"
  name     = "Globex"
  template = tenarium_tenant_template.startup.id

  # Stay on revision 3 of the plan instead of following its changes.
  plan_revision = 3
}
