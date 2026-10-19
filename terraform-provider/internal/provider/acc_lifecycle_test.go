package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// TestAccTenantPlacement covers add-ons, region moves, the billing anchor
// and branding.
func TestAccTenantPlacement(t *testing.T) {
	base, extra := uniq("base"), uniq("extra")
	slug := uniq("placed")
	var firstID string
	cfg := func(region, addOns, anchor, branding string) string {
		return fmt.Sprintf(`
resource "tenarium_plan" "base" {
  id     = %[1]q
  name   = "Base"
  limits = { members = 5 }
}

resource "tenarium_plan" "extra" {
  id     = %[2]q
  name   = "Extra seats"
  limits = { members = 10 }
}

resource "tenarium_tenant" "t" {
  slug           = %[3]q
  name           = "Placed"
  plan           = tenarium_plan.base.id
  region         = %[4]q
  add_ons        = %[5]s
  billing_anchor = %[6]q
  %[7]s
}

data "tenarium_tenant" "t" {
  id         = tenarium_tenant.t.id
  depends_on = [tenarium_tenant.t]
}

data "tenarium_tenant_health" "t" {
  tenant_id  = tenarium_tenant.t.id
  depends_on = [tenarium_tenant.t]
}
`, base, extra, slug, region, addOns, anchor, branding)
	}
	branding := `branding = {
    display_name  = "Placed Inc."
    primary_color = "#1a2b3c"
  }`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy:             checkTenantsGone(slug),
		Steps: []resource.TestStep{
			{
				Config: cfg("eu", `[tenarium_plan.extra.id]`, "2026-01-15T00:00:00+03:00", branding),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant.t", "region", "eu"),
					resource.TestCheckResourceAttr("tenarium_tenant.t", "add_ons.#", "1"),
					resource.TestCheckTypeSetElemAttr("tenarium_tenant.t", "add_ons.*", extra),
					// The configured spelling of the anchor is kept.
					resource.TestCheckResourceAttr("tenarium_tenant.t", "billing_anchor", "2026-01-15T00:00:00+03:00"),
					resource.TestCheckResourceAttr("tenarium_tenant.t", "branding.display_name", "Placed Inc."),
					resource.TestCheckNoResourceAttr("tenarium_tenant.t", "branding.logo_url"),
					resource.TestCheckResourceAttr("tenarium_tenant.t", "plan_revision", "0"),
					resource.TestCheckResourceAttr("data.tenarium_tenant.t", "region", "eu"),
					resource.TestCheckResourceAttr("data.tenarium_tenant.t", "billing_anchor", "2026-01-14T21:00:00Z"),
					resource.TestCheckResourceAttrSet("data.tenarium_tenant_health.t", "score"),
					resource.TestCheckResourceAttrSet("data.tenarium_tenant_health.t", "grade"),
					func(s *terraform.State) error {
						firstID = s.RootModule().Resources["tenarium_tenant.t"].Primary.ID
						return checkTenant(slug, func(ten sdk.Tenant) error {
							if ten.BillingAnchor == nil || !ten.BillingAnchor.Equal(time.Date(2026, 1, 14, 21, 0, 0, 0, time.UTC)) {
								return fmt.Errorf("billing anchor = %v", ten.BillingAnchor)
							}
							if ten.Branding == nil || ten.Branding.PrimaryColor != "#1a2b3c" {
								return fmt.Errorf("branding = %+v", ten.Branding)
							}
							return nil
						})(s)
					},
				),
			},
			{
				// Same instant, other spelling: no diff.
				Config:   cfg("eu", `[tenarium_plan.extra.id]`, "2026-01-14T21:00:00Z", branding),
				PlanOnly: true,
			},
			{
				// Move to another region (no replacement), drop add-ons and
				// branding.
				Config: cfg("us", `[]`, "2026-01-14T21:00:00Z", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant.t", "region", "us"),
					resource.TestCheckResourceAttr("tenarium_tenant.t", "add_ons.#", "0"),
					resource.TestCheckNoResourceAttr("tenarium_tenant.t", "branding"),
					resource.TestCheckResourceAttr("tenarium_tenant.t", "status", "active"),
					func(s *terraform.State) error {
						if id := s.RootModule().Resources["tenarium_tenant.t"].Primary.ID; id != firstID {
							return fmt.Errorf("tenant was replaced: %s != %s", id, firstID)
						}
						return checkTenant(slug, func(ten sdk.Tenant) error {
							if ten.Region != "us" || len(ten.AddOns) != 0 || ten.Branding != nil {
								return fmt.Errorf("region %q, add-ons %v, branding %+v", ten.Region, ten.AddOns, ten.Branding)
							}
							return nil
						})(s)
					},
				),
			},
			{
				// "" removes the anchor.
				Config: cfg("us", `[]`, "", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant.t", "billing_anchor", ""),
					checkTenant(slug, func(ten sdk.Tenant) error {
						if ten.BillingAnchor != nil {
							return fmt.Errorf("billing anchor not removed: %v", ten.BillingAnchor)
						}
						return nil
					}),
				),
			},
			{
				Config:   cfg("us", `[]`, "", ""),
				PlanOnly: true,
			},
			{
				ResourceName:      "tenarium_tenant.t",
				ImportState:       true,
				ImportStateVerify: true,
				// State keeps the configured spellings of add_ons ([]) and the anchor.
				ImportStateVerifyIgnore: []string{"deletion_protection", "force_delete", "move_reprovision", "add_ons", "billing_anchor"},
			},
		},
	})
}

// TestAccPlanRevisions grandfathers a tenant on a plan update, then moves
// it to the current revision.
func TestAccPlanRevisions(t *testing.T) {
	plan, slug := uniq("gf"), uniq("gft")
	cfg := func(members int, pin string) string {
		return fmt.Sprintf(`
resource "tenarium_plan" "p" {
  id                    = %[1]q
  name                  = "Grandfathered"
  limits                = { members = %[3]d }
  grandfather_on_update = true
}

resource "tenarium_tenant" "t" {
  slug = %[2]q
  name = "Old customer"
  plan = tenarium_plan.p.id
  %[4]s
}

data "tenarium_plan_revisions" "p" {
  plan_id    = tenarium_plan.p.id
  depends_on = [tenarium_plan.p]
}
`, plan, slug, members, pin)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy:             checkTenantsGone(slug),
		Steps: []resource.TestStep{
			{
				Config: cfg(5, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_plan.p", "grandfather_on_update", "true"),
					resource.TestCheckResourceAttr("tenarium_tenant.t", "plan_revision", "0"),
					resource.TestCheckResourceAttr("data.tenarium_plan_revisions.p", "latest", "1"),
					resource.TestCheckResourceAttr("data.tenarium_plan_revisions.p", "revisions.0.limits.members", "5"),
				),
			},
			{
				// The update pins the existing tenant to revision 1; the
				// unset plan_revision only reports it.
				Config: cfg(10, ""),
				Check:  checkTenant(slug, func(ten sdk.Tenant) error { return expectRevision(ten, 1) }),
			},
			{
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant.t", "plan_revision", "1"),
					resource.TestCheckResourceAttr("data.tenarium_plan_revisions.p", "latest", "2"),
					resource.TestCheckResourceAttr("data.tenarium_plan_revisions.p", "revisions.#", "2"),
					resource.TestCheckResourceAttr("data.tenarium_plan_revisions.p", "revisions.0.limits.members", "10"),
				),
			},
			{
				// Follow the current plan again.
				Config: cfg(10, "plan_revision = 0"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant.t", "plan_revision", "0"),
					checkTenant(slug, func(ten sdk.Tenant) error { return expectRevision(ten, 0) }),
				),
			},
			{
				// And pin explicitly.
				Config: cfg(10, "plan_revision = 1"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant.t", "plan_revision", "1"),
					checkTenant(slug, func(ten sdk.Tenant) error { return expectRevision(ten, 1) }),
				),
			},
		},
	})
}

// TestAccRolloutTemplate covers rollouts, templates and creating tenants
// from a template.
func TestAccRolloutTemplate(t *testing.T) {
	plan, tpl, feature := uniq("tp"), uniq("tpl"), uniq("feat")
	plain, custom := uniq("fromtpl"), uniq("override")
	cfg := func(percentage int, enabled bool, tplName, plainLabels string) string {
		return fmt.Sprintf(`
resource "tenarium_plan" "p" {
  id   = %[1]q
  name = "Template plan"
}

resource "tenarium_tenant_template" "t" {
  id          = %[2]q
  name        = %[6]q
  description = "Preset for startups"
  plan        = tenarium_plan.p.id
  region      = "eu"
  labels      = { tier = "startup", source = "template" }
  settings    = jsonencode({ theme = { color = "blue" }, locale = "en" })
  features    = { beta = true }
  limits      = { members = 3 }
  branding    = { primary_color = "#00ff00" }
  roles = [{
    name        = "auditor"
    description = "Reads events"
    actions     = ["events:read"]
  }]
}

resource "tenarium_rollout" "r" {
  feature    = %[3]q
  percentage = %[7]d
  enabled    = %[8]t
  plans      = [tenarium_plan.p.id]
  regions    = ["eu"]
  labels     = { tier = "startup" }
  include    = [tenarium_tenant.plain.id]
  exclude    = [tenarium_tenant.custom.id]
}

# Everything from the template.
resource "tenarium_tenant" "plain" {
  slug     = %[4]q
  name     = "From template"
  template = tenarium_tenant_template.t.id
  %[9]s
}

# Configured attributes win over the template.
resource "tenarium_tenant" "custom" {
  slug     = %[5]q
  name     = "Overridden"
  template = tenarium_tenant_template.t.id
  labels   = { tier = "enterprise" }
  settings = jsonencode({ locale = "de" })
  branding = { display_name = "Custom" }
  add_ons  = []
}
`, plan, tpl, feature, plain, custom, tplName, percentage, enabled, plainLabels)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy: resource.ComposeAggregateTestCheckFunc(
			checkTenantsGone(plain, custom),
			func(*terraform.State) error {
				c, err := client.New(testServerURL, client.WithAPIKey(testAPIKey))
				if err != nil {
					return err
				}
				if _, err := c.Rollouts.Get(context.Background(), feature); !client.IsNotFound(err) {
					return fmt.Errorf("rollout still exists: %w", err)
				}
				if _, err := c.Templates.Get(context.Background(), tpl); !client.IsNotFound(err) {
					return fmt.Errorf("template still exists: %w", err)
				}
				return nil
			},
		),
		Steps: []resource.TestStep{
			{
				Config: cfg(25, true, "Startup", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant_template.t", "roles.0.actions.#", "1"),
					resource.TestCheckResourceAttr("tenarium_tenant_template.t", "branding.primary_color", "#00ff00"),
					resource.TestCheckResourceAttr("tenarium_rollout.r", "id", feature),
					resource.TestCheckResourceAttr("tenarium_rollout.r", "percentage", "25"),
					// Template values for everything left unset.
					resource.TestCheckResourceAttr("tenarium_tenant.plain", "plan", plan),
					resource.TestCheckResourceAttr("tenarium_tenant.plain", "region", "eu"),
					resource.TestCheckResourceAttr("tenarium_tenant.plain", "labels.source", "template"),
					resource.TestCheckResourceAttr("tenarium_tenant.plain", "features.beta", "true"),
					resource.TestCheckResourceAttr("tenarium_tenant.plain", "limits.members", "3"),
					resource.TestCheckResourceAttr("tenarium_tenant.plain", "branding.primary_color", "#00ff00"),
					checkTenantSettings(plain, `{"locale":"en","theme":{"color":"blue"}}`),
					// Configured values only.
					resource.TestCheckResourceAttr("tenarium_tenant.custom", "labels.%", "1"),
					resource.TestCheckResourceAttr("tenarium_tenant.custom", "labels.tier", "enterprise"),
					resource.TestCheckResourceAttr("tenarium_tenant.custom", "branding.display_name", "Custom"),
					resource.TestCheckNoResourceAttr("tenarium_tenant.custom", "branding.primary_color"),
					resource.TestCheckResourceAttr("tenarium_tenant.custom", "features.beta", "true"),
					checkTenantSettings(custom, `{"locale":"de"}`),
					// The template's custom role exists in the new tenant.
					checkTenant(plain, func(ten sdk.Tenant) error {
						c, err := client.New(testServerURL, client.WithAPIKey(testAPIKey))
						if err != nil {
							return err
						}
						var role apiRole
						return c.Do(context.Background(), "GET", rolePath(ten.ID, "auditor"), nil, nil, &role)
					}),
				),
			},
			{
				// The template no longer owns labels once they are
				// configured, and template changes do not touch tenants.
				Config: cfg(100, false, "Startup v2", `labels = { tier = "pro" }`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant_template.t", "name", "Startup v2"),
					resource.TestCheckResourceAttr("tenarium_rollout.r", "enabled", "false"),
					resource.TestCheckResourceAttr("tenarium_tenant.plain", "labels.%", "1"),
					resource.TestCheckResourceAttr("tenarium_tenant.plain", "features.beta", "true"),
				),
			},
			{
				// Removing configured labels now clears them.
				Config: cfg(100, false, "Startup v2", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("tenarium_tenant.plain", "labels.%"),
					resource.TestCheckResourceAttr("tenarium_tenant.plain", "limits.members", "3"),
				),
			},
			{
				ResourceName:      "tenarium_tenant_template.t",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "tenarium_rollout.r",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func expectRevision(ten sdk.Tenant, want int64) error {
	if ten.PlanRevision != want {
		return fmt.Errorf("plan_revision = %d, want %d", ten.PlanRevision, want)
	}
	return nil
}

// checkTenant runs check on the server-side tenant.
func checkTenant(slug string, check func(sdk.Tenant) error) resource.TestCheckFunc {
	return func(*terraform.State) error {
		c, err := client.New(testServerURL, client.WithAPIKey(testAPIKey))
		if err != nil {
			return err
		}
		ten, err := c.Tenants.Get(context.Background(), slug)
		if err != nil {
			return err
		}
		return check(ten)
	}
}
