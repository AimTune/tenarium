package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func TestAccPlanTenant(t *testing.T) {
	plan := uniq("plan")
	slug := uniq("acme")
	child := uniq("ws")
	cfg := func(name, settings, labels string) string {
		return fmt.Sprintf(`
resource "tenarium_plan" "pro" {
  id          = %[1]q
  name        = "Pro"
  description = "For teams"
  features    = { sso = true, audit = false }
  limits      = { members = 25 }
}

resource "tenarium_tenant" "acme" {
  slug     = %[2]q
  name     = %[4]q
  plan     = tenarium_plan.pro.id
  labels   = %[6]s
  settings = %[5]s
  features = { audit = true }
  limits   = { members = 50 }
}

resource "tenarium_tenant" "ws" {
  slug      = %[3]q
  name      = "Workspace"
  parent_id = tenarium_tenant.acme.id
}

data "tenarium_tenant" "by_slug" {
  slug       = tenarium_tenant.acme.slug
  depends_on = [tenarium_tenant.acme]
}

data "tenarium_plan" "pro" {
  id = tenarium_plan.pro.id
}

data "tenarium_entitlements" "acme" {
  tenant_id  = tenarium_tenant.acme.id
  depends_on = [tenarium_tenant.acme]
}
`, plan, slug, child, name, settings, labels)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy:             checkTenantsGone(slug, child),
		Steps: []resource.TestStep{
			{
				Config: cfg("Acme", `jsonencode({ theme = { color = "blue", dark = true }, locale = "en" })`, `{ env = "prod" }`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_plan.pro", "features.sso", "true"),
					resource.TestCheckResourceAttr("tenarium_plan.pro", "limits.members", "25"),
					resource.TestCheckResourceAttrSet("tenarium_plan.pro", "version"),
					resource.TestCheckResourceAttrSet("tenarium_tenant.acme", "id"),
					resource.TestCheckResourceAttr("tenarium_tenant.acme", "status", "active"),
					resource.TestCheckResourceAttr("tenarium_tenant.acme", "plan", plan),
					resource.TestCheckResourceAttr("tenarium_tenant.acme", "labels.env", "prod"),
					resource.TestCheckResourceAttr("tenarium_tenant.acme", "deletion_protection", "false"),
					resource.TestCheckResourceAttrPair("tenarium_tenant.ws", "parent_id", "tenarium_tenant.acme", "id"),
					resource.TestCheckResourceAttrPair("data.tenarium_tenant.by_slug", "id", "tenarium_tenant.acme", "id"),
					resource.TestCheckResourceAttr("data.tenarium_tenant.by_slug", "labels.env", "prod"),
					resource.TestCheckResourceAttr("data.tenarium_plan.pro", "name", "Pro"),
					resource.TestCheckResourceAttr("data.tenarium_plan.pro", "description", "For teams"),
					// Plan values with tenant overrides applied.
					resource.TestCheckResourceAttr("data.tenarium_entitlements.acme", "features.sso", "true"),
					resource.TestCheckResourceAttr("data.tenarium_entitlements.acme", "features.audit", "true"),
					resource.TestCheckResourceAttr("data.tenarium_entitlements.acme", "limits.members", "50"),
					checkTenantSettings(slug, `{"locale":"en","theme":{"color":"blue","dark":true}}`),
				),
			},
			{
				// Same settings, different formatting: no diff.
				Config:   cfg("Acme", `"{\"locale\": \"en\", \"theme\": {\"dark\": true, \"color\": \"blue\"}}"`, `{ env = "prod" }`),
				PlanOnly: true,
			},
			{
				// Rename, drop a nested setting and a top-level setting, add a label.
				Config: cfg("Acme Inc", `jsonencode({ theme = { color = "red" }, beta = [1, 2] })`, `{ env = "prod", tier = "gold" }`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant.acme", "name", "Acme Inc"),
					resource.TestCheckResourceAttr("tenarium_tenant.acme", "labels.tier", "gold"),
					checkTenantSettings(slug, `{"beta":[1,2],"theme":{"color":"red"}}`),
				),
			},
			{
				ResourceName:            "tenarium_tenant.acme",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"deletion_protection", "force_delete"},
			},
			{
				// Import by slug.
				ResourceName:            "tenarium_tenant.acme",
				ImportState:             true,
				ImportStateId:           slug,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"deletion_protection", "force_delete"},
			},
			{
				ResourceName:      "tenarium_plan.pro",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccTenantDrift changes a tenant behind Terraform's back:
// the refresh picks the change up and the next apply reverts it.
func TestAccTenantDrift(t *testing.T) {
	slug := uniq("drift")
	cfg := fmt.Sprintf(`
resource "tenarium_tenant" "t" {
  slug   = %q
  name   = "Drift"
  labels = { a = "1" }
}
`, slug)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy:             checkTenantsGone(slug),
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				PreConfig: func() {
					c := testClient(t)
					_, err := c.Tenants.Update(context.Background(), slug, client.UpdateTenantRequest{
						Name: client.Ptr("Changed elsewhere"),
					})
					if err != nil {
						t.Fatal(err)
					}
				},
				Config: cfg,
				Check:  resource.TestCheckResourceAttr("tenarium_tenant.t", "name", "Drift"),
			},
		},
	})
}

func TestAccTenantDeletionProtection(t *testing.T) {
	slug := uniq("protected")
	cfg := func(protect bool) string {
		return fmt.Sprintf(`
resource "tenarium_tenant" "t" {
  slug                = %q
  name                = "Protected"
  deletion_protection = %t
  force_delete        = true
}
`, slug, protect)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy:             checkTenantsGone(slug),
		Steps: []resource.TestStep{
			{Config: cfg(true)},
			{
				// Removing the resource must fail while protected.
				Config:      `# empty`,
				ExpectError: regexp.MustCompile(`protected from deletion`),
			},
			{
				Config: cfg(false),
				Check:  resource.TestCheckResourceAttr("tenarium_tenant.t", "deletion_protection", "false"),
			},
		},
	})
}

// checkTenantSettings compares the server-side settings with want (JSON).
func checkTenantSettings(slug, want string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		c, err := client.New(testServerURL, client.WithAPIKey(testAPIKey))
		if err != nil {
			return err
		}
		ten, err := c.Tenants.Get(context.Background(), slug)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(ten.Settings)
		var got, exp any
		_ = json.Unmarshal(raw, &got)
		if err := json.Unmarshal([]byte(want), &exp); err != nil {
			return err
		}
		if !reflect.DeepEqual(got, exp) {
			return fmt.Errorf("settings = %s, want %s", raw, want)
		}
		return nil
	}
}

// checkTenantsGone verifies the tenants are deleted (or being deleted).
func checkTenantsGone(slugs ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		c, err := client.New(testServerURL, client.WithAPIKey(testAPIKey))
		if err != nil {
			return err
		}
		for _, s := range slugs {
			ten, err := c.Tenants.Get(context.Background(), s)
			if client.IsNotFound(err) {
				continue
			}
			if err != nil {
				return err
			}
			if ten.Status != sdk.StatusDeleted && ten.Status != sdk.StatusDeleting {
				return fmt.Errorf("tenant %s still %s", s, ten.Status)
			}
		}
		return nil
	}
}
