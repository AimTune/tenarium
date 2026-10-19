package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// tenantChildID builds "<tenant_id>/<attr>" import IDs.
func tenantChildID(name, attr string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return "", fmt.Errorf("%s not in state", name)
		}
		return rs.Primary.Attributes["tenant_id"] + "/" + rs.Primary.Attributes[attr], nil
	}
}

func TestAccRBAC(t *testing.T) {
	slug := uniq("rbac")
	cfg := func(actions, groupRoles string) string {
		return fmt.Sprintf(`
resource "tenarium_tenant" "t" {
  slug = %[1]q
  name = "RBAC"
}

resource "tenarium_tenant_role" "support" {
  tenant_id   = tenarium_tenant.t.id
  name        = "support"
  description = "Support staff"
  actions     = %[2]s
}

resource "tenarium_member" "alice" {
  tenant_id = tenarium_tenant.t.id
  email     = "Alice@%[1]s.example.com"
  name      = "Alice"
  role      = "member"
}

resource "tenarium_member" "bob" {
  tenant_id = tenarium_tenant.t.id
  email     = "bob@%[1]s.example.com"
  role      = tenarium_tenant_role.support.name
}

resource "tenarium_tenant_group" "oncall" {
  tenant_id   = tenarium_tenant.t.id
  name        = "On-call"
  description = "Paged at night"
  roles       = %[3]s
  members     = [tenarium_member.alice.id]
}
`, slug, actions, groupRoles)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy:             checkTenantsGone(slug),
		Steps: []resource.TestStep{
			{
				Config: cfg(`["members:read"]`, `[tenarium_tenant_role.support.name]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant_role.support", "actions.#", "1"),
					resource.TestCheckResourceAttrSet("tenarium_member.alice", "id"),
					resource.TestCheckResourceAttr("tenarium_member.alice", "email", "Alice@"+slug+".example.com"),
					resource.TestCheckResourceAttrSet("tenarium_member.alice", "status"),
					resource.TestCheckResourceAttr("tenarium_member.bob", "role", "support"),
					resource.TestCheckResourceAttr("tenarium_tenant_group.oncall", "members.#", "1"),
					resource.TestCheckResourceAttrPair("tenarium_tenant_group.oncall", "members.0", "tenarium_member.alice", "id"),
				),
			},
			{
				// Update in place: role actions, member role, group roles.
				Config: cfg(`["members:read", "usage:read"]`, `["admin", tenarium_tenant_role.support.name]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant_role.support", "actions.#", "2"),
					resource.TestCheckResourceAttr("tenarium_tenant_group.oncall", "roles.#", "2"),
				),
			},
			{
				ResourceName:      "tenarium_tenant_role.support",
				ImportState:       true,
				ImportStateIdFunc: tenantChildID("tenarium_tenant_role.support", "name"),
				ImportStateVerify: true,
			},
			{
				ResourceName:            "tenarium_member.alice",
				ImportState:             true,
				ImportStateIdFunc:       tenantChildID("tenarium_member.alice", "id"),
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"name", "email"}, // name is write-only; email case is normalized
			},
			{
				ResourceName:            "tenarium_tenant_group.oncall",
				ImportState:             true,
				ImportStateIdFunc:       tenantChildID("tenarium_tenant_group.oncall", "id"),
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"members"}, // not managed after import until configured
			},
		},
	})
}

func TestAccDomainWebhookSSO(t *testing.T) {
	slug := uniq("sso")
	verified := slug + verifiableSuffix
	cfg := func(hookURL string, enforce bool) string {
		return fmt.Sprintf(`
resource "tenarium_tenant" "t" {
  slug = %[1]q
  name = "SSO"
}

resource "tenarium_tenant_domain" "pending" {
  tenant_id = tenarium_tenant.t.id
  hostname  = "pending.%[1]s.example.net"
}

resource "tenarium_tenant_domain" "login" {
  tenant_id = tenarium_tenant.t.id
  hostname  = %[2]q
  verify    = true
}

resource "tenarium_tenant_webhook" "events" {
  tenant_id   = tenarium_tenant.t.id
  url         = %[3]q
  description = "Tenant events"
  types       = ["tenant.*", "member.*"]
}

resource "tenarium_tenant_sso" "oidc" {
  tenant_id     = tenarium_tenant.t.id
  issuer        = "http://127.0.0.1:1/realms/acme/"
  client_id     = "tenarium"
  client_secret = "s3cret"
  domains       = [tenarium_tenant_domain.login.hostname]
  enforce       = %[4]t
}
`, slug, verified, hookURL, enforce)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy:             checkTenantsGone(slug),
		Steps: []resource.TestStep{
			{
				Config: cfg("https://hooks.example.com/tenarium", false),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant_domain.pending", "verified", "false"),
					resource.TestCheckResourceAttr("tenarium_tenant_domain.pending", "txt_record_name", "_tenarium-challenge.pending."+slug+".example.net"),
					resource.TestMatchResourceAttr("tenarium_tenant_domain.pending", "txt_record_value", regexp.MustCompile(`^tenarium-verification=`)),
					resource.TestCheckResourceAttr("tenarium_tenant_domain.login", "verified", "true"),
					resource.TestCheckResourceAttrSet("tenarium_tenant_webhook.events", "secret"),
					resource.TestCheckResourceAttr("tenarium_tenant_webhook.events", "enabled", "true"),
					resource.TestCheckResourceAttr("tenarium_tenant_webhook.events", "types.1", "member.*"),
					resource.TestCheckResourceAttr("tenarium_tenant_sso.oidc", "protocol", "oidc"),
					resource.TestCheckResourceAttr("tenarium_tenant_sso.oidc", "default_role", "member"),
					resource.TestCheckResourceAttr("tenarium_tenant_sso.oidc", "enabled", "true"),
				),
			},
			{
				Config: cfg("https://hooks.example.com/v2", true),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_tenant_webhook.events", "url", "https://hooks.example.com/v2"),
					resource.TestCheckResourceAttrSet("tenarium_tenant_webhook.events", "secret"),
					resource.TestCheckResourceAttr("tenarium_tenant_sso.oidc", "enforce", "true"),
				),
			},
			{
				ResourceName:            "tenarium_tenant_domain.login",
				ImportState:             true,
				ImportStateIdFunc:       tenantChildID("tenarium_tenant_domain.login", "hostname"),
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"verify"},
			},
			{
				ResourceName:            "tenarium_tenant_webhook.events",
				ImportState:             true,
				ImportStateIdFunc:       tenantChildID("tenarium_tenant_webhook.events", "id"),
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"secret"},
			},
			{
				ResourceName: "tenarium_tenant_sso.oidc",
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					return s.RootModule().Resources["tenarium_tenant_sso.oidc"].Primary.Attributes["tenant_id"], nil
				},
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"client_secret", "issuer"},
			},
		},
	})
}

func TestAccAPIKeys(t *testing.T) {
	slug := uniq("keys")
	cfg := func(name string) string {
		return fmt.Sprintf(`
resource "tenarium_tenant" "t" {
  slug = %[1]q
  name = "Keys"
}

resource "tenarium_api_key" "ci" {
  tenant_id  = tenarium_tenant.t.id
  name       = %[2]q
  roles      = ["admin"]
  expires_in = "720h"
}

resource "tenarium_api_key" "platform" {
  name  = "platform automation"
  roles = ["admin"]
}
`, slug, name)
	}
	var firstID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy:             checkTenantsGone(slug),
		Steps: []resource.TestStep{
			{
				Config: cfg("ci"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestMatchResourceAttr("tenarium_api_key.ci", "key", regexp.MustCompile(`^tnr_`)),
					resource.TestCheckResourceAttrSet("tenarium_api_key.ci", "expires_at"),
					resource.TestCheckResourceAttrSet("tenarium_api_key.platform", "key"),
					resource.TestCheckNoResourceAttr("tenarium_api_key.platform", "tenant_id"),
					func(s *terraform.State) error {
						firstID = s.RootModule().Resources["tenarium_api_key.ci"].Primary.ID
						return nil
					},
				),
			},
			{
				// Any change replaces (rotates) the key.
				Config: cfg("ci-rotated"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("tenarium_api_key.ci", "name", "ci-rotated"),
					func(s *terraform.State) error {
						if id := s.RootModule().Resources["tenarium_api_key.ci"].Primary.ID; id == firstID {
							return fmt.Errorf("key %s was not replaced", id)
						}
						return nil
					},
				),
			},
			{
				ResourceName:            "tenarium_api_key.ci",
				ImportState:             true,
				ImportStateIdFunc:       tenantChildID("tenarium_api_key.ci", "id"),
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"key", "expires_in"},
			},
			{
				ResourceName:            "tenarium_api_key.platform",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"key"},
			},
		},
	})
}

// TestAccDomainVerifyPending asks to verify a domain whose TXT record is not
// published: apply succeeds with verified = false and the next plan retries.
func TestAccDomainVerifyPending(t *testing.T) {
	slug := uniq("pending")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProviderFactories,
		CheckDestroy:             checkTenantsGone(slug),
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "tenarium_tenant" "t" {
  slug = %[1]q
  name = "Pending"
}

resource "tenarium_tenant_domain" "d" {
  tenant_id = tenarium_tenant.t.id
  hostname  = "App.%[1]s.example.net."
  verify    = true
}
`, slug),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr("tenarium_tenant_domain.d", "verified", "false"),
				resource.TestCheckResourceAttr("tenarium_tenant_domain.d", "hostname", "App."+slug+".example.net."),
				resource.TestCheckResourceAttr("tenarium_tenant_domain.d", "txt_record_name", "_tenarium-challenge.app."+slug+".example.net"),
			),
			ExpectNonEmptyPlan: true,
		}},
	})
}
