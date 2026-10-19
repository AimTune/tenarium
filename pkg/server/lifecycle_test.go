package server_test

import (
	"testing"
)

func TestLifecycleExtrasAPI(t *testing.T) {
	c := client{t: t, base: startServer(t, baseConfig())}
	code, tpl := c.do("PUT", "/v1/tenant-templates/agency", map[string]any{"name": "Agency",
		"labels": map[string]any{"kind": "agency"}, "branding": map[string]any{"display_name": "Agency", "primary_color": "#123456"},
		"roles": []any{map[string]any{"name": "auditor", "actions": []string{"tenants:read"}}}})
	if code != 200 || tpl["id"] != "agency" {
		t.Fatalf("put template: %d %v", code, tpl)
	}
	code, tn := c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme", "template": "agency"})
	if code != 201 || tn["labels"].(map[string]any)["kind"] != "agency" {
		t.Fatalf("create from template: %d %v", code, tn)
	}
	_, ak := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "owner", "roles": []string{"owner"}})
	owner := as(c, ak["key"].(string))

	// Public branding for sign-in pages.
	code, b := c.do("GET", "/v1/auth/branding?tenant=acme", nil)
	if code != 200 || b["display_name"] != "Agency" || b["primary_color"] != "#123456" {
		t.Fatalf("branding: %d %v", code, b)
	}

	// Maintenance makes the tenant read-only for its own callers.
	if code, _ := owner("POST", "/v1/tenants/acme/maintenance", map[string]any{"message": "x"}); code != 403 {
		t.Fatalf("tenant started maintenance on itself: %d", code)
	}
	if code, _ := c.do("POST", "/v1/tenants/acme/maintenance", map[string]any{"message": "moving to eu"}); code != 200 {
		t.Fatalf("start maintenance: %d", code)
	}
	if code, _ := owner("PATCH", "/v1/tenants/acme", map[string]any{"name": "Renamed"}); code != 503 {
		t.Fatalf("write during maintenance: %d", code)
	}
	if code, _ := owner("GET", "/v1/tenants/acme", nil); code != 200 {
		t.Fatalf("read during maintenance: %d", code)
	}
	if code, _ := c.do("PATCH", "/v1/tenants/acme", map[string]any{"name": "Acme Inc"}); code != 200 {
		t.Fatalf("platform write during maintenance: %d", code)
	}
	if code, _ := c.do("DELETE", "/v1/tenants/acme/maintenance", nil); code != 200 {
		t.Fatalf("end maintenance: %d", code)
	}
	if code, _ := owner("PATCH", "/v1/tenants/acme", map[string]any{"name": "Renamed"}); code != 200 {
		t.Fatalf("write after maintenance: %d", code)
	}

	code, cl := c.do("POST", "/v1/tenants/acme/clone", map[string]any{"slug": "acme-2", "name": "Acme 2"})
	if code != 201 || cl["labels"].(map[string]any)["tenarium.io/cloned-from"] != tn["id"] {
		t.Fatalf("clone: %d %v", code, cl)
	}
	_, roles := c.do("GET", "/v1/tenants/acme-2/roles", nil)
	if items := roles["items"].([]any); items[len(items)-1].(map[string]any)["name"] != "auditor" {
		t.Fatalf("cloned roles: %v", roles)
	}
	code, h := c.do("GET", "/v1/tenants/acme/health", nil)
	if code != 200 || h["score"] == nil || h["grade"] == nil {
		t.Fatalf("health: %d %v", code, h)
	}
}
