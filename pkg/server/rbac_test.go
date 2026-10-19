package server_test

import (
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

func TestCustomRolesAndGroups(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	c := client{t: t, base: startServer(t, cfg)}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	_, ak := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "admin", "roles": []string{"admin"}})
	admin := as(c, ak["key"].(string))

	if code, body := c.do("GET", "/v1/actions", nil); code != 200 || len(body["items"].([]any)) < 30 {
		t.Fatalf("actions: %d %v", code, body)
	}
	// Tenant admins define roles, but never beyond their own permissions.
	if code, _ := admin("PUT", "/v1/tenants/acme/roles/billing", map[string]any{"actions": []string{"usage:read", "tenants:read"}}); code != 200 {
		t.Fatalf("define role: %d", code)
	}
	if code, body := admin("PUT", "/v1/tenants/acme/roles/destroyer", map[string]any{"actions": []string{"tenants:delete"}}); code != 403 {
		t.Fatalf("escalation through a role: %d %v", code, body)
	}
	if code, _ := admin("PUT", "/v1/tenants/acme/roles/admin", map[string]any{"actions": []string{"tenants:read"}}); code != 400 {
		t.Fatalf("redefined built-in role: %d", code)
	}
	if code, _ := admin("PUT", "/v1/tenants/acme/roles/x", map[string]any{"actions": []string{"nothing:here"}}); code != 400 {
		t.Fatalf("pattern matching nothing: %d", code)
	}
	_, roles := admin("GET", "/v1/tenants/acme/roles", nil)
	if n := len(roles["items"].([]any)); n != 5 {
		t.Fatalf("roles: %v", roles)
	}

	// A key with the custom role can do exactly what the role allows.
	_, bk := admin("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "finance", "roles": []string{"billing"}})
	billing := as(c, bk["key"].(string))
	if code, _ := billing("GET", "/v1/tenants/acme/usage", nil); code != 200 {
		t.Fatalf("custom role read usage: %d", code)
	}
	if code, _ := billing("GET", "/v1/tenants/acme/members", nil); code != 403 {
		t.Fatalf("custom role read members: %d", code)
	}
	if code, _ := admin("DELETE", "/v1/tenants/acme/roles/billing", nil); code != 409 {
		t.Fatalf("deleted role in use: %d", code)
	}

	// Groups add roles to their members.
	_, m := admin("POST", "/v1/tenants/acme/members", map[string]any{"email": "ann@example.com", "role": "viewer"})
	mid := m["id"].(string)
	code, g := admin("POST", "/v1/tenants/acme/groups", map[string]any{"name": "Finance", "roles": []string{"billing"}})
	if code != 201 {
		t.Fatalf("create group: %d %v", code, g)
	}
	gid := g["id"].(string)
	if code, g := admin("PUT", "/v1/tenants/acme/groups/"+gid+"/members/"+mid, nil); code != 200 || len(g["members"].([]any)) != 1 {
		t.Fatalf("join group: %d %v", code, g)
	}
	// A role defined by the platform with more than the admin holds cannot
	// be handed out by the admin, through a group or a membership.
	if code, _ := c.do("PUT", "/v1/tenants/acme/roles/destroyer", map[string]any{"actions": []string{"tenants:delete"}}); code != 200 {
		t.Fatalf("platform defines role: %d", code)
	}
	if code, body := admin("POST", "/v1/tenants/acme/groups", map[string]any{"name": "Destroyers", "roles": []string{"destroyer"}}); code != 403 {
		t.Fatalf("admin granted a stronger role through a group: %d %v", code, body)
	}
	if code, _ := admin("POST", "/v1/tenants/acme/members", map[string]any{"email": "eve@example.com", "role": "destroyer"}); code != 403 {
		t.Fatalf("admin granted a stronger role to a member: %d", code)
	}
	if code, _ := admin("PATCH", "/v1/tenants/acme/members/"+mid, map[string]any{"role": "destroyer"}); code != 403 {
		t.Fatalf("admin promoted a member beyond itself: %d", code)
	}
	c.do("DELETE", "/v1/tenants/acme/roles/destroyer", nil)
	if code, _ := admin("DELETE", "/v1/tenants/acme/roles/billing", nil); code != 409 {
		t.Fatalf("deleted role used by a group: %d", code)
	}
	// Removing the member drops it from its groups.
	admin("DELETE", "/v1/tenants/acme/members/"+mid, nil)
	if _, g := admin("GET", "/v1/tenants/acme/groups/Finance", nil); len(g["members"].([]any)) != 0 {
		t.Fatalf("removed member still in group: %v", g)
	}
	_, audit := c.do("GET", "/v1/tenants/acme/audit?type=group.*&type=role.*", nil)
	if n := len(audit["items"].([]any)); n < 3 {
		t.Fatalf("audit: %d", n)
	}
}
