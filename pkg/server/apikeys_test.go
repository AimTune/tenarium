package server_test

import (
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

func TestTenantAPIKeys(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Auth.RateLimit = 0
	c := client{t: t, base: startServer(t, cfg)}

	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	c.do("POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})

	// A tenant key with the "member" role.
	code, created := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "ci", "roles": []string{"member"}})
	if code != 201 || !strings.HasPrefix(created["key"].(string), "tnr_") {
		t.Fatalf("create key: %d %v", code, created)
	}
	key := as(c, created["key"].(string))
	if code, me := key("GET", "/v1/me", nil); code != 200 || me["authenticator"] != "core/key" || me["tenant_id"] == nil {
		t.Fatalf("me with key: %d %v", code, me)
	}
	if code, _ := key("GET", "/v1/tenants/acme", nil); code != 200 {
		t.Fatalf("read own tenant: %d", code)
	}
	if code, _ := key("GET", "/v1/tenants/globex", nil); code != 403 {
		t.Fatalf("read other tenant: %d", code)
	}
	if code, _ := key("PATCH", "/v1/tenants/acme", map[string]any{"name": "x"}); code != 403 {
		t.Fatalf("member key updates tenant: %d", code)
	}

	// An owner key may create keys, but only with roles it holds.
	_, ownerKey := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "admin", "roles": []string{"admin"}})
	owner := as(c, ownerKey["key"].(string))
	if code, _ := owner("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "esc", "roles": []string{"owner"}}); code != 403 {
		t.Fatalf("privilege escalation through a new key: %d", code)
	}
	if code, _ := owner("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "ok", "roles": []string{"admin"}}); code != 201 {
		t.Fatalf("same-role key: %d", code)
	}
	if code, _ := owner("GET", "/v1/api-keys", nil); code != 403 {
		t.Fatalf("tenant key lists platform keys: %d", code)
	}

	// Listing never returns secrets; revocation is immediate.
	_, list := c.do("GET", "/v1/tenants/acme/api-keys", nil)
	for _, it := range list["items"].([]any) {
		if _, ok := it.(map[string]any)["key"]; ok {
			t.Fatal("secret returned by list")
		}
	}
	if code, _ := c.do("DELETE", "/v1/tenants/acme/api-keys/"+created["id"].(string), nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := key("GET", "/v1/me", nil); code != 401 {
		t.Fatalf("revoked key still works: %d", code)
	}

	// Keys of a suspended tenant stop working.
	c.do("POST", "/v1/tenants/acme/suspend", map[string]any{"reason": "unpaid"})
	if code, _ := owner("GET", "/v1/me", nil); code != 401 {
		t.Fatalf("key of a suspended tenant: %d", code)
	}

	// Platform keys and expiry.
	code, pk := c.do("POST", "/v1/api-keys", map[string]any{"name": "ops", "roles": []string{"viewer"}, "expires_in": "1h"})
	if code != 201 || pk["expires_at"] == nil {
		t.Fatalf("platform key: %d %v", code, pk)
	}
	ops := as(c, pk["key"].(string))
	if code, _ := ops("GET", "/v1/tenants/globex", nil); code != 200 {
		t.Fatalf("platform viewer reads: %d", code)
	}
	if code, _ := ops("DELETE", "/v1/tenants/globex", nil); code != 403 {
		t.Fatalf("platform viewer deletes: %d", code)
	}
	if code, _ := as(c, "tnr_bogus")("GET", "/v1/me", nil); code != 401 {
		t.Fatalf("bogus key: %d", code)
	}
}
