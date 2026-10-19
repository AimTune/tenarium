package server_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

func TestGDPRExportAndErase(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	c := client{t: t, base: startServer(t, cfg)}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	c.do("POST", "/v1/tenants/acme/members", map[string]any{"email": "ann@example.com", "name": "Ann Example", "role": "admin"})
	c.do("POST", "/v1/tenants/acme/usage/calls", map[string]any{"delta": 2})
	_, ak := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "owner", "roles": []string{"owner"}})
	owner := as(c, ak["key"].(string))

	// Tenant owners can export their tenant.
	code, x, h := c.doH("GET", "/v1/tenants/acme/export", nil, map[string]string{"Authorization": "Bearer " + ak["key"].(string)})
	if code != 200 || !strings.Contains(h.Get("Content-Disposition"), "tenant-acme.json") {
		t.Fatalf("export: %d %v", code, h)
	}
	if len(x["members"].([]any)) != 1 || len(x["usage"].([]any)) != 1 || len(x["events"].([]any)) == 0 {
		t.Fatalf("export content: %v", x)
	}
	for _, k := range x["api_keys"].([]any) {
		if _, leaked := k.(map[string]any)["hash"]; leaked {
			t.Fatal("key hash exported")
		}
	}

	_, ux := c.do("GET", "/v1/users/ann@example.com/export", nil)
	if ux["user"].(map[string]any)["email"] != "ann@example.com" || len(ux["memberships"].([]any)) != 1 {
		t.Fatalf("user export: %v", ux)
	}

	// Erasure is platform-only and removes the person everywhere.
	if code, _ := owner("POST", "/v1/users/ann@example.com/erase", nil); code != 403 {
		t.Fatalf("tenant owner erased a user: %d", code)
	}
	code, er := c.do("POST", "/v1/users/ann@example.com/erase", map[string]any{"redact_events": true})
	if code != 200 || er["redacted_events"].(float64) < 1 {
		t.Fatalf("erase: %d %v", code, er)
	}
	if code, _ := c.do("GET", "/v1/users/ann@example.com", nil); code != 404 {
		t.Fatalf("user still exists: %d", code)
	}
	_, events := c.do("GET", "/v1/events?limit=1000", nil)
	for _, e := range events["items"].([]any) {
		if strings.Contains(toJSON(e), "ann@example.com") || strings.Contains(toJSON(e), "Ann Example") {
			t.Fatalf("personal data left in events: %v", e)
		}
	}
	if _, ms := c.do("GET", "/v1/tenants/acme/members", nil); len(ms["items"].([]any)) != 0 {
		t.Fatalf("membership survived erasure: %v", ms)
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
