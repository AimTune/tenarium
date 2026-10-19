package server_test

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

func TestAuditTrail(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	c := client{t: t, base: startServer(t, cfg)}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	c.do("POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	_, k := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "admin", "roles": []string{"admin"}})
	admin := as(c, k["key"].(string))
	if code, _ := admin("PATCH", "/v1/tenants/acme", map[string]any{"name": "Acme 2"}); code != 200 {
		t.Fatalf("update: %d", code)
	}

	items := func(code int, body map[string]any) []map[string]any {
		t.Helper()
		if code != 200 {
			t.Fatalf("audit: %d %v", code, body)
		}
		var out []map[string]any
		for _, it := range body["items"].([]any) {
			out = append(out, it.(map[string]any))
		}
		return out
	}

	all := items(c.do("GET", "/v1/audit", nil))
	if all[0]["type"] != "tenant.updated" {
		t.Fatalf("not newest first: %v", all[0])
	}
	keyActor := all[0]["actor"].(string)
	byKey := items(c.do("GET", "/v1/audit?actor="+url.QueryEscape(keyActor), nil))
	if len(byKey) != 1 {
		t.Fatalf("by actor: %v", byKey)
	}
	created := items(c.do("GET", "/v1/audit?type=tenant.created&tenant_id=globex", nil))
	if len(created) != 1 || created[0]["subject"] == nil {
		t.Fatalf("by type and tenant: %v", created)
	}
	if got := items(c.do("GET", "/v1/audit?type=tenant.*&limit=1", nil)); len(got) != 1 {
		t.Fatalf("limit: %v", got)
	}
	_, page := c.do("GET", "/v1/audit?limit=2", nil)
	next := page["next"].(string)
	older := items(c.do("GET", "/v1/audit?limit=2&before="+next, nil))
	if seq := fmt.Sprint(older[0]["seq"]); seq != fmt.Sprint(page["items"].([]any)[1].(map[string]any)["seq"].(float64)-1) {
		t.Fatalf("paging: got seq %s after next=%s", seq, next)
	}
	if code, _ := c.do("GET", "/v1/audit?since=yesterday", nil); code != 400 {
		t.Fatalf("bad since: %d", code)
	}

	// Tenant admins see only their tenant's trail.
	own := items(admin("GET", "/v1/audit", nil))
	for _, e := range own {
		if e["tenant_id"] != all[0]["tenant_id"] {
			t.Fatalf("scoped caller saw %v", e)
		}
	}
	if len(own) == 0 {
		t.Fatal("scoped caller saw nothing")
	}
	if code, _ := admin("GET", "/v1/audit?tenant_id=globex", nil); code != 403 {
		t.Fatalf("scoped caller read another tenant: %d", code)
	}
	if code, _ := admin("GET", "/v1/tenants/globex/audit", nil); code != 403 && code != 404 {
		t.Fatalf("scoped caller read another tenant's trail: %d", code)
	}
	if got := items(admin("GET", "/v1/tenants/acme/audit?type=apikey.*", nil)); len(got) != 1 {
		t.Fatalf("tenant audit by type: %v", got)
	}
}
