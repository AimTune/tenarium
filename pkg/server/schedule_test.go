package server_test

import (
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/server"
)

func TestScheduleAndSoftDelete(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Tenants.DeletionGracePeriod = 24 * time.Hour
	cfg.Scheduler.Interval = 20 * time.Millisecond
	c := client{t: t, base: startServer(t, cfg)}
	c.do("POST", "/v1/plans", map[string]any{"id": "free", "name": "Free"})

	// A trial: the plan changes shortly after creation.
	at := time.Now().Add(200 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	code, tn := c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme", "plan": "trial",
		"schedule": []map[string]any{{"action": "set_plan", "plan": "free", "at": at}}})
	if code != 201 {
		t.Fatalf("create: %d %v", code, tn)
	}
	waitFor(t, "trial end", func() bool {
		_, got := c.do("GET", "/v1/tenants/acme", nil)
		return got["plan"] == "free"
	})
	_, list := c.do("GET", "/v1/tenants/acme/schedule", nil)
	items := list["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["status"] != "done" {
		t.Fatalf("schedule: %v", items)
	}

	code, a := c.do("POST", "/v1/tenants/acme/schedule", map[string]any{"action": "suspend", "after": "30d"})
	if code != 201 || a["status"] != "pending" {
		t.Fatalf("schedule suspend: %d %v", code, a)
	}
	if code, _ := c.do("POST", "/v1/tenants/acme/schedule", map[string]any{"action": "explode", "after": "1h"}); code != 400 {
		t.Fatalf("bad action: %d", code)
	}

	// Tenant owners get no commercial or destructive actions by default.
	_, k := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "admin", "roles": []string{"owner"}})
	owner := as(c, k["key"].(string))
	if code, _ := owner("POST", "/v1/tenants/acme/schedule", map[string]any{"action": "set_plan", "plan": "free", "after": "1h"}); code != 403 {
		t.Fatalf("tenant owner scheduled a plan change: %d", code)
	}
	if code, _ := owner("DELETE", "/v1/tenants/acme/schedule/"+a["id"].(string), nil); code != 403 {
		t.Fatalf("tenant owner canceled a suspension: %d", code)
	}
	if code, _ := c.do("DELETE", "/v1/tenants/acme/schedule/"+a["id"].(string), nil); code != 200 {
		t.Fatalf("cancel: %d", code)
	}

	if code, _ := owner("DELETE", "/v1/tenants/acme?force=true", nil); code != 403 {
		t.Fatalf("tenant owner purged: %d", code)
	}

	// Deletion is soft: suspended until the grace period ends.
	code, del, h := c.doH("DELETE", "/v1/tenants/acme", nil, nil)
	if code != 202 || del["status"] != "suspended" || del["status_reason"] != "pending deletion" || h.Get("Tenarium-Deletion-At") == "" {
		t.Fatalf("soft delete: %d %v %v", code, del, h)
	}
	if code, _ := c.do("POST", "/v1/tenants/acme/resume", nil); code != 409 {
		t.Fatalf("resume of pending deletion: %d", code)
	}
	// The tenant's own keys stop working while it is suspended.
	if code, _ := owner("POST", "/v1/tenants/acme/restore", nil); code != 401 {
		t.Fatalf("suspended tenant's key: %d", code)
	}
	if code, r := c.do("POST", "/v1/tenants/acme/restore", nil); code != 200 || r["status"] != "active" {
		t.Fatalf("restore: %d %v", code, r)
	}
	if code, _ := c.do("POST", "/v1/tenants/acme/restore", nil); code != 409 {
		t.Fatalf("restore twice: %d", code)
	}
	if code, r := c.do("DELETE", "/v1/tenants/acme?force=true", nil); code != 202 || r["status"] != "deleted" {
		t.Fatalf("purge: %d %v", code, r)
	}
}
