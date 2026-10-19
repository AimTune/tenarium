package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/internal/webhooks"
	"github.com/AimTune/tenarium/pkg/server"
)

func TestTenantWebhooks(t *testing.T) {
	var (
		mu       sync.Mutex
		received []*http.Request
		bodies   [][]byte
	)
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		received, bodies = append(received, r), append(bodies, b)
		mu.Unlock()
	}))
	defer recv.Close()
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(received) }

	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Webhooks.AllowHTTP, cfg.Webhooks.AllowPrivateNetworks = true, true
	c := client{t: t, base: startServer(t, cfg)}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	c.do("POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})
	_, k := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "admin", "roles": []string{"admin"}})
	admin := as(c, k["key"].(string))
	_, mk := c.do("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "m", "roles": []string{"member"}})
	member := as(c, mk["key"].(string))

	if code, _ := member("POST", "/v1/tenants/acme/webhooks", map[string]any{"url": recv.URL}); code != 403 {
		t.Fatalf("member created webhook: %d", code)
	}
	if code, _ := admin("POST", "/v1/tenants/acme/webhooks", map[string]any{"url": "ftp://x"}); code != 400 {
		t.Fatalf("bad url: %d", code)
	}
	code, created := admin("POST", "/v1/tenants/acme/webhooks", map[string]any{"url": recv.URL, "types": []string{"tenant.*"}})
	if code != 201 {
		t.Fatalf("create: %d %v", code, created)
	}
	hook := created["webhook"].(map[string]any)
	id, secret := hook["id"].(string), created["secret"].(string)
	if _, ok := hook["secret"]; ok {
		t.Fatal("secret in webhook object")
	}
	if code, _ := admin("GET", "/v1/tenants/globex/webhooks", nil); code != 403 {
		t.Fatalf("other tenant's webhooks: %d", code)
	}
	if code, _ := c.do("GET", "/v1/tenants/globex/webhooks/"+id, nil); code != 404 {
		t.Fatalf("webhook through other tenant: %d", code)
	}

	admin("PATCH", "/v1/tenants/acme", map[string]any{"name": "Acme 2"})
	c.do("PATCH", "/v1/tenants/globex", map[string]any{"name": "Globex 2"})
	waitFor(t, "delivery", func() bool { return count() >= 1 })
	mu.Lock()
	r, body := received[0], bodies[0]
	mu.Unlock()
	if r.Header.Get("webhook-signature") != "v1,"+webhooks.Sign(secret, r.Header.Get("webhook-id"), r.Header.Get("webhook-timestamp"), body) {
		t.Fatal("bad signature")
	}

	code, d := admin("POST", "/v1/tenants/acme/webhooks/"+id+"/test", nil)
	if code != 200 || d["success"] != true || d["event_type"] != "webhook.test" {
		t.Fatalf("test: %d %v", code, d)
	}
	_, list := admin("GET", "/v1/tenants/acme/webhooks/"+id+"/deliveries", nil)
	items := list["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("deliveries: %v", items)
	}
	first := items[1].(map[string]any)
	if first["event_type"] != "tenant.updated" {
		t.Fatalf("first delivery: %v", first)
	}
	if code, d := admin("POST", "/v1/tenants/acme/webhooks/"+id+"/deliveries/"+first["id"].(string)+"/redeliver", nil); code != 200 || d["success"] != true {
		t.Fatalf("redeliver: %d %v", code, d)
	}
	if code, rot := admin("POST", "/v1/tenants/acme/webhooks/"+id+"/rotate-secret", nil); code != 200 || rot["secret"] == secret {
		t.Fatalf("rotate: %d %v", code, rot)
	}
	if code, _ := admin("PATCH", "/v1/tenants/acme/webhooks/"+id, map[string]any{"enabled": false}); code != 200 {
		t.Fatalf("disable: %d", code)
	}
	if code, _ := admin("DELETE", "/v1/tenants/acme/webhooks/"+id, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	_, audit := c.do("GET", "/v1/tenants/acme/audit?type=webhook.*", nil)
	if n := len(audit["items"].([]any)); n < 4 {
		t.Fatalf("webhook audit events: %d", n)
	}
	if n := count(); n != 3 {
		t.Fatalf("received %d requests, want 3", n)
	}
}
