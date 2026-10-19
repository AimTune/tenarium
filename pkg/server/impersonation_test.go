package server_test

import (
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

func TestImpersonation(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Auth.RateLimit = 0
	cfg.Bootstrap.Users = []server.BootstrapUser{{Email: "root@example.com", Password: "root password long enough", Roles: []string{"admin"}}}
	c := client{t: t, base: startServer(t, cfg)}
	login := func(email, pw, tenant string) func(string, string, any) (int, map[string]any) {
		_, tok := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "password", "email": email, "password": pw, "tenant": tenant})
		return as(c, tok["access_token"].(string))
	}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	c.do("POST", "/v1/users", map[string]any{"email": "ann@example.com", "password": "ann long passphrase"})
	c.do("POST", "/v1/tenants/acme/members", map[string]any{"email": "ann@example.com", "role": "admin"})
	root := login("root@example.com", "root password long enough", "")
	ann := login("ann@example.com", "ann long passphrase", "acme")

	req := map[string]any{"reason": "ticket #42", "tenant": "acme"}
	if code, body := root("POST", "/v1/users/ann@example.com/impersonate", req); code != 403 || body["error"].(map[string]any)["code"] != "consent_required" {
		t.Fatalf("without consent: %d %v", code, body)
	}
	code, consent := ann("POST", "/v1/me/impersonation-consent", map[string]any{"ttl": "30m"})
	if code != 201 || consent["code"] == nil {
		t.Fatalf("consent: %d %v", code, consent)
	}
	req["consent_code"] = consent["code"]
	code, pair := root("POST", "/v1/users/ann@example.com/impersonate", req)
	if code != 200 || pair["access_token"] == nil || pair["refresh_token"] != nil {
		t.Fatalf("impersonate: %d %v", code, pair)
	}
	if code, _ := root("POST", "/v1/users/ann@example.com/impersonate", req); code != 403 {
		t.Fatalf("consent code reused: %d", code)
	}
	if code, _ := root("POST", "/v1/users/root@example.com/impersonate", map[string]any{"reason": "x", "tenant": "acme"}); code != 403 {
		t.Fatalf("platform admin impersonated: %d", code)
	}

	asAnn := as(c, pair["access_token"].(string))
	if code, me := asAnn("GET", "/v1/me", nil); code != 200 || me["claims"].(map[string]any)["impersonator"] == nil {
		t.Fatalf("me: %d %v", code, me)
	}
	if code, _ := asAnn("PATCH", "/v1/tenants/acme", map[string]any{"name": "Acme Support Fix"}); code != 200 {
		t.Fatalf("act as the user: %d", code)
	}
	if code, _ := asAnn("POST", "/v1/me/password", map[string]any{"current_password": "ann long passphrase", "new_password": "something else long"}); code != 403 {
		t.Fatalf("changed the user's password: %d", code)
	}
	if code, _ := asAnn("POST", "/v1/tenants/acme/api-keys", map[string]any{"name": "x", "roles": []string{"member"}}); code != 403 {
		t.Fatalf("created credentials while impersonating: %d", code)
	}
	if code, _ := asAnn("GET", "/v1/tenants/acme/export", nil); code != 403 {
		t.Fatalf("exported data while impersonating: %d", code)
	}

	_, audit := c.do("GET", "/v1/audit?type=tenant.updated", nil)
	actor := audit["items"].([]any)[0].(map[string]any)["actor"].(string)
	if !strings.Contains(actor, "impersonated-by=core/token:") {
		t.Fatalf("audit actor: %s", actor)
	}
	if _, ev := c.do("GET", "/v1/audit?type=user.impersonated", nil); len(ev["items"].([]any)) != 1 {
		t.Fatalf("impersonation not audited: %v", ev)
	}
}
