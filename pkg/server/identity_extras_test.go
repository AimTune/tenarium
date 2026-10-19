package server_test

import (
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/server"
)

func TestMagicLinkSessionsAndEmailChange(t *testing.T) {
	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Bootstrap.Users = []server.BootstrapUser{{Email: "root@example.com", Password: "root password long enough", Roles: []string{"admin"}}}
	cfg.Users.PublicURL = "https://tenarium.example.com"
	cfg.Users.MagicLinkTTL = 10 * time.Minute
	cfg.Auth.RateLimit = 0
	c := client{t: t, base: startServer(t, cfg)}

	if code, _ := c.do("POST", "/v1/auth/magic-link", map[string]any{"email": "nobody@example.com"}); code != 202 {
		t.Fatalf("unknown address: %d", code)
	}
	if code, _ := c.do("POST", "/v1/auth/magic-link", map[string]any{"email": "root@example.com"}); code != 202 {
		t.Fatalf("request link: %d", code)
	}
	link := testMailbox.token(t, "root@example.com", "magic_link")
	code, tok, _ := c.doH("POST", "/v1/auth/token", map[string]any{"grant_type": "magic_link", "token": link},
		map[string]string{"User-Agent": "Phone/1.0"})
	if code != 200 || tok["refresh_token"] == nil {
		t.Fatalf("magic link sign-in: %d %v", code, tok)
	}
	if code, _ := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "magic_link", "token": link}); code != 400 {
		t.Fatalf("link reused: %d", code)
	}
	root := as(c, tok["access_token"].(string))

	// The session shows up with its client and can be revoked.
	_, ss := root("GET", "/v1/me/sessions", nil)
	items := ss["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["user_agent"] != "Phone/1.0" {
		t.Fatalf("sessions: %v", ss)
	}
	id := items[0].(map[string]any)["id"].(string)
	if _, us := c.do("GET", "/v1/users/root@example.com/sessions", nil); len(us["items"].([]any)) != 1 {
		t.Fatalf("admin view: %v", us)
	}
	if code, _ := root("DELETE", "/v1/me/sessions/"+id, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]}); code != 400 {
		t.Fatalf("revoked session refreshed: %d", code)
	}

	// Email change needs the password and a confirmation from the new address.
	if code, _ := root("POST", "/v1/me/email", map[string]any{"email": "boss@example.com", "password": "wrong"}); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	if code, _ := root("POST", "/v1/me/email", map[string]any{"email": "boss@example.com", "password": "root password long enough"}); code != 202 {
		t.Fatalf("request change: %d", code)
	}
	confirm := testMailbox.token(t, "boss@example.com", "email_change")
	if code, u := c.do("POST", "/v1/auth/email-change/confirm", map[string]any{"token": confirm}); code != 200 || u["email"] != "boss@example.com" {
		t.Fatalf("confirm: %d %v", code, u)
	}
	if code, _ := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "password", "email": "boss@example.com", "password": "root password long enough"}); code != 200 {
		t.Fatalf("login with new address: %d", code)
	}
}
