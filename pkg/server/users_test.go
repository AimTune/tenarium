package server_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/server"
)

// mailbox is a mailer plugin for tests.
type mailbox struct {
	mu   sync.Mutex
	sent []sdk.Message
}

var testMailbox = &mailbox{}

func (m *mailbox) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "mailbox", Name: "Mailbox", Version: "0"}
}
func (m *mailbox) Init(_ context.Context, r sdk.Registrar) error {
	r.Mailer(m)
	return nil
}
func (m *mailbox) Name() string { return "mailbox" }
func (m *mailbox) Send(_ context.Context, msg sdk.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

var mailLink = regexp.MustCompile(`/ui/#/(accept|reset|magic|confirm-email)/([A-Za-z0-9_.-]+)`)

func (m *mailbox) token(t *testing.T, to, tag string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if msg := m.sent[i]; msg.Tag == tag && msg.To[0] == to {
			if mm := mailLink.FindStringSubmatch(msg.Text); mm != nil {
				return mm[2]
			}
		}
	}
	t.Fatalf("no %s email to %s", tag, to)
	return ""
}

func init() { sdk.Register("mailbox", func() sdk.Plugin { return testMailbox }) }

// as sends requests with a bearer token instead of the API key.
func as(c client, token string) func(method, path string, body any) (int, map[string]any) {
	return func(method, path string, body any) (int, map[string]any) {
		code, out, _ := c.doH(method, path, body, map[string]string{"Authorization": "Bearer " + token})
		return code, out
	}
}

func userFlow(t *testing.T, cfg server.Config) {
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Bootstrap.Users = []server.BootstrapUser{{Email: "root@example.com", Password: "root password long enough", Roles: []string{"admin"}}}
	cfg.Users.PublicURL = "https://tenarium.example.com"
	cfg.Auth.RateLimit = 0
	base := startServer(t, cfg)
	c := client{t: t, base: base}

	// Platform admin signs in with a password.
	code, tok := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "password", "email": "root@example.com", "password": "root password long enough"})
	if code != 200 || tok["access_token"] == nil {
		t.Fatalf("admin login: %d %v", code, tok)
	}
	root := as(c, tok["access_token"].(string))
	if code, me := root("GET", "/v1/me", nil); code != 200 || me["authenticator"] != "core/token" {
		t.Fatalf("me: %d %v", code, me)
	}
	code, org := root("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	if code != 201 {
		t.Fatalf("admin creates tenant: %d %v", code, org)
	}

	// Inviting an unknown email creates the user and emails a link.
	if code, m := root("POST", "/v1/tenants/acme/members", map[string]any{"email": "ada@example.com", "role": "viewer", "name": "Ada"}); code != 201 || m["status"] != "invited" {
		t.Fatalf("invite: %d %v", code, m)
	}
	if code, _ := c.do("POST", "/v1/auth/invitations/accept", map[string]any{"token": "bogus", "password": "whatever long enough"}); code != 400 {
		t.Fatalf("bogus invitation token: %d", code)
	}
	invite := testMailbox.token(t, "ada@example.com", "invitation")
	if code, body := c.do("POST", "/v1/auth/invitations/accept", map[string]any{"token": invite, "password": "ada's long passphrase"}); code != 200 || body["status"] != "active" {
		t.Fatalf("accept: %d %v", code, body)
	}

	// Without platform roles Ada must pick a tenant.
	if code, body := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "password", "email": "ada@example.com", "password": "ada's long passphrase"}); code != 400 || body["error"].(map[string]any)["code"] != "tenant_required" {
		t.Fatalf("platform login for tenant user: %d %v", code, body)
	}
	code, tok = c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "password", "email": "ada@example.com", "password": "ada's long passphrase", "tenant": "acme"})
	if code != 200 {
		t.Fatalf("tenant login: %d %v", code, tok)
	}
	ada := as(c, tok["access_token"].(string))
	if code, _ := ada("GET", "/v1/tenants/acme", nil); code != 200 {
		t.Fatalf("viewer reads own tenant: %d", code)
	}
	if code, _ := ada("DELETE", "/v1/tenants/acme", nil); code != 403 {
		t.Fatalf("viewer deletes tenant: %d", code)
	}
	if code, _ := ada("GET", "/v1/users", nil); code != 403 {
		t.Fatalf("tenant user lists all users: %d", code)
	}
	if code, ms := ada("GET", "/v1/me/memberships", nil); code != 200 || len(ms["items"].([]any)) != 1 {
		t.Fatalf("my memberships: %d %v", code, ms)
	}

	// Refresh rotates; the old refresh token is dead afterwards.
	refresh := tok["refresh_token"].(string)
	if code, _ := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "refresh_token", "refresh_token": refresh}); code != 200 {
		t.Fatalf("refresh: %d", code)
	}
	if code, _ := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "refresh_token", "refresh_token": refresh}); code != 400 {
		t.Fatalf("refresh replay: %d", code)
	}

	// Disabling Ada cuts off her access token immediately.
	_, users := root("GET", "/v1/users?q=ada", nil)
	adaID := users["items"].([]any)[0].(map[string]any)["id"].(string)
	if code, _ := root("POST", "/v1/users/"+adaID+"/disable", nil); code != 200 {
		t.Fatalf("disable: %d", code)
	}
	if code, _ := ada("GET", "/v1/tenants/acme", nil); code != 401 {
		t.Fatalf("disabled user's token: %d", code)
	}

	// Password reset never reveals whether an email exists.
	for _, e := range []string{"root@example.com", "nobody@example.com"} {
		if code, _ := c.do("POST", "/v1/auth/password-reset", map[string]any{"email": e}); code != 202 {
			t.Fatalf("reset request for %s: %d", e, code)
		}
	}
	reset := testMailbox.token(t, "root@example.com", "password_reset")
	if code, _ := c.do("POST", "/v1/auth/password-reset/confirm", map[string]any{"token": reset, "password": "a brand new root passphrase"}); code != 204 {
		t.Fatalf("reset confirm: %d", code)
	}
	if code, _ := root("GET", "/v1/me", nil); code != 200 {
		// Access tokens stay valid until expiry; only refresh tokens are revoked.
		t.Fatalf("root access token after reset: %d", code)
	}

	// Tokens are verifiable by anyone through discovery + JWKS.
	for _, p := range []string{"/.well-known/openid-configuration", "/.well-known/jwks.json"} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !json.Valid(b) {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		if p == "/.well-known/openid-configuration" && !strings.Contains(string(b), `"issuer":"https://tenarium.example.com"`) {
			t.Fatalf("issuer: %s", b)
		}
	}
}

func TestUserFlowMemory(t *testing.T) {
	testMailbox.sent = nil
	userFlow(t, baseConfig())
}

func TestUserFlowPostgres(t *testing.T) {
	dsn := os.Getenv("TENARIUM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TENARIUM_TEST_POSTGRES_DSN not set")
	}
	testMailbox.sent = nil
	cfg := baseConfig()
	cfg.Store = server.StoreConfig{Driver: "postgres", DSN: freshPostgres(t, dsn)}
	userFlow(t, cfg)
}

func TestAuthRateLimit(t *testing.T) {
	cfg := baseConfig()
	cfg.Auth.RateLimit = 3
	c := client{t: t, base: startServer(t, cfg)}
	codes := []int{}
	for range 5 {
		code, _ := c.do("POST", "/v1/auth/token", map[string]any{"grant_type": "password", "email": "x@example.com", "password": "nope"})
		codes = append(codes, code)
	}
	if codes[2] != 401 || codes[3] != 429 || codes[4] != 429 {
		t.Fatalf("rate limit codes: %v", codes)
	}
}
