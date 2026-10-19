package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// Integration tests run against a Vault server named by
// TENARIUM_TEST_VAULT_ADDR (e.g. http://127.0.0.1:8200), using the token
// TENARIUM_TEST_VAULT_TOKEN (default "root"). A dev server works:
//
//	docker run -d --name tenarium-test-vault -p 48200:8200 \
//	  -e VAULT_DEV_ROOT_TOKEN_ID=root --cap-add=IPC_LOCK hashicorp/vault
//
// KV v2 must be mounted at secret/ (as in dev mode); the AppRole auth method
// and the transit engine are enabled at approle/ and transit/ if missing.

func integrationAdmin(t *testing.T) (string, *client) {
	t.Helper()
	addr := os.Getenv("TENARIUM_TEST_VAULT_ADDR")
	if addr == "" {
		t.Skip("TENARIUM_TEST_VAULT_ADDR not set")
	}
	token := os.Getenv("TENARIUM_TEST_VAULT_TOKEN")
	if token == "" {
		token = "root"
	}
	addr = strings.TrimSuffix(addr, "/")
	admin := &client{base: addr, http: &http.Client{Timeout: 10 * time.Second}, token: token, now: time.Now}
	ctx := context.Background()
	var auths map[string]any
	if err := admin.do(ctx, "GET", "sys/auth", nil, nil, &auths); err != nil {
		t.Fatal(err)
	}
	if _, ok := auths["approle/"]; !ok {
		if err := admin.do(ctx, "POST", "sys/auth/approle", nil, map[string]any{"type": "approle"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	var mounts map[string]any
	if err := admin.do(ctx, "GET", "sys/mounts", nil, nil, &mounts); err != nil {
		t.Fatal(err)
	}
	if _, ok := mounts["transit/"]; !ok {
		if err := admin.do(ctx, "POST", "sys/mounts/transit", nil, map[string]any{"type": "transit"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	return addr, admin
}

func randSlug(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return prefix + "-" + hex.EncodeToString(b)
}

func integrationPlugin(t *testing.T, addr string, auth map[string]any, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	full := map[string]any{
		"address": addr, "auth": auth,
		"approle": map[string]any{"token_ttl": "10m", "secret_id_ttl": "10m"},
		"transit": map[string]any{},
	}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}
	return p, reg
}

// asToken returns a client authenticated with tok.
func asToken(admin *client, tok string) *client {
	return &client{base: admin.base, http: admin.http, token: tok, now: time.Now}
}

func TestIntegrationLifecycle(t *testing.T) {
	addr, admin := integrationAdmin(t)
	ctx := context.Background()
	p, reg := integrationPlugin(t, addr, map[string]any{"token": admin.token}, nil)
	slug := randSlug(t, "it")
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	t.Cleanup(func() { _ = p.Deprovision(context.Background(), tn) })

	for range 2 {
		if err := p.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	name := "tenant-" + slug
	prefix := "tenants/" + slug

	// The info route shows the role_id; the secret-id route issues
	// credentials that log in to a token limited to the tenant.
	platform := &sdk.Principal{Subject: "it", Kind: "service", Authenticator: "test"}
	req := httptest.NewRequest("GET", "/tenants/"+slug, nil).WithContext(sdk.WithPrincipal(ctx, platform))
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	var info TenantInfo
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &info) != nil || info.AppRole.RoleID == "" || !info.Provisioned {
		t.Fatalf("info %d %s", rec.Code, rec.Body)
	}
	req = httptest.NewRequest("POST", "/tenants/"+slug+"/secret-id", nil).WithContext(sdk.WithPrincipal(ctx, platform))
	rec = httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	var sid SecretIDResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &sid) != nil || sid.SecretID == "" {
		t.Fatalf("secret-id %d %s", rec.Code, rec.Body)
	}
	var login struct {
		Auth struct {
			ClientToken string   `json:"client_token"`
			Policies    []string `json:"policies"`
		} `json:"auth"`
	}
	if err := admin.raw(ctx, "POST", "auth/approle/login", nil, "", map[string]string{"role_id": info.AppRole.RoleID, "secret_id": sid.SecretID}, &login); err != nil {
		t.Fatal(err)
	}
	tc := asToken(admin, login.Auth.ClientToken)

	// Allowed: the tenant's KV prefix and transit key.
	if err := tc.do(ctx, "POST", "secret/data/"+prefix+"/app/db", nil, map[string]any{"data": map[string]any{"password": "x"}}, nil); err != nil {
		t.Fatalf("tenant write: %v", err)
	}
	if err := tc.do(ctx, "GET", "secret/data/"+prefix+"/app/db", nil, nil, nil); err != nil {
		t.Fatalf("tenant read: %v", err)
	}
	if err := tc.do(ctx, "GET", "secret/metadata/"+prefix+"/", map[string][]string{"list": {"true"}}, nil, nil); err != nil {
		t.Fatalf("tenant list: %v", err)
	}
	plaintext := base64.StdEncoding.EncodeToString([]byte("hello"))
	if err := tc.do(ctx, "POST", "transit/encrypt/"+name, nil, map[string]any{"plaintext": plaintext}, nil); err != nil {
		t.Fatalf("tenant encrypt: %v", err)
	}
	if err := tc.do(ctx, "POST", "transit/datakey/plaintext/"+name, nil, map[string]any{}, nil); err != nil {
		t.Fatalf("tenant datakey: %v", err)
	}
	// Denied: the ownership marker, other prefixes, other keys.
	for _, c := range []struct{ method, path string }{
		{"POST", "secret/metadata/" + prefix + "/" + ownerKey},
		{"POST", "secret/data/" + prefix + "/" + ownerKey},
		{"DELETE", "secret/metadata/" + prefix + "/" + ownerKey},
		{"POST", "secret/data/tenants/someone-else/x"},
		{"POST", "secret/data/" + prefix + "x/y"},
		{"POST", "transit/encrypt/other-key"},
		{"GET", "sys/policies/acl/" + name},
	} {
		err := tc.do(ctx, c.method, c.path, nil, map[string]any{"data": map[string]any{"a": "b"}, "custom_metadata": map[string]any{"a": "b"}, "plaintext": plaintext}, nil)
		if statusOf(err) != http.StatusForbidden {
			t.Errorf("%s %s as tenant: %v, want 403", c.method, c.path, err)
		}
	}

	// A second tenant with a colliding prefix is refused.
	clash := reg.HostImpl.AddTenant(sdk.Tenant{ID: "clash-" + slug, Slug: slug})
	if err := p.Provision(ctx, clash); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("clash: %v", err)
	}
	if err := p.Deprovision(ctx, clash); err != nil {
		t.Fatal(err)
	}

	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"sys/policies/acl/" + name, "auth/approle/role/" + name, "transit/keys/" + name, "secret/metadata/" + prefix + "/app/db", "secret/metadata/" + prefix + "/" + ownerKey} {
		if err := admin.do(ctx, "GET", path, nil, nil, nil); !isNotFound(err) {
			t.Errorf("%s after delete: %v", path, err)
		}
	}
	if err := tc.do(ctx, "GET", "secret/data/"+prefix+"/app/db", nil, nil, nil); statusOf(err) != http.StatusForbidden && !isNotFound(err) {
		t.Errorf("tenant token still works: %v", err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationRetainWithAppRoleAuth(t *testing.T) {
	addr, admin := integrationAdmin(t)
	ctx := context.Background()

	// The plugin authenticates with AppRole, with the permissions documented
	// in the README.
	pluginPolicy := randSlug(t, "tenarium-plugin")
	hcl := `
path "secret/metadata/tenants/*" { capabilities = ["create", "read", "update", "delete", "list"] }
path "sys/policies/acl/tenant-*" { capabilities = ["create", "read", "update", "delete"] }
path "auth/approle/role/tenant-*" { capabilities = ["create", "read", "update", "delete"] }
path "transit/keys/tenant-*" { capabilities = ["create", "read", "update", "delete"] }
`
	if err := admin.do(ctx, "PUT", "sys/policies/acl/"+pluginPolicy, nil, map[string]string{"policy": hcl}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = admin.do(context.Background(), "DELETE", "sys/policies/acl/"+pluginPolicy, nil, nil, nil)
		_ = admin.do(context.Background(), "DELETE", "auth/approle/role/"+pluginPolicy, nil, nil, nil)
	})
	if err := admin.do(ctx, "POST", "auth/approle/role/"+pluginPolicy, nil, map[string]any{"token_policies": []string{pluginPolicy}, "token_ttl": "5m"}, nil); err != nil {
		t.Fatal(err)
	}
	var rid, sec struct {
		Data struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	if err := admin.do(ctx, "GET", "auth/approle/role/"+pluginPolicy+"/role-id", nil, nil, &rid); err != nil {
		t.Fatal(err)
	}
	if err := admin.do(ctx, "POST", "auth/approle/role/"+pluginPolicy+"/secret-id", nil, map[string]any{}, &sec); err != nil {
		t.Fatal(err)
	}
	auth := map[string]any{"approle": map[string]any{"role_id": rid.Data.RoleID, "secret_id": sec.Data.SecretID}}
	p, reg := integrationPlugin(t, addr, auth, map[string]any{"on_deprovision": "retain"})

	slug := randSlug(t, "it-retain")
	name, prefix := "tenant-"+slug, "tenants/"+slug
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	t.Cleanup(func() {
		ctx := context.Background()
		_ = admin.do(ctx, "POST", "transit/keys/"+name+"/config", nil, map[string]any{"deletion_allowed": true}, nil)
		_ = admin.do(ctx, "DELETE", "transit/keys/"+name, nil, nil, nil)
		_ = admin.do(ctx, "DELETE", "secret/metadata/"+prefix+"/db", nil, nil, nil)
		_ = admin.do(ctx, "DELETE", "secret/metadata/"+prefix+"/"+ownerKey, nil, nil, nil)
	})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := admin.do(ctx, "POST", "secret/data/"+prefix+"/db", nil, map[string]any{"data": map[string]any{"k": "v"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"sys/policies/acl/" + name, "auth/approle/role/" + name} {
		if err := admin.do(ctx, "GET", path, nil, nil, nil); !isNotFound(err) {
			t.Errorf("%s after retain: %v", path, err)
		}
	}
	for _, path := range []string{"transit/keys/" + name, "secret/data/" + prefix + "/db"} {
		if err := admin.do(ctx, "GET", path, nil, nil, nil); err != nil {
			t.Errorf("%s after retain: %v", path, err)
		}
	}
	m, err := p.readMarker(ctx, target{Prefix: prefix})
	if err != nil || m == nil || m.TenantID != "" || m.DeletedTenantID != tn.ID {
		t.Fatalf("marker %+v %v", m, err)
	}
	next := reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug})
	if err := p.Provision(ctx, next); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("provision over retained data: %v", err)
	}
}
