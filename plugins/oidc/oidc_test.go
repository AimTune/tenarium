package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// idp is a minimal OIDC provider serving discovery and JWKS.
type idp struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	kid  string
	down atomic.Bool
	hits atomic.Int64
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{key: key, kid: "test-key"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.srv.URL,
			"jwks_uri":                              p.srv.URL + "/jwks",
			"authorization_endpoint":                p.srv.URL + "/auth",
			"token_endpoint":                        p.srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: p.kid, Algorithm: "RS256", Use: "sig",
		}}})
	})
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits.Add(1)
		if p.down.Load() {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", p.kid))
	if err != nil {
		t.Fatal(err)
	}
	c := map[string]any{
		"iss": p.srv.URL,
		"sub": "user-1",
		"aud": "tenarium",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	for k, v := range claims {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	tok, err := jwt.Signed(signer).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type fakeHost struct {
	tenants []sdk.Tenant
	calls   atomic.Int64
}

func (h *fakeHost) GetTenant(_ context.Context, idOrSlug string) (sdk.Tenant, error) {
	h.calls.Add(1)
	for _, t := range h.tenants {
		if t.ID == idOrSlug || t.Slug == idOrSlug {
			return t, nil
		}
	}
	return sdk.Tenant{}, sdk.ErrNotFound
}

func (h *fakeHost) ListTenants(context.Context, string, int) ([]sdk.Tenant, error) {
	return h.tenants, nil
}

func (h *fakeHost) GetPlan(context.Context, string) (sdk.Plan, error) {
	return sdk.Plan{}, sdk.ErrNotFound
}

func (h *fakeHost) Entitlements(context.Context, string) (sdk.Entitlements, error) {
	return sdk.Entitlements{}, nil
}

type fakeRegistrar struct {
	cfg   map[string]any
	host  sdk.Host
	authn []sdk.Authenticator
}

func (r *fakeRegistrar) Config(v any) error {
	b, err := json.Marshal(r.cfg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (r *fakeRegistrar) Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
func (r *fakeRegistrar) Host() sdk.Host       { return r.host }
func (r *fakeRegistrar) InstanceName() string { return "oidc" }
func (r *fakeRegistrar) Subscribe(string, sdk.EventFilter, sdk.EventHandler, ...sdk.SubscribeOption) {
}
func (r *fakeRegistrar) Hook(sdk.HookPoint, sdk.HookHandler, ...sdk.HookOption) {}
func (r *fakeRegistrar) Provisioner(sdk.Provisioner)                            {}
func (r *fakeRegistrar) Route(string, http.Handler)                             {}
func (r *fakeRegistrar) Authenticator(a sdk.Authenticator)                      { r.authn = append(r.authn, a) }
func (r *fakeRegistrar) Authorizer(sdk.Authorizer)                              {}

func newPlugin(t *testing.T, cfg map[string]any, host sdk.Host) (*Plugin, sdk.Authenticator) {
	t.Helper()
	if host == nil {
		host = &fakeHost{}
	}
	p := &Plugin{}
	r := &fakeRegistrar{cfg: cfg, host: host}
	if err := p.Init(context.Background(), r); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(r.authn) != 1 {
		t.Fatalf("registered %d authenticators, want 1", len(r.authn))
	}
	if r.authn[0].Name() != "jwt" {
		t.Fatalf("Name() = %q", r.authn[0].Name())
	}
	return p, r.authn[0]
}

func request(auth string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	return r
}

func TestValidTokenMapsClaims(t *testing.T) {
	idp := newIDP(t)
	host := &fakeHost{tenants: []sdk.Tenant{{ID: "t_123", Slug: "acme", Status: sdk.StatusActive}}}
	_, a := newPlugin(t, map[string]any{
		"issuer":       idp.srv.URL,
		"audience":     "tenarium",
		"groups_claim": "groups",
		"tenant_claim": "tenarium.tenant",
		"role_mapping": map[string]string{
			"platform-admin": "admin",
			"/ops":           "operator",
			"viewer":         "viewer",
		},
	}, host)

	tok := idp.sign(t, map[string]any{
		"email":              "jane@example.com",
		"name":               "Jane Doe",
		"preferred_username": "jane",
		"realm_access":       map[string]any{"roles": []string{"platform-admin", "offline_access", "viewer"}},
		"groups":             []string{"/ops", "/unmapped", "viewer"},
		"tenarium":           map[string]any{"tenant": "acme"},
	})
	pr, err := a.Authenticate(context.Background(), request("Bearer "+tok))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if pr.Subject != "user-1" || pr.Kind != "user" {
		t.Errorf("subject/kind = %q/%q", pr.Subject, pr.Kind)
	}
	if want := []string{"admin", "viewer", "operator"}; !slices.Equal(pr.Roles, want) {
		t.Errorf("roles = %v, want %v", pr.Roles, want)
	}
	if pr.TenantID != "t_123" {
		t.Errorf("tenant = %q, want t_123", pr.TenantID)
	}
	for k, want := range map[string]string{
		"email": "jane@example.com", "name": "Jane Doe", "preferred_username": "jane", "iss": idp.srv.URL,
	} {
		if pr.Claims[k] != want {
			t.Errorf("claims[%s] = %v, want %q", k, pr.Claims[k], want)
		}
	}

	// Tenant lookups are cached.
	if _, err := a.Authenticate(context.Background(), request("Bearer "+tok)); err != nil {
		t.Fatal(err)
	}
	if n := host.calls.Load(); n != 1 {
		t.Errorf("GetTenant called %d times, want 1", n)
	}
}

func TestRolesPassThroughAndCustomClaims(t *testing.T) {
	idp := newIDP(t)
	_, a := newPlugin(t, map[string]any{
		"issuer":        idp.srv.URL,
		"client_id":     "tenarium",
		"roles_claim":   "scope",
		"subject_claim": "oid",
		"email_claim":   "upn",
		"kind":          "service",
	}, nil)
	tok := idp.sign(t, map[string]any{"scope": "tenants:read, tenants:write  tenants:read", "oid": "obj-9", "upn": "svc@corp"})
	pr, err := a.Authenticate(context.Background(), request("bearer "+tok))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"tenants:read", "tenants:write"}; !slices.Equal(pr.Roles, want) {
		t.Errorf("roles = %v, want %v", pr.Roles, want)
	}
	if pr.Subject != "obj-9" || pr.Kind != "service" || pr.Claims["email"] != "svc@corp" || pr.TenantID != "" {
		t.Errorf("unexpected principal %+v", pr)
	}
}

func TestNoAudienceSkipsCheck(t *testing.T) {
	idp := newIDP(t)
	_, a := newPlugin(t, map[string]any{"issuer": idp.srv.URL}, nil)
	tok := idp.sign(t, map[string]any{"aud": "something-else"})
	if _, err := a.Authenticate(context.Background(), request("Bearer "+tok)); err != nil {
		t.Fatal(err)
	}
}

func TestJWKSURLWithoutDiscovery(t *testing.T) {
	idp := newIDP(t)
	_, a := newPlugin(t, map[string]any{
		"issuer":   idp.srv.URL,
		"jwks_url": idp.srv.URL + "/jwks",
		"audience": "tenarium",
	}, nil)
	pr, err := a.Authenticate(context.Background(), request("Bearer "+idp.sign(t, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if pr.Subject != "user-1" {
		t.Errorf("subject = %q", pr.Subject)
	}
	if err := a.(sdk.HealthChecker).Health(context.Background()); err != nil {
		t.Errorf("Health: %v", err)
	}
}

func TestRejections(t *testing.T) {
	idp := newIDP(t)
	other := newIDP(t)
	host := &fakeHost{tenants: []sdk.Tenant{{ID: "t_gone", Slug: "gone", Status: sdk.StatusDeleted}}}
	_, a := newPlugin(t, map[string]any{
		"issuer":       idp.srv.URL,
		"audience":     "tenarium",
		"tenant_claim": "tenant",
		"clock_skew":   "10s",
	}, host)

	tests := []struct {
		name   string
		auth   string
		noCred bool
		errHas string
	}{
		{name: "no header", auth: "", noCred: true},
		{name: "basic auth", auth: "Basic dXNlcjpwYXNz", noCred: true},
		{name: "empty bearer", auth: "Bearer ", noCred: true},
		{name: "api key", auth: "Bearer tnm_live_abcdef123456", noCred: true},
		{name: "dotted non-jwt", auth: "Bearer a.b.c", noCred: true},
		{name: "other issuer", auth: "Bearer " + other.sign(t, nil), noCred: true},
		{name: "expired", auth: "Bearer " + idp.sign(t, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}), errHas: "expired"},
		{name: "wrong audience", auth: "Bearer " + idp.sign(t, map[string]any{"aud": "someone-else"}), errHas: "audience"},
		{name: "bad signature", auth: "Bearer " + tamper(idp.sign(t, nil), other.sign(t, nil)), errHas: "signature"},
		{name: "no subject", auth: "Bearer " + idp.sign(t, map[string]any{"sub": nil}), errHas: "sub"},
		{name: "unknown tenant", auth: "Bearer " + idp.sign(t, map[string]any{"tenant": "nope"}), errHas: "does not exist"},
		{name: "deleted tenant", auth: "Bearer " + idp.sign(t, map[string]any{"tenant": "gone"}), errHas: "deleted"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pr, err := a.Authenticate(context.Background(), request(tc.auth))
			if pr != nil {
				t.Fatalf("got principal %+v", pr)
			}
			if tc.noCred {
				if !errors.Is(err, sdk.ErrNoCredentials) {
					t.Fatalf("err = %v, want ErrNoCredentials", err)
				}
				return
			}
			if err == nil || errors.Is(err, sdk.ErrNoCredentials) {
				t.Fatalf("err = %v, want a rejection", err)
			}
			if !strings.Contains(err.Error(), tc.errHas) {
				t.Errorf("err = %v, want it to mention %q", err, tc.errHas)
			}
		})
	}
}

// tamper keeps a's header and payload but uses b's signature.
func tamper(a, b string) string {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	return pa[0] + "." + pa[1] + "." + pb[2]
}

func TestClockSkew(t *testing.T) {
	idp := newIDP(t)
	_, a := newPlugin(t, map[string]any{"issuer": idp.srv.URL, "audience": "tenarium", "clock_skew": "2m"}, nil)
	tok := idp.sign(t, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()})
	if _, err := a.Authenticate(context.Background(), request("Bearer "+tok)); err != nil {
		t.Fatalf("token within skew rejected: %v", err)
	}
}

func TestIdPDownAtInit(t *testing.T) {
	idp := newIDP(t)
	idp.down.Store(true)

	now := time.Now()
	p := &Plugin{now: func() time.Time { return now }, retryEvery: 5 * time.Second}
	r := &fakeRegistrar{cfg: map[string]any{"issuer": idp.srv.URL, "audience": "tenarium"}, host: &fakeHost{}}
	if err := p.Init(context.Background(), r); err != nil {
		t.Fatalf("Init must tolerate an unreachable IdP: %v", err)
	}
	if err := p.Health(context.Background()); err == nil {
		t.Error("Health ok while IdP is down")
	}

	tok := idp.sign(t, map[string]any{"exp": now.Add(time.Hour).Unix()})
	_, err := p.Authenticate(context.Background(), request("Bearer "+tok))
	if err == nil || errors.Is(err, sdk.ErrNoCredentials) {
		t.Fatalf("err = %v, want a rejection while IdP is down", err)
	}

	// Recovered, but still within the retry window: no new discovery request.
	idp.down.Store(false)
	hits := idp.hits.Load()
	if _, err := p.Authenticate(context.Background(), request("Bearer "+tok)); err == nil {
		t.Fatal("expected throttled failure")
	}
	if idp.hits.Load() != hits {
		t.Error("discovery retried within the throttle window")
	}

	now = now.Add(6 * time.Second)
	pr, err := p.Authenticate(context.Background(), request("Bearer "+tok))
	if err != nil {
		t.Fatalf("Authenticate after recovery: %v", err)
	}
	if pr.Subject != "user-1" {
		t.Errorf("subject = %q", pr.Subject)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Errorf("Health after recovery: %v", err)
	}
}

func TestIdPClosedListenerAtInit(t *testing.T) {
	idp := newIDP(t)
	// Point at a closed listener first, then swap the issuer's server in.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	now := time.Now()
	p := &Plugin{now: func() time.Time { return now }, retryEvery: time.Second}
	r := &fakeRegistrar{cfg: map[string]any{"issuer": deadURL, "audience": "tenarium"}, host: &fakeHost{}}
	if err := p.Init(context.Background(), r); err != nil {
		t.Fatalf("Init: %v", err)
	}
	p.cfg.Issuer = idp.srv.URL
	now = now.Add(2 * time.Second)
	tok := idp.sign(t, map[string]any{"exp": now.Add(time.Hour).Unix()})
	if _, err := p.Authenticate(context.Background(), request("Bearer "+tok)); err != nil {
		t.Fatalf("Authenticate after IdP came up: %v", err)
	}
}

func TestInitValidation(t *testing.T) {
	for name, cfg := range map[string]map[string]any{
		"missing issuer": {},
		"bad kind":       {"issuer": "https://idp.example", "kind": "robot"},
		"bad skew":       {"issuer": "https://idp.example", "clock_skew": "soon"},
	} {
		t.Run(name, func(t *testing.T) {
			p := &Plugin{}
			if err := p.Init(context.Background(), &fakeRegistrar{cfg: cfg, host: &fakeHost{}}); err == nil {
				t.Fatal("Init succeeded, want error")
			}
		})
	}
}

func TestManifestSchema(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "oidc" {
		t.Errorf("ID = %q", m.ID)
	}
	var s struct {
		Required             []string       `json:"required"`
		AdditionalProperties bool           `json:"additionalProperties"`
		Properties           map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(m.ConfigSchema, &s); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Required, []string{"issuer"}) || s.AdditionalProperties {
		t.Errorf("unexpected schema: %+v", s)
	}
	b, _ := json.Marshal(Config{})
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	for f := range fields {
		if _, ok := s.Properties[f]; !ok {
			t.Errorf("config field %q missing from schema", f)
		}
	}
}

func TestLookupAndClaimStrings(t *testing.T) {
	claims := map[string]any{
		"https://example.com/roles": []any{"a"},
		"realm_access":              map[string]any{"roles": []any{"x", 1, "y"}},
	}
	if got := claimStrings(lookup(claims, "https://example.com/roles")); !slices.Equal(got, []string{"a"}) {
		t.Errorf("namespaced claim = %v", got)
	}
	if got := claimStrings(lookup(claims, "realm_access.roles")); !slices.Equal(got, []string{"x", "y"}) {
		t.Errorf("nested claim = %v", got)
	}
	if got := lookup(claims, "realm_access.missing.deep"); got != nil {
		t.Errorf("missing path = %v", got)
	}
}

// A configured tenant claim must never fail open to a platform-wide
// principal.
func TestTenantClaimFailsClosed(t *testing.T) {
	idp := newIDP(t)
	host := &fakeHost{tenants: []sdk.Tenant{{ID: "t1", Slug: "acme", Status: sdk.StatusActive}}}
	cfg := map[string]any{"issuer": idp.srv.URL, "audience": "tenarium", "tenant_claim": "tenant"}
	_, strict := newPlugin(t, cfg, host)

	for name, claims := range map[string]map[string]any{
		"missing":      {},
		"empty":        {"tenant": ""},
		"multi-valued": {"tenant": []string{"acme", "globex"}},
		"object":       {"tenant": map[string]any{"id": "acme"}},
	} {
		if pr, err := strict.Authenticate(context.Background(), request("Bearer "+idp.sign(t, claims))); err == nil {
			t.Errorf("%s: accepted as %+v", name, pr)
		}
	}

	cfg["allow_missing_tenant"] = true
	_, lenient := newPlugin(t, cfg, host)
	pr, err := lenient.Authenticate(context.Background(), request("Bearer "+idp.sign(t, map[string]any{})))
	if err != nil || pr.TenantID != "" {
		t.Fatalf("allow_missing_tenant: %+v %v", pr, err)
	}
	if _, err := lenient.Authenticate(context.Background(), request("Bearer "+idp.sign(t, map[string]any{"tenant": []string{"a", "b"}}))); err == nil {
		t.Fatal("multi-valued claim accepted with allow_missing_tenant")
	}
}

func (h *fakeHost) Authorize(context.Context, sdk.Action, sdk.Resource) error { return nil }

func (h *fakeHost) GetUser(context.Context, string) (sdk.User, error) {
	return sdk.User{}, sdk.ErrNotFound
}

func (r *fakeRegistrar) UserDirectory(sdk.UserDirectory) {}
func (r *fakeRegistrar) Mailer(sdk.Mailer)               {}

func (h *fakeHost) SuspendTenant(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h *fakeHost) ResumeTenant(context.Context, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h *fakeHost) SetTenantPlan(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h *fakeHost) RecordUsage(context.Context, string, string, int64) (int64, error) {
	return 0, sdk.ErrUnsupported
}

func (r *fakeRegistrar) PublicRoute(string, http.Handler) {}
