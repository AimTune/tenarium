package ldap

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// --- fake directory ---------------------------------------------------------

type fakeEntry struct {
	dn       string
	password string
	attrs    map[string][]string
}

type fakeDir struct {
	mu      sync.Mutex
	entries []fakeEntry
	dials   int
	filters []string
}

func (d *fakeDir) dial(context.Context, time.Duration) (conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials++
	return &fakeConn{dir: d}, nil
}

type fakeConn struct {
	dir   *fakeDir
	bound string
}

func (c *fakeConn) Bind(dn, password string) error {
	if password == "" {
		return errors.New("empty password")
	}
	for _, e := range c.dir.entries {
		if e.dn == dn && e.password == password {
			c.bound = dn
			return nil
		}
	}
	return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
}

func (c *fakeConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	c.dir.mu.Lock()
	c.dir.filters = append(c.dir.filters, req.Filter)
	c.dir.mu.Unlock()
	attr, value, err := parseEquality(req.Filter)
	if err != nil {
		return nil, err
	}
	res := &ldap.SearchResult{}
	for _, e := range c.dir.entries {
		if !strings.HasSuffix(strings.ToLower(e.dn), strings.ToLower(req.BaseDN)) {
			continue
		}
		if !slices.Contains(e.attrs[attr], value) {
			continue
		}
		if req.SizeLimit > 0 && len(res.Entries) == req.SizeLimit {
			return res, ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size limit"))
		}
		res.Entries = append(res.Entries, ldap.NewEntry(e.dn, e.attrs))
	}
	return res, nil
}

func (c *fakeConn) StartTLS(*tls.Config) error { return nil }
func (c *fakeConn) Close() error               { return nil }

// parseEquality understands a single "(attr=value)" filter with RFC 4515
// escapes, which is all the plugin's default filters produce.
func parseEquality(f string) (string, string, error) {
	inner, ok := strings.CutPrefix(f, "(")
	inner, ok2 := strings.CutSuffix(inner, ")")
	attr, val, ok3 := strings.Cut(inner, "=")
	if !ok || !ok2 || !ok3 || strings.ContainsAny(val, "()*") {
		return "", "", errors.New("fake: unsupported filter " + f)
	}
	var b strings.Builder
	for i := 0; i < len(val); i++ {
		if val[i] == '\\' && i+2 < len(val) {
			x, err := hex.DecodeString(val[i+1 : i+3])
			if err != nil {
				return "", "", err
			}
			b.Write(x)
			i += 2
			continue
		}
		b.WriteByte(val[i])
	}
	return attr, b.String(), nil
}

func newDir() *fakeDir {
	return &fakeDir{entries: []fakeEntry{
		{dn: "cn=svc,dc=example,dc=org", password: "svcpw", attrs: map[string][]string{}},
		{
			dn: "uid=alice,ou=people,dc=example,dc=org", password: "secret",
			attrs: map[string][]string{
				"uid":    {"alice"},
				"cn":     {"Alice Liddell"},
				"mail":   {"alice@example.org"},
				"tenant": {"acme"},
				"memberOf": {
					"cn=admins,ou=groups,dc=example,dc=org",
					"cn=Devs,ou=groups,dc=example,dc=org",
					"cn=other,ou=groups,dc=example,dc=org",
				},
			},
		},
		{dn: "uid=bob1,ou=people,dc=example,dc=org", password: "pw1", attrs: map[string][]string{"uid": {"bob"}}},
		{dn: "uid=bob2,ou=people,dc=example,dc=org", password: "pw2", attrs: map[string][]string{"uid": {"bob"}}},
		{dn: "cn=ops,ou=groups,dc=example,dc=org", attrs: map[string][]string{
			"cn": {"ops"}, "member": {"uid=alice,ou=people,dc=example,dc=org"},
		}},
		{dn: "cn=admins,ou=groups,dc=example,dc=org", attrs: map[string][]string{
			"cn": {"admins"}, "member": {"uid=alice,ou=people,dc=example,dc=org"},
		}},
	}}
}

// --- fake host and registrar ------------------------------------------------

type fakeHost struct{ tenants []sdk.Tenant }

func (h fakeHost) GetTenant(_ context.Context, idOrSlug string) (sdk.Tenant, error) {
	for _, t := range h.tenants {
		if t.ID == idOrSlug || t.Slug == idOrSlug {
			return t, nil
		}
	}
	return sdk.Tenant{}, sdk.ErrNotFound
}
func (fakeHost) ListTenants(context.Context, string, int) ([]sdk.Tenant, error) { return nil, nil }
func (fakeHost) GetPlan(context.Context, string) (sdk.Plan, error) {
	return sdk.Plan{}, sdk.ErrNotFound
}
func (fakeHost) Entitlements(context.Context, string) (sdk.Entitlements, error) {
	return sdk.Entitlements{}, nil
}

type fakeRegistrar struct {
	cfg   map[string]any
	host  sdk.Host
	authn sdk.Authenticator
}

func (r *fakeRegistrar) Config(v any) error {
	raw, err := json.Marshal(r.cfg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
func (r *fakeRegistrar) Logger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func (r *fakeRegistrar) Host() sdk.Host       { return r.host }
func (r *fakeRegistrar) InstanceName() string { return "ldap" }
func (r *fakeRegistrar) Subscribe(string, sdk.EventFilter, sdk.EventHandler, ...sdk.SubscribeOption) {
}
func (r *fakeRegistrar) Hook(sdk.HookPoint, sdk.HookHandler, ...sdk.HookOption) {}
func (r *fakeRegistrar) Provisioner(sdk.Provisioner)                            {}
func (r *fakeRegistrar) Route(string, http.Handler)                             {}
func (r *fakeRegistrar) Authenticator(a sdk.Authenticator)                      { r.authn = a }
func (r *fakeRegistrar) Authorizer(sdk.Authorizer)                              {}

// --- helpers ------------------------------------------------------------------

func baseConfig() map[string]any {
	return map[string]any{
		"url":           "ldap://ldap.example.org:389",
		"bind_dn":       "cn=svc,dc=example,dc=org",
		"bind_password": "svcpw",
		"user_base_dn":  "ou=people,dc=example,dc=org",
	}
}

func setup(t *testing.T, cfg map[string]any, dir *fakeDir) sdk.Authenticator {
	t.Helper()
	p := &Plugin{dial: dir.dial}
	r := &fakeRegistrar{cfg: cfg, host: fakeHost{tenants: []sdk.Tenant{{ID: "t-123", Slug: "acme"}}}}
	if err := p.Init(context.Background(), r); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if r.authn == nil || r.authn.Name() != "basic" {
		t.Fatalf("authenticator not registered: %#v", r.authn)
	}
	return r.authn
}

func basic(user, pass string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
	r.SetBasicAuth(user, pass)
	return r
}

// --- tests --------------------------------------------------------------------

func TestMemberOfRoleMapping(t *testing.T) {
	cfg := baseConfig()
	cfg["role_mapping"] = map[string]string{"admins": "platform-admin", "devs": "developer"}
	a := setup(t, cfg, newDir())

	p, err := a.Authenticate(context.Background(), basic("alice", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "uid=alice,ou=people,dc=example,dc=org" || p.Kind != "user" || p.TenantID != "" {
		t.Errorf("principal = %+v", p)
	}
	if want := []string{"developer", "platform-admin"}; !slices.Equal(p.Roles, want) {
		t.Errorf("roles = %v, want %v", p.Roles, want)
	}
	if p.Claims["email"] != "alice@example.org" || p.Claims["name"] != "Alice Liddell" ||
		p.Claims["username"] != "alice" || p.Claims["dn"] != p.Subject {
		t.Errorf("claims = %v", p.Claims)
	}
}

func TestGroupCNsAsRolesAndSubjectAttribute(t *testing.T) {
	cfg := baseConfig()
	cfg["subject_attribute"] = "uid"
	a := setup(t, cfg, newDir())

	p, err := a.Authenticate(context.Background(), basic("alice", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "alice" {
		t.Errorf("subject = %q", p.Subject)
	}
	if want := []string{"Devs", "admins", "other"}; !slices.Equal(p.Roles, want) {
		t.Errorf("roles = %v, want %v", p.Roles, want)
	}
}

func TestGroupSearchMode(t *testing.T) {
	cfg := baseConfig()
	cfg["group_base_dn"] = "ou=groups,dc=example,dc=org"
	cfg["role_mapping"] = map[string]string{"ops": "operator"}
	dir := newDir()
	a := setup(t, cfg, dir)

	p, err := a.Authenticate(context.Background(), basic("alice", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"operator"}; !slices.Equal(p.Roles, want) {
		t.Errorf("roles = %v, want %v", p.Roles, want)
	}
	if !slices.Contains(dir.filters, `(member=uid=alice,ou=people,dc=example,dc=org)`) {
		t.Errorf("group filter not used: %v", dir.filters)
	}
}

func TestRejections(t *testing.T) {
	a := setup(t, baseConfig(), newDir())
	for name, req := range map[string]*http.Request{
		"wrong password": basic("alice", "nope"),
		"empty password": basic("alice", ""),
		"unknown user":   basic("mallory", "secret"),
		"multiple users": basic("bob", "pw1"),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := a.Authenticate(context.Background(), req)
			if err == nil || errors.Is(err, sdk.ErrNoCredentials) {
				t.Fatalf("got principal %+v, err %v; want auth error", p, err)
			}
		})
	}
}

func TestNoCredentials(t *testing.T) {
	a := setup(t, baseConfig(), newDir())
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer abc")
	if _, err := a.Authenticate(context.Background(), r); !errors.Is(err, sdk.ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestFilterInjectionIsEscaped(t *testing.T) {
	dir := newDir()
	a := setup(t, baseConfig(), dir)
	if _, err := a.Authenticate(context.Background(), basic("*)(uid=*", "secret")); err == nil {
		t.Fatal("injection authenticated")
	}
	want := `(uid=\2a\29\28uid=\2a)`
	if !slices.Contains(dir.filters, want) {
		t.Fatalf("filters = %v, want %s", dir.filters, want)
	}
}

func TestTenantAttribute(t *testing.T) {
	cfg := baseConfig()
	cfg["tenant_attribute"] = "tenant"
	dir := newDir()
	a := setup(t, cfg, dir)

	p, err := a.Authenticate(context.Background(), basic("alice", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if p.TenantID != "t-123" {
		t.Errorf("tenant = %q, want t-123", p.TenantID)
	}

	dir.entries[1].attrs["tenant"] = []string{"unknown"}
	if _, err := a.Authenticate(context.Background(), basic("alice", "secret2")); err == nil {
		t.Error("unknown tenant authenticated")
	}
	dir.entries[1].password = "secret2"
	if _, err := a.Authenticate(context.Background(), basic("alice", "secret2")); !errors.Is(err, sdk.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestCache(t *testing.T) {
	dir := newDir()
	a := setup(t, baseConfig(), dir)
	ctx := context.Background()

	p1, err := a.Authenticate(ctx, basic("alice", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	p1.Roles[0] = "tampered" // must not poison the cache
	p2, err := a.Authenticate(ctx, basic("alice", "secret"))
	if err != nil {
		t.Fatal(err)
	}
	if dir.dials != 1 {
		t.Errorf("dials = %d, want 1 (cache hit)", dir.dials)
	}
	if p2.Roles[0] == "tampered" {
		t.Error("cached principal shared with caller")
	}

	if _, err := a.Authenticate(ctx, basic("alice", "wrong")); err == nil {
		t.Fatal("wrong password served from cache")
	}
	if _, err := a.Authenticate(ctx, basic("alice", "wrong")); err == nil || dir.dials != 3 {
		t.Fatalf("failures must not be cached: err=%v dials=%d", err, dir.dials)
	}
}

func TestCacheBoundAndExpiry(t *testing.T) {
	c := newCache(time.Minute, 2)
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }
	p := &sdk.Principal{Subject: "x"}

	c.put([32]byte{1}, p)
	now = now.Add(time.Second)
	c.put([32]byte{2}, p)
	c.put([32]byte{3}, p) // evicts {1}, the oldest
	if _, ok := c.get([32]byte{1}); ok {
		t.Error("oldest entry not evicted")
	}
	if len(c.entries) != 2 {
		t.Errorf("size = %d, want 2", len(c.entries))
	}
	now = now.Add(time.Minute)
	if _, ok := c.get([32]byte{3}); ok {
		t.Error("expired entry served")
	}
}

func TestCacheDisabled(t *testing.T) {
	cfg := baseConfig()
	cfg["cache_ttl"] = "0s"
	dir := newDir()
	a := setup(t, cfg, dir)
	for range 2 {
		if _, err := a.Authenticate(context.Background(), basic("alice", "secret")); err != nil {
			t.Fatal(err)
		}
	}
	if dir.dials != 2 {
		t.Errorf("dials = %d, want 2", dir.dials)
	}
}

func TestInvalidConfig(t *testing.T) {
	for name, mut := range map[string]func(map[string]any){
		"bad url":          func(c map[string]any) { c["url"] = "http://x" },
		"no base dn":       func(c map[string]any) { delete(c, "user_base_dn") },
		"filter without s": func(c map[string]any) { c["user_filter"] = "(uid=x)" },
		"ldaps+starttls":   func(c map[string]any) { c["url"] = "ldaps://x"; c["start_tls"] = true },
		"bad timeout":      func(c map[string]any) { c["timeout"] = "soon" },
		"unknown field":    func(c map[string]any) { c["nope"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := baseConfig()
			mut(cfg)
			p := &Plugin{dial: newDir().dial}
			if err := p.Init(context.Background(), &fakeRegistrar{cfg: cfg}); err == nil {
				t.Fatal("Init succeeded")
			}
		})
	}
}

func TestHealth(t *testing.T) {
	dir := newDir()
	p := &Plugin{dial: dir.dial}
	if err := p.Init(context.Background(), &fakeRegistrar{cfg: baseConfig()}); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.cfg.BindPassword = "wrong"
	if err := p.Health(context.Background()); err == nil {
		t.Fatal("health ok with wrong service password")
	}
}

func TestFormatGUID(t *testing.T) {
	b, _ := hex.DecodeString("33221100554477668899aabbccddeeff")
	if got, want := formatGUID(b), "00112233-4455-6677-8899-aabbccddeeff"; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// TestIntegration runs against a real directory when TENARIUM_TEST_LDAP_URL
// is set, e.g.:
//
//	docker run --rm -d -p 3389:389 -e LDAP_DOMAIN=example.org \
//	  -e LDAP_ADMIN_PASSWORD=admin osixia/openldap:1.5.0
//	TENARIUM_TEST_LDAP_URL=ldap://localhost:3389 go test ./plugins/ldap/ -run Integration
//
// It binds as cn=admin,dc=example,dc=org (password "admin"), creates a user
// and a group, authenticates through the plugin and removes them again.
func TestIntegration(t *testing.T) {
	u := os.Getenv("TENARIUM_TEST_LDAP_URL")
	if u == "" {
		t.Skip("TENARIUM_TEST_LDAP_URL not set")
	}
	const (
		admin    = "cn=admin,dc=example,dc=org"
		people   = "ou=it-people,dc=example,dc=org"
		groups   = "ou=it-groups,dc=example,dc=org"
		userDN   = "uid=it-alice," + people
		groupDN  = "cn=it-admins," + groups
		password = "s3cret"
	)
	lc, err := ldap.DialURL(u)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	if err := lc.Bind(admin, "admin"); err != nil {
		t.Fatal(err)
	}
	add := func(dn string, attrs map[string][]string) {
		req := ldap.NewAddRequest(dn, nil)
		for k, v := range attrs {
			req.Attribute(k, v)
		}
		if err := lc.Add(req); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			t.Fatalf("add %s: %v", dn, err)
		}
	}
	add(people, map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"it-people"}})
	add(groups, map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"it-groups"}})
	add(userDN, map[string][]string{
		"objectClass": {"inetOrgPerson"}, "uid": {"it-alice"}, "cn": {"Alice"}, "sn": {"Liddell"},
		"mail": {"alice@example.org"}, "userPassword": {password},
	})
	add(groupDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"it-admins"}, "member": {userDN}})
	t.Cleanup(func() {
		for _, dn := range []string{groupDN, userDN, groups, people} {
			_ = lc.Del(ldap.NewDelRequest(dn, nil))
		}
	})

	cfg := map[string]any{
		"url":           u,
		"bind_dn":       admin,
		"bind_password": "admin",
		"user_base_dn":  people,
		"group_base_dn": groups,
		"role_mapping":  map[string]string{"it-admins": "platform-admin"},
	}
	p := &Plugin{}
	r := &fakeRegistrar{cfg: cfg, host: fakeHost{}}
	if err := p.Init(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	pr, err := r.authn.Authenticate(ctx, basic("it-alice", password))
	if err != nil {
		t.Fatal(err)
	}
	if pr.Subject != userDN || !slices.Equal(pr.Roles, []string{"platform-admin"}) || pr.Claims["email"] != "alice@example.org" {
		t.Errorf("principal = %+v", pr)
	}
	if _, err := r.authn.Authenticate(ctx, basic("it-alice", "wrong")); err == nil {
		t.Error("wrong password accepted")
	}
}

func (h fakeHost) Authorize(context.Context, sdk.Action, sdk.Resource) error { return nil }

func (h fakeHost) GetUser(context.Context, string) (sdk.User, error) {
	return sdk.User{}, sdk.ErrNotFound
}

func (r *fakeRegistrar) UserDirectory(sdk.UserDirectory) {}
func (r *fakeRegistrar) Mailer(sdk.Mailer)               {}

func (h fakeHost) SuspendTenant(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h fakeHost) ResumeTenant(context.Context, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h fakeHost) SetTenantPlan(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, sdk.ErrUnsupported
}
func (h fakeHost) RecordUsage(context.Context, string, string, int64) (int64, error) {
	return 0, sdk.ErrUnsupported
}

func (r *fakeRegistrar) PublicRoute(string, http.Handler) {}
