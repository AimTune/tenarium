package mongotenant

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// fakeBackend is an in-memory MongoDB.
type fakeBackend struct {
	mu          sync.Mutex
	collections map[string]map[string]bool // db -> collections
	markers     map[string]map[string]marker
	users       map[string]fakeUser // authDB/name
	pingErr     error
}

type fakeUser struct {
	info     userInfo
	password string
}

func newFake() *fakeBackend {
	return &fakeBackend{
		collections: map[string]map[string]bool{},
		markers:     map[string]map[string]marker{},
		users:       map[string]fakeUser{},
	}
}

func (f *fakeBackend) Ping(context.Context) error  { return f.pingErr }
func (f *fakeBackend) Close(context.Context) error { return nil }

func (f *fakeBackend) addCollection(db, c string) {
	if f.collections[db] == nil {
		f.collections[db] = map[string]bool{}
	}
	f.collections[db][c] = true
}

func (f *fakeBackend) Collections(_ context.Context, db string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(maps.Keys(f.collections[db])), nil
}

func (f *fakeBackend) Markers(_ context.Context, db string) ([]marker, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Collect(maps.Values(f.markers[db])), nil
}

func (f *fakeBackend) put(db string, m marker) {
	if f.markers[db] == nil {
		f.markers[db] = map[string]marker{}
	}
	f.markers[db][m.ID] = m
	f.addCollection(db, MarkerCollection)
}

func (f *fakeBackend) InsertMarker(_ context.Context, db string, m marker) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.markers[db][m.ID]; ok {
		return errDuplicate
	}
	f.put(db, m)
	return nil
}

func (f *fakeBackend) PutMarker(_ context.Context, db string, m marker) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.put(db, m)
	return nil
}

func (f *fakeBackend) DeleteMarker(_ context.Context, db, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.markers[db], id)
	return nil
}

func (f *fakeBackend) DropDatabase(_ context.Context, db string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.markers, db)
	delete(f.collections, db)
	return nil
}

func (f *fakeBackend) User(_ context.Context, authDB, name string) (*userInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[authDB+"/"+name]
	if !ok {
		return nil, nil
	}
	info := u.info
	return &info, nil
}

func (f *fakeBackend) CreateUser(_ context.Context, authDB, name, pwd string, roles []role, custom map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[authDB+"/"+name]; ok {
		return errDuplicate
	}
	f.users[authDB+"/"+name] = fakeUser{info: userInfo{User: name, DB: authDB, Roles: roles, CustomData: custom}, password: pwd}
	return nil
}

func (f *fakeBackend) UpdateUser(_ context.Context, authDB, name, pwd string, roles []role, custom map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[authDB+"/"+name]; !ok {
		return errors.New("user not found")
	}
	f.users[authDB+"/"+name] = fakeUser{info: userInfo{User: name, DB: authDB, Roles: roles, CustomData: custom}, password: pwd}
	return nil
}

func (f *fakeBackend) DropUser(_ context.Context, authDB, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.users, authDB+"/"+name)
	return nil
}

const testSecret = "0123456789abcdef-secret"

// newFakePlugin initializes a plugin over a fake backend.
func newFakePlugin(t *testing.T, cfg map[string]any) (*Plugin, *fakeBackend, *sdktest.Registrar) {
	t.Helper()
	full := map[string]any{"uri": "mongodb://root:pw@db.internal:27017/?authSource=admin&tls=true", "password_secret": testSecret}
	maps.Copy(full, cfg)
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := reg.Config(&p.cfg); err != nil {
		t.Fatal(err)
	}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	f := newFake()
	p.init(f, reg)
	p.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	return p, f, reg
}

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"tenant_acme":         "tenant_acme",
		"Tenant-Acme Corp.":   "tenant-acme_corp",
		"a..b//c$$d":          "a_b_c_d",
		"__x--":               "x",
		"ümlaut":              "mlaut",
		`x"; db.dropDatabase`: "x_db_dropdatabase",
		"":                    "",
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderNameLimits(t *testing.T) {
	tmpl, err := parseNameTemplate("name_template", DefaultNameTemplate)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("very-long-slug-", 10)
	a := sdk.Tenant{ID: "11111111-1111-1111-1111-111111111111", Slug: long}
	b := sdk.Tenant{ID: "22222222-2222-2222-2222-222222222222", Slug: long}
	na, err := renderName(tmpl, a)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := renderName(tmpl, b)
	if err != nil {
		t.Fatal(err)
	}
	if na == nb {
		t.Fatalf("long names collide: %q", na)
	}
	for _, n := range []string{na, nb} {
		if len(n) > maxNameLen || !strings.HasPrefix(n, "tenant_very-long-slug") {
			t.Errorf("bad shortened name %q", n)
		}
		if err := checkDBName(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	if again, _ := renderName(tmpl, a); again != na {
		t.Fatalf("name not stable: %q vs %q", again, na)
	}

	slug, err := parseNameTemplate("name_template", "{{.Slug}}")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"admin", "Local", "config"} {
		if _, err := renderName(slug, sdk.Tenant{ID: "x", Slug: s}); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("slug %q: err %v, want reserved", s, err)
		}
	}
}

func TestCheckDBName(t *testing.T) {
	for _, bad := range []string{"", "a.b", "a/b", `a\b`, "a b", "a$b", `a"b`, "a*b", "a<b", "a>b", "a:b", "a|b", "a?b", strings.Repeat("x", 64)} {
		if checkDBName(bad) == nil {
			t.Errorf("checkDBName(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"admin", "tenant_x-1", strings.Repeat("x", 63)} {
		if err := checkDBName(ok); err != nil {
			t.Errorf("checkDBName(%q): %v", ok, err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	base := func(c Config) Config {
		if c.URI == "" {
			c.URI = "mongodb://root:pw@localhost:27017/?authSource=admin"
		}
		if c.PasswordSecret == "" {
			c.PasswordSecret = testSecret
		}
		return c
	}
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{base(Config{}), ""},
		{base(Config{AuthDatabase: "admin", Roles: []string{"readWrite", "dbAdmin"}, OnDeprovision: "retain"}), ""},
		{base(Config{URI: "mongodb+srv://u:p@cluster0.example.net/?retryWrites=true"}), ""},
		{Config{PasswordSecret: testSecret}, "uri is required"},
		{base(Config{URI: "postgres://x"}), "mongodb://"},
		{base(Config{URI: "mongodb:///db"}), "missing host"},
		{Config{URI: "mongodb://h"}, "password_secret is required"},
		{base(Config{PasswordSecret: "short"}), "at least 16"},
		{base(Config{OnDeprovision: "drop"}), "on_deprovision"},
		{base(Config{AuthDatabase: "a.b"}), "auth_database"},
		{base(Config{AuthDatabase: "local"}), "auth_database"},
		{base(Config{Roles: []string{"read Write"}}), "invalid role"},
		{base(Config{Roles: []string{"read", "read"}}), "duplicate role"},
		{base(Config{NameTemplate: "t_{{.Slug"}), "name_template"},
		{base(Config{NameTemplate: "t_{{.Nope}}"}), "name_template"},
		{base(Config{NameTemplate: "{{if false}}x{{end}}"}), "empty name"},
		{base(Config{NameTemplate: "static"}), "name_template must depend on the tenant"},
		{base(Config{UserTemplate: "app"}), "user_template must depend on the tenant"},
		{base(Config{UserTemplate: "u_{{.Nope}}"}), "user_template"},
		{base(Config{NameTemplate: "{{if eq .Slug \"example-one\"}}shared{{else}}{{.Slug}}{{end}}", AuthDatabase: "shared"}), "auth_database name"},
	} {
		p := &Plugin{cfg: tc.cfg}
		err := p.validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%+v: unexpected error %v", tc.cfg, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%+v: error %v, want containing %q", tc.cfg, err, tc.wantErr)
		}
	}

	p := &Plugin{cfg: base(Config{})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.OnDeprovision != DeprovisionDelete || p.cfg.NameTemplate != DefaultNameTemplate ||
		!slices.Equal(p.cfg.Roles, []string{DefaultRole}) {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	tg, err := p.target(sdk.Tenant{ID: "id", Slug: "acme-corp"})
	if err != nil || tg != (target{Database: "tenant_acme-corp", User: "tenant_acme-corp", AuthDatabase: "tenant_acme-corp"}) {
		t.Fatalf("target = %+v, %v", tg, err)
	}

	p = &Plugin{cfg: base(Config{AuthDatabase: "admin", UserTemplate: "app_{{.ID}}"})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	tg, err = p.target(sdk.Tenant{ID: "ID-1", Slug: "acme"})
	if err != nil || tg != (target{Database: "tenant_acme", User: "app_id-1", AuthDatabase: "admin"}) {
		t.Fatalf("target = %+v, %v", tg, err)
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "mongodb-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(map[string]any{"uri": "mongodb://h", "password_secret": testSecret, "roles": []any{"readWrite"}, "on_deprovision": "retain"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{
		{"uri": "mongodb://h"},
		{"uri": "http://h", "password_secret": testSecret},
		{"uri": "mongodb://h", "password_secret": testSecret, "on_deprovision": "drop"},
		{"uri": "mongodb://h", "password_secret": testSecret, "extra": true},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("expected schema error for %v", bad)
		}
	}
}

func TestInitRegisters(t *testing.T) {
	reg := sdktest.NewRegistrar(map[string]any{"uri": "mongodb://127.0.0.1:1/", "password_secret": testSecret})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(context.Background()) }()
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "mongodb" {
		t.Fatalf("provisioners %v", reg.Provisioners)
	}
	if len(reg.Routes) != 1 || reg.Routes[0] != "GET /tenants/{tenant}" {
		t.Fatalf("routes %v", reg.Routes)
	}
	var _ sdk.HealthChecker = p
	var _ sdk.Stopper = p
}

func TestTenantPassword(t *testing.T) {
	a := TenantPassword(testSecret, "t1")
	if len(a) != 32 || a != TenantPassword(testSecret, "t1") {
		t.Fatalf("password %q not stable", a)
	}
	if a == TenantPassword(testSecret, "t2") || a == TenantPassword("other-secret-value", "t1") {
		t.Fatal("password does not depend on tenant and secret")
	}
}

func TestTenantURI(t *testing.T) {
	tg := target{Database: "tenant_a", User: "tenant_a", AuthDatabase: "tenant_a"}
	for in, want := range map[string]string{
		"mongodb://root:pw@h1:27017,h2:27017/admin?replicaSet=rs0&authSource=admin&authMechanism=SCRAM-SHA-256": "mongodb://tenant_a@h1:27017,h2:27017/tenant_a?authSource=tenant_a&replicaSet=rs0",
		"mongodb+srv://root:p%40ss@cluster.example.net/?tls=true":                                               "mongodb+srv://tenant_a@cluster.example.net/tenant_a?authSource=tenant_a&tls=true",
		"mongodb://localhost": "mongodb://tenant_a@localhost/tenant_a?authSource=tenant_a",
	} {
		got, err := tenantURI(in, tg)
		if err != nil || got != want {
			t.Errorf("tenantURI(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestProvisionLifecycle(t *testing.T) {
	ctx := context.Background()
	p, f, reg := newFakePlugin(t, map[string]any{"roles": []any{"readWrite", "dbAdmin"}})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})

	for range 2 { // idempotent
		if err := p.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	m := f.markers["tenant_acme"][markerOwner]
	if m.TenantID != tn.ID || m.TenantSlug != "acme" || m.CreatedAt.IsZero() {
		t.Fatalf("owner marker %+v", m)
	}
	u := f.users["tenant_acme/tenant_acme"]
	if u.password != TenantPassword(testSecret, tn.ID) || u.info.tenantID() != tn.ID {
		t.Fatalf("user %+v", u)
	}
	if want := []role{{"readWrite", "tenant_acme"}, {"dbAdmin", "tenant_acme"}}; !slices.Equal(u.info.Roles, want) {
		t.Fatalf("roles %v", u.info.Roles)
	}

	// Rotating the secret resets the password on the next Provision.
	p.cfg.PasswordSecret = "rotated-secret-0123456789"
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if f.users["tenant_acme/tenant_acme"].password != TenantPassword("rotated-secret-0123456789", tn.ID) {
		t.Fatal("password not rotated")
	}

	f.addCollection("tenant_acme", "orders")
	for range 2 {
		if err := p.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.users) != 0 || f.collections["tenant_acme"] != nil {
		t.Fatalf("not deleted: users %v, collections %v", f.users, f.collections)
	}
}

func TestProvisionAdoptsOnlyEmptyUnmarked(t *testing.T) {
	ctx := context.Background()
	p, f, reg := newFakePlugin(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})

	// Interrupted Provision: marker collection without documents.
	f.addCollection("tenant_acme", MarkerCollection)
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatalf("empty database not adopted: %v", err)
	}

	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "data"})
	f.addCollection("tenant_data", "foreign")
	if err := p.Provision(ctx, other); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("unmarked data adopted: %v", err)
	}
	if len(f.markers["tenant_data"]) != 0 {
		t.Fatal("marker written into foreign database")
	}
}

func TestProvisionRefusesForeignResources(t *testing.T) {
	ctx := context.Background()
	p, f, reg := newFakePlugin(t, nil)
	a := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	// Same slug, other tenant (e.g. reused after keep).
	b := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "belongs to another tenant") {
		t.Fatalf("foreign database adopted: %v", err)
	}
	// Deprovisioning b must leave a's resources alone.
	if err := p.Deprovision(ctx, b); err != nil {
		t.Fatal(err)
	}
	if f.markers["tenant_acme"][markerOwner].TenantID != a.ID || f.users["tenant_acme/tenant_acme"].info.tenantID() != a.ID {
		t.Fatal("other tenant's resources touched")
	}

	// A user that is unmarked or marked for another tenant is refused.
	c := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "cee"})
	f.users["tenant_cee/tenant_cee"] = fakeUser{info: userInfo{User: "tenant_cee", DB: "tenant_cee"}, password: "x"}
	if err := p.Provision(ctx, c); err == nil || !strings.Contains(err.Error(), "user tenant_cee@tenant_cee already exists and is not managed") {
		t.Fatalf("unmarked user adopted: %v", err)
	}
	f.users["tenant_cee/tenant_cee"] = fakeUser{info: userInfo{User: "tenant_cee", DB: "tenant_cee", CustomData: map[string]any{CustomDataTenantID: "someone"}}, password: "x"}
	if err := p.Provision(ctx, c); err == nil || !strings.Contains(err.Error(), "belongs to another tenant (someone)") {
		t.Fatalf("foreign user adopted: %v", err)
	}
	if err := p.Deprovision(ctx, c); err != nil {
		t.Fatal(err)
	}
	if f.users["tenant_cee/tenant_cee"].password != "x" {
		t.Fatal("foreign user dropped or changed")
	}
}

func TestDeprovisionRetain(t *testing.T) {
	ctx := context.Background()
	p, f, reg := newFakePlugin(t, map[string]any{"on_deprovision": "retain", "auth_database": "admin"})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.users["admin/tenant_acme"]; !ok {
		t.Fatalf("user not in admin: %v", f.users)
	}
	f.addCollection("tenant_acme", "orders")
	for range 2 {
		if err := p.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	ms := f.markers["tenant_acme"]
	if _, ok := ms[markerOwner]; ok || ms[markerRetained].DeletedTenantID != tn.ID || ms[markerRetained].DeletedAt.IsZero() {
		t.Fatalf("markers %+v", ms)
	}
	if len(f.users) != 0 || !f.collections["tenant_acme"]["orders"] {
		t.Fatalf("users %v, collections %v", f.users, f.collections)
	}
	// A new tenant with the same slug cannot take over retained data.
	again := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, again); err == nil || !strings.Contains(err.Error(), "retained from deleted tenant "+tn.ID) {
		t.Fatalf("retained data adopted: %v", err)
	}
}

func TestDeprovisionKeep(t *testing.T) {
	ctx := context.Background()
	p, f, reg := newFakePlugin(t, map[string]any{"on_deprovision": "keep"})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if f.markers["tenant_acme"][markerOwner].TenantID != tn.ID || len(f.users) != 1 {
		t.Fatal("keep touched resources")
	}
}

func TestDeprovisionMissing(t *testing.T) {
	p, _, reg := newFakePlugin(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "ghost"})
	if err := p.Deprovision(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
}

func TestQuotaRecorded(t *testing.T) {
	ctx := context.Background()
	p, f, reg := newFakePlugin(t, map[string]any{"quota_from_limit": "storage_gb"})
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"storage_gb": 50}})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	m := f.markers["tenant_acme"][markerOwner]
	if m.QuotaMetric != "storage_gb" || m.QuotaLimit == nil || *m.QuotaLimit != 50 {
		t.Fatalf("quota not recorded: %+v", m)
	}
	created := m.CreatedAt

	// Unlimited tenants carry no quota; created_at is preserved.
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro"})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	m = f.markers["tenant_acme"][markerOwner]
	if m.QuotaLimit != nil || m.QuotaMetric != "" || !m.CreatedAt.Equal(created) || m.TenantID != tn.ID {
		t.Fatalf("quota not cleared: %+v", m)
	}
}

func TestHealth(t *testing.T) {
	p, f, _ := newFakePlugin(t, nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.pingErr = errors.New("down")
	if err := p.Health(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestTenantRoute(t *testing.T) {
	_, _, reg := newFakePlugin(t, nil)
	acme := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other"})

	get := func(path string, pr *sdk.Principal) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if pr != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), pr))
		}
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		return rec
	}
	admin := &sdk.Principal{Subject: "admin", Kind: "user"}

	rec := get("/tenants/acme", admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Database != "tenant_acme" || info.User != "tenant_acme" || info.AuthDatabase != "tenant_acme" || info.Password != "" ||
		info.URI != "mongodb://tenant_acme@db.internal:27017/tenant_acme?authSource=tenant_acme&tls=true" {
		t.Fatalf("info %+v", info)
	}
	if strings.Contains(rec.Body.String(), "pw@") || strings.Contains(rec.Body.String(), "root") {
		t.Fatalf("admin credentials leaked: %s", rec.Body)
	}

	if rec := get("/tenants/missing", admin); rec.Code != http.StatusNotFound {
		t.Fatalf("missing tenant: %d", rec.Code)
	}
	// A caller scoped to another tenant gets 404, not 403.
	if rec := get("/tenants/acme", &sdk.Principal{Subject: "x", TenantID: other.ID}); rec.Code != http.StatusNotFound {
		t.Fatalf("foreign tenant: %d", rec.Code)
	}
	if rec := get("/tenants/acme", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("anonymous: %d", rec.Code)
	}

	// Password: only with include_password=true and tenants:update.
	rec = get("/tenants/acme?include_password=true", admin)
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil || info.Password != TenantPassword(testSecret, acme.ID) {
		t.Fatalf("password not returned: %s", rec.Body)
	}
	reg.HostImpl.AuthorizeFunc = func(_ context.Context, _ *sdk.Principal, a sdk.Action, _ sdk.Resource) error {
		if a == sdk.ActionTenantsRead {
			return nil
		}
		return sdk.ErrForbidden
	}
	if rec := get("/tenants/acme?include_password=true", admin); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only caller got password: %d %s", rec.Code, rec.Body)
	}
	if rec := get("/tenants/acme", admin); rec.Code != http.StatusOK {
		t.Fatalf("read-only caller: %d", rec.Code)
	}
}
