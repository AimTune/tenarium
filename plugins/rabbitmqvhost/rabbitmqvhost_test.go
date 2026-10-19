package rabbitmqvhost

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

const testSecret = "0123456789abcdef-test-secret"

func strp(s string) *string { return &s }

func baseCfg(c Config) Config {
	if c.URL == "" {
		c.URL = "http://rabbitmq:15672"
	}
	if c.Username == "" {
		c.Username, c.Password = "admin", "secret"
	}
	if c.PasswordSecret == "" {
		c.PasswordSecret = testSecret
	}
	return c
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		cfg     Config
		wantErr string
	}{
		{baseCfg(Config{}), ""},
		{baseCfg(Config{URL: "https://rabbit.example.com/mgmt/", Timeout: "3s", OnDeprovision: "retain",
			DefaultQueueType: "quorum", UserTags: []string{"management"}, AMQPURL: "amqps://rabbit.example.com:5671",
			Limits: map[string]string{"max-connections": "amqp_connections", "max-queues": "amqp_queues"}}), ""},
		{Config{Username: "a", Password: "b", PasswordSecret: testSecret}, "url is required"},
		{baseCfg(Config{URL: "rabbitmq:15672"}), "http(s) URL"},
		{baseCfg(Config{URL: "amqp://rabbitmq"}), "http(s) URL"},
		{baseCfg(Config{URL: "http://u:p@rabbitmq:15672"}), "must not contain credentials"},
		{Config{URL: "http://r", Username: "a", PasswordSecret: testSecret}, "username and password"},
		{baseCfg(Config{Timeout: "soon"}), "timeout"},
		{baseCfg(Config{Timeout: "-1s"}), "timeout must be positive"},
		{Config{URL: "http://r", Username: "a", Password: "b"}, "password_secret is required"},
		{baseCfg(Config{PasswordSecret: "short"}), "at least 16"},
		{baseCfg(Config{OnDeprovision: "archive"}), "on_deprovision"},
		{baseCfg(Config{DefaultQueueType: "lazy"}), "default_queue_type"},
		{baseCfg(Config{UserTags: []string{"a,b"}}), "user_tags"},
		{baseCfg(Config{UserTags: []string{"tenarium-x"}}), "reserved"},
		{baseCfg(Config{UserTags: []string{"administrator"}}), "beyond their vhost"},
		{baseCfg(Config{UserTags: []string{"monitoring"}}), "beyond their vhost"},
		{baseCfg(Config{Limits: map[string]string{"max-channels": "x"}}), "unknown vhost limit"},
		{baseCfg(Config{Limits: map[string]string{"max-queues": ""}}), "must not be empty"},
		{baseCfg(Config{AMQPURL: "http://rabbit"}), "amqp_url"},
		{baseCfg(Config{AMQPURL: "amqp://rabbit/vhost"}), "amqp_url"},
		{baseCfg(Config{AMQPURL: "amqp://u:p@rabbit"}), "amqp_url"},
		{baseCfg(Config{VhostTemplate: "t-{{.Slug"}), "vhost_template"},
		{baseCfg(Config{VhostTemplate: "t-{{.Nope}}"}), "vhost_template"},
		{baseCfg(Config{VhostTemplate: "{{if false}}x{{end}}"}), "empty name"},
		{baseCfg(Config{VhostTemplate: "static"}), "vhost_template must depend on the tenant"},
		{baseCfg(Config{UsernameTemplate: "static"}), "username_template must depend on the tenant"},
		{baseCfg(Config{UsernameTemplate: "{{if eq .Slug \"example-one\"}}admin{{else}}x{{end}}"}), "admin user"},
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

	p := &Plugin{cfg: baseCfg(Config{Permissions: &Permissions{Write: strp("^amq\\.gen.*"), Read: strp("")}})}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	if p.cfg.OnDeprovision != DeprovisionDelete || p.cfg.VhostTemplate != DefaultVhostTemplate ||
		p.cfg.UsernameTemplate != DefaultUsernameTemplate {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	if p.perms != (permissionBody{Configure: ".*", Write: "^amq\\.gen.*", Read: ""}) {
		t.Fatalf("perms %+v", p.perms)
	}
	tg, err := p.target(sdk.Tenant{ID: "id", Slug: "acme-corp"})
	if err != nil || tg.Vhost != "tenant-acme-corp" || tg.User != "tenant-acme-corp" {
		t.Fatalf("target = %+v, %v", tg, err)
	}
}

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"tenant-acme":       "tenant-acme",
		"Tenant_Acme Corp.": "tenant_acme-corp",
		"a/b%c":             "a-b-c",
		"--x--":             "x",
		"ümlaut":            "mlaut",
		"":                  "",
		"a  b":              "a-b",
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRenderNameLimits(t *testing.T) {
	tmpl, err := parseNameTemplate("vhost_template", DefaultVhostTemplate)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("very-long-slug-", 10)
	a := sdk.Tenant{ID: "11111111-1111-1111-1111-111111111111", Slug: long}
	b := sdk.Tenant{ID: "22222222-2222-2222-2222-222222222222", Slug: long}
	na, _ := renderName(tmpl, a)
	nb, _ := renderName(tmpl, b)
	if na == nb {
		t.Fatalf("long names collide: %q", na)
	}
	for _, n := range []string{na, nb} {
		if len(n) > maxNameLen || !strings.HasPrefix(n, "tenant-very-long-slug") {
			t.Errorf("bad shortened name %q", n)
		}
	}
	if again, _ := renderName(tmpl, a); again != na {
		t.Fatalf("name not stable: %q vs %q", again, na)
	}
}

func TestTenantPassword(t *testing.T) {
	p1 := TenantPassword(testSecret, "t1")
	if len(p1) != 43 || strings.ContainsAny(p1, "+/=") {
		t.Fatalf("password %q", p1)
	}
	if p1 != TenantPassword(testSecret, "t1") {
		t.Fatal("not deterministic")
	}
	if p1 == TenantPassword(testSecret, "t2") || p1 == TenantPassword(testSecret+"x", "t1") {
		t.Fatal("password does not depend on tenant and secret")
	}
}

func TestTagListDecoding(t *testing.T) {
	for in, want := range map[string][]string{
		`["a","b"]`: {"a", "b"},
		`"a, b,"`:   {"a", "b"},
		`""`:        nil,
		`null`:      nil,
	} {
		var tl tagList
		if err := json.Unmarshal([]byte(in), &tl); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if !slices.Equal(tl, want) {
			t.Errorf("%s: got %q want %q", in, tl, want)
		}
	}
}

func TestConfigSchemaCompiles(t *testing.T) {
	m := (&Plugin{}).Manifest()
	if m.ID != "rabbitmq-tenant" {
		t.Fatalf("id %q", m.ID)
	}
	s, err := schema.Compile(m.ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{
		"url": "http://r:15672", "username": "a", "password": "b", "password_secret": testSecret,
		"permissions": map[string]any{"configure": ".*", "write": ".*", "read": ".*"},
		"limits":      map[string]any{"max-connections": "conns"},
		"user_tags":   []any{"management"}, "default_queue_type": "quorum", "on_deprovision": "retain",
		"amqp_url": "amqps://r:5671",
	}
	if err := s.Validate(ok); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"missing":      {"url": "http://r"},
		"mode":         {"url": "http://r", "username": "a", "password": "b", "password_secret": testSecret, "on_deprovision": "archive"},
		"limit name":   {"url": "http://r", "username": "a", "password": "b", "password_secret": testSecret, "limits": map[string]any{"max-channels": "x"}},
		"perms extra":  {"url": "http://r", "username": "a", "password": "b", "password_secret": testSecret, "permissions": map[string]any{"all": ".*"}},
		"unknown key":  {"url": "http://r", "username": "a", "password": "b", "password_secret": testSecret, "nope": true},
		"short secret": {"url": "http://r", "username": "a", "password": "b", "password_secret": "x"},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

func TestInitRegisters(t *testing.T) {
	reg := sdktest.NewRegistrar(map[string]any{
		"url": "http://127.0.0.1:9", "username": "a", "password": "b", "password_secret": testSecret,
	})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Provisioners) != 1 || reg.Provisioners[0].Name() != "rabbitmq-vhost" {
		t.Fatalf("provisioners %v", reg.Provisioners)
	}
	if !slices.Equal(reg.Routes, []string{"GET /tenants/{tenant}", "GET /tenants/{tenant}/credentials"}) {
		t.Fatalf("routes %v", reg.Routes)
	}
	var _ sdk.HealthChecker = p
	var _ sdk.Stopper = p
	if err := p.Health(context.Background()); err == nil {
		t.Fatal("expected health error against unreachable server")
	}

	bad := sdktest.NewRegistrar(map[string]any{"url": "http://r", "username": "a", "password": "b", "password_secret": testSecret, "bogus": 1})
	if err := (&Plugin{}).Init(context.Background(), bad); err == nil {
		t.Fatal("expected strict config error")
	}
}

// setup initializes the plugin against a fake server.
func setup(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar, *fakeRabbit) {
	t.Helper()
	f, srv := newFake(t)
	full := map[string]any{"url": srv.URL, "username": "admin", "password": "secret", "password_secret": testSecret}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	return p, reg, f
}

func TestProvisionIdempotent(t *testing.T) {
	p, reg, f := setup(t, map[string]any{
		"user_tags": []any{"management"}, "default_queue_type": "quorum",
		"permissions": map[string]any{"configure": "^tenant\\..*"},
	})
	ctx := context.Background()
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	for range 2 {
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	v := f.vhosts["tenant-acme"]
	if v == nil || !slices.Contains(v.Tags, TagTenantID+ten.ID) || v.DefaultQueueType != "quorum" ||
		!strings.Contains(v.Description, ten.ID) {
		t.Fatalf("vhost %+v", v)
	}
	u := f.users["tenant-acme"]
	if u == nil || u.Password != TenantPassword(testSecret, ten.ID) ||
		!slices.Equal(u.Tags, []string{"management", TagTenantID + ten.ID}) {
		t.Fatalf("user %+v", u)
	}
	if got := f.perms["tenant-acme/tenant-acme"]; got != (permissionBody{Configure: "^tenant\\..*", Write: ".*", Read: ".*"}) {
		t.Fatalf("perms %+v", got)
	}

	// Operator tags on the vhost survive reprovisioning.
	v.Tags = append(v.Tags, "team-a")
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.vhosts["tenant-acme"].Tags, "team-a") {
		t.Fatalf("operator tag lost: %v", f.vhosts["tenant-acme"].Tags)
	}

	// Recovery after a partial failure: the user step failed once.
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "beta"})
	f.fail["PUT /api/users/tenant-beta"] = http.StatusInternalServerError
	if err := p.Provision(ctx, other); err == nil {
		t.Fatal("expected injected failure")
	}
	delete(f.fail, "PUT /api/users/tenant-beta")
	if err := p.Provision(ctx, other); err != nil {
		t.Fatal(err)
	}
	if f.users["tenant-beta"] == nil {
		t.Fatal("user not created on retry")
	}
}

func TestProvisionStringTags(t *testing.T) {
	p, reg, f := setup(t, nil)
	f.stringTags = true
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "old"})
	for range 2 {
		if err := p.Provision(context.Background(), ten); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProvisionRequiresVhostMetadata(t *testing.T) {
	p, reg, f := setup(t, nil)
	f.dropTags = true
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	if err := p.Provision(context.Background(), ten); err == nil || !strings.Contains(err.Error(), "3.11") {
		t.Fatalf("err %v", err)
	}
}

func TestProvisionOwnershipConflicts(t *testing.T) {
	p, reg, f := setup(t, nil)
	ctx := context.Background()
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	for name, prep := range map[string]func(){
		"belongs to tenant other": func() {
			f.vhosts["tenant-acme"] = &fakeVhost{Tags: []string{TagTenantID + "other"}, Limits: map[string]int64{}}
		},
		"not managed by tenarium": func() {
			f.vhosts["tenant-acme"] = &fakeVhost{Tags: []string{"team"}, Limits: map[string]int64{}}
		},
		"retained data": func() {
			f.vhosts["tenant-acme"] = &fakeVhost{Tags: []string{TagRetainedTenantID + "old"}, Limits: map[string]int64{}}
		},
		"user \"tenant-acme\" already exists": func() {
			f.users["tenant-acme"] = &fakeUser{Password: "x", Tags: []string{"administrator"}}
		},
		"user \"tenant-acme\" belongs to tenant other": func() {
			f.users["tenant-acme"] = &fakeUser{Password: "x", Tags: []string{TagTenantID + "other"}}
		},
	} {
		clear(f.vhosts)
		clear(f.users)
		prep()
		err := p.Provision(ctx, ten)
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err %v", name, err)
		}
		// Nothing was changed.
		if u := f.users["tenant-acme"]; u != nil && u.Password != "x" {
			t.Errorf("%s: foreign user modified", name)
		}
		if v := f.vhosts["tenant-acme"]; v != nil && slices.Contains(v.Tags, TagTenantID+ten.ID) {
			t.Errorf("%s: foreign vhost claimed", name)
		}
	}
}

func TestProvisionLimits(t *testing.T) {
	p, reg, f := setup(t, map[string]any{
		"limits": map[string]any{"max-connections": "amqp_connections", "max-queues": "amqp_queues"},
	})
	ctx := context.Background()
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"amqp_connections": 10, "amqp_queues": 50}})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if l := f.vhosts["tenant-acme"].Limits; l["max-connections"] != 10 || l["max-queues"] != 50 {
		t.Fatalf("limits %v", l)
	}
	// Negative tenant override = unlimited; zero is a real limit.
	ten, _ = reg.HostImpl.SetTenantPlan(ctx, ten.ID, "pro")
	ten.Limits = map[string]int64{"amqp_connections": -1, "amqp_queues": 0}
	reg.HostImpl.AddTenant(ten)
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	l := f.vhosts["tenant-acme"].Limits
	if _, ok := l["max-connections"]; ok || l["max-queues"] != 0 {
		t.Fatalf("limits %v", l)
	}
	if _, ok := l["max-queues"]; !ok {
		t.Fatalf("zero limit not applied: %v", l)
	}
}

func TestDeprovisionModes(t *testing.T) {
	ctx := context.Background()

	t.Run("delete", func(t *testing.T) {
		p, reg, f := setup(t, nil)
		ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
		// Never provisioned: no error.
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := p.Deprovision(ctx, ten); err != nil {
				t.Fatal(err)
			}
		}
		if len(f.vhosts) != 0 || len(f.users) != 0 || len(f.perms) != 0 {
			t.Fatalf("left over: %v %v %v", f.vhosts, f.users, f.perms)
		}
	})

	t.Run("keep", func(t *testing.T) {
		p, reg, f := setup(t, map[string]any{"on_deprovision": "keep"})
		ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatal(err)
		}
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
		if f.vhosts["tenant-acme"] == nil || f.users["tenant-acme"] == nil {
			t.Fatal("keep removed resources")
		}
	})

	t.Run("retain", func(t *testing.T) {
		p, reg, f := setup(t, map[string]any{"on_deprovision": "retain", "default_queue_type": "quorum"})
		ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatal(err)
		}
		f.vhosts["tenant-acme"].Tags = append(f.vhosts["tenant-acme"].Tags, "team-a")
		for range 2 {
			if err := p.Deprovision(ctx, ten); err != nil {
				t.Fatal(err)
			}
		}
		v := f.vhosts["tenant-acme"]
		want := []string{"team-a", TagRetainedTenantID + ten.ID, TagDeletedAt + "2026-01-02T03:04:05Z"}
		if v == nil || !slices.Equal(v.Tags, want) || v.DefaultQueueType != "quorum" {
			t.Fatalf("vhost %+v", v)
		}
		if f.users["tenant-acme"] != nil {
			t.Fatal("user not deleted")
		}
		// A new tenant with the same slug cannot adopt the retained vhost.
		again := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme-2"})
		again.Slug = "acme"
		if err := p.Provision(ctx, again); err == nil || !strings.Contains(err.Error(), "retained data") {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("foreign resources untouched", func(t *testing.T) {
		p, reg, f := setup(t, nil)
		ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
		f.vhosts["tenant-acme"] = &fakeVhost{Tags: []string{TagTenantID + "other"}, Limits: map[string]int64{}}
		f.users["tenant-acme"] = &fakeUser{Password: "x"}
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
		if f.vhosts["tenant-acme"] == nil || f.users["tenant-acme"] == nil {
			t.Fatal("foreign resources deleted")
		}
	})
}

func TestRoutes(t *testing.T) {
	p, reg, _ := setup(t, map[string]any{"amqp_url": "amqps://rabbit.example.com:5671"})
	_ = p
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other"})

	call := func(path string, pr *sdk.Principal) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if pr != nil {
			req = req.WithContext(sdk.WithPrincipal(req.Context(), pr))
		}
		rec := httptest.NewRecorder()
		reg.Mux.ServeHTTP(rec, req)
		return rec
	}
	admin := &sdk.Principal{Subject: "admin", Kind: "user"}
	member := &sdk.Principal{Subject: "m", Kind: "user", TenantID: ten.ID}

	rec := call("/tenants/acme", member)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	var info TenantInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info != (TenantInfo{Vhost: "tenant-acme", Username: "tenant-acme", AMQPURL: "amqps://rabbit.example.com:5671/tenant-acme"}) {
		t.Fatalf("info %+v", info)
	}
	if strings.Contains(rec.Body.String(), TenantPassword(testSecret, ten.ID)) {
		t.Fatal("password leaked")
	}
	for _, path := range []string{"/tenants/other", "/tenants/other/credentials", "/tenants/missing", "/tenants/missing/credentials"} {
		if rec := call(path, member); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", path, rec.Code)
		}
	}
	if rec := call("/tenants/acme", nil); rec.Code != http.StatusNotFound {
		t.Errorf("anonymous: status %d", rec.Code)
	}

	// Credentials need tenants:update.
	reg.HostImpl.AuthorizeFunc = func(_ context.Context, pr *sdk.Principal, a sdk.Action, res sdk.Resource) error {
		if pr.TenantID != "" && pr.TenantID != res.TenantID {
			return sdk.ErrForbidden
		}
		if a == sdk.ActionTenantsUpdate && pr.Subject != "admin" {
			return sdk.ErrForbidden
		}
		return nil
	}
	if rec := call("/tenants/acme/credentials", member); rec.Code != http.StatusForbidden {
		t.Fatalf("member credentials: status %d", rec.Code)
	}
	rec = call("/tenants/"+other.ID+"/credentials", admin)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d headers %v", rec.Code, rec.Header())
	}
	var cr Credentials
	if err := json.Unmarshal(rec.Body.Bytes(), &cr); err != nil {
		t.Fatal(err)
	}
	pw := TenantPassword(testSecret, other.ID)
	if cr.Vhost != "tenant-other" || cr.Username != "tenant-other" || cr.Password != pw ||
		cr.URI != "amqps://tenant-other:"+pw+"@rabbit.example.com:5671/tenant-other" {
		t.Fatalf("credentials %+v", cr)
	}
}
