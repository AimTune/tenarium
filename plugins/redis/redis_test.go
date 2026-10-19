package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestConfigValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg     map[string]any
		wantErr string
	}{
		"missing addr":   {map[string]any{"cache": map[string]any{}}, "addr is required"},
		"bad addr":       {map[string]any{"addr": "localhost", "cache": map[string]any{}}, "host:port"},
		"no feature":     {map[string]any{"addr": "localhost:6379"}, "at least one"},
		"bad mode":       {map[string]any{"addr": "localhost:6379", "publish": map[string]any{"mode": "queue"}}, "publish.mode"},
		"bad ttl":        {map[string]any{"addr": "localhost:6379", "cache": map[string]any{"ttl": "soon"}}, "cache.ttl"},
		"no secret":      {map[string]any{"addr": "localhost:6379", "acl": map[string]any{}}, "password_secret"},
		"unknown field":  {map[string]any{"addr": "localhost:6379", "cache": map[string]any{}, "bogus": 1}, "unknown field"},
		"bad template":   {aclCfg(map[string]any{"key_pattern": "t:{{.Slug"}), "acl.key_pattern"},
		"missing field":  {aclCfg(map[string]any{"username_template": "u-{{.Nope}}"}), "acl.username_template"},
		"space in user":  {aclCfg(map[string]any{"username_template": "tenant {{.Slug}}"}), "invalid user name"},
		"shared user":    {aclCfg(map[string]any{"username_template": "app"}), "must depend on the tenant"},
		"shared pattern": {aclCfg(map[string]any{"key_pattern": "app:*"}), "must depend on the tenant"},
		"bad commands":   {aclCfg(map[string]any{"commands": "+@all nopass"}), "acl.commands"},
		"ok": {map[string]any{
			"addr": "localhost:6379", "publish": map[string]any{}, "cache": map[string]any{"ttl": "1h"},
			"acl": map[string]any{"password_secret": "s"},
		}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			p := &Plugin{}
			err := p.Init(context.Background(), sdktest.NewRegistrar(tc.cfg))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				_ = p.Stop(context.Background())
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func aclCfg(acl map[string]any) map[string]any {
	acl["password_secret"] = "secret"
	return map[string]any{"addr": "localhost:6379", "acl": acl}
}

func TestDefaults(t *testing.T) {
	p := &Plugin{}
	reg := sdktest.NewRegistrar(map[string]any{
		"addr": "localhost:6379", "publish": map[string]any{}, "cache": map[string]any{},
		"acl": map[string]any{"password_secret": "s"},
	})
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(context.Background()) }()
	c := p.cfg
	if c.KeyPrefix != "tenarium:" || c.Publish.Mode != ModeStream || c.Publish.Stream != "events" ||
		c.Publish.Channel != "events" || c.Publish.MaxLen != 100000 || p.ttl != 0 {
		t.Fatalf("defaults not applied: %+v %+v", c, c.Publish)
	}
	if len(reg.Subscriptions) != 2 || len(reg.Provisioners) != 1 || len(reg.Routes) != 2 {
		t.Fatalf("registrations: %d subs, %d provisioners, %v", len(reg.Subscriptions), len(reg.Provisioners), reg.Routes)
	}
	tg, err := p.acl.target(sdk.Tenant{ID: "id-1", Slug: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if tg.User != "tenant-acme" || tg.Keys[0] != "t:acme:*" || tg.Channels[0] != "t:acme:*" {
		t.Fatalf("target = %+v", tg)
	}
}

func TestConfigSchema(t *testing.T) {
	s, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{
		"addr": "localhost:6379", "key_prefix": "app:",
		"publish": map[string]any{"mode": "stream", "stream": "events", "events": []string{"tenant.*"}, "max_len": 1000, "per_tenant": true},
		"cache":   map[string]any{"ttl": "0"},
		"acl":     map[string]any{"password_secret": "x", "channels": "", "purge_keys_on_delete": true},
	}
	if err := s.Validate(ok); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"no feature":    {"addr": "localhost:6379"},
		"no addr":       {"cache": map[string]any{}},
		"unknown field": {"addr": "a:1", "cache": map[string]any{"ttl": "0", "extra": true}},
		"bad mode":      {"addr": "a:1", "publish": map[string]any{"mode": "list"}},
		"acl no secret": {"addr": "a:1", "acl": map[string]any{}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

func TestTenantPassword(t *testing.T) {
	a := TenantPassword("secret", "tenant-1")
	if len(a) != 32 || a != TenantPassword("secret", "tenant-1") {
		t.Fatalf("not deterministic or wrong length: %q", a)
	}
	if a == TenantPassword("secret", "tenant-2") || a == TenantPassword("other", "tenant-1") {
		t.Fatal("password does not depend on secret and tenant")
	}
	// HMAC-SHA256("secret", "tenant-1"), first 32 hex characters.
	if want := "06433c7e8c2697bf8bf073fc9d0bd6ce"; a != want {
		t.Fatalf("TenantPassword = %s, want %s", a, want)
	}
}

// --- integration tests (TENARIUM_TEST_REDIS_ADDR) ---

type env struct {
	addr   string
	prefix string
	admin  *redis.Client
	reg    *sdktest.Registrar
	p      *Plugin
}

// setup starts the plugin against the test Redis with a unique key prefix.
func setup(t *testing.T, cfg map[string]any) *env {
	t.Helper()
	addr := os.Getenv("TENARIUM_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TENARIUM_TEST_REDIS_ADDR not set")
	}
	ctx := context.Background()
	e := &env{addr: addr, prefix: fmt.Sprintf("tenarium-test:%s:%s:", t.Name(), uuid.NewString()[:8])}
	e.admin = redis.NewClient(&redis.Options{Addr: addr})
	if err := e.admin.Ping(ctx).Err(); err != nil {
		t.Fatalf("redis: %v", err)
	}
	cfg["addr"] = addr
	cfg["key_prefix"] = e.prefix
	e.reg = sdktest.NewRegistrar(cfg)
	e.p = &Plugin{}
	if err := e.p.Init(ctx, e.reg); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.purge(t, e.prefix+"*")
		_ = e.p.Stop(ctx)
		_ = e.admin.Close()
	})
	return e
}

func (e *env) purge(t *testing.T, pattern string) {
	ctx := context.Background()
	iter := e.admin.Scan(ctx, 0, pattern, 500).Iterator()
	for iter.Next(ctx) {
		e.admin.Unlink(ctx, iter.Val())
	}
	if err := iter.Err(); err != nil {
		t.Error(err)
	}
}

func TestStreamPublish(t *testing.T) {
	e := setup(t, map[string]any{"publish": map[string]any{"events": []string{"tenant.*"}, "max_len": 10}})
	ctx := context.Background()
	tn := sdk.Tenant{ID: "t1", Slug: "acme", Status: sdk.StatusActive}
	ev := sdktest.TenantEvent(sdk.EventTenantCreated, tn)
	ev.Seq = 42
	if err := e.reg.Deliver(ctx, "publish", ev); err != nil {
		t.Fatal(err)
	}
	// Filtered out.
	if err := e.reg.Deliver(ctx, "publish", sdk.Event{ID: "x", Type: sdk.EventPlanCreated}); err != nil {
		t.Fatal(err)
	}
	msgs, err := e.admin.XRange(ctx, e.prefix+"events", "-", "+").Result()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d entries", len(msgs))
	}
	v := msgs[0].Values
	if v["type"] != sdk.EventTenantCreated || v["id"] != ev.ID || v["tenant"] != "t1" || v["seq"] != "42" {
		t.Fatalf("fields = %v", v)
	}
	var ce sdk.CloudEvent
	if err := json.Unmarshal([]byte(v["event"].(string)), &ce); err != nil {
		t.Fatal(err)
	}
	if ce.SpecVersion != "1.0" || ce.ID != ev.ID || ce.Sequence != "42" || ce.TenantID != "t1" {
		t.Fatalf("cloudevent = %+v", ce)
	}

	// MAXLEN ~ trims in whole macro nodes, so the length stays near the cap.
	for range 500 {
		if err := e.reg.Deliver(ctx, "publish", sdktest.TenantEvent(sdk.EventTenantUpdated, tn)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := e.admin.XLen(ctx, e.prefix+"events").Result()
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 || n >= 250 {
		t.Fatalf("stream length %d not trimmed approximately to 10", n)
	}
}

func TestStreamPerTenant(t *testing.T) {
	e := setup(t, map[string]any{"publish": map[string]any{"stream": "ev", "per_tenant": true}})
	ctx := context.Background()
	for _, id := range []string{"a", "b", "a"} {
		if err := e.reg.Deliver(ctx, "publish", sdktest.TenantEvent(sdk.EventTenantUpdated, sdk.Tenant{ID: id})); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.reg.Deliver(ctx, "publish", sdk.Event{ID: "p", Type: sdk.EventPlanCreated}); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]int64{"ev:a": 2, "ev:b": 1, "ev": 1} {
		if n := e.admin.XLen(ctx, e.prefix+key).Val(); n != want {
			t.Errorf("XLEN %s = %d, want %d", key, n, want)
		}
	}
}

func TestPubSubPublish(t *testing.T) {
	e := setup(t, map[string]any{"publish": map[string]any{"mode": "pubsub", "channel": "ch"}})
	ctx := context.Background()
	sub := e.admin.Subscribe(ctx, e.prefix+"ch")
	defer sub.Close()
	if _, err := sub.Receive(ctx); err != nil { // subscription confirmation
		t.Fatal(err)
	}
	ev := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t1"})
	if err := e.reg.Deliver(ctx, "publish", ev); err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	msg, err := sub.ReceiveMessage(rctx)
	if err != nil {
		t.Fatal(err)
	}
	var ce sdk.CloudEvent
	if err := json.Unmarshal([]byte(msg.Payload), &ce); err != nil || ce.ID != ev.ID || ce.Type != ev.Type {
		t.Fatalf("payload %s: %v", msg.Payload, err)
	}
}

func get(t *testing.T, reg *sdktest.Registrar, method, path string, p *sdk.Principal) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	return rec
}

func TestCache(t *testing.T) {
	e := setup(t, map[string]any{"cache": map[string]any{}})
	ctx := context.Background()
	h := e.reg.HostImpl
	h.AddPlan(sdk.Plan{ID: "pro", Features: map[string]bool{"sso": true}, Limits: map[string]int64{"seats": 10}})
	h.AddPlan(sdk.Plan{ID: "free", Limits: map[string]int64{"seats": 1}})
	acme := h.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro", Version: 2,
		Labels: map[string]string{"region": "eu"}, Limits: map[string]int64{"seats": 20}})
	other := h.AddTenant(sdk.Tenant{Slug: "other", Name: "Other", Plan: "free", Version: 1})

	if err := e.reg.Deliver(ctx, "cache", sdktest.TenantEvent(sdk.EventTenantCreated, acme)); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{acme.ID, "acme"} {
		ct, err := ReadTenant(ctx, e.admin, e.prefix, key)
		if err != nil {
			t.Fatal(err)
		}
		if ct.ID != acme.ID || ct.Name != "Acme" || ct.Status != sdk.StatusActive || ct.Plan != "pro" ||
			ct.Version != 2 || ct.Labels["region"] != "eu" || !ct.HasFeature("sso") {
			t.Fatalf("cached = %+v", ct)
		}
		if seats, _ := ct.Limit("seats"); seats != 20 {
			t.Fatalf("seats = %d, want tenant override 20", seats)
		}
	}
	if _, err := ReadTenant(ctx, e.admin, e.prefix, other.ID); !errors.Is(err, ErrNotCached) {
		t.Fatalf("uncached tenant: %v", err)
	}

	// An older event does not overwrite the newer state.
	old := acme
	old.Name, old.Version = "Acme Old", 1
	if err := e.reg.Deliver(ctx, "cache", sdktest.TenantEvent(sdk.EventTenantUpdated, old)); err != nil {
		t.Fatal(err)
	}
	if ct, _ := ReadTenant(ctx, e.admin, e.prefix, acme.ID); ct.Name != "Acme" || ct.Version != 2 {
		t.Fatalf("older event overwrote cache: %+v", ct)
	}

	// Routes.
	platform := &sdk.Principal{Subject: "admin"}
	rec := get(t, e.reg, "GET", "/tenants/acme", platform)
	if rec.Code != http.StatusOK {
		t.Fatalf("platform GET = %d %s", rec.Code, rec.Body)
	}
	var ct CachedTenant
	if err := json.Unmarshal(rec.Body.Bytes(), &ct); err != nil || ct.ID != acme.ID {
		t.Fatalf("body %s: %v", rec.Body, err)
	}
	if rec := get(t, e.reg, "GET", "/tenants/acme", &sdk.Principal{Subject: "u", TenantID: other.ID}); rec.Code != http.StatusNotFound {
		t.Fatalf("other tenant GET = %d", rec.Code)
	}
	if rec := get(t, e.reg, "GET", "/tenants/"+acme.ID, &sdk.Principal{Subject: "u", TenantID: acme.ID}); rec.Code != http.StatusOK {
		t.Fatalf("own tenant GET = %d", rec.Code)
	}
	if rec := get(t, e.reg, "GET", "/tenants/other", platform); rec.Code != http.StatusNotFound {
		t.Fatalf("uncached GET = %d", rec.Code)
	}

	// Resync caches every tenant; tenant-scoped callers may not trigger it.
	if rec := get(t, e.reg, "POST", "/resync", &sdk.Principal{Subject: "u", TenantID: acme.ID}); rec.Code != http.StatusForbidden {
		t.Fatalf("tenant resync = %d", rec.Code)
	}
	rec = get(t, e.reg, "POST", "/resync", platform)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"tenants":2}` {
		t.Fatalf("resync = %d %s", rec.Code, rec.Body)
	}
	if ct, err := ReadTenant(ctx, e.admin, e.prefix, "other"); err != nil || ct.Plan != "free" {
		t.Fatalf("after resync: %+v %v", ct, err)
	}

	// A plan change re-caches the tenants on that plan only.
	pro := sdk.Plan{ID: "pro", Features: map[string]bool{"sso": true, "audit": true}, Limits: map[string]int64{"seats": 50}, Version: 2}
	h.AddPlan(pro)
	h.AddPlan(sdk.Plan{ID: "free", Features: map[string]bool{"audit": true}})
	data, _ := json.Marshal(sdk.PlanEventData{Plan: pro})
	if err := e.reg.Deliver(ctx, "cache", sdk.Event{ID: "pe", Type: sdk.EventPlanUpdated, Data: data}); err != nil {
		t.Fatal(err)
	}
	if ct, _ := ReadTenant(ctx, e.admin, e.prefix, acme.ID); !ct.HasFeature("audit") {
		t.Fatalf("plan update not applied: %+v", ct)
	}
	if ct, _ := ReadTenant(ctx, e.admin, e.prefix, other.ID); ct.HasFeature("audit") {
		t.Fatalf("tenant on another plan re-cached: %+v", ct)
	}

	// A slug change drops the old slug key.
	renamed := acme
	renamed.Slug, renamed.Version = "acme-inc", 3
	h.AddTenant(renamed)
	if err := e.reg.Deliver(ctx, "cache", sdktest.TenantEvent(sdk.EventTenantUpdated, renamed)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTenant(ctx, e.admin, e.prefix, "acme"); !errors.Is(err, ErrNotCached) {
		t.Fatalf("old slug still cached: %v", err)
	}
	if ct, err := ReadTenant(ctx, e.admin, e.prefix, "acme-inc"); err != nil || ct.Version != 3 {
		t.Fatalf("new slug: %+v %v", ct, err)
	}

	// Member events also match tenant.* and are ignored.
	if err := e.reg.Deliver(ctx, "cache", sdktest.MemberEvent(sdk.EventMemberAdded, sdk.Member{ID: "m", TenantID: acme.ID})); err != nil {
		t.Fatal(err)
	}

	// tenant.deleted removes both keys.
	deleted := renamed
	deleted.Status, deleted.Version = sdk.StatusDeleted, 4
	if err := e.reg.Deliver(ctx, "cache", sdktest.TenantEvent(sdk.EventTenantDeleted, deleted)); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{tenantKey(e.prefix, acme.ID), slugKey(e.prefix, "acme-inc")} {
		if n := e.admin.Exists(ctx, k).Val(); n != 0 {
			t.Fatalf("%s still exists", k)
		}
	}
}

func TestCacheTTL(t *testing.T) {
	e := setup(t, map[string]any{"cache": map[string]any{"ttl": "1h"}})
	ctx := context.Background()
	tn := e.reg.HostImpl.AddTenant(sdk.Tenant{Slug: "ttl", Version: 1})
	if err := e.reg.Deliver(ctx, "cache", sdktest.TenantEvent(sdk.EventTenantCreated, tn)); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{tenantKey(e.prefix, tn.ID), slugKey(e.prefix, "ttl")} {
		if ttl := e.admin.TTL(ctx, k).Val(); ttl <= 0 || ttl > time.Hour {
			t.Fatalf("TTL %s = %v", k, ttl)
		}
	}
}

// aclEnv sets up an ACL test with a unique slug and removes the users it
// creates.
func aclEnv(t *testing.T, purge bool) (*env, sdk.Provisioner, string) {
	t.Helper()
	e := setup(t, map[string]any{"acl": map[string]any{
		"password_secret": "test-secret", "purge_keys_on_delete": purge,
	}})
	if len(e.reg.Provisioners) != 1 || e.reg.Provisioners[0].Name() != "acl" {
		t.Fatalf("provisioners = %v", e.reg.Provisioners)
	}
	slug := "s" + uuid.NewString()[:8]
	t.Cleanup(func() {
		e.admin.ACLDelUser(context.Background(), "tenant-"+slug)
		e.purge(t, "t:"+slug+":*")
	})
	return e, e.reg.Provisioners[0], slug
}

func TestACLProvision(t *testing.T) {
	e, prov, slug := aclEnv(t, false)
	ctx := context.Background()
	tn := sdk.Tenant{ID: uuid.NewString(), Slug: slug}
	for range 2 { // idempotent
		if err := prov.Provision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	if owner := e.admin.Get(ctx, e.prefix+"acl-owner:tenant-"+slug).Val(); owner != tn.ID {
		t.Fatalf("owner marker = %q", owner)
	}

	tc := redis.NewClient(&redis.Options{Addr: e.addr, Username: "tenant-" + slug, Password: TenantPassword("test-secret", tn.ID)})
	defer tc.Close()
	if err := tc.Set(ctx, "t:"+slug+":k", "v", 0).Err(); err != nil {
		t.Fatalf("SET inside pattern: %v", err)
	}
	if err := tc.Set(ctx, "outside:"+slug, "v", 0).Err(); err == nil || !strings.Contains(err.Error(), "NOPERM") {
		t.Fatalf("SET outside pattern: %v", err)
	}
	if err := tc.Do(ctx, "CONFIG", "GET", "maxmemory").Err(); err == nil {
		t.Fatal("admin command allowed")
	}
	bad := redis.NewClient(&redis.Options{Addr: e.addr, Username: "tenant-" + slug, Password: "wrong", MaxRetries: -1})
	defer bad.Close()
	if err := bad.Ping(ctx).Err(); err == nil {
		t.Fatal("wrong password accepted")
	}

	// Deprovision without purge keeps the keys.
	if err := prov.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if n := e.admin.Exists(ctx, "t:"+slug+":k").Val(); n != 1 {
		t.Fatal("key removed without purge_keys_on_delete")
	}
	if err := e.admin.Do(ctx, "ACL", "GETUSER", "tenant-"+slug).Err(); !errors.Is(err, redis.Nil) {
		t.Fatalf("user still exists: %v", err)
	}
}

func TestACLOwnership(t *testing.T) {
	e, prov, slug := aclEnv(t, true)
	ctx := context.Background()
	a := sdk.Tenant{ID: uuid.NewString(), Slug: slug}
	b := sdk.Tenant{ID: uuid.NewString(), Slug: slug} // slug reused: same user name
	if err := prov.Provision(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := prov.Provision(ctx, b); err == nil || !strings.Contains(err.Error(), "belongs to tenant "+a.ID) {
		t.Fatalf("conflicting provision: %v", err)
	}
	e.admin.Set(ctx, "t:"+slug+":keep", "v", 0)
	if err := prov.Deprovision(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := e.admin.Do(ctx, "ACL", "GETUSER", "tenant-"+slug).Err(); err != nil {
		t.Fatalf("other tenant's deprovision removed the user: %v", err)
	}
	if e.admin.Exists(ctx, "t:"+slug+":keep").Val() != 1 {
		t.Fatal("other tenant's deprovision purged keys")
	}

	// Users not created by the plugin are never adopted.
	foreign := "s" + uuid.NewString()[:8]
	if err := e.admin.ACLSetUser(ctx, "tenant-"+foreign, "on", "nopass").Err(); err != nil {
		t.Fatal(err)
	}
	defer e.admin.ACLDelUser(ctx, "tenant-"+foreign)
	if err := prov.Provision(ctx, sdk.Tenant{ID: uuid.NewString(), Slug: foreign}); err == nil || !strings.Contains(err.Error(), "not managed") {
		t.Fatalf("foreign user adopted: %v", err)
	}
}

func TestACLDeprovisionPurge(t *testing.T) {
	e, prov, slug := aclEnv(t, true)
	ctx := context.Background()
	tn := sdk.Tenant{ID: uuid.NewString(), Slug: slug}
	if err := prov.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	for i := range 1200 {
		e.admin.Set(ctx, fmt.Sprintf("t:%s:%d", slug, i), "v", 0)
	}
	e.admin.Set(ctx, "t:"+slug+"x:survivor", "v", 0)
	defer e.admin.Del(ctx, "t:"+slug+"x:survivor")

	for range 2 { // idempotent
		if err := prov.Deprovision(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	if keys := e.admin.Keys(ctx, "t:"+slug+":*").Val(); len(keys) != 0 {
		t.Fatalf("%d keys left after purge", len(keys))
	}
	if e.admin.Exists(ctx, "t:"+slug+"x:survivor").Val() != 1 {
		t.Fatal("purge removed a key outside the pattern")
	}
	if e.admin.Exists(ctx, e.prefix+"acl-owner:tenant-"+slug).Val() != 0 {
		t.Fatal("owner marker not removed")
	}
	if err := e.admin.Do(ctx, "ACL", "GETUSER", "tenant-"+slug).Err(); !errors.Is(err, redis.Nil) {
		t.Fatalf("user still exists: %v", err)
	}
}
