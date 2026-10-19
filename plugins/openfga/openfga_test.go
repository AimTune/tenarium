package openfga

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// fakeFGA is a tiny OpenFGA: a tuple set plus one-level "parent" inheritance
// through contextual or stored tuples.
type fakeFGA struct {
	mu       sync.Mutex
	tuples   map[tupleKey]bool
	checks   []checkRequest
	writes   int
	fail     bool
	slow     time.Duration
	lastAuth string
}

func newFake() *fakeFGA { return &fakeFGA{tuples: map[tupleKey]bool{}} }

func (f *fakeFGA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAuth = r.Header.Get("Authorization")
	if f.slow > 0 {
		f.mu.Unlock()
		select { // stop early when the client gives up
		case <-time.After(f.slow):
		case <-r.Context().Done():
		}
		f.mu.Lock()
	}
	if f.fail {
		http.Error(w, `{"code":"internal_error","message":"boom"}`, http.StatusInternalServerError)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/stores/s1":
		_, _ = w.Write([]byte(`{"id":"s1"}`))
	case r.URL.Path == "/stores/s1/check":
		var req checkRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.checks = append(f.checks, req)
		all := map[tupleKey]bool{}
		for k := range f.tuples {
			all[k] = true
		}
		if req.ContextualTuples != nil {
			for _, k := range req.ContextualTuples.TupleKeys {
				all[k] = true
			}
		}
		allowed := all[req.TupleKey]
		// admin on any ancestor grants can_* on descendants.
		if !allowed && strings.HasPrefix(req.TupleKey.Relation, "can_") {
			obj := req.TupleKey.Object
			for range 10 {
				if all[tupleKey{User: req.TupleKey.User, Relation: "admin", Object: obj}] {
					allowed = true
					break
				}
				next := ""
				for k := range all {
					if k.Relation == "parent" && k.Object == obj {
						next = k.User
					}
				}
				if next == "" {
					break
				}
				obj = next
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": allowed})
	case r.URL.Path == "/stores/s1/write":
		var req writeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.writes++
		if req.Writes != nil {
			for _, k := range req.Writes.TupleKeys {
				if f.tuples[k] {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"code":"write_failed_due_to_invalid_input","message":"cannot write a tuple which already exists: user: 'x'"}`))
					return
				}
				f.tuples[k] = true
			}
		}
		if req.Deletes != nil {
			for _, k := range req.Deletes.TupleKeys {
				if !f.tuples[k] {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"code":"write_failed_due_to_invalid_input","message":"cannot delete a tuple which does not exist: user: 'x'"}`))
					return
				}
				delete(f.tuples, k)
			}
		}
		_, _ = w.Write([]byte(`{}`))
	default:
		http.NotFound(w, r)
	}
}

func setup(t *testing.T, cfg map[string]any) (*Plugin, *fakeFGA, *sdktest.Registrar) {
	t.Helper()
	f := newFake()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	if cfg == nil {
		cfg = map[string]any{}
	}
	cfg["url"] = srv.URL
	cfg["store_id"] = "s1"
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	validate(t, p, cfg)
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	return p, f, reg
}

func validate(t *testing.T, p *Plugin, cfg map[string]any) {
	t.Helper()
	sch, err := schema.Compile(p.Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	var v any
	_ = json.Unmarshal(raw, &v)
	if err := sch.Validate(v); err != nil {
		t.Fatalf("schema: %v", err)
	}
}

var (
	ann    = &sdk.Principal{Subject: "ann", Kind: "user", Authenticator: "oidc"}
	tenant = sdk.Resource{Type: "tenant", ID: "t1", TenantID: "t1"}
)

func TestCheckMapping(t *testing.T) {
	p, f, _ := setup(t, map[string]any{
		"relations":      map[string]any{"members:write": "can_manage_members", "events:read": ""},
		"objects":        map[string]any{"member": "tenant:{resource.tenant_id}"},
		"global_object":  "platform:default",
		"api_token":      "secret",
		"consistency":    "higher_consistency",
		"cache_ttl":      "0s",
		"on_not_allowed": "deny",
	})
	ctx := context.Background()
	f.tuples[tupleKey{"user:ann", "can_update", "tenant:t1"}] = true
	f.tuples[tupleKey{"user:ann", "can_manage_members", "tenant:t1"}] = true
	f.tuples[tupleKey{"user:ann", "can_read", "platform:default"}] = true

	cases := []struct {
		action sdk.Action
		res    sdk.Resource
		want   sdk.Decision
	}{
		{sdk.ActionTenantsUpdate, tenant, sdk.Allow},
		{sdk.ActionTenantsDelete, tenant, sdk.Deny},
		{sdk.ActionMembersWrite, sdk.Resource{Type: "member", TenantID: "t1"}, sdk.Allow},
		{sdk.ActionPlansRead, sdk.Resource{Type: "plan"}, sdk.Allow},                      // global object
		{sdk.ActionEventsRead, sdk.Resource{Type: "event"}, sdk.Abstain},                  // unmapped action
		{sdk.ActionTenantsCreate, sdk.Resource{Type: "tenant", TenantID: "t1"}, sdk.Deny}, // create under t1
	}
	for _, c := range cases {
		got, err := p.Authorize(ctx, ann, c.action, c.res)
		if err != nil || got != c.want {
			t.Errorf("%s %+v: got %v %v, want %v", c.action, c.res, got, err, c.want)
		}
	}
	last := f.checks[len(f.checks)-1]
	if last.TupleKey != (tupleKey{"user:ann", "can_create", "tenant:t1"}) || last.Consistency != "HIGHER_CONSISTENCY" {
		t.Errorf("last check %+v", last)
	}
	if f.lastAuth != "Bearer secret" {
		t.Errorf("auth header %q", f.lastAuth)
	}
	r := p.Check(ctx, ann, sdk.ActionTenantsDelete, tenant)
	if !strings.Contains(r.Reason, "user:ann can_delete tenant:t1") {
		t.Errorf("reason %q", r.Reason)
	}
}

func TestAbstainsByDefault(t *testing.T) {
	p, _, _ := setup(t, nil)
	got, err := p.Authorize(context.Background(), ann, sdk.ActionTenantsDelete, tenant)
	if err != nil || got != sdk.Abstain {
		t.Fatalf("got %v %v", got, err)
	}
	// No global object: listing plans cannot be expressed.
	r := p.Check(context.Background(), ann, sdk.ActionPlansRead, sdk.Resource{Type: "plan"})
	if r.Decision != sdk.Abstain || !strings.Contains(r.Reason, "resource.id_or_tenant") {
		t.Fatalf("got %+v", r)
	}
}

func TestFailMode(t *testing.T) {
	p, f, _ := setup(t, nil)
	f.fail = true
	ctx := context.Background()
	if got, err := p.Authorize(ctx, ann, sdk.ActionTenantsRead, tenant); err != nil || got != sdk.Abstain {
		t.Fatalf("abstain mode: %v %v", got, err)
	}
	p.denyOnError = true
	r := p.Check(ctx, ann, sdk.ActionTenantsRead, tenant)
	if r.Decision != sdk.Deny || !strings.Contains(r.Reason, "fail_mode deny") {
		t.Fatalf("deny mode: %+v", r)
	}
	if err := p.Health(ctx); err == nil {
		t.Error("health should fail")
	}
}

func TestTimeout(t *testing.T) {
	p, f, _ := setup(t, map[string]any{"timeout": "50ms"})
	f.slow = 2 * time.Second // far beyond the timeout, so the bound below holds under load
	start := time.Now()
	r := p.Check(context.Background(), ann, sdk.ActionTenantsRead, tenant)
	if r.Decision != sdk.Abstain || time.Since(start) > time.Second {
		t.Fatalf("got %+v after %v", r, time.Since(start))
	}
}

func TestCache(t *testing.T) {
	p, f, _ := setup(t, map[string]any{"cache_ttl": "1m"})
	f.tuples[tupleKey{"user:ann", "can_read", "tenant:t1"}] = true
	ctx := context.Background()
	for range 3 {
		if got, _ := p.Authorize(ctx, ann, sdk.ActionTenantsRead, tenant); got != sdk.Allow {
			t.Fatal(got)
		}
	}
	if len(f.checks) != 1 {
		t.Fatalf("checks = %d, want 1", len(f.checks))
	}
	now := time.Now()
	p.cache.now = func() time.Time { return now.Add(2 * time.Minute) }
	_, _ = p.Authorize(ctx, ann, sdk.ActionTenantsRead, tenant)
	if len(f.checks) != 2 {
		t.Fatalf("expired entry not refreshed: %d", len(f.checks))
	}
	// Errors are not cached.
	f.fail = true
	p.cache.purge()
	_, _ = p.Authorize(ctx, ann, sdk.ActionTenantsRead, tenant)
	f.fail = false
	if got, _ := p.Authorize(ctx, ann, sdk.ActionTenantsRead, tenant); got != sdk.Allow {
		t.Fatal("error was cached")
	}
}

func TestContextualTuples(t *testing.T) {
	p, f, reg := setup(t, map[string]any{
		"contextual_parents":        true,
		"principal_tenant_relation": "member",
		"cache_ttl":                 "0s",
	})
	org := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "org"})
	ws := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "ws", ParentID: org.ID})
	f.tuples[tupleKey{"user:ann", "admin", "tenant:" + org.ID}] = true
	ctx := context.Background()
	scoped := &sdk.Principal{Subject: "ann", Kind: "user", TenantID: org.ID}
	got, _ := p.Authorize(ctx, scoped, sdk.ActionTenantsUpdate, sdk.Resource{Type: "tenant", ID: ws.ID, TenantID: ws.ID})
	if got != sdk.Allow {
		t.Fatalf("hierarchy via contextual tuples: %v", got)
	}
	ct := f.checks[0].ContextualTuples.TupleKeys
	want := []tupleKey{
		{"user:ann", "member", "tenant:" + org.ID},
		{"tenant:" + org.ID, "parent", "tenant:" + ws.ID},
	}
	if len(ct) != 2 || ct[0] != want[0] || ct[1] != want[1] {
		t.Fatalf("contextual tuples %+v", ct)
	}
}

func TestSync(t *testing.T) {
	p, f, reg := setup(t, map[string]any{
		"sync": map[string]any{"tenant_parents": true, "members": true, "roles": map[string]any{"owner": "admin", "admin": "admin"}},
	})
	ctx := context.Background()
	org := sdk.Tenant{ID: "org", Slug: "org"}
	ws := sdk.Tenant{ID: "ws", Slug: "ws", ParentID: "org"}
	deliver := func(e sdk.Event) {
		t.Helper()
		if err := reg.Deliver(ctx, "tuples", e); err != nil {
			t.Fatal(err)
		}
	}
	deliver(sdktest.TenantEvent(sdk.EventTenantCreated, org))
	deliver(sdktest.TenantEvent(sdk.EventTenantCreated, ws))
	deliver(sdktest.TenantEvent(sdk.EventTenantCreated, ws)) // redelivery is idempotent
	parent := tupleKey{"tenant:org", "parent", "tenant:ws"}
	if !f.tuples[parent] || len(f.tuples) != 1 {
		t.Fatalf("tuples %v", f.tuples)
	}

	m := sdk.Member{ID: "m1", TenantID: "org", UserID: "u1", Role: "owner", Status: sdk.MemberActive}
	deliver(sdktest.MemberEvent(sdk.EventMemberAdded, m))
	adminT := tupleKey{"user:u1", "admin", "tenant:org"}
	if !f.tuples[adminT] {
		t.Fatalf("member tuple missing: %v", f.tuples)
	}
	// Now ann... u1 can update the child through the synced parent tuple.
	u1 := &sdk.Principal{Subject: "u1", Kind: "user"}
	if got, _ := p.Authorize(ctx, u1, sdk.ActionTenantsUpdate, sdk.Resource{Type: "tenant", ID: "ws", TenantID: "ws"}); got != sdk.Allow {
		t.Fatalf("synced hierarchy: %v", got)
	}

	// Role change to an unmapped role removes the tuple.
	prev := m
	m.Role = "viewer"
	data, _ := json.Marshal(sdk.MemberEventData{Member: m, Previous: &prev})
	ev := sdktest.MemberEvent(sdk.EventMemberUpdated, m)
	ev.Data = data
	deliver(ev)
	if f.tuples[adminT] {
		t.Fatal("old role tuple kept")
	}
	deliver(sdktest.MemberEvent(sdk.EventMemberRemoved, m)) // nothing to delete: tolerated
	// Invited members (no user yet) produce nothing.
	deliver(sdktest.MemberEvent(sdk.EventMemberAdded, sdk.Member{ID: "m2", TenantID: "org", Email: "x@y", Role: "admin", Status: sdk.MemberInvited}))
	deliver(sdktest.TenantEvent(sdk.EventTenantDeleted, ws))
	deliver(sdktest.TenantEvent(sdk.EventTenantDeleted, ws))
	if len(f.tuples) != 0 {
		t.Fatalf("tuples left: %v", f.tuples)
	}
	f.fail = true
	if err := reg.Deliver(ctx, "tuples", sdktest.TenantEvent(sdk.EventTenantCreated, ws)); err == nil {
		t.Fatal("server error must be retried")
	}
}

func TestInitValidation(t *testing.T) {
	bad := []map[string]any{
		{},
		{"url": "ftp://x", "store_id": "s"},
		{"url": "http://x", "store_id": "s", "user": "{principal.nope}"},
		{"url": "http://x", "store_id": "s", "object": "{resource.id"},
		{"url": "http://x", "store_id": "s", "object": "{resource.id}"},
		{"url": "http://x", "store_id": "s", "timeout": "-1s"},
		{"url": "http://x", "store_id": "s", "cache_ttl": "soon"},
		{"url": "http://x", "store_id": "s", "fail_mode": "allow"},
		{"url": "http://x", "store_id": "s", "global_object": "platform"},
		{"url": "http://x", "store_id": "s", "sync": map[string]any{"member_user": "{principal.subject}"}},
		{"url": "http://x", "store_id": "s", "unknown": 1},
	}
	for _, cfg := range bad {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("accepted %v", cfg)
		}
	}
	if _, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema); err != nil {
		t.Fatal(err)
	}
}

func TestRegistered(t *testing.T) {
	if _, ok := sdk.Lookup("openfga"); !ok {
		t.Fatal("not registered")
	}
}

func TestReconfigure(t *testing.T) {
	p, f, reg := setup(t, map[string]any{"api_token": "old", "cache_ttl": "1m", "sync": map[string]any{"members": true}})
	ctx := context.Background()
	f.tuples[tupleKey{"user:ann", "can_update", "tenant:t1"}] = true
	if got, _ := p.Authorize(ctx, ann, sdk.ActionTenantsUpdate, tenant); got != sdk.Allow {
		t.Fatalf("got %v", got)
	}
	cfg := func(extra map[string]any) func(any) error {
		m := map[string]any{"url": reg.ConfigData["url"], "store_id": "s1", "sync": map[string]any{"members": true}}
		for k, v := range extra {
			m[k] = v
		}
		return sdktest.NewRegistrar(m).Config
	}

	// New token and relations apply live; the cached allow is not reused.
	if err := p.Reconfigure(ctx, cfg(map[string]any{"api_token": "new", "relations": map[string]any{"tenants:update": "can_edit"}})); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.Authorize(ctx, ann, sdk.ActionTenantsUpdate, tenant); got != sdk.Abstain {
		t.Fatalf("after reconfigure: %v", got)
	}
	if last := f.checks[len(f.checks)-1]; last.TupleKey.Relation != "can_edit" || f.lastAuth != "Bearer new" {
		t.Fatalf("check %+v auth %q", last, f.lastAuth)
	}

	// An invalid config is rejected and the current settings stay.
	if err := p.Reconfigure(ctx, cfg(map[string]any{"api_token": "bad", "timeout": "fast"})); err == nil {
		t.Fatal("invalid timeout accepted")
	}
	if err := p.Health(ctx); err != nil || f.lastAuth != "Bearer new" {
		t.Fatalf("health %v auth %q", err, f.lastAuth)
	}

	// The synced event types are fixed at startup.
	err := p.Reconfigure(ctx, cfg(map[string]any{"sync": map[string]any{"members": true, "tenant_parents": true}}))
	if err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("sync change: %v", err)
	}
}
