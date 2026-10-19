package spicedb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

type checkReq struct {
	Consistency map[string]json.RawMessage `json:"consistency"`
	Resource    objectRef                  `json:"resource"`
	Permission  string                     `json:"permission"`
	Subject     subjectRef                 `json:"subject"`
}

// fakeSpice grants a permission when the relationship
// resource#permission@subject is stored.
type fakeSpice struct {
	mu       sync.Mutex
	rels     map[relationship]bool
	checks   []checkReq
	fail     bool
	noSchema bool
}

func (f *fakeSpice) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer key" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":16,"message":"invalid preshared key"}`))
		return
	}
	if f.fail {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"code":14,"message":"unavailable"}`))
		return
	}
	switch r.URL.Path {
	case "/v1/permissions/check":
		var req checkReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.checks = append(f.checks, req)
		ps := "PERMISSIONSHIP_NO_PERMISSION"
		if f.rels[relationship{Resource: req.Resource, Relation: req.Permission, Subject: req.Subject}] {
			ps = "PERMISSIONSHIP_HAS_PERMISSION"
		}
		if req.Permission == "conditional" {
			ps = "PERMISSIONSHIP_CONDITIONAL_PERMISSION"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"checkedAt": map[string]string{"token": "t"}, "permissionship": ps})
	case "/v1/relationships/write":
		var req struct {
			Updates []update `json:"updates"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		for _, u := range req.Updates {
			if u.Operation == "OPERATION_DELETE" {
				delete(f.rels, u.Relationship)
			} else {
				f.rels[u.Relationship] = true
			}
		}
		_, _ = w.Write([]byte(`{"writtenAt":{"token":"zed-1"}}`))
	case "/v1/schema/read":
		if f.noSchema {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":5,"message":"no schema has been defined"}`))
			return
		}
		_, _ = w.Write([]byte(`{"schemaText":""}`))
	default:
		http.NotFound(w, r)
	}
}

func setup(t *testing.T, cfg map[string]any) (*Plugin, *fakeSpice, *sdktest.Registrar) {
	t.Helper()
	f := &fakeSpice{rels: map[relationship]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	if cfg == nil {
		cfg = map[string]any{}
	}
	cfg["url"] = srv.URL
	if _, ok := cfg["token"]; !ok {
		cfg["token"] = "key"
	}
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	var v any
	_ = json.Unmarshal(raw, &v)
	if err := sch.Validate(v); err != nil {
		t.Fatalf("schema: %v", err)
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	return p, f, reg
}

func rel(res, relation, subj string) relationship {
	r, _ := parseObject(res)
	s, _ := parseSubject(subj)
	return relationship{Resource: r, Relation: relation, Subject: s}
}

var (
	ann    = &sdk.Principal{Subject: "ann", Kind: "user", Authenticator: "oidc"}
	tenant = sdk.Resource{Type: "tenant", ID: "t1", TenantID: "t1"}
)

func TestCheck(t *testing.T) {
	p, f, _ := setup(t, map[string]any{
		"permissions":     map[string]any{"members:write": "manage_members", "events:read": "", "plans:read": "conditional"},
		"resources":       map[string]any{"member": "tenant:{resource.tenant_id}"},
		"global_resource": "platform:default",
		"consistency":     "fully_consistent",
		"on_not_allowed":  "deny",
		"cache_ttl":       "0s",
	})
	f.rels[rel("tenant:t1", "can_update", "user:ann")] = true
	f.rels[rel("tenant:t1", "manage_members", "user:ann")] = true
	ctx := context.Background()
	cases := []struct {
		action sdk.Action
		res    sdk.Resource
		want   sdk.Decision
	}{
		{sdk.ActionTenantsUpdate, tenant, sdk.Allow},
		{sdk.ActionTenantsDelete, tenant, sdk.Deny},
		{sdk.ActionMembersWrite, sdk.Resource{Type: "member", TenantID: "t1"}, sdk.Allow},
		{sdk.ActionEventsRead, sdk.Resource{Type: "event"}, sdk.Abstain},
		{sdk.ActionPlansRead, sdk.Resource{Type: "plan"}, sdk.Deny}, // conditional is not a grant
	}
	for _, c := range cases {
		got, err := p.Authorize(ctx, ann, c.action, c.res)
		if err != nil || got != c.want {
			t.Errorf("%s: got %v %v, want %v", c.action, got, err, c.want)
		}
	}
	last := f.checks[len(f.checks)-1]
	if last.Resource != (objectRef{"platform", "default"}) || string(last.Consistency["fullyConsistent"]) != "true" {
		t.Errorf("last check %+v", last)
	}
	r := p.Check(ctx, ann, sdk.ActionTenantsDelete, tenant)
	if !strings.Contains(r.Reason, "tenant:t1#can_delete@user:ann") {
		t.Errorf("reason %q", r.Reason)
	}
}

func TestSubjectRelationAndBadIDs(t *testing.T) {
	p, f, _ := setup(t, map[string]any{"subject": "apikey:{principal.subject}#holder", "cache_ttl": "0s"})
	_, _ = p.Authorize(context.Background(), &sdk.Principal{Subject: "ci"}, sdk.ActionTenantsRead, tenant)
	if s := f.checks[0].Subject; s.Object != (objectRef{"apikey", "ci"}) || s.OptionalRelation != "holder" {
		t.Fatalf("subject %+v", s)
	}
}

func TestFailModeAndHealth(t *testing.T) {
	p, f, _ := setup(t, nil)
	ctx := context.Background()
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	f.noSchema = true
	if err := p.Health(ctx); err != nil {
		t.Fatalf("missing schema is healthy: %v", err)
	}
	f.fail = true
	if got, err := p.Authorize(ctx, ann, sdk.ActionTenantsRead, tenant); err != nil || got != sdk.Abstain {
		t.Fatalf("got %v %v", got, err)
	}
	p.denyOnError = true
	if r := p.Check(ctx, ann, sdk.ActionTenantsRead, tenant); r.Decision != sdk.Deny || !strings.Contains(r.Reason, "unavailable") {
		t.Fatalf("got %+v", r)
	}
	if err := p.Health(ctx); err == nil {
		t.Fatal("health should fail")
	}

	bad, _, _ := setup(t, map[string]any{"token": "wrong"})
	if err := bad.Health(ctx); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestCache(t *testing.T) {
	p, f, _ := setup(t, map[string]any{"cache_ttl": "1m"})
	ctx := context.Background()
	for range 3 {
		_, _ = p.Authorize(ctx, ann, sdk.ActionTenantsRead, tenant)
	}
	if len(f.checks) != 1 {
		t.Fatalf("checks = %d", len(f.checks))
	}
}

func TestSync(t *testing.T) {
	p, f, reg := setup(t, map[string]any{
		"consistency": "at_least_as_fresh",
		"cache_ttl":   "1m",
		"sync":        map[string]any{"tenant_parents": true, "members": true},
	})
	ctx := context.Background()
	deliver := func(e sdk.Event) {
		t.Helper()
		if err := reg.Deliver(ctx, "relationships", e); err != nil {
			t.Fatal(err)
		}
	}
	ws := sdk.Tenant{ID: "ws", ParentID: "org"}
	// Cached "no" must be dropped after a write.
	_, _ = p.Authorize(ctx, &sdk.Principal{Subject: "u1", Kind: "user"}, sdk.ActionTenantsRead, sdk.Resource{Type: "tenant", ID: "org", TenantID: "org"})
	deliver(sdktest.TenantEvent(sdk.EventTenantCreated, ws))
	if !f.rels[rel("tenant:ws", "parent", "tenant:org")] {
		t.Fatalf("parent missing: %v", f.rels)
	}
	m := sdk.Member{ID: "m1", TenantID: "org", UserID: "u1", Role: "can_read", Status: sdk.MemberActive}
	deliver(sdktest.MemberEvent(sdk.EventMemberAdded, m))
	got, _ := p.Authorize(ctx, &sdk.Principal{Subject: "u1", Kind: "user"}, sdk.ActionTenantsRead, sdk.Resource{Type: "tenant", ID: "org", TenantID: "org"})
	if got != sdk.Allow {
		t.Fatalf("after sync: %v", got)
	}
	last := f.checks[len(f.checks)-1]
	if !strings.Contains(string(last.Consistency["atLeastAsFresh"]), "zed-1") {
		t.Fatalf("consistency %v", last.Consistency)
	}
	prev := m
	m.Status = sdk.MemberSuspended
	data, _ := json.Marshal(sdk.MemberEventData{Member: m, Previous: &prev})
	ev := sdktest.MemberEvent(sdk.EventMemberUpdated, m)
	ev.Data = data
	deliver(ev)
	deliver(sdktest.MemberEvent(sdk.EventMemberRemoved, m))
	deliver(sdktest.TenantEvent(sdk.EventTenantDeleted, ws))
	if len(f.rels) != 0 {
		t.Fatalf("left: %v", f.rels)
	}
}

func TestInitValidation(t *testing.T) {
	bad := []map[string]any{
		{},
		{"url": "http://x"},
		{"url": "x", "token": "k"},
		{"url": "http://x", "token": "k", "consistency": "eventual"},
		{"url": "http://x", "token": "k", "subject": "{principal.subject}"},
		{"url": "http://x", "token": "k", "permission": "{nope}"},
		{"url": "http://x", "token": "k", "timeout": "0s"},
		{"url": "http://x", "token": "k", "extra": true},
	}
	for _, cfg := range bad {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("accepted %v", cfg)
		}
	}
	if _, ok := sdk.Lookup("spicedb"); !ok {
		t.Fatal("not registered")
	}
}

func TestReconfigure(t *testing.T) {
	syncCfg := map[string]any{"members": true}
	p, f, reg := setup(t, map[string]any{"consistency": "at_least_as_fresh", "cache_ttl": "1m", "sync": syncCfg})
	ctx := context.Background()
	m := sdk.Member{ID: "m1", TenantID: "t1", UserID: "ann", Role: "can_update", Status: sdk.MemberActive}
	if err := reg.Deliver(ctx, "relationships", sdktest.MemberEvent(sdk.EventMemberAdded, m)); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.Authorize(ctx, ann, sdk.ActionTenantsUpdate, tenant); got != sdk.Allow {
		t.Fatalf("got %v", got)
	}
	cfg := func(extra map[string]any) func(any) error {
		c := map[string]any{"url": reg.ConfigData["url"], "token": "key", "consistency": "at_least_as_fresh", "cache_ttl": "1m", "sync": syncCfg}
		for k, v := range extra {
			c[k] = v
		}
		return sdktest.NewRegistrar(c).Config
	}

	// A new token applies live.
	if err := p.Reconfigure(ctx, cfg(map[string]any{"token": "rotated"})); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err == nil {
		t.Fatal("old token still used")
	}
	// New permissions apply, the cached allow is dropped and the ZedToken
	// of the last write is kept for the same server.
	if err := p.Reconfigure(ctx, cfg(map[string]any{"permissions": map[string]any{"tenants:update": "can_edit"}})); err != nil {
		t.Fatal(err)
	}
	if got, _ := p.Authorize(ctx, ann, sdk.ActionTenantsUpdate, tenant); got != sdk.Abstain {
		t.Fatalf("after reconfigure: %v", got)
	}
	last := f.checks[len(f.checks)-1]
	if last.Permission != "can_edit" || !strings.Contains(string(last.Consistency["atLeastAsFresh"]), "zed-1") {
		t.Fatalf("check %+v", last)
	}

	// An invalid config is rejected and the current settings stay.
	if err := p.Reconfigure(ctx, cfg(map[string]any{"token": "rotated", "timeout": "fast"})); err == nil {
		t.Fatal("invalid timeout accepted")
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}

	// The synced event types are fixed at startup.
	err := p.Reconfigure(ctx, cfg(map[string]any{"sync": map[string]any{"members": true, "tenant_parents": true}}))
	if err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("sync change: %v", err)
	}
}
