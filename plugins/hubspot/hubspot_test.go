package hubspot

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
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

const token = "pat-na1-test"

type call struct{ Method, Path string }

// fakeHubSpot keeps companies (unique on tenarium_tenant_id) and contacts
// (unique on email) in memory.
type fakeHubSpot struct {
	mu        sync.Mutex
	srv       *httptest.Server
	nextID    int
	companies map[string]map[string]string // HubSpot ID → properties
	contacts  map[string]map[string]string
	assoc     map[[2]string]bool // contact, company
	calls     []call
	failWith  int
}

func newFake(t *testing.T) *fakeHubSpot {
	f := &fakeHubSpot{companies: map[string]map[string]string{}, contacts: map[string]map[string]string{}, assoc: map[[2]string]bool{}, nextID: 100}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /crm/v3/objects/{type}/batch/upsert", f.upsert)
	mux.HandleFunc("GET /crm/v3/objects/{type}/{id}", f.get)
	mux.HandleFunc("GET /crm/v3/objects/companies", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[]}`))
	})
	mux.HandleFunc("DELETE /crm/v3/objects/companies/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, ok := f.companies[r.PathValue("id")]; !ok {
			notFound(w)
			return
		}
		delete(f.companies, r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /crm/v4/objects/contact/{c}/associations/default/company/{co}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.assoc[[2]string{r.PathValue("c"), r.PathValue("co")}] = true
		_, _ = w.Write([]byte(`{"status":"COMPLETE","results":[]}`))
	})
	mux.HandleFunc("DELETE /crm/v4/objects/contact/{c}/associations/company/{co}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.assoc, [2]string{r.PathValue("c"), r.PathValue("co")})
		w.WriteHeader(http.StatusNoContent)
	})
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, call{r.Method, r.URL.Path})
		fail := f.failWith
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"status":"error","category":"INVALID_AUTHENTICATION","message":"bad token"}`))
			return
		}
		if fail != 0 {
			w.Header().Set("Retry-After", "10")
			w.WriteHeader(fail)
			_, _ = w.Write([]byte(`{"status":"error","category":"RATE_LIMITS","message":"slow down"}`))
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func notFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"status":"error","category":"OBJECT_NOT_FOUND","message":"not found"}`))
}

func (f *fakeHubSpot) store(typ string) map[string]map[string]string {
	if typ == "companies" {
		return f.companies
	}
	return f.contacts
}

func (f *fakeHubSpot) find(store map[string]map[string]string, prop, value string) string {
	for id, props := range store {
		if props[prop] == value {
			return id
		}
	}
	return ""
}

func (f *fakeHubSpot) upsert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Inputs []struct {
			IDProperty string            `json:"idProperty"`
			ID         string            `json:"id"`
			Properties map[string]string `json:"properties"`
		} `json:"inputs"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	defer f.mu.Unlock()
	store := f.store(r.PathValue("type"))
	var results []map[string]any
	for _, in := range body.Inputs {
		id := f.find(store, in.IDProperty, in.ID)
		if id == "" {
			f.nextID++
			id = fmt.Sprint(f.nextID)
			store[id] = map[string]string{in.IDProperty: in.ID}
		}
		maps.Copy(store[id], in.Properties)
		results = append(results, map[string]any{"id": id, "properties": store[id]})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "COMPLETE", "results": results})
}

func (f *fakeHubSpot) get(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.find(f.store(r.PathValue("type")), r.URL.Query().Get("idProperty"), r.PathValue("id"))
	if id == "" {
		notFound(w)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
}

func (f *fakeHubSpot) snapshot() (companies, contacts map[string]map[string]string, assoc map[[2]string]bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.companies), maps.Clone(f.contacts), maps.Clone(f.assoc)
}

func setup(t *testing.T, overrides map[string]any) (*Plugin, *sdktest.Registrar, *fakeHubSpot) {
	t.Helper()
	f := newFake(t)
	cfg := map[string]any{"access_token": token, "api_base": f.srv.URL}
	maps.Copy(cfg, overrides)
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p, reg, f
}

func deliver(t *testing.T, reg *sdktest.Registrar, sub string, e sdk.Event) {
	t.Helper()
	if err := reg.Deliver(context.Background(), sub, e); err != nil {
		t.Fatalf("deliver %s: %v", e.Type, err)
	}
}

func TestCompanyUpsertIsIdempotent(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"properties": map[string]string{
		"name": "{{.Name}}", "tenarium_plan": "{{.Plan}}", "domain": `{{index .Labels "domain"}}`,
	}})
	tn := sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme", Plan: "pro"}
	e := sdktest.TenantEvent(sdk.EventTenantCreated, tn)
	deliver(t, reg, "sync", e)
	deliver(t, reg, "sync", e)
	tn.Plan, tn.Labels = "enterprise", map[string]string{"domain": "acme.io"}
	deliver(t, reg, "sync", sdktest.TenantEvent(sdk.EventTenantPlanChanged, tn))

	companies, _, _ := f.snapshot()
	if len(companies) != 1 {
		t.Fatalf("companies = %v", companies)
	}
	for _, c := range companies {
		if c["tenarium_tenant_id"] != "t-1" || c["name"] != "Acme" || c["tenarium_plan"] != "enterprise" || c["domain"] != "acme.io" {
			t.Fatalf("company = %v", c)
		}
	}
}

func TestEmptyValuesAreNotSent(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"properties": map[string]string{"name": "{{.Name}}", "domain": `{{index .Labels "domain"}}`}})
	deliver(t, reg, "sync", sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t-1", Name: "Acme"}))
	companies, _, _ := f.snapshot()
	for _, c := range companies {
		if _, sent := c["domain"]; sent || c["name"] != "Acme" {
			t.Fatalf("company = %v", c)
		}
	}
}

func TestDeleteArchives(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := sdk.Tenant{ID: "t-1", Name: "Acme"}
	deliver(t, reg, "sync", sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	del := sdktest.TenantEvent(sdk.EventTenantDeleted, tn)
	deliver(t, reg, "sync", del)
	deliver(t, reg, "sync", del) // already archived: no error
	if companies, _, _ := f.snapshot(); len(companies) != 0 {
		t.Fatalf("companies = %v", companies)
	}
}

func TestDeleteKeep(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"on_delete": "keep"})
	tn := sdk.Tenant{ID: "t-1", Name: "Acme"}
	deliver(t, reg, "sync", sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	deliver(t, reg, "sync", sdktest.TenantEvent(sdk.EventTenantDeleted, tn))
	if companies, _, _ := f.snapshot(); len(companies) != 1 {
		t.Fatalf("companies = %v", companies)
	}
}

func TestMembers(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"contact_properties": map[string]string{"jobtitle": "{{.Member.Role}} at {{.Tenant.Name}}"}})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme"})
	m := sdk.Member{ID: "m-1", TenantID: tn.ID, Email: "ann@acme.io", Role: "admin"}
	added := sdktest.MemberEvent(sdk.EventMemberAdded, m)
	deliver(t, reg, "members", added)
	deliver(t, reg, "members", added)

	companies, contacts, assoc := f.snapshot()
	if len(companies) != 1 || len(contacts) != 1 || len(assoc) != 1 {
		t.Fatalf("companies=%v contacts=%v assoc=%v", companies, contacts, assoc)
	}
	for _, c := range contacts {
		if c["email"] != "ann@acme.io" || c["jobtitle"] != "admin at Acme" {
			t.Fatalf("contact = %v", c)
		}
	}
	deliver(t, reg, "members", sdktest.MemberEvent(sdk.EventMemberRemoved, m))
	_, contacts, assoc = f.snapshot()
	if len(assoc) != 0 || len(contacts) != 1 {
		t.Fatalf("after removal: contacts=%v assoc=%v", contacts, assoc)
	}
	// Removing again, or an unknown contact, is harmless.
	deliver(t, reg, "members", sdktest.MemberEvent(sdk.EventMemberRemoved, m))
	deliver(t, reg, "members", sdktest.MemberEvent(sdk.EventMemberRemoved, sdk.Member{TenantID: tn.ID, Email: "x@y.io"}))
}

func TestMembersSkipUnknownAndDeletedTenants(t *testing.T) {
	_, reg, f := setup(t, nil)
	gone := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "gone", Status: sdk.StatusDeleted})
	deliver(t, reg, "members", sdktest.MemberEvent(sdk.EventMemberAdded, sdk.Member{TenantID: gone.ID, Email: "a@b.io"}))
	deliver(t, reg, "members", sdktest.MemberEvent(sdk.EventMemberAdded, sdk.Member{TenantID: "unknown", Email: "a@b.io"}))
	deliver(t, reg, "members", sdktest.MemberEvent(sdk.EventMemberAdded, sdk.Member{TenantID: gone.ID})) // no email
	if companies, contacts, _ := f.snapshot(); len(companies)+len(contacts) != 0 {
		t.Fatalf("companies=%v contacts=%v", companies, contacts)
	}
}

func TestSyncMembersOff(t *testing.T) {
	_, reg, _ := setup(t, map[string]any{"sync_members": false})
	if len(reg.Subscriptions) != 1 || reg.Subscriptions[0].Name != "sync" {
		t.Fatalf("subscriptions = %+v", reg.Subscriptions)
	}
}

func TestErrorsAreRetried(t *testing.T) {
	p, reg, f := setup(t, nil)
	f.failWith = http.StatusTooManyRequests
	err := reg.Deliver(context.Background(), "sync", sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t-1", Name: "A"}))
	if err == nil || !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "retry after 10s") {
		t.Fatalf("err = %v", err)
	}
	if err := p.Health(context.Background()); err == nil {
		t.Fatal("health passed on errors")
	}
	f.failWith = 0
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Template failures (missing field) are errors, not silent drops.
	_, reg2, _ := setup(t, map[string]any{"properties": map[string]string{"name": "{{.Nope}}"}})
	if err := reg2.Deliver(context.Background(), "sync", sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t-1"})); err == nil {
		t.Fatal("bad template field not reported")
	}
}

func TestBadToken(t *testing.T) {
	f := newFake(t)
	reg := sdktest.NewRegistrar(map[string]any{"access_token": "wrong", "api_base": f.srv.URL})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "INVALID_AUTHENTICATION") {
		t.Fatalf("health = %v", err)
	}
}

func TestDefaults(t *testing.T) {
	p, reg, _ := setup(t, nil)
	if p.cfg.TenantIDProperty != "tenarium_tenant_id" || p.cfg.OnDelete != "archive" || p.client.Timeout != 15*time.Second ||
		len(p.companyTmpl) != 1 || !p.syncsMembers || len(reg.Subscriptions) != 2 {
		t.Fatalf("defaults: %+v", p.cfg)
	}
	p2 := &Plugin{}
	if err := p2.Init(context.Background(), sdktest.NewRegistrar(map[string]any{"access_token": "x"})); err != nil || p2.base != "https://api.hubapi.com" {
		t.Fatalf("base = %s, %v", p2.base, err)
	}
}

func TestInitValidation(t *testing.T) {
	for name, cfg := range map[string]map[string]any{
		"no token":         {},
		"blank token":      {"access_token": "  "},
		"bad base":         {"access_token": "x", "api_base": "api.hubapi.com"},
		"bad timeout":      {"access_token": "x", "timeout": "0s"},
		"bad id property":  {"access_token": "x", "tenant_id_property": "Tenant-ID"},
		"id in properties": {"access_token": "x", "properties": map[string]string{"tenarium_tenant_id": "{{.ID}}"}},
		"bad property":     {"access_token": "x", "properties": map[string]string{"Name": "{{.Name}}"}},
		"bad template":     {"access_token": "x", "properties": map[string]string{"name": "{{.Name"}},
		"empty template":   {"access_token": "x", "properties": map[string]string{"name": " "}},
		"email contact":    {"access_token": "x", "contact_properties": map[string]string{"email": "x"}},
		"contacts no sync": {"access_token": "x", "sync_members": false, "contact_properties": map[string]string{"jobtitle": "x"}},
		"bad on_delete":    {"access_token": "x", "on_delete": "delete"},
		"unknown key":      {"access_token": "x", "token": "y"},
	} {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{
		"access_token": "pat", "api_base": "https://api.hubapi.com", "timeout": "10s", "tenant_id_property": "tenarium_tenant_id",
		"properties": map[string]any{"name": "{{.Name}}"}, "sync_members": true,
		"contact_properties": map[string]any{"jobtitle": "{{.Member.Role}}"}, "on_delete": "keep",
	}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, bad := range []map[string]any{
		{},
		{"access_token": ""},
		{"access_token": "x", "on_delete": "delete"},
		{"access_token": "x", "properties": map[string]any{"Bad-Name": "x"}},
		{"access_token": "x", "tenant_id_property": "X"},
		{"access_token": "x", "extra": 1},
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

func TestReconfigure(t *testing.T) {
	p, reg, f := setup(t, nil)
	tn := sdk.Tenant{ID: "t-1", Name: "Acme"}
	cfg := map[string]any{"access_token": token, "api_base": f.srv.URL, "properties": map[string]string{"name": "New {{.Name}}"}}
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(cfg).Config); err != nil {
		t.Fatal(err)
	}
	deliver(t, reg, "sync", sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	companies, _, _ := f.snapshot()
	for _, c := range companies {
		if c["name"] != "New Acme" {
			t.Fatalf("company = %v", c)
		}
	}

	// Invalid config: rejected, the previous one stays.
	cfg["properties"] = map[string]string{"name": "{{.Name"}
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(cfg).Config); err == nil {
		t.Fatal("bad template accepted")
	}
	tn.Name = "Acme 2"
	deliver(t, reg, "sync", sdktest.TenantEvent(sdk.EventTenantUpdated, tn))
	companies, _, _ = f.snapshot()
	for _, c := range companies {
		if c["name"] != "New Acme 2" {
			t.Fatalf("company = %v", c)
		}
	}

	// sync_members decides the subscriptions.
	cfg = map[string]any{"access_token": token, "api_base": f.srv.URL, "sync_members": false}
	if err := p.Reconfigure(context.Background(), sdktest.NewRegistrar(cfg).Config); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("sync_members change = %v", err)
	}
}
