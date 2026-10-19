package lago

import (
	"context"
	"encoding/json"
	"io"
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

type request struct {
	Method, Path, Query, Auth, UA string
	Body                          map[string]any
}

// fakeLago is an in-memory Lago API.
type fakeLago struct {
	t         *testing.T
	srv       *httptest.Server
	key       string
	mu        sync.Mutex
	reqs      []request
	events    map[string]bool
	customers map[string]map[string]any
	failWith  int // next event POST fails with this status
}

func newFakeLago(t *testing.T) *fakeLago {
	f := &fakeLago{t: t, key: "lago_test_key", events: map[string]bool{}, customers: map[string]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeLago) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := io.ReadAll(r.Body)
	req := request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization"), UA: r.Header.Get("User-Agent")}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req.Body); err != nil {
			f.t.Errorf("invalid JSON body: %s", raw)
		}
	}
	f.reqs = append(f.reqs, req)
	if req.Auth != "Bearer "+f.key {
		writeJSON(w, 401, map[string]any{"status": 401, "error": "Unauthorized"})
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/billable_metrics":
		writeJSON(w, 200, map[string]any{"billable_metrics": []any{}})
	case r.Method == "POST" && r.URL.Path == "/api/v1/events":
		if f.failWith != 0 {
			s := f.failWith
			f.failWith = 0
			writeJSON(w, s, map[string]any{"status": s, "error": "boom"})
			return
		}
		ev := req.Body["event"].(map[string]any)
		id := ev["transaction_id"].(string)
		if f.events[id] {
			writeJSON(w, 422, map[string]any{"status": 422, "error": "Unprocessable Entity", "code": "validation_errors",
				"error_details": map[string]any{"transaction_id": []string{"value_already_exist"}}})
			return
		}
		f.events[id] = true
		writeJSON(w, 200, map[string]any{"event": ev})
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v1/customers/"):
		c, ok := f.customers[strings.TrimPrefix(r.URL.Path, "/api/v1/customers/")]
		if !ok {
			writeJSON(w, 404, map[string]any{"status": 404, "error": "Not Found", "code": "customer_not_found"})
			return
		}
		writeJSON(w, 200, map[string]any{"customer": c})
	case r.Method == "POST" && r.URL.Path == "/api/v1/customers":
		in := req.Body["customer"].(map[string]any)
		var meta []any
		for i, m := range in["metadata"].([]any) {
			m := maps.Clone(m.(map[string]any))
			m["lago_id"] = cmpOr(m["id"], "meta-"+string(rune('a'+i)))
			delete(m, "id")
			meta = append(meta, m)
		}
		c := map[string]any{"external_id": in["external_id"], "name": in["name"], "metadata": meta}
		f.customers[in["external_id"].(string)] = c
		writeJSON(w, 200, map[string]any{"customer": c})
	default:
		writeJSON(w, 404, map[string]any{"status": 404, "error": "Not Found"})
	}
}

func cmpOr(v any, def string) any {
	if s, _ := v.(string); s != "" {
		return s
	}
	return def
}

func (f *fakeLago) calls(method, path string) []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []request
	for _, r := range f.reqs {
		if r.Method == method && r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

func setup(t *testing.T, overrides map[string]any) (*Plugin, *sdktest.Registrar, *fakeLago) {
	t.Helper()
	f := newFakeLago(t)
	cfg := map[string]any{
		"api_key": f.key,
		"api_url": f.srv.URL,
		"metrics": map[string]string{"api_calls": "api_calls_code"},
	}
	maps.Copy(cfg, overrides)
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p, reg, f
}

var periodEnd = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func periodClosed(tenantID, metric string, value int64) sdk.Event {
	end := periodEnd
	data, _ := json.Marshal(sdk.UsagePeriodData{TenantID: tenantID, Metric: metric, Period: "2026-10", PeriodEnd: &end, Value: value})
	return sdk.Event{ID: "evt-" + metric, Type: sdk.EventTenantUsagePeriodClosed, TenantID: tenantID, Data: data}
}

func TestUsageEvents(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"customer_id_template": "cus-{{.Slug}}"})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme"})
	ctx := context.Background()
	noEnd := periodClosed(tn.ID, "api_calls", 5)
	noEnd.Data, _ = json.Marshal(sdk.UsagePeriodData{TenantID: tn.ID, Metric: "api_calls", Period: "2026-10", Value: 5})
	for _, e := range []sdk.Event{
		periodClosed(tn.ID, "api_calls", 1234),
		periodClosed(tn.ID, "api_calls", 1234), // redelivery: Lago answers 422 value_already_exist
		periodClosed(tn.ID, "storage_gb", 5),   // not mapped
		periodClosed(tn.ID, "api_calls", 0),    // nothing to bill
		noEnd,                                  // no period end
	} {
		if err := reg.Deliver(ctx, "meters", e); err != nil {
			t.Fatal(err)
		}
	}
	calls := f.calls("POST", "/api/v1/events")
	if len(calls) != 2 {
		t.Fatalf("event calls: %+v", calls)
	}
	ev := calls[0].Body["event"].(map[string]any)
	want := map[string]any{
		"transaction_id":       "tenarium-t-1-api_calls-2026-10",
		"external_customer_id": "cus-acme",
		"code":                 "api_calls_code",
		"timestamp":            float64(1793491199),
		"properties":           map[string]any{"value": float64(1234)},
	}
	if b1, b2 := mustJSON(ev), mustJSON(want); b1 != b2 {
		t.Fatalf("event = %s, want %s", b1, b2)
	}
	if calls[1].Body["event"].(map[string]any)["transaction_id"] != want["transaction_id"] {
		t.Fatal("redelivery used another transaction_id")
	}
	if calls[0].UA != "tenarium-lago/"+version {
		t.Fatalf("user agent %q", calls[0].UA)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestUsageSubscriptionID(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"subscription_id_template": "sub-{{index .Labels \"billing\"}}"})
	reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1", Slug: "acme", Labels: map[string]string{"billing": "42"}})
	ctx := context.Background()
	if err := reg.Deliver(ctx, "meters", periodClosed("t-1", "api_calls", 7)); err != nil {
		t.Fatal(err)
	}
	ev := f.calls("POST", "/api/v1/events")[0].Body["event"].(map[string]any)
	if ev["external_subscription_id"] != "sub-42" || ev["external_customer_id"] != nil {
		t.Fatalf("event = %v", ev)
	}
	// A template rendering nothing (a missing label) is rejected.
	_, reg2, f2 := setup(t, map[string]any{"subscription_id_template": "{{index .Labels \"billing\"}}"})
	reg2.HostImpl.AddTenant(sdk.Tenant{ID: "t-2", Slug: "nolabel"})
	if err := reg2.Deliver(ctx, "meters", periodClosed("t-2", "api_calls", 7)); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v", err)
	}
	if n := len(f2.calls("POST", "/api/v1/events")); n != 0 {
		t.Fatalf("%d events sent", n)
	}
}

func TestUsageDeletedTenant(t *testing.T) {
	_, reg, f := setup(t, nil)
	if err := reg.Deliver(context.Background(), "meters", periodClosed("t-gone", "api_calls", 3)); err != nil {
		t.Fatal(err)
	}
	ev := f.calls("POST", "/api/v1/events")[0].Body["event"].(map[string]any)
	if ev["external_customer_id"] != "t-gone" {
		t.Fatalf("event = %v", ev)
	}
}

func TestUsageErrorsAreRetried(t *testing.T) {
	_, reg, f := setup(t, nil)
	reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1", Slug: "acme"})
	ctx := context.Background()
	f.failWith = 503
	if err := reg.Deliver(ctx, "meters", periodClosed("t-1", "api_calls", 3)); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err = %v", err)
	}
	if err := reg.Deliver(ctx, "meters", periodClosed("t-1", "api_calls", 3)); err != nil {
		t.Fatal(err)
	}
	// Other validation errors are not mistaken for duplicates.
	f.failWith = 422
	if err := reg.Deliver(ctx, "meters", periodClosed("t-1", "api_calls", 3)); err == nil {
		t.Fatal("422 without value_already_exist treated as success")
	}
}

func TestCustomerSync(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"sync_customers": true, "customer_id_template": "cus-{{.ID}}"})
	tn := sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme"}
	ctx := context.Background()
	created := sdktest.TenantEvent(sdk.EventTenantCreated, tn)
	for range 2 { // redelivery converges on the same customer
		if err := reg.Deliver(ctx, "customers", created); err != nil {
			t.Fatal(err)
		}
	}
	posts := f.calls("POST", "/api/v1/customers")
	if len(posts) != 2 {
		t.Fatalf("customer posts: %+v", posts)
	}
	c := posts[0].Body["customer"].(map[string]any)
	if c["external_id"] != "cus-t-1" || c["name"] != "Acme" ||
		mustJSON(c["metadata"]) != `[{"display_in_invoice":false,"key":"tenarium_tenant_id","value":"t-1"},{"display_in_invoice":false,"key":"tenarium_slug","value":"acme"}]` {
		t.Fatalf("customer = %v", c)
	}
	// The second post updates the existing metadata entries by ID.
	if m := mustJSON(posts[1].Body["customer"].(map[string]any)["metadata"]); !strings.Contains(m, `"id":"meta-a"`) || !strings.Contains(m, `"id":"meta-b"`) {
		t.Fatalf("metadata = %s", m)
	}

	// Metadata added in Lago is kept.
	f.mu.Lock()
	cus := f.customers["cus-t-1"]
	cus["metadata"] = append(cus["metadata"].([]any), map[string]any{"lago_id": "meta-x", "key": "vat", "value": "DE1", "display_in_invoice": true})
	f.mu.Unlock()

	unchanged := sdktest.TenantEvent(sdk.EventTenantUpdated, tn)
	unchanged.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: tn, Previous: &tn})
	if err := reg.Deliver(ctx, "customers", unchanged); err != nil {
		t.Fatal(err)
	}
	if n := len(f.calls("POST", "/api/v1/customers")); n != 2 {
		t.Fatalf("unchanged update synced (%d posts)", n)
	}

	renamed := tn
	renamed.Name, renamed.Slug = "Acme Inc", "acme-inc"
	upd := sdktest.TenantEvent(sdk.EventTenantUpdated, renamed)
	upd.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: renamed, Previous: &tn})
	if err := reg.Deliver(ctx, "customers", upd); err != nil {
		t.Fatal(err)
	}
	posts = f.calls("POST", "/api/v1/customers")
	c = posts[len(posts)-1].Body["customer"].(map[string]any)
	if c["name"] != "Acme Inc" || mustJSON(c["metadata"]) !=
		`[{"display_in_invoice":false,"id":"meta-a","key":"tenarium_tenant_id","value":"t-1"},{"display_in_invoice":false,"id":"meta-b","key":"tenarium_slug","value":"acme-inc"},{"display_in_invoice":true,"id":"meta-x","key":"vat","value":"DE1"}]` {
		t.Fatalf("customer = %v", mustJSON(c))
	}
}

func TestNoCustomerSyncByDefault(t *testing.T) {
	_, reg, _ := setup(t, nil)
	if err := reg.Deliver(context.Background(), "customers", sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t"})); err == nil {
		t.Fatal("customers subscription registered without sync_customers")
	}
}

func TestHealth(t *testing.T) {
	p, _, f := setup(t, nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q := f.calls("GET", "/api/v1/billable_metrics")[0].Query; q != "per_page=1" {
		t.Fatalf("query %q", q)
	}
	f.key = "rotated"
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := map[string]any{"api_key": "k", "metrics": map[string]string{"api_calls": "calls"}}
	cases := []struct {
		name string
		set  map[string]any
		want string
	}{
		{"missing key", map[string]any{"api_key": ""}, "api_key is required"},
		{"no metrics", map[string]any{"metrics": map[string]string{}}, "metrics"},
		{"empty code", map[string]any{"metrics": map[string]string{"a": ""}}, "must not be empty"},
		{"bad url", map[string]any{"api_url": "ftp://x"}, "api_url"},
		{"relative url", map[string]any{"api_url": "/api"}, "api_url"},
		{"bad timeout", map[string]any{"timeout": "soon"}, "timeout"},
		{"zero timeout", map[string]any{"timeout": "0s"}, "timeout"},
		{"bad customer template", map[string]any{"customer_id_template": "{{.ID"}, "customer_id_template"},
		{"unknown field in template", map[string]any{"customer_id_template": "{{.Id}}"}, "customer_id_template"},
		{"bad subscription template", map[string]any{"subscription_id_template": "{{.Nope}}"}, "subscription_id_template"},
		{"unknown field", map[string]any{"meters": map[string]string{}}, "unknown field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := maps.Clone(base)
			maps.Copy(cfg, tc.set)
			err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	p := &Plugin{}
	cfg := maps.Clone(base)
	cfg["customer_id_template"] = `{{index .Labels "billing"}}` // label keys are only checked at render time
	reg := sdktest.NewRegistrar(cfg)
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if p.base != "https://api.getlago.com" || p.client.Timeout != 10*time.Second || p.subTmpl != nil || p.cfg.SyncCustomers {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	if len(reg.Subscriptions) != 1 || reg.Subscriptions[0].Name != "meters" ||
		reg.Subscriptions[0].Filter.Types[0] != sdk.EventTenantUsagePeriodClosed {
		t.Fatalf("subscriptions = %+v", reg.Subscriptions)
	}
	p = &Plugin{}
	if err := p.Init(context.Background(), sdktest.NewRegistrar(base)); err != nil || p.cfg.CustomerIDTemplate != "{{.ID}}" {
		t.Fatalf("default template: %v %q", err, p.cfg.CustomerIDTemplate)
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{
		"api_key": "k", "api_url": "https://api.eu.getlago.com", "timeout": "5s",
		"metrics": map[string]any{"api_calls": "calls"}, "customer_id_template": "{{.ID}}",
		"subscription_id_template": "sub-{{.Slug}}", "sync_customers": true,
	}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, bad := range []map[string]any{
		{"metrics": map[string]any{"a": "b"}},
		{"api_key": "k"},
		{"api_key": "k", "metrics": map[string]any{}},
		{"api_key": "k", "metrics": map[string]any{"a": ""}},
		{"api_key": "k", "metrics": map[string]any{"a": "b"}, "api_url": "ftp://x"},
		{"api_key": "k", "metrics": map[string]any{"a": "b"}, "extra": 1},
		{"api_key": "k", "metrics": map[string]any{"a": "b"}, "sync_customers": "yes"},
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

func TestReconfigure(t *testing.T) {
	p, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1", Slug: "acme"})
	ctx := context.Background()
	f.mu.Lock()
	f.key = "lago_rotated_key"
	f.mu.Unlock()
	cfg := map[string]any{"api_key": "lago_rotated_key", "api_url": f.srv.URL, "metrics": map[string]string{"api_calls": "new_code"}}
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg).Config); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(ctx, "meters", periodClosed(tn.ID, "api_calls", 7)); err != nil {
		t.Fatal(err)
	}

	// Invalid config: rejected, the previous one stays.
	cfg["customer_id_template"] = "{{.Id}}"
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg).Config); err == nil {
		t.Fatal("bad template accepted")
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	calls := f.calls("POST", "/api/v1/events")
	if len(calls) != 1 || calls[0].Auth != "Bearer lago_rotated_key" || calls[0].Body["event"].(map[string]any)["code"] != "new_code" {
		t.Fatalf("event calls: %+v", calls)
	}

	// sync_customers decides the subscriptions.
	delete(cfg, "customer_id_template")
	cfg["sync_customers"] = true
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg).Config); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("sync_customers change = %v", err)
	}
}
