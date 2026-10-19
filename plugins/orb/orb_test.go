package orb

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
	Method, Path, Query, Auth, UA, ContentType string
	Body                                       map[string]any
}

// fakeOrb is an in-memory Orb API.
type fakeOrb struct {
	t        *testing.T
	srv      *httptest.Server
	key      string
	mu       sync.Mutex
	reqs     []request
	keys     map[string]bool
	ingested int
	failWith int    // next ingest fails with this status
	reject   string // customer ID whose events fail validation
}

func newFakeOrb(t *testing.T) *fakeOrb {
	f := &fakeOrb{t: t, key: "orb_test_key", keys: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeOrb) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := io.ReadAll(r.Body)
	req := request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization"),
		UA: r.Header.Get("User-Agent"), ContentType: r.Header.Get("Content-Type")}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req.Body); err != nil {
			f.t.Errorf("invalid JSON body: %s", raw)
		}
	}
	f.reqs = append(f.reqs, req)
	if req.Auth != "Bearer "+f.key {
		writeJSON(w, 401, map[string]any{"status": 401, "title": "Authentication error", "detail": "invalid API key"})
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/ping":
		writeJSON(w, 200, map[string]any{"response": "pong"})
	case r.Method == "POST" && r.URL.Path == "/v1/ingest":
		if f.failWith != 0 {
			s := f.failWith
			f.failWith = 0
			writeJSON(w, s, map[string]any{"status": s, "title": "Server error"})
			return
		}
		failed := []any{}
		ingested, dup := []string{}, []string{}
		for _, e := range req.Body["events"].([]any) {
			ev := e.(map[string]any)
			key := ev["idempotency_key"].(string)
			switch {
			case ev["external_customer_id"] == f.reject:
				failed = append(failed, map[string]any{"idempotency_key": key, "validation_errors": []string{"customer not found"}})
			case f.keys[key]:
				dup = append(dup, key)
			default:
				f.keys[key] = true
				f.ingested++
				ingested = append(ingested, key)
			}
		}
		res := map[string]any{"validation_failed": failed}
		if r.URL.Query().Get("debug") == "true" {
			res["debug"] = map[string]any{"duplicate": dup, "ingested": ingested}
		}
		writeJSON(w, 200, res)
	default:
		writeJSON(w, 404, map[string]any{"status": 404, "title": "Not found"})
	}
}

func (f *fakeOrb) calls(method, path string) []request {
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

func setup(t *testing.T, overrides map[string]any) (*Plugin, *sdktest.Registrar, *fakeOrb) {
	t.Helper()
	f := newFakeOrb(t)
	cfg := map[string]any{
		"api_key": f.key,
		"api_url": f.srv.URL,
		"metrics": map[string]string{"api_calls": "api_request"},
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

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestUsageEvents(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"customer_id_template": "{{.Slug}}-{{.Labels.region}}", "property_name": "units", "debug": true})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1", Slug: "acme", Labels: map[string]string{"region": "eu"}})
	ctx := context.Background()
	noEnd := periodClosed(tn.ID, "api_calls", 5)
	noEnd.Data, _ = json.Marshal(sdk.UsagePeriodData{TenantID: tn.ID, Metric: "api_calls", Period: "2026-10", Value: 5})
	for _, e := range []sdk.Event{
		periodClosed(tn.ID, "api_calls", 1234),
		periodClosed(tn.ID, "api_calls", 1234), // redelivery: deduplicated by Orb
		periodClosed(tn.ID, "storage_gb", 5),   // not mapped
		periodClosed(tn.ID, "api_calls", -1),   // nothing to bill
		noEnd,                                  // no period end
	} {
		if err := reg.Deliver(ctx, "meters", e); err != nil {
			t.Fatal(err)
		}
	}
	calls := f.calls("POST", "/v1/ingest")
	if len(calls) != 2 || f.ingested != 1 {
		t.Fatalf("ingest calls: %+v (ingested %d)", calls, f.ingested)
	}
	c := calls[0]
	want := `{"events":[{"event_name":"api_request","external_customer_id":"acme-eu","idempotency_key":"tenarium-t-1-api_calls-2026-10",` +
		`"properties":{"tenarium_metric":"api_calls","tenarium_period":"2026-10","units":1234},"timestamp":"2026-10-31T23:59:59Z"}]}`
	if got := mustJSON(c.Body); got != want {
		t.Fatalf("body = %s\nwant %s", got, want)
	}
	if mustJSON(calls[1].Body) != want || c.Query != "debug=true" || c.ContentType != "application/json" || c.UA != "tenarium-orb/"+version {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestUsageTemplateErrors(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"customer_id_template": "{{.Labels.billing_id}}"})
	reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1", Slug: "acme"})
	err := reg.Deliver(context.Background(), "meters", periodClosed("t-1", "api_calls", 1))
	if err == nil || !strings.Contains(err.Error(), "customer_id_template") {
		t.Fatalf("err = %v", err)
	}
	if len(f.calls("POST", "/v1/ingest")) != 0 {
		t.Fatal("event sent despite template error")
	}
}

func TestUsageDeletedTenant(t *testing.T) {
	_, reg, f := setup(t, nil)
	if err := reg.Deliver(context.Background(), "meters", periodClosed("t-gone", "api_calls", 3)); err != nil {
		t.Fatal(err)
	}
	ev := f.calls("POST", "/v1/ingest")[0].Body["events"].([]any)[0].(map[string]any)
	if ev["external_customer_id"] != "t-gone" || ev["properties"].(map[string]any)["value"] != float64(3) {
		t.Fatalf("event = %v", ev)
	}
}

func TestUsageErrors(t *testing.T) {
	_, reg, f := setup(t, nil)
	reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1"})
	reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-bad"})
	ctx := context.Background()
	f.failWith = 500
	if err := reg.Deliver(ctx, "meters", periodClosed("t-1", "api_calls", 3)); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err = %v", err)
	}
	if err := reg.Deliver(ctx, "meters", periodClosed("t-1", "api_calls", 3)); err != nil {
		t.Fatal(err)
	}
	f.reject = "t-bad"
	err := reg.Deliver(ctx, "meters", periodClosed("t-bad", "api_calls", 3))
	if err == nil || !strings.Contains(err.Error(), "customer not found") {
		t.Fatalf("validation failure not reported: %v", err)
	}
}

func TestHealth(t *testing.T) {
	p, _, f := setup(t, nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.key = "rotated"
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid API key") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := map[string]any{"api_key": "k", "metrics": map[string]string{"api_calls": "api_request"}}
	cases := []struct {
		name string
		set  map[string]any
		want string
	}{
		{"missing key", map[string]any{"api_key": ""}, "api_key is required"},
		{"no metrics", map[string]any{"metrics": nil}, "metrics"},
		{"empty event name", map[string]any{"metrics": map[string]string{"a": ""}}, "must not be empty"},
		{"bad url", map[string]any{"api_url": "withorb.com"}, "api_url"},
		{"bad timeout", map[string]any{"timeout": "-1s"}, "timeout"},
		{"reserved property", map[string]any{"property_name": "tenarium_metric"}, "property_name"},
		{"bad template", map[string]any{"customer_id_template": "{{"}, "customer_id_template"},
		{"unknown template field", map[string]any{"customer_id_template": "{{.Customer}}"}, "customer_id_template"},
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
	reg := sdktest.NewRegistrar(base)
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if p.base != "https://api.withorb.com" || p.client.Timeout != 10*time.Second || p.cfg.PropertyName != "value" ||
		p.cfg.CustomerIDTemplate != "{{.ID}}" || p.cfg.Debug {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	if len(reg.Subscriptions) != 1 || reg.Subscriptions[0].Name != "meters" ||
		reg.Subscriptions[0].Filter.Types[0] != sdk.EventTenantUsagePeriodClosed {
		t.Fatalf("subscriptions = %+v", reg.Subscriptions)
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{
		"api_key": "k", "api_url": "https://api.withorb.com", "timeout": "5s",
		"metrics": map[string]any{"api_calls": "api_request"}, "customer_id_template": "{{.ID}}",
		"property_name": "units", "debug": true,
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
		{"api_key": "k", "metrics": map[string]any{"a": "b"}, "property_name": "tenarium_period"},
		{"api_key": "k", "metrics": map[string]any{"a": "b"}, "extra": 1},
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
	f.key = "orb_rotated_key"
	f.mu.Unlock()
	cfg := map[string]any{"api_key": "orb_rotated_key", "api_url": f.srv.URL, "metrics": map[string]string{"api_calls": "new_event"}}
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg).Config); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(ctx, "meters", periodClosed(tn.ID, "api_calls", 7)); err != nil {
		t.Fatal(err)
	}

	// Invalid config: rejected, the previous one stays.
	cfg["property_name"] = "tenarium_metric"
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg).Config); err == nil {
		t.Fatal("reserved property_name accepted")
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	calls := f.calls("POST", "/v1/ingest")
	if len(calls) != 1 || calls[0].Auth != "Bearer orb_rotated_key" {
		t.Fatalf("ingest calls: %+v", calls)
	}
	if ev := calls[0].Body["events"].([]any)[0].(map[string]any); ev["event_name"] != "new_event" {
		t.Fatalf("event = %v", ev)
	}
	// Nothing in the configuration is fixed at startup: the subscribed
	// event is not configurable.
}
