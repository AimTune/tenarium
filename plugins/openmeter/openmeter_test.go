package openmeter

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
	Method, Path, Auth, UA, ContentType string
	Body                                map[string]any
}

// fakeOpenMeter is an in-memory OpenMeter API. key "" disables auth.
type fakeOpenMeter struct {
	t        *testing.T
	srv      *httptest.Server
	key      string
	mu       sync.Mutex
	reqs     []request
	seen     map[string]bool // id + source
	stored   int
	failWith int // next event POST fails with this status
}

func newFake(t *testing.T, key string) *fakeOpenMeter {
	f := &fakeOpenMeter{t: t, key: key, seen: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func problem(w http.ResponseWriter, status int, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": title, "status": status, "detail": title + " detail"})
}

func (f *fakeOpenMeter) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := io.ReadAll(r.Body)
	req := request{Method: r.Method, Path: r.URL.Path, Auth: r.Header.Get("Authorization"),
		UA: r.Header.Get("User-Agent"), ContentType: r.Header.Get("Content-Type")}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req.Body); err != nil {
			f.t.Errorf("invalid JSON body: %s", raw)
		}
	}
	f.reqs = append(f.reqs, req)
	if f.key != "" && req.Auth != "Bearer "+f.key {
		problem(w, 401, "Unauthorized")
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/meters":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	case r.Method == "POST" && r.URL.Path == "/api/v1/events":
		if f.failWith != 0 {
			s := f.failWith
			f.failWith = 0
			problem(w, s, "Internal Server Error")
			return
		}
		if req.ContentType != "application/cloudevents+json" || req.Body["specversion"] != "1.0" {
			problem(w, 400, "Bad Request")
			return
		}
		k := req.Body["id"].(string) + "|" + req.Body["source"].(string)
		if !f.seen[k] { // duplicates are accepted and dropped
			f.seen[k] = true
			f.stored++
		}
		w.WriteHeader(204)
	default:
		problem(w, 404, "Not Found")
	}
}

func (f *fakeOpenMeter) calls(method, path string) []request {
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

func setup(t *testing.T, key string, overrides map[string]any) (*Plugin, *sdktest.Registrar, *fakeOpenMeter) {
	t.Helper()
	f := newFake(t, key)
	cfg := map[string]any{
		"api_url": f.srv.URL,
		"metrics": map[string]string{"api_calls": "tenarium.api_calls"},
	}
	if key != "" {
		cfg["api_key"] = key
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
	_, reg, f := setup(t, "om_key", map[string]any{"subject_template": "{{.Plan}}:{{.Slug}}", "source": "tenarium-prod", "value_property": "amount"})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1", Slug: "acme", Plan: "pro"})
	ctx := context.Background()
	noEnd := periodClosed(tn.ID, "api_calls", 5)
	noEnd.Data, _ = json.Marshal(sdk.UsagePeriodData{TenantID: tn.ID, Metric: "api_calls", Period: "2026-10", Value: 5})
	for _, e := range []sdk.Event{
		periodClosed(tn.ID, "api_calls", 1234),
		periodClosed(tn.ID, "api_calls", 1234), // redelivery: deduplicated by OpenMeter
		periodClosed(tn.ID, "storage_gb", 5),   // not mapped
		periodClosed(tn.ID, "api_calls", 0),    // nothing to bill
		noEnd,                                  // no period end
	} {
		if err := reg.Deliver(ctx, "meters", e); err != nil {
			t.Fatal(err)
		}
	}
	calls := f.calls("POST", "/api/v1/events")
	if len(calls) != 2 || f.stored != 1 {
		t.Fatalf("event calls: %+v (stored %d)", calls, f.stored)
	}
	want := `{"data":{"amount":1234,"metric":"api_calls","period":"2026-10"},"datacontenttype":"application/json",` +
		`"id":"tenarium-t-1-api_calls-2026-10","source":"tenarium-prod","specversion":"1.0","subject":"pro:acme",` +
		`"time":"2026-10-31T23:59:59Z","type":"tenarium.api_calls"}`
	if got := mustJSON(calls[0].Body); got != want {
		t.Fatalf("body = %s\nwant %s", got, want)
	}
	if mustJSON(calls[1].Body) != want || calls[0].Auth != "Bearer om_key" || calls[0].UA != "tenarium-openmeter/"+version {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestNoAPIKey(t *testing.T) {
	p, reg, f := setup(t, "", nil)
	if err := reg.Deliver(context.Background(), "meters", periodClosed("t-gone", "api_calls", 2)); err != nil {
		t.Fatal(err)
	}
	c := f.calls("POST", "/api/v1/events")[0]
	// Deleted tenant: rendered with its ID only.
	if c.Auth != "" || c.Body["subject"] != "t-gone" || c.Body["data"].(map[string]any)["value"] != float64(2) {
		t.Fatalf("call = %+v", c)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUsageErrors(t *testing.T) {
	_, reg, f := setup(t, "k", map[string]any{"subject_template": `{{index .Labels "customer"}}`})
	reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1", Labels: map[string]string{"customer": "c-1"}})
	reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-2"})
	ctx := context.Background()
	f.failWith = 503
	if err := reg.Deliver(ctx, "meters", periodClosed("t-1", "api_calls", 3)); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("err = %v", err)
	}
	if err := reg.Deliver(ctx, "meters", periodClosed("t-1", "api_calls", 3)); err != nil {
		t.Fatal(err)
	}
	f.failWith = 400
	if err := reg.Deliver(ctx, "meters", periodClosed("t-1", "api_calls", 3)); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("err = %v", err)
	}
	if err := reg.Deliver(ctx, "meters", periodClosed("t-2", "api_calls", 3)); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty subject: %v", err)
	}
}

func TestHealth(t *testing.T) {
	p, _, f := setup(t, "k", nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.key = "rotated"
	if err := p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "401 Unauthorized") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := map[string]any{"metrics": map[string]string{"api_calls": "api.calls"}}
	cases := []struct {
		name string
		set  map[string]any
		want string
	}{
		{"no metrics", map[string]any{"metrics": map[string]string{}}, "metrics"},
		{"empty type", map[string]any{"metrics": map[string]string{"a": " "}}, "must not be empty"},
		{"bad url", map[string]any{"api_url": "openmeter.cloud"}, "api_url"},
		{"bad timeout", map[string]any{"timeout": "1 minute"}, "timeout"},
		{"reserved value property", map[string]any{"value_property": "metric"}, "value_property"},
		{"bad template", map[string]any{"subject_template": "{{end}}"}, "subject_template"},
		{"unknown template field", map[string]any{"subject_template": "{{.Subject}}"}, "subject_template"},
		{"unknown field", map[string]any{"api_token": "x"}, "unknown field"},
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
	if p.base != "https://openmeter.cloud" || p.client.Timeout != 10*time.Second || p.cfg.Source != "tenarium" ||
		p.cfg.ValueProperty != "value" || p.cfg.SubjectTemplate != "{{.ID}}" {
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
		"api_key": "om_1", "api_url": "http://openmeter:8888", "timeout": "5s",
		"metrics": map[string]any{"api_calls": "api.calls"}, "subject_template": "{{.Slug}}",
		"source": "tenarium", "value_property": "amount",
	}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := sch.Validate(map[string]any{"metrics": map[string]any{"a": "b"}}); err != nil {
		t.Fatalf("minimal config rejected: %v", err)
	}
	for _, bad := range []map[string]any{
		{},
		{"metrics": map[string]any{}},
		{"metrics": map[string]any{"a": ""}},
		{"metrics": map[string]any{"a": "b"}, "api_url": "ftp://x"},
		{"metrics": map[string]any{"a": "b"}, "value_property": "period"},
		{"metrics": map[string]any{"a": "b"}, "source": ""},
		{"metrics": map[string]any{"a": "b"}, "extra": 1},
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

func TestReconfigure(t *testing.T) {
	p, reg, f := setup(t, "om_key", nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1", Slug: "acme"})
	ctx := context.Background()
	f.mu.Lock()
	f.key = "om_rotated_key"
	f.mu.Unlock()
	cfg := map[string]any{"api_key": "om_rotated_key", "api_url": f.srv.URL, "metrics": map[string]string{"api_calls": "new.type"}}
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg).Config); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(ctx, "meters", periodClosed(tn.ID, "api_calls", 7)); err != nil {
		t.Fatal(err)
	}

	// Invalid config: rejected, the previous one stays.
	cfg["value_property"] = "metric"
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg).Config); err == nil {
		t.Fatal("reserved value_property accepted")
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("health: %v", err)
	}
	calls := f.calls("POST", "/api/v1/events")
	if len(calls) != 1 || calls[0].Auth != "Bearer om_rotated_key" || calls[0].Body["type"] != "new.type" {
		t.Fatalf("event calls: %+v", calls)
	}

	// source is part of the deduplication key.
	delete(cfg, "value_property")
	cfg["source"] = "other"
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg).Config); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("source change = %v", err)
	}
}
