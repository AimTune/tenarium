package segment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

var testNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type batchReq struct {
	User, Pass string
	Batch      []map[string]any
	SentAt     string
}

type fakeSegment struct {
	mu     sync.Mutex
	reqs   []batchReq
	status int
	// gate, if set, blocks requests until closed.
	gate chan struct{}
	srv  *httptest.Server
}

func newFake(t *testing.T) *fakeSegment {
	f := &fakeSegment{status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/batch" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		gate := f.gate
		f.mu.Unlock()
		if gate != nil {
			<-gate
		}
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Batch  []map[string]any `json:"batch"`
			SentAt string           `json:"sentAt"`
		}
		_ = json.Unmarshal(raw, &body)
		u, p, _ := r.BasicAuth()
		f.mu.Lock()
		f.reqs = append(f.reqs, batchReq{u, p, body.Batch, body.SentAt})
		status := f.status
		f.mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSegment) requests() []batchReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]batchReq(nil), f.reqs...)
}

func (f *fakeSegment) messages() []map[string]any {
	var out []map[string]any
	for _, r := range f.requests() {
		out = append(out, r.Batch...)
	}
	return out
}

func setup(t *testing.T, f *fakeSegment, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	full := map[string]any{"write_key": "wk_123", "api_url": f.srv.URL}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{now: func() time.Time { return testNow }}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p, reg
}

func tenant() sdk.Tenant {
	return sdk.Tenant{
		ID: "t-1", Slug: "acme", Name: "Acme", Plan: "pro", Status: sdk.StatusActive,
		Labels: map[string]string{"region": "eu"}, CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

func TestGroup(t *testing.T) {
	f := newFake(t)
	_, reg := setup(t, f, nil)
	e := sdktest.TenantEvent(sdk.EventTenantCreated, tenant())
	e.Time = testNow.Add(-time.Minute)
	if err := reg.Deliver(context.Background(), "group", e); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	if len(reqs) != 1 || reqs[0].User != "wk_123" || reqs[0].Pass != "" || reqs[0].SentAt != "2026-10-10T12:00:00Z" {
		t.Fatalf("requests = %+v", reqs)
	}
	m := reqs[0].Batch[0]
	traits := m["traits"].(map[string]any)
	if m["type"] != "group" || m["messageId"] != e.ID+":group" || m["groupId"] != "t-1" || m["anonymousId"] != "tenant:t-1" ||
		m["timestamp"] != "2026-10-10T11:59:00Z" || traits["plan"] != "pro" || traits["slug"] != "acme" ||
		traits["status"] != "active" || traits["label_region"] != "eu" || traits["created_at"] != "2026-01-02T03:04:05Z" {
		t.Fatalf("message = %v", m)
	}
	lib := m["context"].(map[string]any)["library"].(map[string]any)
	if lib["name"] != "tenarium-segment" || lib["version"] != version {
		t.Fatalf("library = %v", lib)
	}
	// Member and usage events match tenant.* but are not group calls.
	for _, e := range []sdk.Event{
		sdktest.MemberEvent(sdk.EventMemberAdded, sdk.Member{TenantID: "t-1", UserID: "u-1"}),
		{ID: "q", Type: sdk.EventTenantQuotaExceeded, TenantID: "t-1", Data: json.RawMessage(`{}`)},
	} {
		if err := reg.Deliver(context.Background(), "group", e); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.requests()) != 1 {
		t.Fatal("non-tenant event sent as group")
	}
}

func TestIdentifyAndMembers(t *testing.T) {
	f := newFake(t)
	_, reg := setup(t, f, map[string]any{"include_labels": false})
	ctx := context.Background()
	data, _ := json.Marshal(sdk.UserEventData{User: sdk.User{ID: "u-1", Email: "a@x.io", Name: "Ann", Status: sdk.UserActive}})
	if err := reg.Deliver(ctx, "identify", sdk.Event{ID: "e1", Type: sdk.EventUserCreated, Time: testNow, Data: data}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(ctx, "members", sdktest.MemberEvent(sdk.EventMemberAdded, sdk.Member{ID: "m", TenantID: "t-1", UserID: "u-1", Email: "a@x.io", Role: "admin"})); err != nil {
		t.Fatal(err)
	}
	// Invited members have no user yet.
	if err := reg.Deliver(ctx, "members", sdktest.MemberEvent(sdk.EventMemberAdded, sdk.Member{ID: "m2", TenantID: "t-1", Email: "b@x.io"})); err != nil {
		t.Fatal(err)
	}
	msgs := f.messages()
	if len(msgs) != 2 {
		t.Fatalf("messages = %v", msgs)
	}
	id := msgs[0]
	if id["type"] != "identify" || id["userId"] != "u-1" || id["messageId"] != "e1:identify" ||
		id["traits"].(map[string]any)["email"] != "a@x.io" || id["traits"].(map[string]any)["name"] != "Ann" {
		t.Fatalf("identify = %v", id)
	}
	g := msgs[1]
	if g["type"] != "group" || g["userId"] != "u-1" || g["groupId"] != "t-1" || !strings.HasSuffix(g["messageId"].(string), ":member") ||
		g["context"].(map[string]any)["traits"].(map[string]any)["role"] != "admin" {
		t.Fatalf("member group = %v", g)
	}
}

func TestTrack(t *testing.T) {
	f := newFake(t)
	_, reg := setup(t, f, map[string]any{
		"track_events":        []string{"tenant.plan_changed", "tenant.quota_exceeded"},
		"event_names":         map[string]string{"tenant.plan_changed": "Plan Changed"},
		"user_actor_prefixes": []string{"session"},
	})
	ctx := context.Background()
	tn := tenant()
	prev := tn
	prev.Plan = "free"
	e := sdktest.TenantEvent(sdk.EventTenantPlanChanged, tn)
	e.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: tn, Previous: &prev})
	e.Actor = "session:u-9"
	if err := reg.Deliver(ctx, "track", e); err != nil {
		t.Fatal(err)
	}
	quota, _ := json.Marshal(sdk.UsageEventData{TenantID: "t-1", Metric: "seats", Current: 5, Requested: 1, Limit: 5})
	if err := reg.Deliver(ctx, "track", sdk.Event{ID: "q", Type: sdk.EventTenantQuotaExceeded, TenantID: "t-1", Actor: "oidc:abc", Data: quota}); err != nil {
		t.Fatal(err)
	}
	// Not selected.
	if err := reg.Deliver(ctx, "track", sdktest.TenantEvent(sdk.EventTenantUpdated, tn)); err != nil {
		t.Fatal(err)
	}
	msgs := f.messages()
	if len(msgs) != 2 {
		t.Fatalf("messages = %v", msgs)
	}
	m := msgs[0]
	props := m["properties"].(map[string]any)
	if m["type"] != "track" || m["event"] != "Plan Changed" || m["userId"] != "u-9" || m["anonymousId"] != nil ||
		m["context"].(map[string]any)["groupId"] != "t-1" || props["plan"] != "pro" || props["previous_plan"] != "free" ||
		props["tenant_id"] != "t-1" || props["actor"] != "session:u-9" {
		t.Fatalf("track = %v", m)
	}
	q := msgs[1]
	if q["event"] != "tenant.quota_exceeded" || q["anonymousId"] != "tenant:t-1" || q["properties"].(map[string]any)["metric"] != "seats" {
		t.Fatalf("track = %v", q)
	}
}

func TestBatchingSharesRequests(t *testing.T) {
	f := newFake(t)
	f.gate = make(chan struct{})
	_, reg := setup(t, f, map[string]any{"track_events": []string{"*"}, "batch_size": 3})
	ctx := context.Background()
	const n = 7
	errs := make(chan error, n)
	// The first delivery holds the request open; the others queue behind it.
	go func() { errs <- reg.Deliver(ctx, "track", sdk.Event{ID: "e0", Type: "x.y"}) }()
	time.Sleep(50 * time.Millisecond)
	for i := 1; i < n; i++ {
		go func() { errs <- reg.Deliver(ctx, "track", sdk.Event{ID: fmt.Sprint("e", i), Type: "x.y"}) }()
	}
	time.Sleep(100 * time.Millisecond)
	close(f.gate)
	for range n {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	reqs := f.requests()
	sizes := make([]int, len(reqs))
	total := 0
	for i, r := range reqs {
		sizes[i] = len(r.Batch)
		total += len(r.Batch)
	}
	// 1 + 6 queued messages in batches of at most 3.
	if total != n || len(reqs) != 3 || sizes[0] != 1 || sizes[1] != 3 || sizes[2] != 3 {
		t.Fatalf("batch sizes = %v", sizes)
	}
}

func TestBatchErrorPropagates(t *testing.T) {
	f := newFake(t)
	f.status = http.StatusUnauthorized
	p, reg := setup(t, f, map[string]any{"track_events": []string{"*"}})
	err := reg.Deliver(context.Background(), "track", sdk.Event{ID: "e", Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "wk_123") {
		t.Fatalf("err = %v", err)
	}
	if err := p.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOversizedMessage(t *testing.T) {
	f := newFake(t)
	_, reg := setup(t, f, nil)
	tn := tenant()
	tn.Labels = map[string]string{"big": strings.Repeat("x", 40<<10)}
	if err := reg.Deliver(context.Background(), "group", sdktest.TenantEvent(sdk.EventTenantUpdated, tn)); err == nil {
		t.Fatal("oversized message accepted")
	}
	if len(f.requests()) != 0 {
		t.Fatal("oversized message sent")
	}
}

func TestSubscriptionsAndDefaults(t *testing.T) {
	f := newFake(t)
	p, reg := setup(t, f, map[string]any{"group_events": []string{}, "identify_users": false})
	if len(reg.Subscriptions) != 1 || reg.Subscriptions[0].Name != "members" {
		t.Fatalf("subscriptions = %+v", reg.Subscriptions)
	}
	if p.client.Timeout != 10*time.Second || p.cfg.BatchSize != 100 {
		t.Fatalf("defaults: %+v", p.cfg)
	}
	reg2 := sdktest.NewRegistrar(map[string]any{"write_key": "k"})
	p2 := &Plugin{}
	if err := p2.Init(context.Background(), reg2); err != nil {
		t.Fatal(err)
	}
	if p2.base != "https://api.segment.io" || len(reg2.Subscriptions) != 3 || p2.Health(context.Background()) != nil {
		t.Fatalf("defaults: %s %+v", p2.base, reg2.Subscriptions)
	}
}

func TestInitValidation(t *testing.T) {
	for name, cfg := range map[string]map[string]any{
		"no key":        {},
		"bad url":       {"write_key": "k", "api_url": "api.segment.io"},
		"bad timeout":   {"write_key": "k", "timeout": "x"},
		"batch size":    {"write_key": "k", "batch_size": 501},
		"bad pattern":   {"write_key": "k", "track_events": []string{"["}},
		"bad group":     {"write_key": "k", "group_events": []string{""}},
		"empty name":    {"write_key": "k", "event_names": map[string]string{"x": ""}},
		"actor colon":   {"write_key": "k", "user_actor_prefixes": []string{"a:b"}},
		"unknown field": {"write_key": "k", "writekey": "k"},
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
		"write_key": "k", "api_url": "https://events.eu1.segmentapis.com", "timeout": "5s",
		"group_events": []any{"tenant.*"}, "identify_users": true, "link_members": false,
		"track_events": []any{"tenant.created"}, "event_names": map[string]any{"tenant.created": "Tenant Created"},
		"user_actor_prefixes": []any{"session"}, "include_labels": false, "batch_size": 50,
	}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, bad := range []map[string]any{
		{},
		{"write_key": ""},
		{"write_key": "k", "batch_size": 0},
		{"write_key": "k", "api_url": "ftp://x"},
		{"write_key": "k", "extra": 1},
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

func TestReconfigure(t *testing.T) {
	f := newFake(t)
	p, reg := setup(t, f, map[string]any{"track_events": []any{"tenant.*"}})
	ctx := context.Background()
	track := func() batchReq {
		t.Helper()
		if err := reg.Deliver(ctx, "track", sdktest.TenantEvent(sdk.EventTenantCreated, tenant())); err != nil {
			t.Fatal(err)
		}
		reqs := f.requests()
		return reqs[len(reqs)-1]
	}
	cfg := func(extra map[string]any) func(v any) error {
		full := map[string]any{"write_key": "wk_new", "api_url": f.srv.URL, "track_events": []any{"tenant.*"}}
		for k, v := range extra {
			full[k] = v
		}
		return sdktest.NewRegistrar(full).Config
	}
	track()

	if err := p.Reconfigure(ctx, cfg(map[string]any{"event_names": map[string]any{"tenant.created": "Tenant Created"}})); err != nil {
		t.Fatal(err)
	}
	if r := track(); r.User != "wk_new" || r.Batch[0]["event"] != "Tenant Created" {
		t.Fatalf("new settings not used: %+v", r)
	}

	if err := p.Reconfigure(ctx, cfg(map[string]any{"write_key": "wk_bad", "timeout": "-1s"})); err == nil {
		t.Fatal("invalid timeout accepted")
	}
	if r := track(); r.User != "wk_new" {
		t.Fatalf("invalid config applied: %+v", r)
	}

	for _, extra := range []map[string]any{
		{"track_events": []any{"user.*"}},
		{"link_members": false},
		{"batch_size": 10},
	} {
		if err := p.Reconfigure(ctx, cfg(extra)); err == nil || !strings.Contains(err.Error(), "restart") {
			t.Fatalf("%v: err = %v", extra, err)
		}
	}
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
