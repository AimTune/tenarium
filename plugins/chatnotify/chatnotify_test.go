package chatnotify

import (
	"context"
	"encoding/json"
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

type req struct {
	Path   string
	Header http.Header
	Body   map[string]any
}

type fake struct {
	mu     sync.Mutex
	reqs   []req
	srv    *httptest.Server
	status int
	body   string
}

func newFake(t *testing.T) *fake {
	f := &fake{status: http.StatusOK, body: "ok"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		f.mu.Lock()
		f.reqs = append(f.reqs, req{r.URL.Path, r.Header.Clone(), m})
		status, body := f.status, f.body
		f.mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/auth.test") || strings.HasSuffix(r.URL.Path, "/chat.postMessage") {
			if body == "ok" {
				body = `{"ok":true}`
			}
		}
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "30")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) requests() []req {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]req(nil), f.reqs...)
}

func (f *fake) set(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func setup(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{now: clk.now}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p, reg, clk
}

func suspended() sdk.Event {
	e := sdktest.TenantEvent(sdk.EventTenantSuspended, sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme", Status: sdk.StatusSuspended, StatusReason: "billing: unpaid"})
	e.Actor = "plugin:stripe"
	e.Time = time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	return e
}

func TestSlackWebhook(t *testing.T) {
	f := newFake(t)
	_, reg, _ := setup(t, map[string]any{"targets": []any{map[string]any{
		"name": "ops", "type": "slack_webhook", "url": f.srv.URL + "/services/T/B/X",
	}}})
	ctx := context.Background()
	e := suspended()
	if err := reg.Deliver(ctx, "notify-ops", e); err != nil {
		t.Fatal(err)
	}
	if err := reg.Deliver(ctx, "notify-ops", e); err != nil { // redelivery: not posted twice
		t.Fatal(err)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	want := "*Tenarium: tenant.suspended*\nTenant Acme (acme) was suspended: billing: unpaid (by plugin:stripe)."
	if reqs[0].Path != "/services/T/B/X" || reqs[0].Body["text"] != want {
		t.Fatalf("request = %+v", reqs[0])
	}
	// Events outside the default filter are not delivered.
	if err := reg.Deliver(ctx, "notify-ops", sdktest.TenantEvent(sdk.EventTenantUpdated, sdk.Tenant{ID: "t-1"})); err != nil {
		t.Fatal(err)
	}
	if len(f.requests()) != 1 {
		t.Fatal("filtered event was posted")
	}
}

func TestSlackBot(t *testing.T) {
	f := newFake(t)
	p, reg, _ := setup(t, map[string]any{"targets": []any{map[string]any{
		"name": "bot", "type": "slack_bot", "token": "xoxb-1", "channel": "C123", "api_base": f.srv.URL + "/api",
	}}})
	ctx := context.Background()
	if err := reg.Deliver(ctx, "notify-bot", suspended()); err != nil {
		t.Fatal(err)
	}
	r := f.requests()[0]
	if r.Path != "/api/chat.postMessage" || r.Header.Get("Authorization") != "Bearer xoxb-1" || r.Body["channel"] != "C123" {
		t.Fatalf("request = %+v", r)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if f.requests()[1].Path != "/api/auth.test" {
		t.Fatal("health did not call auth.test")
	}
	f.set(http.StatusOK, `{"ok":false,"error":"channel_not_found"}`)
	e := suspended()
	e.ID = "other"
	if err := reg.Deliver(ctx, "notify-bot", e); err == nil || !strings.Contains(err.Error(), "channel_not_found") {
		t.Fatalf("err = %v", err)
	}
	if err := p.Health(ctx); err == nil {
		t.Fatal("health passed with a failing token")
	}
	f.set(http.StatusTooManyRequests, "")
	if err := reg.Deliver(ctx, "notify-bot", e); err == nil || !strings.Contains(err.Error(), "Retry-After") {
		t.Fatalf("err = %v", err)
	}
}

func TestTeams(t *testing.T) {
	f := newFake(t)
	f.set(http.StatusAccepted, "")
	_, reg, _ := setup(t, map[string]any{
		"title": "{{.TenantLabel}}",
		"targets": []any{
			map[string]any{"name": "wf", "type": "teams_workflow", "url": f.srv.URL + "/workflows/x?sig=secret"},
			map[string]any{"name": "legacy", "type": "teams_webhook", "url": f.srv.URL + "/webhookb2/x"},
		},
	})
	ctx := context.Background()
	if err := reg.Deliver(ctx, "notify-wf", suspended()); err != nil {
		t.Fatal(err)
	}
	r := f.requests()[0]
	if r.Body["type"] != "message" {
		t.Fatalf("body = %v", r.Body)
	}
	att := r.Body["attachments"].([]any)[0].(map[string]any)
	card := att["content"].(map[string]any)
	body := card["body"].([]any)
	if att["contentType"] != "application/vnd.microsoft.card.adaptive" || card["type"] != "AdaptiveCard" ||
		body[0].(map[string]any)["text"] != "Acme (acme)" ||
		!strings.HasPrefix(body[1].(map[string]any)["text"].(string), "Tenant Acme (acme) was suspended") {
		t.Fatalf("card = %v", card)
	}
	facts := body[2].(map[string]any)["facts"].([]any)
	if len(facts) != 4 || facts[2].(map[string]any)["value"] != "plugin:stripe" {
		t.Fatalf("facts = %v", facts)
	}
	// A legacy connector reports failures in a 200 body.
	f.set(http.StatusOK, "Webhook message delivery failed with error: Microsoft Teams endpoint returned HTTP error 400")
	if err := reg.Deliver(ctx, "notify-legacy", suspended()); err == nil {
		t.Fatal("legacy failure not detected")
	}
	f.set(http.StatusOK, "1")
	if err := reg.Deliver(ctx, "notify-legacy", suspended()); err != nil {
		t.Fatal(err)
	}
	// Errors must not leak the secret-bearing URL.
	f.set(http.StatusBadRequest, "bad")
	e := suspended()
	e.ID = "x"
	if err := reg.Deliver(ctx, "notify-wf", e); err == nil || strings.Contains(err.Error(), "sig=secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestTemplates(t *testing.T) {
	f := newFake(t)
	p, reg, _ := setup(t, map[string]any{
		"events": []string{"tenant.*"},
		"templates": map[string]string{
			"tenant.*":              "generic {{.Event.Type}}",
			"tenant.quota_exceeded": "{{upper .Tenant.Slug}} over {{.Quota.Metric}} ({{.Quota.Limit}})",
			"tenant.created":        "{{.Tenant.Nope}}", // fails at execution: fallback
		},
		"targets": []any{
			map[string]any{"name": "a", "type": "slack_webhook", "url": f.srv.URL},
			map[string]any{"name": "b", "type": "slack_webhook", "url": f.srv.URL, "template": "custom {{.Event.ID}}", "events": []string{"tenant.created"}},
		},
	})
	reg.HostImpl.AddTenant(sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme"})
	ctx := context.Background()
	quota, _ := json.Marshal(sdk.UsageEventData{TenantID: "t-1", Metric: "seats", Current: 5, Requested: 1, Limit: 5})
	created := sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme"})
	created.ID = "ev-c"
	steps := []struct {
		sub string
		e   sdk.Event
	}{
		{"notify-a", sdk.Event{ID: "q", Type: sdk.EventTenantQuotaExceeded, TenantID: "t-1", Data: quota}},
		{"notify-a", sdktest.TenantEvent(sdk.EventTenantResumed, sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme"})},
		{"notify-a", created},
		{"notify-b", created},
	}
	for _, s := range steps {
		if err := reg.Deliver(ctx, s.sub, s.e); err != nil {
			t.Fatal(err)
		}
	}
	var texts []string
	for _, r := range f.requests() {
		texts = append(texts, strings.SplitN(r.Body["text"].(string), "\n", 2)[1])
	}
	want := []string{"ACME over seats (5)", "generic tenant.resumed", "tenant.created for tenant Acme (acme)", "custom ev-c"}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Fatalf("texts = %q, want %q", texts, want)
	}
	if p.templates[0].pattern != "tenant.created" || p.templates[2].pattern != "tenant.*" {
		t.Fatalf("template order = %v", p.templates)
	}
}

func TestBuiltinTemplates(t *testing.T) {
	p, _, _ := setup(t, map[string]any{"targets": []any{map[string]any{"name": "a", "type": "slack_webhook", "url": "https://x"}}})
	tn := sdk.Tenant{ID: "t-1", Slug: "acme", Name: "Acme", Plan: "pro"}
	prev := tn
	prev.Plan = "free"
	limit := int64(1000)
	usage, _ := json.Marshal(sdk.UsagePeriodData{TenantID: "t-1", Metric: "api_calls", Period: "2026-10", Value: 800, Limit: &limit, Percent: 80})
	planChanged := sdktest.TenantEvent(sdk.EventTenantPlanChanged, tn)
	planChanged.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: tn, Previous: &prev})
	member := sdktest.MemberEvent(sdk.EventMemberAdded, sdk.Member{TenantID: "t-1", Email: "a@x.io", Role: "admin"})
	for e, want := range map[*sdk.Event]string{
		&planChanged: "Tenant Acme (acme) changed plan from free to pro.",
		{Type: sdk.EventTenantUsageThreshold, TenantID: "t-1", Data: usage}: "Tenant t-1 reached 80% of its api_calls limit (800 of 1000, period 2026-10).",
		&member:                                 "a@x.io was added to tenant t-1 as admin.",
		{Type: "user.created", Actor: "system"}: "user.created by system",
	} {
		d := newData(*e)
		if got := p.render(p.templateFor(p.targets[0], e.Type), d); got != want {
			t.Errorf("%s: got %q, want %q", e.Type, got, want)
		}
	}
	for typ := range builtin {
		// Every built-in template renders with an empty payload (fallback).
		if got := p.render(builtinTemplates[typ], Data{Event: sdk.Event{Type: typ}}); got == "" {
			t.Errorf("%s renders empty", typ)
		}
	}
}

func TestRateLimit(t *testing.T) {
	f := newFake(t)
	_, reg, clk := setup(t, map[string]any{"targets": []any{map[string]any{
		"name": "ops", "type": "slack_webhook", "url": f.srv.URL, "rate_limit": map[string]any{"per_minute": 2, "burst": 2},
	}}})
	ctx := context.Background()
	send := func(id string) {
		e := suspended()
		e.ID = id
		if err := reg.Deliver(ctx, "notify-ops", e); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"1", "2", "3", "4"} {
		send(id)
	}
	if n := len(f.requests()); n != 2 {
		t.Fatalf("sent %d, want 2 (burst)", n)
	}
	clk.add(30 * time.Second) // one token refilled
	send("5")
	reqs := f.requests()
	if len(reqs) != 3 || !strings.Contains(reqs[2].Body["text"].(string), "(2 earlier notification(s) suppressed") {
		t.Fatalf("requests = %+v", reqs)
	}
	clk.add(30 * time.Second)
	send("6")
	if text := f.requests()[3].Body["text"].(string); strings.Contains(text, "suppressed") {
		t.Fatalf("suppressed count not reset: %s", text)
	}
	// A failed post gives its token back, so the retry is not rate limited.
	f.set(http.StatusInternalServerError, "")
	clk.add(30 * time.Second)
	if err := reg.Deliver(ctx, "notify-ops", suspended()); err == nil {
		t.Fatal("5xx not reported")
	}
	f.set(http.StatusOK, "ok")
	if err := reg.Deliver(ctx, "notify-ops", suspended()); err != nil {
		t.Fatal(err)
	}
	if n := len(f.requests()); n != 6 {
		t.Fatalf("retry was rate limited: %d requests", n)
	}
}

func TestInitValidation(t *testing.T) {
	ok := map[string]any{"name": "a", "type": "slack_webhook", "url": "https://hooks.slack.com/x"}
	with := func(kv ...any) map[string]any {
		m := map[string]any{}
		for k, v := range ok {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	for name, cfg := range map[string]map[string]any{
		"no targets":     {},
		"empty targets":  {"targets": []any{}},
		"bad name":       {"targets": []any{with("name", "Ops Team")}},
		"duplicate":      {"targets": []any{ok, ok}},
		"bad type":       {"targets": []any{with("type", "discord")}},
		"no url":         {"targets": []any{with("url", "")}},
		"relative url":   {"targets": []any{with("url", "/hook")}},
		"bot no token":   {"targets": []any{map[string]any{"name": "b", "type": "slack_bot", "channel": "C1"}}},
		"bot with url":   {"targets": []any{map[string]any{"name": "b", "type": "slack_bot", "token": "x", "channel": "C1", "url": "https://x"}}},
		"token on hook":  {"targets": []any{with("token", "x")}},
		"bad template":   {"targets": []any{with("template", "{{.Event")}},
		"bad templates":  {"targets": []any{ok}, "templates": map[string]string{"tenant.*": "{{if}}"}},
		"bad pattern":    {"targets": []any{ok}, "templates": map[string]string{"[": "x"}},
		"bad events":     {"targets": []any{with("events", []string{"["})}},
		"bad title":      {"targets": []any{ok}, "title": "{{"},
		"bad timeout":    {"targets": []any{ok}, "timeout": "-1s"},
		"negative limit": {"targets": []any{with("rate_limit", map[string]any{"per_minute": -1})}},
		"unknown key":    {"targets": []any{with("colour", "red")}},
	} {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}

func TestDefaults(t *testing.T) {
	p, reg, _ := setup(t, map[string]any{"targets": []any{map[string]any{"name": "ops", "type": "slack_bot", "token": "x", "channel": "C1"}}})
	tg := p.targets[0]
	if p.client.Timeout != 10*time.Second || tg.cfg.APIBase != "https://slack.com/api" || tg.limiter.burst != 30 ||
		len(tg.events) != len(DefaultEvents) {
		t.Fatalf("defaults not applied: %+v", tg.cfg)
	}
	if len(reg.Subscriptions) != 1 || reg.Subscriptions[0].Name != "notify-ops" {
		t.Fatalf("subscriptions = %+v", reg.Subscriptions)
	}
}

func TestHealthWebhookOnly(t *testing.T) {
	p, _, _ := setup(t, map[string]any{"targets": []any{map[string]any{"name": "a", "type": "teams_webhook", "url": "https://unreachable.invalid/x"}}})
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{
		"events": []any{"tenant.*"}, "templates": map[string]any{"tenant.created": "x"}, "title": "t", "timeout": "5s",
		"targets": []any{
			map[string]any{"name": "a", "type": "slack_webhook", "url": "https://hooks.slack.com/x", "events": []any{"tenant.*"},
				"template": "x", "rate_limit": map[string]any{"per_minute": 10, "burst": 5}},
			map[string]any{"name": "b", "type": "slack_bot", "token": "xoxb", "channel": "C1", "api_base": "https://slack.com/api"},
			map[string]any{"name": "c", "type": "teams_workflow", "url": "https://x.logic.azure.com/w"},
		},
	}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, bad := range []map[string]any{
		{},
		{"targets": []any{}},
		{"targets": []any{map[string]any{"name": "a", "type": "slack_webhook"}}},
		{"targets": []any{map[string]any{"name": "a", "type": "slack_bot", "token": "x"}}},
		{"targets": []any{map[string]any{"name": "A B", "type": "slack_webhook", "url": "https://x"}}},
		{"targets": []any{map[string]any{"name": "a", "type": "irc", "url": "https://x"}}},
		{"targets": []any{map[string]any{"name": "a", "type": "slack_webhook", "url": "https://x", "x": 1}}},
		{"targets": []any{map[string]any{"name": "a", "type": "slack_webhook", "url": "https://x", "rate_limit": map[string]any{"per_minute": 0}}}},
		{"targets": []any{map[string]any{"name": "a", "type": "slack_webhook", "url": "https://x"}}, "extra": true},
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

func TestReconfigure(t *testing.T) {
	f := newFake(t)
	cfg := func(url, tmpl string) map[string]any {
		return map[string]any{
			"events":    []any{"tenant.*"},
			"templates": map[string]any{"tenant.suspended": tmpl},
			"targets":   []any{map[string]any{"name": "ops", "type": "slack_webhook", "url": url}},
		}
	}
	p, reg, _ := setup(t, cfg(f.srv.URL+"/old", "old {{.Tenant.Name}}"))
	ctx := context.Background()
	send := func(id string) req {
		t.Helper()
		e := suspended()
		e.ID = id
		if err := reg.Deliver(ctx, "notify-ops", e); err != nil {
			t.Fatal(err)
		}
		reqs := f.requests()
		return reqs[len(reqs)-1]
	}
	send("1")

	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg(f.srv.URL+"/new", "new {{.Tenant.Name}}")).Config); err != nil {
		t.Fatal(err)
	}
	if r := send("2"); r.Path != "/new" || !strings.Contains(r.Body["text"].(string), "new Acme") {
		t.Fatalf("new settings not used: %+v", r)
	}
	send("1") // already posted before the reload: still deduplicated
	if n := len(f.requests()); n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}

	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(cfg(f.srv.URL+"/bad", "{{.Nope")).Config); err == nil {
		t.Fatal("invalid template accepted")
	}
	if r := send("3"); r.Path != "/new" {
		t.Fatalf("invalid config applied: %+v", r)
	}

	fixed := cfg(f.srv.URL+"/new", "x")
	fixed["events"] = []any{"tenant.created"}
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(fixed).Config); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("events change: err = %v", err)
	}
	renamed := cfg(f.srv.URL+"/new", "x")
	renamed["targets"] = []any{map[string]any{"name": "dev", "type": "slack_webhook", "url": f.srv.URL}}
	if err := p.Reconfigure(ctx, sdktest.NewRegistrar(renamed).Config); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("renamed target: err = %v", err)
	}
}
