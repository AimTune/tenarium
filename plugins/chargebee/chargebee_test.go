package chargebee

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

const (
	testUser = "chargebee"
	testPass = "s3cret-webhook-password"
)

var testNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T, overrides map[string]any) (*Plugin, *sdktest.Registrar, *fakeChargebee) {
	t.Helper()
	f := newFakeChargebee(t)
	cfg := map[string]any{
		"site":             "acme-test",
		"api_key":          f.key,
		"api_base":         f.base(),
		"webhook_username": testUser,
		"webhook_password": testPass,
		"plans":            map[string]string{"pro": "pro-USD-Monthly", "enterprise": "ent-USD-Yearly"},
	}
	maps.Copy(cfg, overrides)
	reg := sdktest.NewRegistrar(cfg)
	for _, id := range []string{"free", "pro", "enterprise"} {
		reg.HostImpl.AddPlan(sdk.Plan{ID: id, Name: id})
	}
	p := &Plugin{now: func() time.Time { return testNow }}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p, reg, f
}

func deliver(t *testing.T, reg *sdktest.Registrar, e sdk.Event) {
	t.Helper()
	if err := reg.Deliver(context.Background(), "sync", e); err != nil {
		t.Fatalf("deliver %s: %v", e.Type, err)
	}
}

func planEvent(t sdk.Tenant, from string) sdk.Event {
	e := sdktest.TenantEvent(sdk.EventTenantPlanChanged, t)
	prev := t
	prev.Plan = from
	e.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: t, Previous: &prev})
	return e
}

func TestCreatedIsIdempotent(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"tenant_id_field": "cf_tenarium_tenant_id"})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro"})
	e := sdktest.TenantEvent(sdk.EventTenantCreated, tn)
	deliver(t, reg, e)
	deliver(t, reg, e) // redelivery

	c := f.customer(tn.ID)
	if c == nil {
		t.Fatalf("no customer with the tenant ID (%s)", f)
	}
	if c.Company != "Acme" || c.MetaData["tenarium_slug"] != "acme" || c.MetaData["tenarium_tenant_id"] != tn.ID ||
		c.Custom["cf_tenarium_tenant_id"] != tn.ID {
		t.Errorf("customer = %+v", c)
	}
	subs := f.subsOf(tn.ID)
	if len(subs) != 1 {
		t.Fatalf("subscriptions = %d, want 1", len(subs))
	}
	if s := subs[0]; s.ID != tn.ID || s.Price != "pro-USD-Monthly" || s.MetaData["tenarium_tenant_id"] != tn.ID || s.Status != "active" {
		t.Errorf("subscription = %+v", s)
	}
	if n := len(f.callsTo("POST", "/customers")); n != 2 {
		t.Errorf("POST /customers... calls = %d, want 2 (one customer, one subscription)", n)
	}
}

func TestCreatedTreatsDuplicateAsExisting(t *testing.T) {
	// A redelivery whose lookups miss the objects created by the first
	// attempt runs into duplicate_entry, which must count as success.
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro"})
	e := sdktest.TenantEvent(sdk.EventTenantCreated, tn)
	deliver(t, reg, e)
	f.hideCustomer = 1 // the first GET misses the customer
	f.mu.Lock()
	f.subOrder = nil // and the subscription list misses the subscription
	f.mu.Unlock()
	deliver(t, reg, e)
	if n := len(f.callsTo("POST", "/customers/"+tn.ID+"/subscription_for_items")); n != 2 {
		t.Fatalf("subscription creations = %d, want 2", n)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.customers) != 1 || len(f.subs) != 1 || f.subs[tn.ID].Price != "pro-USD-Monthly" {
		t.Fatalf("state: %d customers, %d subscriptions", len(f.customers), len(f.subs))
	}
}

func TestCreatedUnbilledPlan(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "free"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if f.customer(tn.ID) == nil {
		t.Fatal("no customer")
	}
	if subs := f.subsOf(tn.ID); len(subs) != 0 {
		t.Fatalf("unbilled plan got subscriptions: %+v", subs)
	}
}

func TestCreatedWithoutCreateCustomers(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"create_customers": false})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if f.customer(tn.ID) != nil {
		t.Fatal("customer created although create_customers is off")
	}
	f.seedCustomer(tn.ID, nil)
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if subs := f.subsOf(tn.ID); len(subs) != 1 || subs[0].Price != "pro-USD-Monthly" {
		t.Fatalf("subscriptions = %+v", subs)
	}
}

func TestPlanChanged(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))

	// Billed → billed: the items are replaced.
	tn.Plan = "enterprise"
	deliver(t, reg, planEvent(tn, "pro"))
	subs := f.subsOf(tn.ID)
	if len(subs) != 1 || subs[0].Price != "ent-USD-Yearly" {
		t.Fatalf("after upgrade: %+v", subs)
	}
	upd := f.callsTo("POST", "/subscriptions/"+tn.ID+"/update_for_items")
	if len(upd) != 1 || upd[0].Form["replace_items_list"] != "true" || upd[0].Form["subscription_items[item_price_id][0]"] != "ent-USD-Yearly" {
		t.Fatalf("update calls = %+v", upd)
	}
	deliver(t, reg, planEvent(tn, "pro")) // redelivery is a no-op
	if n := len(f.callsTo("POST", "/subscriptions/"+tn.ID+"/update_for_items")); n != 1 {
		t.Fatalf("redelivery updated again (%d calls)", n)
	}

	// Billed → unbilled: cancelled immediately.
	tn.Plan = "free"
	deliver(t, reg, planEvent(tn, "enterprise"))
	if s := f.subsOf(tn.ID)[0]; s.Status != "cancelled" {
		t.Fatalf("after downgrade status = %s", s.Status)
	}
	if c := f.callsTo("POST", "/subscriptions/"+tn.ID+"/cancel_for_items"); len(c) != 1 || c[0].Form["end_of_term"] != "false" {
		t.Fatalf("cancel calls = %+v", c)
	}

	// Unbilled → billed: the cancelled subscription (same ID) is reactivated.
	tn.Plan = "pro"
	deliver(t, reg, planEvent(tn, "free"))
	subs = f.subsOf(tn.ID)
	if len(subs) != 1 || subs[0].Status != "active" || subs[0].Price != "pro-USD-Monthly" {
		t.Fatalf("after re-upgrade: %+v", subs)
	}
	upd = f.callsTo("POST", "/subscriptions/"+tn.ID+"/update_for_items")
	if last := upd[len(upd)-1]; last.Form["reactivate"] != "true" {
		t.Fatalf("reactivation call = %+v", last)
	}
}

func TestUpdatedRenamesCustomer(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "free"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	f.mu.Lock()
	f.customers[tn.ID].MetaData["crm_id"] = "42" // set by someone else
	f.mu.Unlock()

	prev := tn
	tn.Name, tn.Slug = "Acme Corp", "acme-corp"
	e := sdktest.TenantEvent(sdk.EventTenantUpdated, tn)
	e.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: tn, Previous: &prev})
	deliver(t, reg, e)
	c := f.customer(tn.ID)
	if c.Company != "Acme Corp" || c.MetaData["tenarium_slug"] != "acme-corp" || c.MetaData["crm_id"] != "42" {
		t.Fatalf("customer = %+v", c)
	}
	// Redelivery: already up to date, no write.
	deliver(t, reg, e)
	if n := len(f.callsTo("POST", "/customers/"+tn.ID)); n != 1 {
		t.Fatalf("customer updates = %d, want 1", n)
	}

	// An update not touching name or slug makes no Chargebee call.
	before := len(f.callsTo("GET", "/"))
	prev = tn
	tn.Labels = map[string]string{"x": "y"}
	e = sdktest.TenantEvent(sdk.EventTenantUpdated, tn)
	e.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: tn, Previous: &prev})
	deliver(t, reg, e)
	if after := len(f.callsTo("GET", "/")); after != before {
		t.Fatal("unrelated update called Chargebee")
	}
}

func TestDeletedCancels(t *testing.T) {
	for _, mode := range []string{"immediately", "end_of_term"} {
		t.Run(mode, func(t *testing.T) {
			_, reg, f := setup(t, map[string]any{"cancel_on_delete": mode})
			tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro"})
			deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
			tn.Status = sdk.StatusDeleted
			e := sdktest.TenantEvent(sdk.EventTenantDeleted, tn)
			deliver(t, reg, e)
			deliver(t, reg, e)

			if f.customer(tn.ID) == nil {
				t.Fatal("customer must be kept")
			}
			s := f.subsOf(tn.ID)[0]
			calls := f.callsTo("POST", "/subscriptions/"+tn.ID+"/cancel_for_items")
			want := map[string]string{"immediately": "cancelled", "end_of_term": "non_renewing"}[mode]
			if s.Status != want || len(calls) != 1 || calls[0].Form["end_of_term"] != map[string]string{"immediately": "false", "end_of_term": "true"}[mode] {
				t.Fatalf("status = %s, calls = %+v", s.Status, calls)
			}
			lists := f.callsTo("GET", "/subscriptions")
			if q := lists[len(lists)-1].Form; q["customer_id[is]"] != tn.ID || !strings.Contains(q["status[in]"], `"non_renewing"`) {
				t.Fatalf("list query = %v", q)
			}
		})
	}
}

func TestSyncReturnsChargebeeErrors(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	f.failNext = 1
	err := reg.Deliver(context.Background(), "sync", sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if err == nil || !strings.Contains(err.Error(), "simulated outage") {
		t.Fatalf("err = %v, want Chargebee's message", err)
	}
}

func get(reg *sdktest.Registrar, path string, pr *sdk.Principal) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if pr != nil {
		req = req.WithContext(sdk.WithPrincipal(req.Context(), pr))
	}
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	return rec
}

func TestTenantRoute(t *testing.T) {
	_, reg, _ := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other", Name: "Other", Plan: "free"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	admin := &sdk.Principal{Subject: "admin", Kind: "user"}

	rec := get(reg, "/tenants/acme", admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var info map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if info["customer_id"] != tn.ID || info["subscription_id"] != tn.ID || info["status"] != "active" ||
		info["item_price_id"] != "pro-USD-Monthly" || info["current_term_end"] != "2030-01-01T00:00:00Z" {
		t.Fatalf("info = %v", info)
	}
	if rec := get(reg, "/tenants/"+tn.ID, &sdk.Principal{Subject: "u", TenantID: tn.ID}); rec.Code != http.StatusOK {
		t.Errorf("own tenant: %d", rec.Code)
	}
	if rec := get(reg, "/tenants/acme", &sdk.Principal{Subject: "u", TenantID: other.ID}); rec.Code != http.StatusNotFound {
		t.Errorf("other tenant's caller: %d, want 404", rec.Code)
	}
	if rec := get(reg, "/tenants/acme", nil); rec.Code != http.StatusNotFound {
		t.Errorf("anonymous caller: %d, want 404", rec.Code)
	}
	if rec := get(reg, "/tenants/missing", admin); rec.Code != http.StatusNotFound {
		t.Errorf("unknown tenant: %d", rec.Code)
	}
	if rec := get(reg, "/tenants/other", admin); rec.Code != http.StatusNotFound {
		t.Errorf("tenant without customer: %d", rec.Code)
	}
}

func TestHealth(t *testing.T) {
	p, _, f := setup(t, nil)
	if err := p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.key = "rotated"
	err := p.Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "api_authentication_failed") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := map[string]any{"site": "acme", "api_key": "k", "webhook_username": "u", "webhook_password": "p"}
	cases := []struct {
		name string
		set  map[string]any
		want string
	}{
		{"missing site", map[string]any{"site": ""}, "site is required"},
		{"bad site", map[string]any{"site": "Acme.com"}, "site must match"},
		{"missing key", map[string]any{"api_key": ""}, "api_key is required"},
		{"missing username", map[string]any{"webhook_username": ""}, "webhook_username is required"},
		{"missing password", map[string]any{"webhook_password": ""}, "webhook_password is required"},
		{"bad base", map[string]any{"api_base": "ftp://x"}, "api_base"},
		{"relative base", map[string]any{"api_base": "/api/v2"}, "api_base"},
		{"bad timeout", map[string]any{"timeout": "soon"}, "timeout"},
		{"negative timeout", map[string]any{"timeout": "-1s"}, "timeout"},
		{"bad cancel", map[string]any{"cancel_on_delete": "later"}, "cancel_on_delete"},
		{"bad cf field", map[string]any{"tenant_id_field": "tenant_id"}, "tenant_id_field"},
		{"duplicate price", map[string]any{"plans": map[string]string{"a": "p1", "b": "p1"}}, "mapped to both"},
		{"empty price", map[string]any{"plans": map[string]string{"a": ""}}, "must not be empty"},
		{"empty suspend_on", map[string]any{"suspend_on": []string{""}}, "suspend_on"},
		{"unknown field", map[string]any{"webhook_secret": "x"}, "unknown field"},
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
	reg := sdktest.NewRegistrar(maps.Clone(base))
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if p.base != "https://acme.chargebee.com/api/v2" || p.cfg.CancelOnDelete != "immediately" ||
		!p.suspendOn["subscription_cancelled"] || !p.suspendOn["subscription_paused"] || len(p.suspendOn) != 2 ||
		p.client.Timeout != 15*time.Second || !enabled(p.cfg.CreateCustomers) || !enabled(p.cfg.ResumeOnPayment) ||
		!enabled(p.cfg.SyncPlanFromChargebee) || p.cfg.SuspendOnPaymentFailed {
		t.Fatalf("defaults not applied: base=%s %+v", p.base, p.cfg)
	}
	if len(reg.Subscriptions) != 1 || reg.Subscriptions[0].Name != "sync" {
		t.Fatalf("subscriptions = %+v", reg.Subscriptions)
	}
	routes := strings.Join(reg.Routes, ",")
	if !strings.Contains(routes, "public: POST /webhook") || !strings.Contains(routes, "GET /tenants/{tenant}") {
		t.Fatalf("routes = %v", reg.Routes)
	}
	m := p.Manifest()
	if m.ID != "chargebee" || m.Name != "Chargebee" || m.Version != version {
		t.Fatalf("manifest = %+v", m)
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{
		"site": "acme-test", "api_key": "live_x", "api_base": "https://acme.chargebee.com/api/v2", "timeout": "10s",
		"webhook_username": "u", "webhook_password": "p", "plans": map[string]any{"pro": "pro-USD-Monthly"},
		"create_customers": false, "suspend_on": []any{"subscription_cancelled"}, "suspend_on_payment_failed": true,
		"resume_on_payment": false, "sync_plan_from_chargebee": false, "cancel_on_delete": "end_of_term",
		"tenant_id_field": "cf_tenarium_tenant_id",
	}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	req := map[string]any{"site": "acme", "api_key": "k", "webhook_username": "u", "webhook_password": "p"}
	if err := sch.Validate(req); err != nil {
		t.Fatalf("minimal config rejected: %v", err)
	}
	with := func(k string, v any) map[string]any {
		m := maps.Clone(req)
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for _, bad := range []map[string]any{
		with("site", nil),
		with("webhook_password", nil),
		with("site", "Acme.com"),
		with("extra", 1),
		with("cancel_on_delete", "later"),
		with("tenant_id_field", "tenant"),
		with("api_base", "ftp://x"),
		with("plans", map[string]any{"pro": ""}),
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

// TestReconfigure covers live API key and webhook credential rotation.
// Chargebee has no settings fixed at startup, so nothing is rejected as
// needing a restart.
func TestReconfigure(t *testing.T) {
	p, reg, f := setup(t, nil)
	ctx := context.Background()
	cfg := func(site, key, pass string) func(any) error {
		return sdktest.NewRegistrar(map[string]any{
			"site": site, "api_key": key, "api_base": f.base(),
			"webhook_username": testUser, "webhook_password": pass,
		}).Config
	}
	ev := func() []byte {
		body, _ := json.Marshal(cbEvent("invoice_generated", map[string]any{"invoice": map[string]any{"id": "inv_1"}}))
		return body
	}

	// Invalid config: rejected, old settings stay.
	if err := p.Reconfigure(ctx, cfg("Not A Site", "rotated", "new-pass")); err == nil {
		t.Fatal("invalid site accepted")
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("old key no longer used: %v", err)
	}

	if err := p.Reconfigure(ctx, cfg("acme-test", "rotated", "new-pass")); err != nil {
		t.Fatal(err)
	}
	f.key = "rotated"
	if err := p.Health(ctx); err != nil {
		t.Fatalf("new key not used: %v", err)
	}
	if rec := post(reg, ev(), testUser, testPass); rec.Code != http.StatusUnauthorized {
		t.Errorf("old password: %d", rec.Code)
	}
	if rec := post(reg, ev(), testUser, "new-pass"); rec.Code != http.StatusOK {
		t.Errorf("new password: %d %s", rec.Code, rec.Body)
	}
}
