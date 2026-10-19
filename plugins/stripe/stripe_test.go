package stripe

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

const testSecret = "whsec_test_secret"

var testNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T, overrides map[string]any) (*Plugin, *sdktest.Registrar, *fakeStripe) {
	t.Helper()
	f := newFakeStripe(t)
	cfg := map[string]any{
		"api_key":        f.key,
		"webhook_secret": testSecret,
		"api_base":       f.srv.URL,
		"plans":          map[string]string{"pro": "price_pro", "enterprise": "price_ent"},
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
	_, reg, f := setup(t, map[string]any{"trial_days": 14})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro"})
	e := sdktest.TenantEvent(sdk.EventTenantCreated, tn)
	deliver(t, reg, e)
	deliver(t, reg, e) // redelivery

	custs := f.customersOf(tn.ID)
	if len(custs) != 1 {
		t.Fatalf("customers = %d, want 1 (%s)", len(custs), f)
	}
	c := custs[0]
	if c.Name != "Acme" || c.Metadata["tenarium_slug"] != "acme" {
		t.Errorf("customer = %+v", c)
	}
	subs := f.subsOf(c.ID)
	if len(subs) != 1 {
		t.Fatalf("subscriptions = %d, want 1", len(subs))
	}
	s := subs[0]
	if s.Price != "price_pro" || s.Metadata["tenarium_tenant_id"] != tn.ID || s.Status != "trialing" {
		t.Errorf("subscription = %+v", s)
	}
	if s.Form["trial_period_days"] != "14" || s.Form["collection_method"] != "charge_automatically" {
		t.Errorf("subscription params = %v", s.Form)
	}
	if calls := f.callsTo("POST", "/v1/customers"); len(calls) != 1 || calls[0].IdemKey != "tenarium-customer-"+tn.ID {
		t.Errorf("customer creations = %+v", calls)
	}
	if calls := f.callsTo("POST", "/v1/subscriptions"); len(calls) != 1 || calls[0].IdemKey != "tenarium-sub-"+tn.ID+"-"+e.ID {
		t.Errorf("subscription creations = %+v", calls)
	}
}

func TestCreatedSurvivesSearchLag(t *testing.T) {
	_, reg, f := setup(t, nil)
	f.hideFromSearch = true // a just-created customer is not searchable yet
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro"})
	e := sdktest.TenantEvent(sdk.EventTenantCreated, tn)
	deliver(t, reg, e)
	deliver(t, reg, e)
	custs := f.customersOf(tn.ID)
	if len(custs) != 1 {
		t.Fatalf("customers = %d, want 1: the idempotency key must dedupe", len(custs))
	}
	if subs := f.subsOf(custs[0].ID); len(subs) != 1 {
		t.Fatalf("subscriptions = %d, want 1", len(subs))
	}
}

func TestCreatedUnbilledPlan(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "free"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	custs := f.customersOf(tn.ID)
	if len(custs) != 1 {
		t.Fatalf("customers = %d, want 1", len(custs))
	}
	if subs := f.subsOf(custs[0].ID); len(subs) != 0 {
		t.Fatalf("unbilled plan got subscriptions: %+v", subs)
	}
	if calls := f.callsTo("POST", "/v1/subscriptions"); len(calls) != 0 {
		t.Fatalf("unexpected subscription calls: %+v", calls)
	}
}

func TestCreatedWithoutCreateCustomers(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"create_customers": false})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if n := len(f.customersOf(tn.ID)); n != 0 {
		t.Fatalf("customers = %d, want 0", n)
	}

	// An existing (e.g. Checkout-created) customer is used.
	cus, _ := f.seed(tn.ID, "", "")
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if subs := f.subsOf(cus); len(subs) != 1 || subs[0].Price != "price_pro" {
		t.Fatalf("subscriptions = %+v", subs)
	}
}

func TestPlanChanged(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	cus := f.customersOf(tn.ID)[0].ID
	first := f.subsOf(cus)[0]

	// Billed → billed: the price is swapped on the same item.
	tn.Plan = "enterprise"
	deliver(t, reg, planEvent(tn, "pro"))
	subs := f.subsOf(cus)
	if len(subs) != 1 || subs[0].ID != first.ID || subs[0].Price != "price_ent" || subs[0].ItemID != first.ItemID {
		t.Fatalf("after upgrade: %+v", subs)
	}
	upd := f.callsTo("POST", "/v1/subscriptions/"+first.ID)
	if len(upd) != 1 || upd[0].Form["proration_behavior"] != "create_prorations" || upd[0].Form["items[0][id]"] != first.ItemID {
		t.Fatalf("update calls = %+v", upd)
	}
	// Redelivery is a no-op.
	deliver(t, reg, planEvent(tn, "pro"))
	if n := len(f.callsTo("POST", "/v1/subscriptions/"+first.ID)); n != 1 {
		t.Fatalf("redelivery updated again (%d calls)", n)
	}

	// Billed → unbilled: the subscription is canceled.
	tn.Plan = "free"
	deliver(t, reg, planEvent(tn, "enterprise"))
	if s := f.subsOf(cus)[0]; s.Status != "canceled" {
		t.Fatalf("after downgrade status = %s", s.Status)
	}

	// Unbilled → billed: a new subscription is created.
	tn.Plan = "pro"
	deliver(t, reg, planEvent(tn, "free"))
	subs = f.subsOf(cus)
	if len(subs) != 2 || subs[1].Status != "active" || subs[1].Price != "price_pro" {
		t.Fatalf("after re-upgrade: %+v", subs)
	}
}

func TestUpdatedRenamesCustomer(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "free"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))

	prev := tn
	tn.Name = "Acme Corp"
	e := sdktest.TenantEvent(sdk.EventTenantUpdated, tn)
	e.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: tn, Previous: &prev})
	deliver(t, reg, e)
	if c := f.customersOf(tn.ID)[0]; c.Name != "Acme Corp" {
		t.Fatalf("name = %q", c.Name)
	}

	// An update not touching name or slug makes no Stripe call.
	before := len(f.callsTo("GET", "/"))
	prev = tn
	tn.Labels = map[string]string{"x": "y"}
	e = sdktest.TenantEvent(sdk.EventTenantUpdated, tn)
	e.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: tn, Previous: &prev})
	deliver(t, reg, e)
	if after := len(f.callsTo("GET", "/")); after != before {
		t.Fatalf("unrelated update called Stripe")
	}
}

func TestDeletedCancels(t *testing.T) {
	for _, atEnd := range []bool{false, true} {
		_, reg, f := setup(t, map[string]any{"cancel_at_period_end_on_delete": atEnd})
		tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "pro"})
		deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
		tn.Status = sdk.StatusDeleted
		e := sdktest.TenantEvent(sdk.EventTenantDeleted, tn)
		deliver(t, reg, e)
		deliver(t, reg, e)

		custs := f.customersOf(tn.ID)
		if len(custs) != 1 {
			t.Fatalf("customer must be kept, got %d", len(custs))
		}
		s := f.subsOf(custs[0].ID)[0]
		if atEnd {
			if s.Status != "active" || !s.CancelAtPeriodEnd {
				t.Errorf("at period end: %+v", s)
			}
			if n := len(f.callsTo("POST", "/v1/subscriptions/"+s.ID)); n != 1 {
				t.Errorf("cancel_at_period_end calls = %d, want 1", n)
			}
		} else {
			if s.Status != "canceled" {
				t.Errorf("immediately: status = %s", s.Status)
			}
			if n := len(f.callsTo("DELETE", "/v1/subscriptions/")); n != 1 {
				t.Errorf("DELETE calls = %d, want 1", n)
			}
		}
	}
}

func TestSyncReturnsStripeErrors(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	f.failNext = 1
	err := reg.Deliver(context.Background(), "sync", sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if err == nil || !strings.Contains(err.Error(), "simulated outage") {
		t.Fatalf("err = %v, want Stripe's message", err)
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
	_, reg, f := setup(t, nil)
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
	cus := f.customersOf(tn.ID)[0]
	sub := f.subsOf(cus.ID)[0]
	if info["customer_id"] != cus.ID || info["subscription_id"] != sub.ID || info["status"] != "active" ||
		info["price"] != "price_pro" || info["current_period_end"] != "2030-01-01T00:00:00Z" {
		t.Fatalf("info = %v", info)
	}

	// The tenant's own scoped caller may read it; another tenant's may not.
	if rec := get(reg, "/tenants/"+tn.ID, &sdk.Principal{Subject: "u", TenantID: tn.ID}); rec.Code != http.StatusOK {
		t.Errorf("own tenant: %d", rec.Code)
	}
	if rec := get(reg, "/tenants/acme", &sdk.Principal{Subject: "u", TenantID: other.ID}); rec.Code != http.StatusNotFound {
		t.Errorf("other tenant's caller: %d, want 404", rec.Code)
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
	f.key = "sk_test_rotated"
	err := p.Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Invalid API Key") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := map[string]any{"api_key": "sk_test_1", "webhook_secret": "whsec_1"}
	cases := []struct {
		name string
		set  map[string]any
		want string
	}{
		{"missing key", map[string]any{"api_key": ""}, "api_key is required"},
		{"publishable key", map[string]any{"api_key": "pk_test_1"}, "api_key must be"},
		{"missing secret", map[string]any{"webhook_secret": ""}, "webhook_secret is required"},
		{"bad secret", map[string]any{"webhook_secret": "abc"}, "whsec_"},
		{"bad base", map[string]any{"api_base": "ftp://x"}, "api_base"},
		{"bad timeout", map[string]any{"timeout": "soon"}, "timeout"},
		{"negative trial", map[string]any{"trial_days": -1}, "trial_days"},
		{"bad collection", map[string]any{"collection_method": "cash"}, "collection_method"},
		{"due without invoice", map[string]any{"days_until_due": 10}, "days_until_due"},
		{"duplicate price", map[string]any{"plans": map[string]string{"a": "price_1", "b": "price_1"}}, "mapped to both"},
		{"empty price", map[string]any{"plans": map[string]string{"a": ""}}, "must not be empty"},
		{"unknown field", map[string]any{"usage": map[string]string{}}, "unknown field"},
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
	cfg["collection_method"] = "send_invoice"
	reg := sdktest.NewRegistrar(cfg)
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if p.cfg.DaysUntilDue != 30 || p.base != "https://api.stripe.com" || !p.suspendOn["customer.subscription.deleted"] ||
		!p.suspendOn["customer.subscription.paused"] || p.client.Timeout != 15*time.Second {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	if len(reg.Subscriptions) != 1 || reg.Subscriptions[0].Name != "sync" {
		t.Fatalf("subscriptions = %+v", reg.Subscriptions)
	}
	if !strings.Contains(strings.Join(reg.Routes, ","), "public: POST /webhook") {
		t.Fatalf("routes = %v", reg.Routes)
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{
		"api_key": "sk_live_1", "webhook_secret": "whsec_1", "api_base": "https://api.stripe.com",
		"timeout": "15s", "plans": map[string]any{"pro": "price_1"}, "create_customers": true, "trial_days": 7,
		"collection_method": "send_invoice", "days_until_due": 14, "cancel_at_period_end_on_delete": true,
		"suspend_on": []any{"invoice.payment_failed"}, "suspend_on_past_due": true,
		"resume_on_payment": false, "sync_plan_from_stripe": false,
	}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, bad := range []map[string]any{
		{"webhook_secret": "whsec_1"},
		{"api_key": "pk_1", "webhook_secret": "whsec_1"},
		{"api_key": "sk_1", "webhook_secret": "whsec_1", "extra": 1},
		{"api_key": "sk_1", "webhook_secret": "whsec_1", "collection_method": "cash"},
		{"api_key": "sk_1", "webhook_secret": "whsec_1", "trial_days": -1},
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

func TestReconfigure(t *testing.T) {
	p, reg, f := setup(t, nil)
	ctx := context.Background()
	cfg := func(key, secret string, extra map[string]any) func(any) error {
		c := map[string]any{"api_key": key, "webhook_secret": secret, "api_base": f.srv.URL}
		maps.Copy(c, extra)
		return sdktest.NewRegistrar(c).Config
	}
	ev := func() []byte {
		body, _ := json.Marshal(stripeEvent("charge.refunded", map[string]any{"id": "ch_1"}, nil))
		return body
	}

	// Invalid config: rejected, old settings stay.
	if err := p.Reconfigure(ctx, cfg("bad", "whsec_new", nil)); err == nil {
		t.Fatal("invalid api_key accepted")
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("old key no longer used: %v", err)
	}
	// Init-fixed: meters cannot be turned on live.
	if err := p.Reconfigure(ctx, cfg(f.key, testSecret, map[string]any{"meters": map[string]string{"api_calls": "api_requests"}})); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("meters change: err = %v", err)
	}

	// Key and secret rotation apply live.
	if err := p.Reconfigure(ctx, cfg("sk_test_rotated", "whsec_rotated", nil)); err != nil {
		t.Fatal(err)
	}
	f.key = "sk_test_rotated"
	if err := p.Health(ctx); err != nil {
		t.Fatalf("new key not used: %v", err)
	}
	body := ev()
	if rec := post(reg, body, Sign(testSecret, testNow, body)); rec.Code != http.StatusBadRequest {
		t.Errorf("old secret: %d", rec.Code)
	}
	body = ev()
	if rec := post(reg, body, Sign("whsec_rotated", testNow, body)); rec.Code != http.StatusOK {
		t.Errorf("new secret: %d %s", rec.Code, rec.Body)
	}
}
