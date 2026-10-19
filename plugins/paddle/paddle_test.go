package paddle

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

const testSecret = "pdl_ntfset_test_secret"

var testNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T, overrides map[string]any) (*Plugin, *sdktest.Registrar, *fakePaddle) {
	t.Helper()
	f := newFakePaddle(t)
	cfg := map[string]any{
		"api_key":        f.key,
		"webhook_secret": testSecret,
		"api_base":       f.srv.URL,
		"plans":          map[string]string{"pro": "pri_pro", "enterprise": "pri_ent"},
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

// addTenant adds a tenant with the billing_email label <slug>@example.com.
func addTenant(reg *sdktest.Registrar, slug, plan string) sdk.Tenant {
	return reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Name: strings.ToUpper(slug), Plan: plan,
		Labels: map[string]string{"billing_email": slug + "@example.com"}})
}

func deliver(t *testing.T, reg *sdktest.Registrar, e sdk.Event) {
	t.Helper()
	if err := reg.Deliver(context.Background(), "sync", e); err != nil {
		t.Fatalf("deliver %s: %v", e.Type, err)
	}
}

// changePlan sets the tenant's plan in the host and returns the event.
func changePlan(reg *sdktest.Registrar, tn sdk.Tenant, plan string) (sdk.Tenant, sdk.Event) {
	prev := tn
	tn.Plan = plan
	reg.HostImpl.AddTenant(tn)
	e := sdktest.TenantEvent(sdk.EventTenantPlanChanged, tn)
	e.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: tn, Previous: &prev})
	return tn, e
}

func updatedEvent(tn, prev sdk.Tenant) sdk.Event {
	e := sdktest.TenantEvent(sdk.EventTenantUpdated, tn)
	e.Data, _ = json.Marshal(sdk.TenantEventData{Tenant: tn, Previous: &prev})
	return e
}

func TestCreatedIsIdempotent(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	e := sdktest.TenantEvent(sdk.EventTenantCreated, tn)
	deliver(t, reg, e)
	deliver(t, reg, e) // redelivery

	custs := f.customersOf(tn.ID)
	if len(custs) != 1 {
		t.Fatalf("customers = %d, want 1 (%s)", len(custs), f)
	}
	c := custs[0]
	if c.Email != "acme@example.com" || c.Name != "ACME" || c.CustomData[CustomDataSlug] != "acme" {
		t.Errorf("customer = %+v", c)
	}
	if n := len(f.callsTo("POST", "/customers")); n != 1 {
		t.Errorf("customer creations = %d, want 1", n)
	}
	// Paddle has no subscription creation API: nothing but lookups.
	if n := len(f.callsTo("PATCH", "/subscriptions")) + len(f.callsTo("POST", "/subscriptions")); n != 0 {
		t.Errorf("subscription writes = %d", n)
	}
}

func TestCreatedConflictReturnsExistingCustomer(t *testing.T) {
	// The email lookup misses (e.g. the customer is archived); Paddle's
	// unique email conflict names the existing customer.
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	f.hideFromList = true
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if custs := f.customersOf(tn.ID); len(custs) != 1 {
		t.Fatalf("customers = %d, want 1", len(custs))
	}
	if n := len(f.callsTo("POST", "/customers")); n != 2 {
		t.Fatalf("customer creations = %d, want 2 (second conflicting)", n)
	}
}

func TestCreatedClaimsUnlinkedCustomer(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	cus := f.addCustomer("acme@example.com", "")
	f.mu.Lock()
	f.customers[cus].CustomData["crm_id"] = "42"
	f.mu.Unlock()
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	c := f.customer(cus)
	if c.CustomData[CustomDataTenantID] != tn.ID || c.CustomData["crm_id"] != "42" || c.CustomData[CustomDataSlug] != "acme" {
		t.Fatalf("custom_data = %v", c.CustomData)
	}
	if n := len(f.callsTo("POST", "/customers")); n != 0 {
		t.Fatalf("created a customer although one exists")
	}
}

func TestCreatedSkipsOtherTenantsCustomer(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	f.addCustomer("acme@example.com", "someone-else")
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if n := len(f.callsTo("PATCH", "/customers")); n != 0 {
		t.Fatalf("another tenant's customer was modified")
	}
	if c := f.customersOf(tn.ID); len(c) != 0 {
		t.Fatalf("customers = %+v", c)
	}
}

func TestCreatedWithoutEmail(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if f.String() != "0 customers, 0 subscriptions, 0 calls" {
		t.Fatalf("unexpected calls: %s", f)
	}
}

func TestEmailTemplate(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"customer_email_template": "billing+{{.Slug}}@example.com"})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Name: "Acme", Plan: "free"})
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if c := f.customersOf(tn.ID); len(c) != 1 || c[0].Email != "billing+acme@example.com" {
		t.Fatalf("customers = %+v", c)
	}
}

func TestCreatedWithoutCreateCustomers(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"create_customers": false})
	tn := addTenant(reg, "acme", "pro")
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if n := len(f.callsTo("POST", "/customers")); n != 0 {
		t.Fatalf("customer creations = %d, want 0", n)
	}
	// An existing (e.g. checkout-created) customer is used and linked.
	cus := f.addCustomer("acme@example.com", "")
	sub := f.addSub(cus, "", "pri_pro", "active")
	tn, e := changePlan(reg, tn, "enterprise")
	deliver(t, reg, e)
	if c := f.customer(cus); c.CustomData[CustomDataTenantID] != tn.ID {
		t.Fatalf("customer not linked: %+v", c)
	}
	if s := f.sub(sub); s.Items[0].Price != "pri_ent" || s.CustomData[CustomDataTenantID] != tn.ID {
		t.Fatalf("subscription = %+v", s)
	}
}

func TestPlanChanged(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "active")
	f.setSub(sub, func(s *fakeSub) { s.Items = append(s.Items, fakeItem{Price: "pri_addon", Quantity: 3}) })

	// Billed → billed: the plan item is swapped, add-ons are kept.
	tn, e := changePlan(reg, tn, "enterprise")
	deliver(t, reg, e)
	s := f.sub(sub)
	if len(s.Items) != 2 || s.Items[0] != (fakeItem{"pri_ent", 1}) || s.Items[1] != (fakeItem{"pri_addon", 3}) {
		t.Fatalf("items = %+v", s.Items)
	}
	upd := f.callsTo("PATCH", "/subscriptions/"+sub)
	if len(upd) != 1 || upd[0].Body["proration_billing_mode"] != "prorated_immediately" {
		t.Fatalf("update calls = %+v", upd)
	}
	// Redelivery is a no-op.
	deliver(t, reg, e)
	if n := len(f.callsTo("PATCH", "/subscriptions/")); n != 1 {
		t.Fatalf("redelivery updated again (%d calls)", n)
	}

	// Billed → unbilled: the subscription is canceled immediately.
	tn, e = changePlan(reg, tn, "free")
	deliver(t, reg, e)
	if s := f.sub(sub); s.Status != "canceled" {
		t.Fatalf("after downgrade status = %s", s.Status)
	}
	if c := f.callsTo("POST", "/subscriptions/"+sub+"/cancel"); len(c) != 1 || c[0].Body["effective_from"] != "immediately" {
		t.Fatalf("cancel calls = %+v", c)
	}

	// Unbilled → billed: no subscription can be created; nothing happens.
	_, e = changePlan(reg, tn, "pro")
	deliver(t, reg, e)
	if n := len(f.callsTo("PATCH", "/subscriptions/")); n != 1 {
		t.Fatalf("unexpected subscription updates: %d", n)
	}
}

func TestPlanChangedCustomProration(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"proration_billing_mode": "full_next_billing_period"})
	tn := addTenant(reg, "acme", "pro")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "active")
	_, e := changePlan(reg, tn, "enterprise")
	deliver(t, reg, e)
	if upd := f.callsTo("PATCH", "/subscriptions/"+sub); len(upd) != 1 || upd[0].Body["proration_billing_mode"] != "full_next_billing_period" {
		t.Fatalf("update calls = %+v", upd)
	}
}

func TestPlanChangedActsOnCurrentPlan(t *testing.T) {
	// The plan changed back (e.g. from Paddle) before the event was
	// handled: the stale plan must not be pushed to Paddle.
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	f.seed(tn.ID, "acme@example.com", "pri_pro", "active")
	stale := tn
	stale.Plan = "enterprise"
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantPlanChanged, stale))
	if n := len(f.callsTo("PATCH", "/subscriptions/")); n != 0 {
		t.Fatalf("stale plan pushed to Paddle")
	}
}

func TestUpdatedRenamesCustomer(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "free")
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	cus := f.customersOf(tn.ID)[0].ID

	prev := tn
	tn.Name, tn.Slug = "Acme Corp", "acme-corp"
	deliver(t, reg, updatedEvent(tn, prev))
	if c := f.customer(cus); c.Name != "Acme Corp" || c.CustomData[CustomDataSlug] != "acme-corp" || c.CustomData[CustomDataTenantID] != tn.ID {
		t.Fatalf("customer = %+v", c)
	}

	// A new billing email is followed from the previous one.
	prev = tn
	tn.Labels = map[string]string{"billing_email": "finance@acme.test"}
	deliver(t, reg, updatedEvent(tn, prev))
	if c := f.customer(cus); c.Email != "finance@acme.test" {
		t.Fatalf("email = %q", c.Email)
	}

	// An update not touching name, slug or email makes no Paddle call.
	before := len(f.callsTo("GET", "/"))
	prev = tn
	tn.Labels = map[string]string{"billing_email": "finance@acme.test", "x": "y"}
	deliver(t, reg, updatedEvent(tn, prev))
	if after := len(f.callsTo("GET", "/")); after != before {
		t.Fatalf("unrelated update called Paddle")
	}
}

func TestDeletedCancels(t *testing.T) {
	for _, when := range []string{"immediately", "next_billing_period"} {
		t.Run(when, func(t *testing.T) {
			_, reg, f := setup(t, map[string]any{"cancel_on_delete": when})
			tn := addTenant(reg, "acme", "pro")
			cus, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "active")
			tn.Status = sdk.StatusDeleted
			e := sdktest.TenantEvent(sdk.EventTenantDeleted, tn)
			deliver(t, reg, e)
			deliver(t, reg, e)

			if c := f.customer(cus); c.ID == "" {
				t.Fatal("customer must be kept")
			}
			s := f.sub(sub)
			calls := f.callsTo("POST", "/subscriptions/"+sub+"/cancel")
			if len(calls) != 1 || calls[0].Body["effective_from"] != when {
				t.Fatalf("cancel calls = %+v", calls)
			}
			if when == "immediately" && s.Status != "canceled" || when != "immediately" && !s.ScheduledCancel {
				t.Fatalf("subscription = %+v", s)
			}
		})
	}
}

func TestSyncReturnsPaddleErrors(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	f.failNext = 1
	err := reg.Deliver(context.Background(), "sync", sdktest.TenantEvent(sdk.EventTenantCreated, tn))
	if err == nil || !strings.Contains(err.Error(), "simulated outage") {
		t.Fatalf("err = %v, want Paddle's message", err)
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
	tn := addTenant(reg, "acme", "pro")
	other := addTenant(reg, "other", "free")
	cus, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "active")
	admin := &sdk.Principal{Subject: "admin", Kind: "user"}

	rec := get(reg, "/tenants/acme", admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var info map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if info["customer_id"] != cus || info["subscription_id"] != sub || info["status"] != "active" ||
		info["price"] != "pri_pro" || info["current_period_end"] != "2030-01-01T00:00:00Z" ||
		info["email"] != "acme@example.com" {
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
	f.key = "pdl_rotated"
	err := p.Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := map[string]any{"api_key": "pdl_live_apikey_1", "webhook_secret": "pdl_ntfset_1"}
	cases := []struct {
		name string
		set  map[string]any
		want string
	}{
		{"missing key", map[string]any{"api_key": ""}, "api_key is required"},
		{"missing secret", map[string]any{"webhook_secret": " "}, "webhook_secret is required"},
		{"bad environment", map[string]any{"environment": "staging"}, "environment"},
		{"bad base", map[string]any{"api_base": "ftp://x"}, "api_base"},
		{"relative base", map[string]any{"api_base": "/paddle"}, "api_base"},
		{"bad timeout", map[string]any{"timeout": "soon"}, "timeout"},
		{"zero timeout", map[string]any{"timeout": "0s"}, "timeout"},
		{"duplicate price", map[string]any{"plans": map[string]string{"a": "pri_1", "b": "pri_1"}}, "mapped to both"},
		{"empty price", map[string]any{"plans": map[string]string{"a": ""}}, "must not be empty"},
		{"bad template", map[string]any{"customer_email_template": "{{.Nope"}, "customer_email_template"},
		{"empty suspend_on", map[string]any{"suspend_on": []string{""}}, "suspend_on"},
		{"bad cancel", map[string]any{"cancel_on_delete": "later"}, "cancel_on_delete"},
		{"bad proration", map[string]any{"proration_billing_mode": "free"}, "proration_billing_mode"},
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
	reg := sdktest.NewRegistrar(maps.Clone(base))
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if p.base != ProductionBase || p.cfg.Environment != "production" || !p.suspendOn["subscription.canceled"] ||
		!p.suspendOn["subscription.paused"] || p.client.Timeout != 15*time.Second ||
		p.cfg.CancelOnDelete != "immediately" || p.cfg.ProrationBillingMode != "prorated_immediately" ||
		p.cfg.CustomerEmailTemplate != `{{index .Labels "billing_email"}}` {
		t.Fatalf("defaults not applied: %+v", p.cfg)
	}
	if len(reg.Subscriptions) != 1 || reg.Subscriptions[0].Name != "sync" {
		t.Fatalf("subscriptions = %+v", reg.Subscriptions)
	}
	if routes := strings.Join(reg.Routes, ","); !strings.Contains(routes, "public: POST /webhook") || !strings.Contains(routes, "GET /tenants/{tenant}") {
		t.Fatalf("routes = %v", reg.Routes)
	}

	sandbox := maps.Clone(base)
	sandbox["environment"] = "sandbox"
	p = &Plugin{}
	if err := p.Init(context.Background(), sdktest.NewRegistrar(sandbox)); err != nil || p.base != SandboxBase {
		t.Fatalf("sandbox: base = %q, err = %v", p.base, err)
	}
	sandbox["api_base"] = "http://localhost:8080/"
	p = &Plugin{}
	if err := p.Init(context.Background(), sdktest.NewRegistrar(sandbox)); err != nil || p.base != "http://localhost:8080" {
		t.Fatalf("api_base override: base = %q, err = %v", p.base, err)
	}
}

func TestConfigSchema(t *testing.T) {
	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{
		"api_key": "pdl_live_apikey_1", "webhook_secret": "pdl_ntfset_1", "environment": "sandbox",
		"api_base": "https://sandbox-api.paddle.com", "timeout": "15s", "plans": map[string]any{"pro": "pri_1"},
		"create_customers": true, "customer_email_template": "{{.Slug}}@example.com",
		"suspend_on": []any{"transaction.payment_failed"}, "suspend_on_past_due": true,
		"resume_on_payment": false, "sync_plan_from_paddle": false, "cancel_on_delete": "next_billing_period",
		"proration_billing_mode": "do_not_bill",
	}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, bad := range []map[string]any{
		{"webhook_secret": "s"},
		{"api_key": "k"},
		{"api_key": "", "webhook_secret": "s"},
		{"api_key": "k", "webhook_secret": "s", "extra": 1},
		{"api_key": "k", "webhook_secret": "s", "environment": "staging"},
		{"api_key": "k", "webhook_secret": "s", "cancel_on_delete": "later"},
		{"api_key": "k", "webhook_secret": "s", "proration_billing_mode": "free"},
		{"api_key": "k", "webhook_secret": "s", "api_base": "ftp://x"},
		{"api_key": "k", "webhook_secret": "s", "plans": map[string]any{"pro": ""}},
	} {
		if err := sch.Validate(bad); err == nil {
			t.Errorf("invalid config accepted: %v", bad)
		}
	}
}

// TestReconfigure covers live key and secret rotation. Paddle has no
// settings fixed at startup, so nothing is rejected as needing a restart.
func TestReconfigure(t *testing.T) {
	p, reg, f := setup(t, nil)
	ctx := context.Background()
	cfg := func(key, secret, timeout string) func(any) error {
		c := map[string]any{"api_key": key, "webhook_secret": secret, "api_base": f.srv.URL}
		if timeout != "" {
			c["timeout"] = timeout
		}
		return sdktest.NewRegistrar(c).Config
	}
	ev := func() []byte {
		body, _ := json.Marshal(paddleEvent("transaction.created", map[string]any{"id": "txn_1"}))
		return body
	}

	// Invalid config: rejected, old settings stay.
	if err := p.Reconfigure(ctx, cfg("pdl_rotated", "pdl_ntfset_rotated", "bogus")); err == nil {
		t.Fatal("invalid timeout accepted")
	}
	if err := p.Health(ctx); err != nil {
		t.Fatalf("old key no longer used: %v", err)
	}

	if err := p.Reconfigure(ctx, cfg("pdl_rotated", "pdl_ntfset_rotated", "")); err != nil {
		t.Fatal(err)
	}
	f.key = "pdl_rotated"
	if err := p.Health(ctx); err != nil {
		t.Fatalf("new key not used: %v", err)
	}
	body := ev()
	if rec := post(reg, body, Sign(testSecret, testNow, body)); rec.Code != http.StatusBadRequest {
		t.Errorf("old secret: %d", rec.Code)
	}
	body = ev()
	if rec := post(reg, body, Sign("pdl_ntfset_rotated", testNow, body)); rec.Code != http.StatusOK {
		t.Errorf("new secret: %d %s", rec.Code, rec.Body)
	}
}
