package stripe

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

func TestVerifySignature(t *testing.T) {
	payload := []byte(`{"id":"evt_1"}`)
	good := Sign(testSecret, testNow, payload)
	ts := strconv.FormatInt(testNow.Unix(), 10)
	wrong := signature("whsec_other", ts, payload)
	cases := []struct {
		name   string
		header string
		now    time.Time
		want   error
	}{
		{"valid", good, testNow, nil},
		{"within tolerance", good, testNow.Add(4 * time.Minute), nil},
		{"multiple v1, one matching", "t=" + ts + ",v1=" + wrong + ",v1=" + signature(testSecret, ts, payload) + ",v0=abc", testNow, nil},
		{"wrong secret", "t=" + ts + ",v1=" + wrong, testNow, errBadSignature},
		{"tampered timestamp", strings.Replace(good, "t="+ts, "t="+strconv.FormatInt(testNow.Unix()+1, 10), 1), testNow, errBadSignature},
		{"expired", good, testNow.Add(6 * time.Minute), errExpired},
		{"from the future", good, testNow.Add(-6 * time.Minute), errExpired},
		{"missing", "", testNow, errBadSignature},
		{"no v1", "t=" + ts + ",v0=" + wrong, testNow, errBadSignature},
		{"bad timestamp", "t=abc,v1=" + wrong, testNow, errBadSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifySignature(payload, tc.header, testSecret, tc.now)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if err := VerifySignature([]byte(`{"id":"evt_2"}`), good, testSecret, testNow); !errors.Is(err, errBadSignature) {
		t.Fatalf("tampered payload: err = %v", err)
	}
}

var evtN int

func stripeEvent(typ string, obj any, prev map[string]any) map[string]any {
	evtN++
	data := map[string]any{"object": obj}
	if prev != nil {
		data["previous_attributes"] = prev
	}
	return map[string]any{"id": "evt_" + strconv.Itoa(evtN), "object": "event", "type": typ, "created": testNow.Unix(), "data": data}
}

func post(reg *sdktest.Registrar, body []byte, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/public/webhook", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	return rec
}

func send(t *testing.T, reg *sdktest.Registrar, ev map[string]any, want int) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(ev)
	rec := post(reg, body, Sign(testSecret, testNow, body))
	if rec.Code != want {
		t.Fatalf("%s: status = %d, want %d: %s", ev["type"], rec.Code, want, rec.Body)
	}
	return rec
}

func actions(reg *sdktest.Registrar, kind string) []sdktest.Action {
	var out []sdktest.Action
	for _, a := range reg.HostImpl.Actions() {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

func status(t *testing.T, reg *sdktest.Registrar, id string) sdk.Tenant {
	t.Helper()
	tn, err := reg.HostImpl.GetTenant(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

func TestWebhookRejectsBadRequests(t *testing.T) {
	_, reg, _ := setup(t, nil)
	body := []byte(`{"id":"evt_x","type":"invoice.paid","data":{"object":{}}}`)
	if rec := post(reg, body, Sign("whsec_wrong", testNow, body)); rec.Code != http.StatusBadRequest {
		t.Errorf("bad signature: %d", rec.Code)
	}
	if rec := post(reg, body, Sign(testSecret, testNow.Add(-time.Hour), body)); rec.Code != http.StatusBadRequest {
		t.Errorf("expired: %d", rec.Code)
	}
	bad := []byte(`not json`)
	if rec := post(reg, bad, Sign(testSecret, testNow, bad)); rec.Code != http.StatusBadRequest {
		t.Errorf("bad payload: %d", rec.Code)
	}
	big := bytes.Repeat([]byte("x"), maxWebhookBody+1)
	if rec := post(reg, big, Sign(testSecret, testNow, big)); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized: %d", rec.Code)
	}
	// Valid but unhandled events are acknowledged.
	send(t, reg, stripeEvent("charge.refunded", map[string]any{"id": "ch_1"}, nil), http.StatusOK)
	if len(reg.HostImpl.Actions()) != 0 {
		t.Fatal("unexpected host actions")
	}
}

func TestSubscriptionDeletedSuspends(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	_, sub := f.seed(tn.ID, "price_pro", "active")
	f.setSub(sub, func(s *fakeSub) { s.Status = "canceled" })

	ev := stripeEvent("customer.subscription.deleted", f.subObject(sub), nil)
	send(t, reg, ev, http.StatusOK)
	sus := actions(reg, "suspend")
	if len(sus) != 1 || sus[0].TenantID != tn.ID || sus[0].Value != "billing: customer.subscription.deleted" {
		t.Fatalf("suspensions = %+v", sus)
	}

	// Duplicate deliveries are acknowledged without reprocessing.
	rec := send(t, reg, ev, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "duplicate") {
		t.Errorf("duplicate not reported: %s", rec.Body)
	}
	if n := len(f.callsTo("GET", "/v1/subscriptions/"+sub)); n != 1 {
		t.Errorf("duplicate reprocessed: %d subscription fetches", n)
	}
}

func TestSubscriptionDeletedSkipsUnbilledTenant(t *testing.T) {
	// A downgrade to a free plan cancels the subscription; the resulting
	// webhook must not suspend the tenant.
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "free"})
	_, sub := f.seed(tn.ID, "price_pro", "canceled")
	send(t, reg, stripeEvent("customer.subscription.deleted", f.subObject(sub), nil), http.StatusOK)
	if a := reg.HostImpl.Actions(); len(a) != 0 {
		t.Fatalf("actions = %+v", a)
	}
}

func TestSubscriptionPausedSuspendsAndResumedResumes(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	_, sub := f.seed(tn.ID, "price_pro", "paused")
	send(t, reg, stripeEvent("customer.subscription.paused", f.subObject(sub), nil), http.StatusOK)
	if s := status(t, reg, tn.ID); s.Status != sdk.StatusSuspended {
		t.Fatalf("status = %s", s.Status)
	}
	f.setSub(sub, func(s *fakeSub) { s.Status = "active" })
	send(t, reg, stripeEvent("customer.subscription.resumed", f.subObject(sub), nil), http.StatusOK)
	if s := status(t, reg, tn.ID); s.Status != sdk.StatusActive {
		t.Fatalf("status = %s", s.Status)
	}
}

func TestInvoicePaidResumesOnlyBillingSuspensions(t *testing.T) {
	_, reg, f := setup(t, nil)
	billing := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "billing", Plan: "pro", Status: sdk.StatusSuspended,
		StatusReason: "billing: customer.subscription.updated (past_due)"})
	manual := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "manual", Plan: "pro", Status: sdk.StatusSuspended,
		StatusReason: "terms of service violation"})
	dunning := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "dunning", Plan: "pro", Status: sdk.StatusSuspended,
		StatusReason: "billing: invoice.payment_failed"})
	cusB, subB := f.seed(billing.ID, "price_pro", "active")
	cusM, subM := f.seed(manual.ID, "price_pro", "active")
	cusD, subD := f.seed(dunning.ID, "price_pro", "past_due") // other invoices still open

	for _, c := range [][2]string{{cusB, subB}, {cusM, subM}, {cusD, subD}} {
		// Invoices carry no tenant metadata: the customer is looked up.
		inv := map[string]any{"id": "in_" + c[1], "object": "invoice", "customer": c[0], "subscription": c[1], "status": "paid"}
		send(t, reg, stripeEvent("invoice.paid", inv, nil), http.StatusOK)
	}
	res := actions(reg, "resume")
	if len(res) != 1 || res[0].TenantID != billing.ID {
		t.Fatalf("resumes = %+v", res)
	}
	if s := status(t, reg, manual.ID); s.Status != sdk.StatusSuspended {
		t.Errorf("manually suspended tenant was resumed")
	}
	if n := len(f.callsTo("GET", "/v1/customers/"+cusB)); n != 1 {
		t.Errorf("customer lookups = %d", n)
	}

	// The newer invoice format (parent.subscription_details) works too.
	f.setSub(subD, func(s *fakeSub) { s.Status = "active" })
	inv := map[string]any{"id": "in_new", "object": "invoice", "customer": cusD,
		"parent": map[string]any{"subscription_details": map[string]any{"subscription": subD, "metadata": map[string]string{"tenarium_tenant_id": dunning.ID}}}}
	send(t, reg, stripeEvent("invoice.paid", inv, nil), http.StatusOK)
	if s := status(t, reg, dunning.ID); s.Status != sdk.StatusActive {
		t.Errorf("dunning tenant status = %s", s.Status)
	}
}

func TestResumeOnPaymentOff(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"resume_on_payment": false})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro", Status: sdk.StatusSuspended, StatusReason: "billing: x"})
	cus, sub := f.seed(tn.ID, "price_pro", "active")
	send(t, reg, stripeEvent("invoice.paid", map[string]any{"id": "in_1", "customer": cus, "subscription": sub}, nil), http.StatusOK)
	send(t, reg, stripeEvent("customer.subscription.updated", f.subObject(sub), map[string]any{"status": "past_due"}), http.StatusOK)
	if a := reg.HostImpl.Actions(); len(a) != 0 {
		t.Fatalf("actions = %+v", a)
	}
}

func TestPastDue(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run("suspend_on_past_due="+strconv.FormatBool(on), func(t *testing.T) {
			_, reg, f := setup(t, map[string]any{"suspend_on_past_due": on})
			tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
			_, sub := f.seed(tn.ID, "price_pro", "past_due")
			send(t, reg, stripeEvent("customer.subscription.updated", f.subObject(sub), map[string]any{"status": "active"}), http.StatusOK)
			sus := actions(reg, "suspend")
			if !on {
				if len(sus) != 0 {
					t.Fatalf("suspended although suspend_on_past_due is off: %+v", sus)
				}
				return
			}
			if len(sus) != 1 || sus[0].Value != "billing: customer.subscription.updated (past_due)" {
				t.Fatalf("suspensions = %+v", sus)
			}
			// Back to active: resumed.
			f.setSub(sub, func(s *fakeSub) { s.Status = "active" })
			send(t, reg, stripeEvent("customer.subscription.updated", f.subObject(sub), map[string]any{"status": "past_due"}), http.StatusOK)
			if res := actions(reg, "resume"); len(res) != 1 {
				t.Fatalf("resumes = %+v", res)
			}
		})
	}
}

func TestStaleEventUsesCurrentState(t *testing.T) {
	// A past_due event arriving after the subscription recovered must not
	// suspend the tenant.
	_, reg, f := setup(t, map[string]any{"suspend_on_past_due": true})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	_, sub := f.seed(tn.ID, "price_pro", "active")
	obj := f.subObject(sub)
	obj["status"] = "past_due"
	send(t, reg, stripeEvent("customer.subscription.updated", obj, map[string]any{"status": "active"}), http.StatusOK)
	if a := actions(reg, "suspend"); len(a) != 0 {
		t.Fatalf("stale event suspended: %+v", a)
	}
}

func TestPlanSyncFromStripe(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	_, sub := f.seed(tn.ID, "price_pro", "active")
	itemsChanged := map[string]any{"items": map[string]any{"data": []any{}}}

	// Price unchanged (e.g. Tenarium caused the change): nothing to do.
	send(t, reg, stripeEvent("customer.subscription.updated", f.subObject(sub), itemsChanged), http.StatusOK)
	if a := actions(reg, "set_plan"); len(a) != 0 {
		t.Fatalf("set_plan on equal plan: %+v", a)
	}

	// Upgraded in the Stripe customer portal.
	f.setSub(sub, func(s *fakeSub) { s.Price = "price_ent" })
	send(t, reg, stripeEvent("customer.subscription.updated", f.subObject(sub), itemsChanged), http.StatusOK)
	sp := actions(reg, "set_plan")
	if len(sp) != 1 || sp[0].TenantID != tn.ID || sp[0].Value != "enterprise" {
		t.Fatalf("set_plan = %+v", sp)
	}
	if s := status(t, reg, tn.ID); s.Plan != "enterprise" {
		t.Fatalf("plan = %s", s.Plan)
	}

	// Again (redelivered under a new event ID): the plans already match.
	send(t, reg, stripeEvent("customer.subscription.updated", f.subObject(sub), itemsChanged), http.StatusOK)
	if n := len(actions(reg, "set_plan")); n != 1 {
		t.Fatalf("set_plan calls = %d, want 1", n)
	}

	// Updates that do not touch the price, and unknown prices, are ignored.
	f.setSub(sub, func(s *fakeSub) { s.Price = "price_pro" })
	send(t, reg, stripeEvent("customer.subscription.updated", f.subObject(sub), map[string]any{"status": "trialing"}), http.StatusOK)
	f.setSub(sub, func(s *fakeSub) { s.Price = "price_unknown" })
	send(t, reg, stripeEvent("customer.subscription.updated", f.subObject(sub), itemsChanged), http.StatusOK)
	if n := len(actions(reg, "set_plan")); n != 1 {
		t.Fatalf("set_plan calls = %d, want 1", n)
	}
}

func TestPlanSyncDisabled(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"sync_plan_from_stripe": false})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	_, sub := f.seed(tn.ID, "price_ent", "active")
	send(t, reg, stripeEvent("customer.subscription.created", f.subObject(sub), nil), http.StatusOK)
	if a := actions(reg, "set_plan"); len(a) != 0 {
		t.Fatalf("set_plan = %+v", a)
	}
}

func TestWebhookTransientFailureIsRetried(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	_, sub := f.seed(tn.ID, "price_pro", "canceled")
	ev := stripeEvent("customer.subscription.deleted", f.subObject(sub), nil)
	f.failNext = 1
	send(t, reg, ev, http.StatusInternalServerError)
	// Stripe retries the same event; it is processed this time.
	send(t, reg, ev, http.StatusOK)
	if sus := actions(reg, "suspend"); len(sus) != 1 {
		t.Fatalf("suspensions = %+v", sus)
	}
}

func TestCustomSuspendOn(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"suspend_on": []string{"invoice.payment_failed"}})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "other", Plan: "pro"})
	cus, _ := f.seed(tn.ID, "price_pro", "past_due")
	_, sub := f.seed(other.ID, "price_pro", "canceled")

	send(t, reg, stripeEvent("invoice.payment_failed", map[string]any{"id": "in_1", "customer": cus}, nil), http.StatusOK)
	// subscription.deleted is no longer in suspend_on.
	send(t, reg, stripeEvent("customer.subscription.deleted", f.subObject(sub), nil), http.StatusOK)
	sus := actions(reg, "suspend")
	if len(sus) != 1 || sus[0].TenantID != tn.ID || sus[0].Value != "billing: invoice.payment_failed" {
		t.Fatalf("suspensions = %+v", sus)
	}
}

func TestSeenSetIsBounded(t *testing.T) {
	s := newSeenSet(3)
	for _, id := range []string{"a", "b", "c", "d"} {
		s.add(id)
	}
	got := slices.DeleteFunc([]string{"a", "b", "c", "d"}, func(id string) bool { return !s.has(id) })
	if !slices.Equal(got, []string{"b", "c", "d"}) || len(s.ids) != 3 {
		t.Fatalf("remembered %v", got)
	}
}
