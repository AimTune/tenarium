package chargebee

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

var evN int

func cbEvent(typ string, content map[string]any) map[string]any {
	evN++
	return map[string]any{
		"id": "ev_" + strconv.Itoa(evN), "object": "event", "api_version": "v2", "event_type": typ,
		"occurred_at": testNow.Unix(), "source": "admin_console", "content": content,
	}
}

func post(reg *sdktest.Registrar, body []byte, user, pass string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/public/webhook", bytes.NewReader(body))
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	return rec
}

func send(t *testing.T, reg *sdktest.Registrar, ev map[string]any, want int) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(ev)
	rec := post(reg, body, testUser, testPass)
	if rec.Code != want {
		t.Fatalf("%s: status = %d, want %d: %s", ev["event_type"], rec.Code, want, rec.Body)
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

func subContent(f *fakeChargebee, id string) map[string]any {
	return map[string]any{"subscription": f.subObject(id)}
}

func TestWebhookAuth(t *testing.T) {
	_, reg, _ := setup(t, nil)
	body, _ := json.Marshal(cbEvent("customer_changed", map[string]any{"customer": map[string]any{"id": "x"}}))
	for _, c := range []struct{ name, user, pass string }{
		{"none", "", ""},
		{"wrong password", testUser, "wrong"},
		{"wrong user", "other", testPass},
		{"password prefix", testUser, testPass[:5]},
	} {
		rec := post(reg, body, c.user, c.pass)
		if rec.Code != http.StatusUnauthorized || !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic ") {
			t.Errorf("%s: status = %d, WWW-Authenticate = %q", c.name, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
	if rec := post(reg, body, testUser, testPass); rec.Code != http.StatusOK {
		t.Fatalf("valid credentials: %d %s", rec.Code, rec.Body)
	}
}

func TestWebhookRejectsBadPayloads(t *testing.T) {
	_, reg, _ := setup(t, nil)
	for name, body := range map[string][]byte{
		"not json":   []byte(`not json`),
		"no id":      []byte(`{"event_type":"payment_succeeded","content":{}}`),
		"no type":    []byte(`{"id":"ev_1","content":{}}`),
		"no content": []byte(`{"id":"ev_1","event_type":"payment_succeeded"}`),
		"oversized":  bytes.Repeat([]byte("x"), maxWebhookBody+1),
	} {
		if rec := post(reg, body, testUser, testPass); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	// Valid but unhandled events are acknowledged.
	send(t, reg, cbEvent("invoice_generated", map[string]any{"invoice": map[string]any{"id": "inv_1"}}), http.StatusOK)
	if len(reg.HostImpl.Actions()) != 0 {
		t.Fatal("unexpected host actions")
	}
}

func TestSubscriptionCancelledSuspendsAndDedupes(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	sub := f.seed(tn.ID, "pro-USD-Monthly", "cancelled")

	ev := cbEvent("subscription_cancelled", subContent(f, sub))
	send(t, reg, ev, http.StatusOK)
	sus := actions(reg, "suspend")
	if len(sus) != 1 || sus[0].TenantID != tn.ID || sus[0].Value != "billing: subscription_cancelled" {
		t.Fatalf("suspensions = %+v", sus)
	}
	rec := send(t, reg, ev, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "duplicate") {
		t.Errorf("duplicate not reported: %s", rec.Body)
	}
	if n := len(f.callsTo("GET", "/subscriptions/"+sub)); n != 1 {
		t.Errorf("duplicate reprocessed: %d subscription fetches", n)
	}
}

func TestStaleCancelledEventUsesCurrentState(t *testing.T) {
	// Cancelled, then reactivated; the cancellation arrives late.
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	sub := f.seed(tn.ID, "pro-USD-Monthly", "active")
	c := subContent(f, sub)
	c["subscription"].(map[string]any)["status"] = "cancelled"
	send(t, reg, cbEvent("subscription_cancelled", c), http.StatusOK)
	if a := reg.HostImpl.Actions(); len(a) != 0 {
		t.Fatalf("stale event acted: %+v", a)
	}
}

func TestCancelledWithAnotherHealthySubscription(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	sub := f.seed(tn.ID, "pro-USD-Monthly", "cancelled")
	f.mu.Lock()
	f.subs["checkout_sub"] = &fakeSub{ID: "checkout_sub", Customer: tn.ID, Status: "active", Price: "ent-USD-Yearly", MetaData: map[string]any{}}
	f.subOrder = append(f.subOrder, "checkout_sub")
	f.mu.Unlock()
	send(t, reg, cbEvent("subscription_cancelled", subContent(f, sub)), http.StatusOK)
	if a := actions(reg, "suspend"); len(a) != 0 {
		t.Fatalf("suspended although another plan subscription is active: %+v", a)
	}
}

func TestCancelledSkipsUnbilledTenant(t *testing.T) {
	// A downgrade to a free plan cancels the subscription; the resulting
	// webhook must not suspend the tenant.
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "free"})
	sub := f.seed(tn.ID, "pro-USD-Monthly", "cancelled")
	send(t, reg, cbEvent("subscription_cancelled", subContent(f, sub)), http.StatusOK)
	if a := reg.HostImpl.Actions(); len(a) != 0 {
		t.Fatalf("actions = %+v", a)
	}
}

func TestPausedSuspendsAndResumedResumes(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	sub := f.seed(tn.ID, "pro-USD-Monthly", "paused")
	send(t, reg, cbEvent("subscription_paused", subContent(f, sub)), http.StatusOK)
	if s := status(t, reg, tn.ID); s.Status != sdk.StatusSuspended || s.StatusReason != "billing: subscription_paused" {
		t.Fatalf("tenant = %s %q", s.Status, s.StatusReason)
	}
	f.setSub(sub, func(s *fakeSub) { s.Status = "active" })
	send(t, reg, cbEvent("subscription_resumed", subContent(f, sub)), http.StatusOK)
	if s := status(t, reg, tn.ID); s.Status != sdk.StatusActive {
		t.Fatalf("status = %s", s.Status)
	}
}

func TestResumeOnlyBillingSuspensions(t *testing.T) {
	_, reg, f := setup(t, nil)
	manual := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "manual", Plan: "pro", Status: sdk.StatusSuspended, StatusReason: "terms of service violation"})
	sub := f.seed(manual.ID, "pro-USD-Monthly", "active")
	for _, typ := range []string{"subscription_reactivated", "subscription_activated", "subscription_renewed"} {
		send(t, reg, cbEvent(typ, subContent(f, sub)), http.StatusOK)
	}
	inv := map[string]any{"subscription_id": sub, "customer_id": manual.ID}
	send(t, reg, cbEvent("payment_succeeded", map[string]any{"invoice": inv}), http.StatusOK)
	if a := reg.HostImpl.Actions(); len(a) != 0 {
		t.Fatalf("manually suspended tenant touched: %+v", a)
	}
}

func TestPaymentSucceeded(t *testing.T) {
	_, reg, f := setup(t, nil)
	billing := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "billing", Plan: "pro", Status: sdk.StatusSuspended, StatusReason: "billing: payment_failed"})
	dunning := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "dunning", Plan: "pro", Status: sdk.StatusSuspended, StatusReason: "billing: payment_failed"})
	subB := f.seed(billing.ID, "pro-USD-Monthly", "active")
	subD := f.seed(dunning.ID, "pro-USD-Monthly", "active")
	f.setSub(subD, func(s *fakeSub) { s.DueInvoices = 1 }) // other invoices still due

	for _, c := range [][2]string{{billing.ID, subB}, {dunning.ID, subD}} {
		// Transactions carry no tenant metadata: the customer ID is the tenant ID.
		tx := map[string]any{"id": "txn_" + c[1], "customer_id": c[0], "subscription_id": c[1], "status": "success"}
		send(t, reg, cbEvent("payment_succeeded", map[string]any{"transaction": tx}), http.StatusOK)
	}
	res := actions(reg, "resume")
	if len(res) != 1 || res[0].TenantID != billing.ID {
		t.Fatalf("resumes = %+v", res)
	}
	if s := status(t, reg, dunning.ID); s.Status != sdk.StatusSuspended {
		t.Fatal("tenant with due invoices was resumed")
	}
}

func TestPaymentFailed(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run(fmt.Sprint("suspend_on_payment_failed=", on), func(t *testing.T) {
			_, reg, f := setup(t, map[string]any{"suspend_on_payment_failed": on})
			tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
			sub := f.seed(tn.ID, "pro-USD-Monthly", "active")
			c := subContent(f, sub)
			c["transaction"] = map[string]any{"id": "txn_1", "status": "failure", "subscription_id": sub, "customer_id": tn.ID}
			send(t, reg, cbEvent("payment_failed", c), http.StatusOK)
			sus := actions(reg, "suspend")
			if !on {
				if len(sus) != 0 {
					t.Fatalf("suspended although suspend_on_payment_failed is off: %+v", sus)
				}
				return
			}
			if len(sus) != 1 || sus[0].Value != "billing: payment_failed" {
				t.Fatalf("suspensions = %+v", sus)
			}
			// A renewal reminder (not a resume event) does not resume.
			send(t, reg, cbEvent("subscription_renewal_reminder", subContent(f, sub)), http.StatusOK)
			// Paid: resumed.
			send(t, reg, cbEvent("payment_succeeded", c), http.StatusOK)
			if res := actions(reg, "resume"); len(res) != 1 {
				t.Fatalf("resumes = %+v", res)
			}
		})
	}
}

func TestResumeOnPaymentOff(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"resume_on_payment": false})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro", Status: sdk.StatusSuspended, StatusReason: "billing: x"})
	sub := f.seed(tn.ID, "pro-USD-Monthly", "active")
	send(t, reg, cbEvent("payment_succeeded", subContent(f, sub)), http.StatusOK)
	send(t, reg, cbEvent("subscription_reactivated", subContent(f, sub)), http.StatusOK)
	if a := reg.HostImpl.Actions(); len(a) != 0 {
		t.Fatalf("actions = %+v", a)
	}
}

func TestPlanSyncFromChargebee(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	sub := f.seed(tn.ID, "pro-USD-Monthly", "active")

	// Item price unchanged (e.g. Tenarium caused the change): nothing to do.
	send(t, reg, cbEvent("subscription_changed", subContent(f, sub)), http.StatusOK)
	if a := actions(reg, "set_plan"); len(a) != 0 {
		t.Fatalf("set_plan on equal plan: %+v", a)
	}

	// Upgraded in the Chargebee self-serve portal.
	f.setSub(sub, func(s *fakeSub) { s.Price = "ent-USD-Yearly" })
	send(t, reg, cbEvent("subscription_changed", subContent(f, sub)), http.StatusOK)
	sp := actions(reg, "set_plan")
	if len(sp) != 1 || sp[0].TenantID != tn.ID || sp[0].Value != "enterprise" {
		t.Fatalf("set_plan = %+v", sp)
	}
	if s := status(t, reg, tn.ID); s.Plan != "enterprise" {
		t.Fatalf("plan = %s", s.Plan)
	}

	// Loop prevention: the plan.changed this caused reaches the sync handler,
	// which finds the subscription already on the price and does nothing.
	deliver(t, reg, planEvent(status(t, reg, tn.ID), "pro"))
	if n := len(f.callsTo("POST", "/subscriptions/"+sub+"/update_for_items")); n != 0 {
		t.Fatalf("sync wrote back to Chargebee (%d updates)", n)
	}
	// Another event with the same state: the plans already match.
	send(t, reg, cbEvent("subscription_changed", subContent(f, sub)), http.StatusOK)
	if n := len(actions(reg, "set_plan")); n != 1 {
		t.Fatalf("set_plan calls = %d, want 1", n)
	}

	// Unknown item prices, and mapped plans missing in Tenarium, are ignored.
	f.setSub(sub, func(s *fakeSub) { s.Price = "unknown-price" })
	send(t, reg, cbEvent("subscription_changed", subContent(f, sub)), http.StatusOK)
	if n := len(actions(reg, "set_plan")); n != 1 {
		t.Fatalf("set_plan calls = %d, want 1", n)
	}
}

func TestPlanSyncSkipsMissingPlan(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"plans": map[string]string{"pro": "pro-USD-Monthly", "ghost": "ghost-USD"}})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	sub := f.seed(tn.ID, "ghost-USD", "active")
	send(t, reg, cbEvent("subscription_changed", subContent(f, sub)), http.StatusOK)
	if a := actions(reg, "set_plan"); len(a) != 0 {
		t.Fatalf("set_plan to a missing plan: %+v", a)
	}
}

func TestPlanSyncDisabled(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"sync_plan_from_chargebee": false})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	sub := f.seed(tn.ID, "ent-USD-Yearly", "active")
	send(t, reg, cbEvent("subscription_created", subContent(f, sub)), http.StatusOK)
	if a := actions(reg, "set_plan"); len(a) != 0 {
		t.Fatalf("set_plan = %+v", a)
	}
}

func TestTenantResolution(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"tenant_id_field": "cf_tenarium_tenant_id"})
	byMeta := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "meta", Plan: "pro"})
	byCF := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "cf", Plan: "pro"})
	// Customers created elsewhere (e.g. hosted checkout) with their own IDs.
	f.seedCustomer("cb_meta", map[string]any{"tenarium_tenant_id": byMeta.ID})
	f.seedCustomer("cb_cf", nil)
	f.mu.Lock()
	f.customers["cb_cf"].Custom["cf_tenarium_tenant_id"] = byCF.ID
	f.mu.Unlock()
	f.seedCustomer("cb_stranger", nil)

	for _, cust := range []string{"cb_meta", "cb_cf", "cb_stranger", "meta" /* a slug, not an ID */} {
		// Only the customer ID is in the event: the customer is fetched.
		send(t, reg, cbEvent("payment_failed", map[string]any{"transaction": map[string]any{"customer_id": cust}}), http.StatusOK)
	}
	// payment_failed is not handled by default; use suspend_on instead.
	if a := reg.HostImpl.Actions(); len(a) != 0 {
		t.Fatalf("actions = %+v", a)
	}

	_, reg2, f2 := setup(t, map[string]any{"tenant_id_field": "cf_tenarium_tenant_id", "suspend_on": []string{"payment_failed"}})
	byMeta = reg2.HostImpl.AddTenant(byMeta)
	byCF = reg2.HostImpl.AddTenant(byCF)
	f2.seedCustomer("cb_meta", map[string]any{"tenarium_tenant_id": byMeta.ID})
	f2.seedCustomer("cb_cf", nil)
	f2.mu.Lock()
	f2.customers["cb_cf"].Custom["cf_tenarium_tenant_id"] = byCF.ID
	f2.mu.Unlock()
	f2.seedCustomer("cb_stranger", nil)
	for _, cust := range []string{"cb_meta", "cb_cf", "cb_stranger", "meta"} {
		send(t, reg2, cbEvent("payment_failed", map[string]any{"transaction": map[string]any{"customer_id": cust}}), http.StatusOK)
	}
	var got []string
	for _, a := range actions(reg2, "suspend") {
		got = append(got, a.TenantID)
	}
	if want := []string{byMeta.ID, byCF.ID}; !slices.Equal(got, want) {
		t.Fatalf("suspended %v, want %v", got, want)
	}
}

type rejectHost struct{ *sdktest.Host }

func (h rejectHost) SuspendTenant(context.Context, string, string) (sdk.Tenant, error) {
	return sdk.Tenant{}, &sdk.RejectError{Reason: "policy says no"}
}

func TestRejectedSuspensionIsSwallowed(t *testing.T) {
	p, reg, f := setup(t, nil)
	p.host = rejectHost{reg.HostImpl}
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	sub := f.seed(tn.ID, "pro-USD-Monthly", "cancelled")
	send(t, reg, cbEvent("subscription_cancelled", subContent(f, sub)), http.StatusOK)
}

func TestWebhookTransientFailureIsRetried(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro"})
	sub := f.seed(tn.ID, "pro-USD-Monthly", "cancelled")
	ev := cbEvent("subscription_cancelled", subContent(f, sub))
	f.failNext = 1
	send(t, reg, ev, http.StatusInternalServerError)
	send(t, reg, ev, http.StatusOK) // Chargebee retries; not marked seen before
	if sus := actions(reg, "suspend"); len(sus) != 1 {
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
