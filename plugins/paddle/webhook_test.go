package paddle

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
	body := []byte(`{"event_id":"evt_1"}`)
	good := Sign(testSecret, testNow, body)
	ts := strconv.FormatInt(testNow.Unix(), 10)
	wrong := signature("pdl_ntfset_other", ts, body)
	cases := []struct {
		name   string
		header string
		now    time.Time
		want   error
	}{
		{"valid", good, testNow, nil},
		{"within tolerance", good, testNow.Add(4 * time.Minute), nil},
		{"rotated secret, one h1 matching", "ts=" + ts + ";h1=" + wrong + ";h1=" + signature(testSecret, ts, body), testNow, nil},
		{"spaces", "ts=" + ts + "; h1=" + signature(testSecret, ts, body), testNow, nil},
		{"wrong secret", "ts=" + ts + ";h1=" + wrong, testNow, errBadSignature},
		{"tampered timestamp", strings.Replace(good, "ts="+ts, "ts="+strconv.FormatInt(testNow.Unix()+1, 10), 1), testNow, errBadSignature},
		{"expired", good, testNow.Add(6 * time.Minute), errExpired},
		{"from the future", good, testNow.Add(-6 * time.Minute), errExpired},
		{"missing", "", testNow, errBadSignature},
		{"no h1", "ts=" + ts + ";h2=" + wrong, testNow, errBadSignature},
		{"bad timestamp", "ts=abc;h1=" + wrong, testNow, errBadSignature},
		{"stripe style", "t=" + ts + ",v1=" + signature(testSecret, ts, body), testNow, errBadSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifySignature(body, tc.header, testSecret, tc.now)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if err := VerifySignature([]byte(`{"event_id":"evt_2"}`), good, testSecret, testNow); !errors.Is(err, errBadSignature) {
		t.Fatalf("tampered body: err = %v", err)
	}
}

var evtN int

func paddleEvent(typ string, data any) map[string]any {
	evtN++
	return map[string]any{
		"event_id": "evt_" + strconv.Itoa(evtN), "event_type": typ, "occurred_at": testNow.Format(time.RFC3339Nano),
		"notification_id": "ntf_" + strconv.Itoa(evtN), "data": data,
	}
}

func post(reg *sdktest.Registrar, body []byte, sig string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/public/webhook", bytes.NewReader(body))
	req.Header.Set("Paddle-Signature", sig)
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	return rec
}

func send(t *testing.T, reg *sdktest.Registrar, ev map[string]any, want int) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(ev)
	rec := post(reg, body, Sign(testSecret, testNow, body))
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

func TestWebhookRejectsBadRequests(t *testing.T) {
	_, reg, _ := setup(t, nil)
	body := []byte(`{"event_id":"evt_x","event_type":"transaction.completed","data":{}}`)
	if rec := post(reg, body, Sign("pdl_ntfset_wrong", testNow, body)); rec.Code != http.StatusBadRequest {
		t.Errorf("bad signature: %d", rec.Code)
	}
	if rec := post(reg, body, Sign(testSecret, testNow.Add(-time.Hour), body)); rec.Code != http.StatusBadRequest {
		t.Errorf("expired: %d", rec.Code)
	}
	if rec := post(reg, body, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("unsigned: %d", rec.Code)
	}
	for _, bad := range [][]byte{[]byte(`not json`), []byte(`{"event_type":"x","data":{}}`), []byte(`{"event_id":"e","event_type":"x","data":[]}`)} {
		if rec := post(reg, bad, Sign(testSecret, testNow, bad)); rec.Code != http.StatusBadRequest {
			t.Errorf("bad payload %s: %d", bad, rec.Code)
		}
	}
	big := bytes.Repeat([]byte("x"), maxWebhookBody+1)
	if rec := post(reg, big, Sign(testSecret, testNow, big)); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized: %d", rec.Code)
	}
	// Valid but unhandled notifications are acknowledged.
	send(t, reg, paddleEvent("adjustment.created", map[string]any{"id": "adj_1"}), http.StatusOK)
	if len(reg.HostImpl.Actions()) != 0 {
		t.Fatal("unexpected host actions")
	}
}

func TestSubscriptionCanceledSuspends(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "canceled")

	ev := paddleEvent("subscription.canceled", f.subObject(sub))
	send(t, reg, ev, http.StatusOK)
	sus := actions(reg, "suspend")
	if len(sus) != 1 || sus[0].TenantID != tn.ID || sus[0].Value != "billing: subscription.canceled" {
		t.Fatalf("suspensions = %+v", sus)
	}

	// Duplicate deliveries are acknowledged without reprocessing.
	rec := send(t, reg, ev, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "duplicate") {
		t.Errorf("duplicate not reported: %s", rec.Body)
	}
	if n := len(f.callsTo("GET", "/subscriptions/"+sub)); n != 1 {
		t.Errorf("duplicate reprocessed: %d subscription fetches", n)
	}
}

func TestSubscriptionCanceledSkipsUnbilledTenant(t *testing.T) {
	// A downgrade to a free plan cancels the subscription; the resulting
	// notification must not suspend the tenant.
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "free")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "canceled")
	send(t, reg, paddleEvent("subscription.canceled", f.subObject(sub)), http.StatusOK)
	if a := reg.HostImpl.Actions(); len(a) != 0 {
		t.Fatalf("actions = %+v", a)
	}
}

func TestSubscriptionCanceledWithReplacement(t *testing.T) {
	// The customer switched via a new checkout; the old subscription's
	// cancellation must not suspend the tenant.
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	cus, old := f.seed(tn.ID, "acme@example.com", "pri_pro", "canceled")
	f.addSub(cus, tn.ID, "pri_pro", "active")
	send(t, reg, paddleEvent("subscription.canceled", f.subObject(old)), http.StatusOK)
	if a := actions(reg, "suspend"); len(a) != 0 {
		t.Fatalf("suspensions = %+v", a)
	}
}

func TestTenantFromCustomerCustomData(t *testing.T) {
	// Checkout-created subscriptions may lack custom_data: the customer's
	// is used.
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	cus := f.addCustomer("acme@example.com", tn.ID)
	sub := f.addSub(cus, "", "pri_pro", "paused")
	send(t, reg, paddleEvent("subscription.paused", f.subObject(sub)), http.StatusOK)
	if s := status(t, reg, tn.ID); s.Status != sdk.StatusSuspended {
		t.Fatalf("status = %s", s.Status)
	}
	if n := len(f.callsTo("GET", "/customers/"+cus)); n != 1 {
		t.Fatalf("customer lookups = %d", n)
	}
}

func TestSubscriptionPausedSuspendsAndResumedResumes(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "paused")
	send(t, reg, paddleEvent("subscription.paused", f.subObject(sub)), http.StatusOK)
	if s := status(t, reg, tn.ID); s.Status != sdk.StatusSuspended || s.StatusReason != "billing: subscription.paused" {
		t.Fatalf("tenant = %s %q", s.Status, s.StatusReason)
	}
	f.setSub(sub, func(s *fakeSub) { s.Status = "active" })
	send(t, reg, paddleEvent("subscription.resumed", f.subObject(sub)), http.StatusOK)
	if s := status(t, reg, tn.ID); s.Status != sdk.StatusActive {
		t.Fatalf("status = %s", s.Status)
	}
}

func TestTransactionCompletedResumesOnlyBillingSuspensions(t *testing.T) {
	_, reg, f := setup(t, nil)
	add := func(slug, reason string) sdk.Tenant {
		return reg.HostImpl.AddTenant(sdk.Tenant{Slug: slug, Plan: "pro", Status: sdk.StatusSuspended, StatusReason: reason})
	}
	billing := add("billing", "billing: subscription.past_due")
	manual := add("manual", "terms of service violation")
	dunning := add("dunning", "billing: subscription.past_due")
	cusB, subB := f.seed(billing.ID, "b@example.com", "pri_pro", "active")
	cusM, subM := f.seed(manual.ID, "m@example.com", "pri_pro", "active")
	cusD, subD := f.seed(dunning.ID, "d@example.com", "pri_pro", "past_due") // still past due

	for _, c := range [][2]string{{cusB, subB}, {cusM, subM}, {cusD, subD}} {
		// Transactions carry no tenant custom_data here: the subscription's
		// is used.
		tx := map[string]any{"id": "txn_" + c[1], "status": "completed", "customer_id": c[0], "subscription_id": c[1]}
		send(t, reg, paddleEvent("transaction.completed", tx), http.StatusOK)
	}
	res := actions(reg, "resume")
	if len(res) != 1 || res[0].TenantID != billing.ID {
		t.Fatalf("resumes = %+v", res)
	}
	if s := status(t, reg, manual.ID); s.Status != sdk.StatusSuspended {
		t.Errorf("manually suspended tenant was resumed")
	}

	// A one-off transaction with tenant custom_data resumes too.
	f.setSub(subD, func(s *fakeSub) { s.Status = "active" })
	tx := map[string]any{"id": "txn_x", "status": "completed", "customer_id": cusD,
		"custom_data": map[string]any{CustomDataTenantID: dunning.ID}}
	send(t, reg, paddleEvent("transaction.completed", tx), http.StatusOK)
	if s := status(t, reg, dunning.ID); s.Status != sdk.StatusActive {
		t.Errorf("dunning tenant status = %s", s.Status)
	}
}

func TestResumeOnPaymentOff(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"resume_on_payment": false})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro", Status: sdk.StatusSuspended, StatusReason: "billing: x"})
	cus, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "active")
	send(t, reg, paddleEvent("transaction.completed", map[string]any{"id": "txn_1", "customer_id": cus, "subscription_id": sub}), http.StatusOK)
	send(t, reg, paddleEvent("subscription.activated", f.subObject(sub)), http.StatusOK)
	if a := reg.HostImpl.Actions(); len(a) != 0 {
		t.Fatalf("actions = %+v", a)
	}
}

func TestPastDue(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run("suspend_on_past_due="+strconv.FormatBool(on), func(t *testing.T) {
			_, reg, f := setup(t, map[string]any{"suspend_on_past_due": on})
			tn := addTenant(reg, "acme", "pro")
			_, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "past_due")
			send(t, reg, paddleEvent("subscription.past_due", f.subObject(sub)), http.StatusOK)
			sus := actions(reg, "suspend")
			if !on {
				if len(sus) != 0 {
					t.Fatalf("suspended although suspend_on_past_due is off: %+v", sus)
				}
				return
			}
			if len(sus) != 1 || sus[0].Value != "billing: subscription.past_due" {
				t.Fatalf("suspensions = %+v", sus)
			}
			// Back to active: resumed.
			f.setSub(sub, func(s *fakeSub) { s.Status = "active" })
			send(t, reg, paddleEvent("subscription.updated", f.subObject(sub)), http.StatusOK)
			if res := actions(reg, "resume"); len(res) != 1 {
				t.Fatalf("resumes = %+v", res)
			}
		})
	}
}

func TestPastDueViaUpdated(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"suspend_on_past_due": true})
	tn := addTenant(reg, "acme", "pro")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "past_due")
	send(t, reg, paddleEvent("subscription.updated", f.subObject(sub)), http.StatusOK)
	if sus := actions(reg, "suspend"); len(sus) != 1 || sus[0].Value != "billing: subscription.updated (past_due)" {
		t.Fatalf("suspensions = %+v", sus)
	}
}

func TestStaleEventUsesCurrentState(t *testing.T) {
	// A past_due notification arriving after the subscription recovered
	// must not suspend the tenant.
	_, reg, f := setup(t, map[string]any{"suspend_on_past_due": true})
	tn := addTenant(reg, "acme", "pro")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "active")
	obj := f.subObject(sub)
	obj["status"] = "past_due"
	send(t, reg, paddleEvent("subscription.past_due", obj), http.StatusOK)
	if a := actions(reg, "suspend"); len(a) != 0 {
		t.Fatalf("stale notification suspended: %+v", a)
	}
}

func TestPlanSyncFromPaddle(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "active")

	// Price unchanged (e.g. Tenarium caused the change): nothing to do.
	send(t, reg, paddleEvent("subscription.updated", f.subObject(sub)), http.StatusOK)
	if a := actions(reg, "set_plan"); len(a) != 0 {
		t.Fatalf("set_plan on equal plan: %+v", a)
	}

	// Upgraded in Paddle (customer portal or dashboard).
	f.setSub(sub, func(s *fakeSub) { s.Items[0].Price = "pri_ent" })
	send(t, reg, paddleEvent("subscription.updated", f.subObject(sub)), http.StatusOK)
	sp := actions(reg, "set_plan")
	if len(sp) != 1 || sp[0].TenantID != tn.ID || sp[0].Value != "enterprise" {
		t.Fatalf("set_plan = %+v", sp)
	}
	tn = status(t, reg, tn.ID)
	if tn.Plan != "enterprise" {
		t.Fatalf("plan = %s", tn.Plan)
	}

	// The resulting tenant.plan_changed finds Paddle already matching: no
	// update is sent back (loop prevention).
	deliver(t, reg, sdktest.TenantEvent(sdk.EventTenantPlanChanged, tn))
	if n := len(f.callsTo("PATCH", "/subscriptions/")); n != 0 {
		t.Fatalf("plan change echoed back to Paddle: %d updates", n)
	}

	// Again (another notification): the plans already match.
	send(t, reg, paddleEvent("subscription.updated", f.subObject(sub)), http.StatusOK)
	if n := len(actions(reg, "set_plan")); n != 1 {
		t.Fatalf("set_plan calls = %d, want 1", n)
	}

	// Unknown prices are ignored; so are plans missing in Tenarium.
	f.setSub(sub, func(s *fakeSub) { s.Items[0].Price = "pri_unknown" })
	send(t, reg, paddleEvent("subscription.updated", f.subObject(sub)), http.StatusOK)
	if n := len(actions(reg, "set_plan")); n != 1 {
		t.Fatalf("set_plan calls = %d, want 1", n)
	}
}

func TestPlanSyncSkipsMissingPlan(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"plans": map[string]string{"pro": "pri_pro", "ghost": "pri_ghost"}})
	tn := addTenant(reg, "acme", "pro")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_ghost", "active")
	send(t, reg, paddleEvent("subscription.updated", f.subObject(sub)), http.StatusOK)
	if a := actions(reg, "set_plan"); len(a) != 0 {
		t.Fatalf("set_plan = %+v", a)
	}
}

func TestPlanSyncDisabled(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"sync_plan_from_paddle": false})
	tn := addTenant(reg, "acme", "pro")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_ent", "active")
	send(t, reg, paddleEvent("subscription.created", f.subObject(sub)), http.StatusOK)
	if a := actions(reg, "set_plan"); len(a) != 0 {
		t.Fatalf("set_plan = %+v", a)
	}
}

func TestWebhookTransientFailureIsRetried(t *testing.T) {
	_, reg, f := setup(t, nil)
	tn := addTenant(reg, "acme", "pro")
	_, sub := f.seed(tn.ID, "acme@example.com", "pri_pro", "canceled")
	ev := paddleEvent("subscription.canceled", f.subObject(sub))
	f.failNext = 1
	send(t, reg, ev, http.StatusInternalServerError)
	// Paddle retries the same notification; it is processed this time.
	send(t, reg, ev, http.StatusOK)
	if sus := actions(reg, "suspend"); len(sus) != 1 {
		t.Fatalf("suspensions = %+v", sus)
	}
}

func TestCustomSuspendOn(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"suspend_on": []string{"transaction.payment_failed"}})
	tn := addTenant(reg, "acme", "pro")
	other := addTenant(reg, "other", "pro")
	cus, _ := f.seed(tn.ID, "acme@example.com", "pri_pro", "past_due")
	_, sub := f.seed(other.ID, "other@example.com", "pri_pro", "canceled")

	send(t, reg, paddleEvent("transaction.payment_failed", map[string]any{"id": "txn_1", "customer_id": cus}), http.StatusOK)
	// subscription.canceled is no longer in suspend_on.
	send(t, reg, paddleEvent("subscription.canceled", f.subObject(sub)), http.StatusOK)
	sus := actions(reg, "suspend")
	if len(sus) != 1 || sus[0].TenantID != tn.ID || sus[0].Value != "billing: transaction.payment_failed" {
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
