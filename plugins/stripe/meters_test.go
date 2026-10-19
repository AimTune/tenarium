package stripe

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func periodClosed(tenantID, metric string, value int64) sdk.Event {
	end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	data, _ := json.Marshal(sdk.UsagePeriodData{TenantID: tenantID, Metric: metric, Period: "2026-10", PeriodEnd: &end, Value: value})
	return sdk.Event{ID: "evt-" + metric, Type: sdk.EventTenantUsagePeriodClosed, TenantID: tenantID, Data: data}
}

func TestMeterEvents(t *testing.T) {
	_, reg, f := setup(t, map[string]any{"meters": map[string]string{"api_calls": "api_requests"}})
	cus, _ := f.seed("t-1", "price_pro", "active")
	ctx := context.Background()
	for _, e := range []sdk.Event{
		periodClosed("t-1", "api_calls", 1234),
		periodClosed("t-1", "api_calls", 1234), // redelivery
		periodClosed("t-1", "storage_gb", 5),   // not mapped
		periodClosed("t-1", "api_calls", 0),    // nothing to bill
	} {
		if err := reg.Deliver(ctx, "meters", e); err != nil {
			t.Fatal(err)
		}
	}
	calls := f.callsTo("POST", "/v1/billing/meter_events")
	if len(calls) != 2 {
		t.Fatalf("meter calls: %+v", calls)
	}
	c := calls[0]
	if c.Form["event_name"] != "api_requests" || c.Form["payload[stripe_customer_id]"] != cus ||
		c.Form["payload[value]"] != "1234" || c.Form["timestamp"] != "1793491199" ||
		c.Form["identifier"] != "tenarium-t-1-api_calls-2026-10" || c.IdemKey != c.Form["identifier"] || calls[1].IdemKey != c.IdemKey {
		t.Fatalf("meter event: %+v", c)
	}
	// Missing customers are retried (and dead-lettered) rather than dropped.
	if err := reg.Deliver(ctx, "meters", periodClosed("t-unknown", "api_calls", 1)); err == nil {
		t.Fatal("missing customer not reported")
	}
}

func TestNoMetersNoSubscription(t *testing.T) {
	_, reg, _ := setup(t, nil)
	if err := reg.Deliver(context.Background(), "meters", periodClosed("t-1", "api_calls", 1)); err == nil {
		t.Fatal("meters subscription registered without meters")
	}
}
