package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// reportUsage sends the final value of an ended usage period to the Stripe
// meter mapped to the metric (Billing Meters, sum aggregation). Each period
// is reported with a stable identifier and idempotency key, so retries and
// redeliveries never double-bill.
func (p *Plugin) reportUsage(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.reportUsage(ctx, e)
	}
	var d sdk.UsagePeriodData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return err
	}
	meter, ok := p.cfg.Meters[d.Metric]
	if !ok || d.Value <= 0 || d.PeriodEnd == nil {
		return nil
	}
	cus, err := p.findCustomer(ctx, d.TenantID)
	if err != nil {
		return err
	}
	if cus == nil {
		if !enabled(p.cfg.CreateCustomers) {
			p.log.Info("usage not reported: tenant has no Stripe customer", "tenant", d.TenantID, "metric", d.Metric)
			return nil
		}
		// The customer should exist (or search is lagging): retry, and
		// dead-letter if it never appears so the usage is not lost silently.
		return errors.New("no Stripe customer found for tenant " + d.TenantID)
	}
	id := "tenarium-" + d.TenantID + "-" + d.Metric + "-" + d.Period
	form := url.Values{
		"event_name":                  {meter},
		"identifier":                  {id},
		"payload[stripe_customer_id]": {cus.ID},
		"payload[value]":              {strconv.FormatInt(d.Value, 10)},
		// Inside the period, so Stripe bills it to the right invoice.
		"timestamp": {strconv.FormatInt(d.PeriodEnd.Unix()-1, 10)},
	}
	return p.call(ctx, http.MethodPost, "/v1/billing/meter_events", form, id, nil)
}
