package lago

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// event is a Lago usage event (POST /api/v1/events).
type event struct {
	TransactionID          string         `json:"transaction_id"`
	ExternalCustomerID     string         `json:"external_customer_id,omitempty"`
	ExternalSubscriptionID string         `json:"external_subscription_id,omitempty"`
	Code                   string         `json:"code"`
	Timestamp              int64          `json:"timestamp"`
	Properties             map[string]any `json:"properties"`
}

// reportUsage sends the final value of an ended usage period to the Lago
// billable metric mapped to the metric. The transaction ID is stable per
// tenant, metric and period, so retries and redeliveries never double-bill.
func (p *Plugin) reportUsage(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.reportUsage(ctx, e)
	}
	var d sdk.UsagePeriodData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return err
	}
	code, ok := p.cfg.Metrics[d.Metric]
	if !ok || d.Value <= 0 || d.PeriodEnd == nil {
		return nil
	}
	t, err := p.tenant(ctx, d.TenantID)
	if err != nil {
		return err
	}
	id := "tenarium-" + d.TenantID + "-" + d.Metric + "-" + d.Period
	ev := event{
		TransactionID: id,
		Code:          code,
		// Inside the period, so Lago bills it to the right invoice.
		Timestamp:  d.PeriodEnd.Unix() - 1,
		Properties: map[string]any{"value": d.Value},
	}
	if p.subTmpl != nil {
		if ev.ExternalSubscriptionID, err = render(p.subTmpl, t); err != nil {
			return err
		}
	} else if ev.ExternalCustomerID, err = render(p.custTmpl, t); err != nil {
		return err
	}
	err = p.call(ctx, http.MethodPost, "/api/v1/events", map[string]any{"event": ev}, nil)
	if isDuplicate(err) {
		p.log.Debug("usage already reported", "tenant", d.TenantID, "metric", d.Metric, "period", d.Period)
		return nil
	}
	return err
}
