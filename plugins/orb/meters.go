package orb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// event is an Orb usage event (POST /v1/ingest).
type event struct {
	IdempotencyKey     string         `json:"idempotency_key"`
	ExternalCustomerID string         `json:"external_customer_id"`
	EventName          string         `json:"event_name"`
	Timestamp          string         `json:"timestamp"`
	Properties         map[string]any `json:"properties"`
}

// ingestResponse is the body of a 200 response from POST /v1/ingest.
type ingestResponse struct {
	ValidationFailed []struct {
		IdempotencyKey   string   `json:"idempotency_key"`
		ValidationErrors []string `json:"validation_errors"`
	} `json:"validation_failed"`
	Debug *struct {
		Duplicate []string `json:"duplicate"`
		Ingested  []string `json:"ingested"`
	} `json:"debug"`
}

// reportUsage ingests the final value of an ended usage period as an Orb
// event. The idempotency key is stable per tenant, metric and period, and
// Orb deduplicates by it, so retries and redeliveries never double-bill.
func (p *Plugin) reportUsage(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.reportUsage(ctx, e)
	}
	var d sdk.UsagePeriodData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return err
	}
	name, ok := p.cfg.Metrics[d.Metric]
	if !ok || d.Value <= 0 || d.PeriodEnd == nil {
		return nil
	}
	t, err := p.tenant(ctx, d.TenantID)
	if err != nil {
		return err
	}
	customer, err := render(p.custTmpl, t)
	if err != nil {
		return err
	}
	id := "tenarium-" + d.TenantID + "-" + d.Metric + "-" + d.Period
	ev := event{
		IdempotencyKey:     id,
		ExternalCustomerID: customer,
		EventName:          name,
		// Inside the period, so Orb bills it to the right invoice.
		Timestamp: d.PeriodEnd.Add(-time.Second).UTC().Format(time.RFC3339),
		Properties: map[string]any{
			"tenarium_metric":  d.Metric,
			"tenarium_period":  d.Period,
			p.cfg.PropertyName: d.Value,
		},
	}
	path := "/v1/ingest"
	if p.cfg.Debug {
		path += "?debug=true"
	}
	var res ingestResponse
	if err := p.call(ctx, http.MethodPost, path, map[string]any{"events": []event{ev}}, &res); err != nil {
		return err
	}
	for _, f := range res.ValidationFailed {
		if f.IdempotencyKey == id {
			return fmt.Errorf("orb: event %s rejected: %s", id, strings.Join(f.ValidationErrors, "; "))
		}
	}
	if res.Debug != nil {
		p.log.Debug("orb ingest", "idempotency_key", id, "ingested", res.Debug.Ingested, "duplicate", res.Debug.Duplicate)
	}
	return nil
}
