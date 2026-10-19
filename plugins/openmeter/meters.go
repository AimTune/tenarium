package openmeter

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// cloudEvent is a CloudEvents 1.0 event in structured JSON mode.
type cloudEvent struct {
	SpecVersion     string         `json:"specversion"`
	ID              string         `json:"id"`
	Source          string         `json:"source"`
	Type            string         `json:"type"`
	Subject         string         `json:"subject"`
	Time            string         `json:"time"`
	DataContentType string         `json:"datacontenttype"`
	Data            map[string]any `json:"data"`
}

// reportUsage sends the final value of an ended usage period to OpenMeter.
// The event ID is stable per tenant, metric and period, and OpenMeter
// deduplicates by (id, source), so retries and redeliveries never count
// twice.
func (p *Plugin) reportUsage(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.reportUsage(ctx, e)
	}
	var d sdk.UsagePeriodData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return err
	}
	typ, ok := p.cfg.Metrics[d.Metric]
	if !ok || d.Value <= 0 || d.PeriodEnd == nil {
		return nil
	}
	t, err := p.tenant(ctx, d.TenantID)
	if err != nil {
		return err
	}
	subject, err := render(p.subTmpl, t)
	if err != nil {
		return err
	}
	ce := cloudEvent{
		SpecVersion: "1.0",
		ID:          "tenarium-" + d.TenantID + "-" + d.Metric + "-" + d.Period,
		Source:      p.cfg.Source,
		Type:        typ,
		Subject:     subject,
		// Inside the period, so the usage falls into the right window.
		Time:            d.PeriodEnd.Add(-time.Second).UTC().Format(time.RFC3339),
		DataContentType: "application/json",
		Data: map[string]any{
			"metric":            d.Metric,
			"period":            d.Period,
			p.cfg.ValueProperty: d.Value,
		},
	}
	body, err := json.Marshal(ce)
	if err != nil {
		return err
	}
	return p.call(ctx, http.MethodPost, "/api/v1/events", "application/cloudevents+json", body)
}
