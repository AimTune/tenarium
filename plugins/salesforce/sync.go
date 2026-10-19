package salesforce

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// sync mirrors tenant events into Salesforce.
func (p *Plugin) sync(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.sync(ctx, e)
	}
	var data sdk.TenantEventData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return fmt.Errorf("decode event: %w", err)
	}
	t := data.Tenant
	if t.ID == "" {
		return errors.New("event carries no tenant")
	}
	if e.Type != sdk.EventTenantDeleted {
		return p.upsert(ctx, t, p.fields)
	}
	switch p.cfg.OnDelete {
	case onDeleteDelete:
		if _, err := p.api(ctx, http.MethodDelete, p.recordPath(t.ID), nil); err != nil && !isNotFound(err) {
			return err
		}
		p.log.Info("deleted record of deleted tenant", "tenant", t.ID, "sobject", p.cfg.SObject)
	case onDeleteUpdate:
		merged := maps.Clone(p.fields)
		maps.Copy(merged, p.deletedFields)
		return p.upsert(ctx, t, merged)
	}
	return nil
}

// recordPath is the upsert-by-external-ID path of the tenant's record.
func (p *Plugin) recordPath(tenantID string) string {
	return "/sobjects/" + p.cfg.SObject + "/" + p.cfg.ExternalIDField + "/" + url.PathEscape(tenantID)
}

// upsert creates or updates the tenant's record. Empty rendered values are
// left out so they never clear fields maintained in Salesforce.
func (p *Plugin) upsert(ctx context.Context, t sdk.Tenant, tmpls map[string]*template.Template) error {
	fields := make(map[string]string, len(tmpls))
	for name, tmpl := range tmpls {
		var b strings.Builder
		if err := tmpl.Execute(&b, t); err != nil {
			return fmt.Errorf("render field %s: %w", name, err)
		}
		if v := strings.TrimSpace(b.String()); v != "" {
			fields[name] = v
		}
	}
	raw, err := p.api(ctx, http.MethodPatch, p.recordPath(t.ID), fields)
	if err != nil {
		return err
	}
	var res struct {
		ID      string `json:"id"`
		Created bool   `json:"created"`
	}
	_ = json.Unmarshal(raw, &res) // 204 responses have no body
	p.log.Debug("upserted record", "tenant", t.ID, "sobject", p.cfg.SObject, "id", res.ID, "created", res.Created)
	return nil
}
