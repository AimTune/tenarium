package lago

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Metadata keys set on Lago customers.
const (
	MetadataTenantID = "tenarium_tenant_id"
	MetadataSlug     = "tenarium_slug"
)

// Customer is the subset of a Lago customer the plugin uses.
type Customer struct {
	LagoID     string     `json:"lago_id,omitempty"`
	ExternalID string     `json:"external_id"`
	Name       string     `json:"name"`
	Metadata   []Metadata `json:"metadata"`
}

// Metadata is a Lago customer metadata entry. Responses identify entries
// by lago_id; requests update an existing entry by passing it as id.
type Metadata struct {
	LagoID           string `json:"lago_id,omitempty"`
	ID               string `json:"id,omitempty"`
	Key              string `json:"key"`
	Value            string `json:"value"`
	DisplayInInvoice bool   `json:"display_in_invoice"`
}

// syncCustomer creates or updates the tenant's Lago customer. Lago upserts
// customers by external_id; existing metadata entries are sent back with
// their IDs so they are updated in place rather than duplicated or dropped.
func (p *Plugin) syncCustomer(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.syncCustomer(ctx, e)
	}
	var d sdk.TenantEventData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		return err
	}
	t := d.Tenant
	if e.Type == sdk.EventTenantUpdated && d.Previous != nil && d.Previous.Name == t.Name && d.Previous.Slug == t.Slug {
		return nil
	}
	extID, err := render(p.custTmpl, t)
	if err != nil {
		return err
	}
	var existing struct {
		Customer Customer `json:"customer"`
	}
	err = p.call(ctx, http.MethodGet, "/api/v1/customers/"+url.PathEscape(extID), nil, &existing)
	if err != nil && !isNotFound(err) {
		return err
	}
	ours := map[string]string{MetadataTenantID: t.ID, MetadataSlug: t.Slug}
	var meta []Metadata
	for _, m := range existing.Customer.Metadata {
		item := Metadata{ID: m.LagoID, Key: m.Key, Value: m.Value, DisplayInInvoice: m.DisplayInInvoice}
		if v, ok := ours[m.Key]; ok {
			item.Value, item.DisplayInInvoice = v, false
			delete(ours, m.Key)
		}
		meta = append(meta, item)
	}
	for _, k := range []string{MetadataTenantID, MetadataSlug} {
		if v, ok := ours[k]; ok {
			meta = append(meta, Metadata{Key: k, Value: v})
		}
	}
	c := Customer{ExternalID: extID, Name: t.Name, Metadata: meta}
	return p.call(ctx, http.MethodPost, "/api/v1/customers", map[string]any{"customer": c}, nil)
}
