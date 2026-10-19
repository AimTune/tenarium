package hubspot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// sync mirrors tenant events. Upserts are keyed by the tenant ID, so
// redelivered events converge on the same company.
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
	if e.Type == sdk.EventTenantDeleted {
		if p.cfg.OnDelete == onDeleteKeep {
			return nil
		}
		return p.archiveCompany(ctx, t.ID)
	}
	_, err := p.upsertCompany(ctx, t)
	return err
}

// upsertCompany creates or updates the tenant's company and returns its ID.
func (p *Plugin) upsertCompany(ctx context.Context, t sdk.Tenant) (string, error) {
	props, err := render(p.companyTmpl, t)
	if err != nil {
		return "", err
	}
	props[p.cfg.TenantIDProperty] = t.ID
	id, err := p.upsert(ctx, "companies", p.cfg.TenantIDProperty, t.ID, props)
	if err != nil {
		return "", err
	}
	p.log.Debug("upserted company", "tenant", t.ID, "company", id)
	return id, nil
}

// archiveCompany archives (soft-deletes) the tenant's company. A missing
// company is not an error.
func (p *Plugin) archiveCompany(ctx context.Context, tenantID string) error {
	id, err := p.lookup(ctx, "companies", p.cfg.TenantIDProperty, tenantID)
	if err != nil || id == "" {
		return err
	}
	err = p.call(ctx, http.MethodDelete, "/crm/v3/objects/companies/"+url.PathEscape(id), nil, nil, nil)
	if err != nil && !isNotFound(err) {
		return err
	}
	p.log.Info("archived company of deleted tenant", "tenant", tenantID, "company", id)
	return nil
}

// members mirrors memberships as contacts associated with the tenant's
// company.
func (p *Plugin) members(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.members(ctx, e)
	}
	var data sdk.MemberEventData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return fmt.Errorf("decode event: %w", err)
	}
	m := data.Member
	if m.Email == "" || m.TenantID == "" {
		return nil
	}
	if e.Type == sdk.EventMemberRemoved {
		return p.unlink(ctx, m)
	}
	t, err := p.host.GetTenant(ctx, m.TenantID)
	if errors.Is(err, sdk.ErrNotFound) {
		p.log.Debug("member of unknown tenant; skipped", "tenant", m.TenantID)
		return nil
	} else if err != nil {
		return err
	}
	if !t.IsLive() {
		return nil // do not resurrect the company of a deleted tenant
	}
	companyID, err := p.upsertCompany(ctx, t)
	if err != nil {
		return err
	}
	props, err := render(p.contactTmpl, ContactData{Member: m, Tenant: t})
	if err != nil {
		return err
	}
	props["email"] = m.Email
	contactID, err := p.upsert(ctx, "contacts", "email", m.Email, props)
	if err != nil {
		return err
	}
	// The default (unlabeled) association; PUT is idempotent.
	path := "/crm/v4/objects/contact/" + url.PathEscape(contactID) + "/associations/default/company/" + url.PathEscape(companyID)
	if err := p.call(ctx, http.MethodPut, path, nil, nil, nil); err != nil {
		return err
	}
	p.log.Debug("associated contact with company", "tenant", t.ID, "contact", contactID, "company", companyID)
	return nil
}

// unlink removes the association between a removed member's contact and
// the tenant's company. The contact itself is kept.
func (p *Plugin) unlink(ctx context.Context, m sdk.Member) error {
	contactID, err := p.lookup(ctx, "contacts", "email", m.Email)
	if err != nil || contactID == "" {
		return err
	}
	companyID, err := p.lookup(ctx, "companies", p.cfg.TenantIDProperty, m.TenantID)
	if err != nil || companyID == "" {
		return err
	}
	path := "/crm/v4/objects/contact/" + url.PathEscape(contactID) + "/associations/company/" + url.PathEscape(companyID)
	if err := p.call(ctx, http.MethodDelete, path, nil, nil, nil); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}
