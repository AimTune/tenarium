package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// sync mirrors tenant events into Stripe. Every step looks up the current
// Stripe state first, so redelivered events are harmless.
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
	switch e.Type {
	case sdk.EventTenantCreated, sdk.EventTenantPlanChanged:
		return p.reconcile(ctx, t, e.ID)
	case sdk.EventTenantUpdated:
		if prev := data.Previous; prev != nil && prev.Name == t.Name && prev.Slug == t.Slug {
			return nil
		}
		return p.updateDetails(ctx, t)
	case sdk.EventTenantDeleted:
		return p.cancelAll(ctx, t)
	}
	return nil
}

// reconcile ensures the tenant has a customer and that its plan
// subscription matches its plan: present with the plan's price when the plan
// is billed, canceled otherwise.
func (p *Plugin) reconcile(ctx context.Context, t sdk.Tenant, eventID string) error {
	cust, err := p.ensureCustomer(ctx, t)
	if err != nil || cust == nil {
		return err
	}
	subs, err := p.liveSubscriptions(ctx, cust.ID)
	if err != nil {
		return err
	}
	subs = p.planSubscriptions(t.ID, subs)
	price := p.priceFor(t.Plan)
	if price == "" {
		for _, s := range subs {
			if err := p.cancelSubscription(ctx, s.ID, false); err != nil {
				return err
			}
			p.log.Info("canceled subscription of unbilled plan", "tenant", t.ID, "plan", t.Plan, "subscription", s.ID)
		}
		return nil
	}
	if len(subs) == 0 {
		s, err := p.createSubscription(ctx, cust.ID, t.ID, price, "tenarium-sub-"+t.ID+"-"+eventID)
		if err != nil {
			return err
		}
		p.log.Info("created subscription", "tenant", t.ID, "plan", t.Plan, "subscription", s.ID)
		return nil
	}
	if len(subs) > 1 {
		p.log.Warn("tenant has several plan subscriptions; updating the newest", "tenant", t.ID, "customer", cust.ID)
	}
	if s := subs[0]; s.price() != price {
		if err := p.changePrice(ctx, s, price); err != nil {
			return err
		}
		p.log.Info("changed subscription price", "tenant", t.ID, "plan", t.Plan, "subscription", s.ID, "price", price)
	}
	return nil
}

// ensureCustomer finds the tenant's customer or creates it. It returns nil
// without error when the customer is missing and create_customers is off.
func (p *Plugin) ensureCustomer(ctx context.Context, t sdk.Tenant) (*Customer, error) {
	cust, err := p.findCustomer(ctx, t.ID)
	if err != nil || cust != nil {
		return cust, err
	}
	if !enabled(p.cfg.CreateCustomers) {
		p.log.Debug("tenant has no Stripe customer; create_customers is off", "tenant", t.ID)
		return nil, nil
	}
	cust, err = p.createCustomer(ctx, t.ID, t.Slug, t.Name)
	if err != nil {
		return nil, err
	}
	p.log.Info("created customer", "tenant", t.ID, "customer", cust.ID)
	return cust, nil
}

// planSubscriptions keeps the subscriptions that bill the tenant's plan:
// tagged with the tenant ID or on a price from the plans map. Other
// subscriptions of the customer (e.g. add-ons) are left alone.
func (p *Plugin) planSubscriptions(tenantID string, subs []Subscription) []Subscription {
	var out []Subscription
	for _, s := range subs {
		if s.Metadata[MetadataTenantID] == tenantID || p.planOf[s.price()] != "" {
			out = append(out, s)
		}
	}
	return out
}

// updateDetails copies the tenant's name and slug to its customer.
func (p *Plugin) updateDetails(ctx context.Context, t sdk.Tenant) error {
	cust, err := p.findCustomer(ctx, t.ID)
	if err != nil || cust == nil {
		return err
	}
	if cust.Name == t.Name && cust.Metadata[MetadataSlug] == t.Slug {
		return nil
	}
	return p.updateCustomer(ctx, cust.ID, t.Name, t.Slug)
}

// cancelAll cancels every live subscription of a deleted tenant. The
// customer is kept for its billing history.
func (p *Plugin) cancelAll(ctx context.Context, t sdk.Tenant) error {
	cust, err := p.findCustomer(ctx, t.ID)
	if err != nil || cust == nil {
		return err
	}
	subs, err := p.liveSubscriptions(ctx, cust.ID)
	if err != nil {
		return err
	}
	atPeriodEnd := p.cfg.CancelAtPeriodEndOnDelete
	for _, s := range subs {
		if atPeriodEnd && s.CancelAtPeriodEnd {
			continue
		}
		if err := p.cancelSubscription(ctx, s.ID, atPeriodEnd); err != nil {
			return err
		}
		p.log.Info("canceled subscription of deleted tenant", "tenant", t.ID, "subscription", s.ID, "at_period_end", atPeriodEnd)
	}
	return nil
}
