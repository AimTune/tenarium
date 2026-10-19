package chargebee

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// sync mirrors tenant events into Chargebee. Every step looks up the
// current Chargebee state first, and creations use the tenant ID as the
// object ID, so redelivered events are harmless.
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
	if len(t.ID) > maxIDLen {
		p.log.Error("tenant ID is too long for a Chargebee ID; skipping", "tenant", t.ID, "max", maxIDLen)
		return nil
	}
	switch e.Type {
	case sdk.EventTenantCreated, sdk.EventTenantPlanChanged:
		return p.reconcile(ctx, t)
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
// subscription matches its plan: present with the plan's item price when
// the plan is billed, cancelled otherwise.
func (p *Plugin) reconcile(ctx context.Context, t sdk.Tenant) error {
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
			p.log.Info("cancelled subscription of unbilled plan", "tenant", t.ID, "plan", t.Plan, "subscription", s.ID)
		}
		return nil
	}
	if len(subs) == 0 {
		return p.createOrReactivate(ctx, t, cust.ID, price)
	}
	if len(subs) > 1 {
		p.log.Warn("tenant has several plan subscriptions; updating one", "tenant", t.ID, "subscription", subs[0].ID)
	}
	if s := subs[0]; s.planPrice() != price {
		if err := p.changeItems(ctx, s.ID, price, false); err != nil {
			return err
		}
		p.log.Info("changed subscription item price", "tenant", t.ID, "plan", t.Plan, "subscription", s.ID, "item_price", price)
	}
	return nil
}

// createOrReactivate creates the tenant's subscription (ID = tenant ID).
// If it already exists — a redelivered event, or a subscription cancelled
// by an earlier downgrade — it is brought to price and reactivated.
func (p *Plugin) createOrReactivate(ctx context.Context, t sdk.Tenant, customerID, price string) error {
	err := p.createSubscription(ctx, customerID, t.ID, price)
	if err == nil {
		p.log.Info("created subscription", "tenant", t.ID, "plan", t.Plan, "subscription", t.ID)
		return nil
	}
	if !isDuplicate(err) {
		return err
	}
	s, _, err := p.getSubscription(ctx, t.ID)
	if err != nil {
		return err
	}
	switch {
	case !s.live():
		if err := p.changeItems(ctx, s.ID, price, true); err != nil {
			return err
		}
		p.log.Info("reactivated subscription", "tenant", t.ID, "plan", t.Plan, "subscription", s.ID)
	case s.planPrice() != price:
		if err := p.changeItems(ctx, s.ID, price, false); err != nil {
			return err
		}
		p.log.Info("changed subscription item price", "tenant", t.ID, "plan", t.Plan, "subscription", s.ID, "item_price", price)
	}
	return nil
}

// ensureCustomer finds the tenant's customer (ID = tenant ID) or creates
// it. It returns nil without error when the customer is missing and
// create_customers is off, or when it was deleted in Chargebee.
func (p *Plugin) ensureCustomer(ctx context.Context, t sdk.Tenant) (*Customer, error) {
	cust, err := p.getCustomer(ctx, t.ID)
	if err == nil {
		if cust.Deleted {
			p.log.Warn("tenant's Chargebee customer is deleted; skipping", "tenant", t.ID)
			return nil, nil
		}
		return cust, nil
	}
	if !isNotFound(err) {
		return nil, err
	}
	if !enabled(p.cfg.CreateCustomers) {
		p.log.Debug("tenant has no Chargebee customer; create_customers is off", "tenant", t.ID)
		return nil, nil
	}
	cust, err = p.createCustomer(ctx, t.ID, t.Slug, t.Name)
	if isDuplicate(err) {
		// Created concurrently or by an earlier attempt: use it.
		return p.getCustomer(ctx, t.ID)
	} else if err != nil {
		return nil, err
	}
	p.log.Info("created customer", "tenant", t.ID, "customer", cust.ID)
	return cust, nil
}

// planSubscriptions keeps the subscriptions that bill the tenant's plan:
// the one whose ID is the tenant ID, ones tagged with the tenant ID, or
// ones on an item price from the plans map. The one with the tenant ID
// comes first. Other subscriptions (e.g. add-ons sold separately) are left
// alone.
func (p *Plugin) planSubscriptions(tenantID string, subs []Subscription) []Subscription {
	var out []Subscription
	for _, s := range subs {
		if !p.isPlanSubscription(tenantID, s) {
			continue
		}
		if s.ID == tenantID {
			out = append([]Subscription{s}, out...)
		} else {
			out = append(out, s)
		}
	}
	return out
}

func (p *Plugin) isPlanSubscription(tenantID string, s Subscription) bool {
	if s.ID == tenantID || metaString(s.MetaData, MetadataTenantID) == tenantID {
		return true
	}
	for _, it := range s.Items {
		if p.planOf[it.ItemPriceID] != "" {
			return true
		}
	}
	return false
}

// updateDetails copies the tenant's name and slug to its customer.
func (p *Plugin) updateDetails(ctx context.Context, t sdk.Tenant) error {
	cust, err := p.getCustomer(ctx, t.ID)
	if isNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}
	if cust.Deleted || (cust.Company == t.Name && metaString(cust.MetaData, MetadataSlug) == t.Slug) {
		return nil
	}
	meta := maps.Clone(cust.MetaData)
	if meta == nil {
		meta = map[string]any{}
	}
	meta[MetadataTenantID] = t.ID
	meta[MetadataSlug] = t.Slug
	if err := p.updateCustomer(ctx, cust.ID, t.Name, meta); err != nil {
		return err
	}
	p.log.Info("updated customer", "tenant", t.ID, "customer", cust.ID)
	return nil
}

// cancelAll cancels every live subscription of a deleted tenant. The
// customer is kept for its billing history.
func (p *Plugin) cancelAll(ctx context.Context, t sdk.Tenant) error {
	subs, err := p.liveSubscriptions(ctx, t.ID)
	if err != nil {
		return err
	}
	endOfTerm := p.cfg.CancelOnDelete == cancelEndOfTerm
	for _, s := range subs {
		if endOfTerm && s.Status == "non_renewing" {
			continue // already scheduled to end
		}
		if err := p.cancelSubscription(ctx, s.ID, endOfTerm); err != nil {
			return err
		}
		p.log.Info("cancelled subscription of deleted tenant", "tenant", t.ID, "subscription", s.ID, "end_of_term", endOfTerm)
	}
	return nil
}
