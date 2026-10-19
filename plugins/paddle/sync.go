package paddle

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// sync mirrors tenant events into Paddle. Every step looks up the current
// Paddle state first, so redelivered events are harmless.
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
		// Act on the tenant's current plan, not the event's: a plan change
		// from Paddle may have happened since, and pushing the stale plan
		// back would make the two systems flip-flop.
		cur, err := p.host.GetTenant(ctx, t.ID)
		if errors.Is(err, sdk.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		if !cur.IsLive() {
			return nil // tenant.deleted cancels
		}
		return p.reconcile(ctx, cur)
	case sdk.EventTenantUpdated:
		return p.updateDetails(ctx, t, data.Previous)
	case sdk.EventTenantDeleted:
		return p.cancelAll(ctx, t)
	}
	return nil
}

// reconcile ensures the tenant has a customer and that its plan
// subscription matches its plan: on the plan's price when the plan is
// billed, canceled otherwise. Paddle cannot create subscriptions without a
// checkout, so a billed plan without a subscription is only logged.
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
			if err := p.cancelSubscription(ctx, s.ID, cancelImmediately); err != nil {
				return err
			}
			p.log.Info("canceled subscription of unbilled plan", "tenant", t.ID, "plan", t.Plan, "subscription", s.ID)
		}
		return nil
	}
	if len(subs) == 0 {
		p.log.Info("tenant has no Paddle subscription; the customer must complete a checkout",
			"tenant", t.ID, "plan", t.Plan, "customer", cust.ID, "price", price)
		return nil
	}
	if len(subs) > 1 {
		p.log.Warn("tenant has several plan subscriptions; updating the newest", "tenant", t.ID, "customer", cust.ID)
	}
	if s := subs[0]; !s.hasPrice(price) {
		if err := p.changePrice(ctx, s, t.ID, price); err != nil {
			return err
		}
		p.log.Info("changed subscription price", "tenant", t.ID, "plan", t.Plan, "subscription", s.ID, "price", price)
	}
	return nil
}

// ensureCustomer finds the tenant's customer or creates it. It returns nil
// without error when the tenant has no billing email, when the customer is
// missing and create_customers is off, or when the email belongs to
// another tenant's customer.
func (p *Plugin) ensureCustomer(ctx context.Context, t sdk.Tenant) (*Customer, error) {
	email := p.emailFor(t)
	if email == "" {
		p.log.Info("tenant has no billing email; skipping the Paddle customer", "tenant", t.ID)
		return nil, nil
	}
	cust, err := p.findCustomer(ctx, t, email)
	if err != nil {
		return nil, err
	}
	if cust == nil {
		if !enabled(p.cfg.CreateCustomers) {
			p.log.Debug("tenant has no Paddle customer; create_customers is off", "tenant", t.ID)
			return nil, nil
		}
		if cust, err = p.createCustomer(ctx, t, email); err != nil {
			return nil, err
		}
		if owner := tenantIDOf(cust.CustomData); owner == t.ID {
			p.log.Info("created customer", "tenant", t.ID, "customer", cust.ID)
		}
	}
	switch owner := tenantIDOf(cust.CustomData); owner {
	case t.ID:
		return cust, nil
	case "":
		if err := p.updateCustomer(ctx, cust, t, ""); err != nil {
			return nil, err
		}
		p.log.Info("linked existing customer to tenant", "tenant", t.ID, "customer", cust.ID)
		return cust, nil
	default:
		p.log.Warn("billing email belongs to another tenant's Paddle customer", "tenant", t.ID, "customer", cust.ID, "owner", owner)
		return nil, nil
	}
}

// planSubscriptions keeps the subscriptions that bill the tenant's plan:
// tagged with the tenant ID or with an item on a price from the plans map.
// Other subscriptions of the customer are left alone.
func (p *Plugin) planSubscriptions(tenantID string, subs []Subscription) []Subscription {
	var out []Subscription
	for _, s := range subs {
		if tenantIDOf(s.CustomData) == tenantID || p.mappedPlan(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// mappedPlan returns the plan mapped to the first mapped item price.
func (p *Plugin) mappedPlan(s Subscription) string {
	for _, it := range s.Items {
		if plan := p.planOf[it.Price.ID]; plan != "" {
			return plan
		}
	}
	return ""
}

// updateDetails copies the tenant's name, slug and billing email to its
// customer. A changed billing email is followed: the customer is found by
// the previous email and moved to the new one.
func (p *Plugin) updateDetails(ctx context.Context, t sdk.Tenant, prev *sdk.Tenant) error {
	email := p.emailFor(t)
	oldEmail := email
	if prev != nil {
		oldEmail = p.emailFor(*prev)
		if prev.Name == t.Name && prev.Slug == t.Slug && oldEmail == email {
			return nil
		}
	}
	cust, err := p.findCustomer(ctx, t, email)
	if err != nil {
		return err
	}
	if cust == nil && oldEmail != email {
		if cust, err = p.findCustomer(ctx, t, oldEmail); err != nil {
			return err
		}
	}
	if cust == nil {
		return nil
	}
	if cust.Name == cmp.Or(t.Name, t.Slug) && (email == "" || cust.Email == email) &&
		tenantIDOf(cust.CustomData) == t.ID && cust.CustomData[CustomDataSlug] == t.Slug {
		return nil
	}
	if err := p.updateCustomer(ctx, cust, t, email); err != nil {
		return err
	}
	p.log.Info("updated customer", "tenant", t.ID, "customer", cust.ID)
	return nil
}

// cancelAll cancels every live subscription of a deleted tenant. The
// customer is kept for its billing history.
func (p *Plugin) cancelAll(ctx context.Context, t sdk.Tenant) error {
	cust, err := p.findCustomer(ctx, t, p.emailFor(t))
	if err != nil || cust == nil {
		return err
	}
	subs, err := p.liveSubscriptions(ctx, cust.ID)
	if err != nil {
		return err
	}
	when := p.cfg.CancelOnDelete
	for _, s := range subs {
		if when == cancelNextPeriod && s.ScheduledChange != nil && s.ScheduledChange.Action == "cancel" {
			continue
		}
		if err := p.cancelSubscription(ctx, s.ID, when); err != nil {
			return err
		}
		p.log.Info("canceled subscription of deleted tenant", "tenant", t.ID, "subscription", s.ID, "effective_from", when)
	}
	return nil
}
