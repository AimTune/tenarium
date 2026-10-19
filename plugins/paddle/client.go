package paddle

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// CustomDataTenantID is the custom_data key linking Paddle customers and
// subscriptions to a tenant.
const CustomDataTenantID = "tenarium_tenant_id"

// CustomDataSlug is the custom_data key holding the tenant slug.
const CustomDataSlug = "tenarium_slug"

// Cancellation timings (effective_from).
const (
	cancelImmediately = "immediately"
	cancelNextPeriod  = "next_billing_period"
)

// liveStatuses are the subscription statuses that still bill or may bill
// again.
const liveStatuses = "active,trialing,past_due,paused"

// Customer is the subset of a Paddle customer the plugin uses.
type Customer struct {
	ID         string         `json:"id"`
	Email      string         `json:"email"`
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	CustomData map[string]any `json:"custom_data"`
}

// Subscription is the subset of a Paddle subscription the plugin uses.
type Subscription struct {
	ID                   string             `json:"id"`
	Status               string             `json:"status"`
	CustomerID           string             `json:"customer_id"`
	CustomData           map[string]any     `json:"custom_data"`
	Items                []SubscriptionItem `json:"items"`
	NextBilledAt         *time.Time         `json:"next_billed_at"`
	CurrentBillingPeriod *struct {
		StartsAt *time.Time `json:"starts_at"`
		EndsAt   *time.Time `json:"ends_at"`
	} `json:"current_billing_period"`
	ScheduledChange *struct {
		Action      string     `json:"action"`
		EffectiveAt *time.Time `json:"effective_at"`
	} `json:"scheduled_change"`
}

// SubscriptionItem is one price on a subscription.
type SubscriptionItem struct {
	Status   string `json:"status"`
	Quantity int    `json:"quantity"`
	Price    struct {
		ID string `json:"id"`
	} `json:"price"`
}

// live reports whether the subscription still bills or may bill again.
func (s Subscription) live() bool { return s.Status != "" && s.Status != "canceled" }

// healthy reports whether the subscription is in good standing.
func (s Subscription) healthy() bool { return s.Status == "active" || s.Status == "trialing" }

// price returns the first item's price ID.
func (s Subscription) price() string {
	if len(s.Items) == 0 {
		return ""
	}
	return s.Items[0].Price.ID
}

// hasPrice reports whether any item bills price.
func (s Subscription) hasPrice(price string) bool {
	return slices.ContainsFunc(s.Items, func(it SubscriptionItem) bool { return it.Price.ID == price })
}

// tenantIDOf returns the tenant ID in Paddle custom_data.
func tenantIDOf(cd map[string]any) string {
	s, _ := cd[CustomDataTenantID].(string)
	return s
}

// APIError is an error response from the Paddle API.
type APIError struct {
	Status int
	Type   string `json:"type"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (e *APIError) Error() string {
	msg := cmp.Or(e.Detail, http.StatusText(e.Status))
	if e.Code != "" {
		return fmt.Sprintf("paddle: %d %s: %s", e.Status, e.Code, msg)
	}
	return fmt.Sprintf("paddle: %d: %s", e.Status, msg)
}

func isNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.Status == http.StatusNotFound || ae.Code == "not_found")
}

// maxResponse bounds Paddle response bodies.
const maxResponse = 8 << 20

// call sends a JSON request to the Paddle API and decodes the "data" member
// of the response into out (if non-nil).
func (p *Plugin) call(ctx context.Context, method, path string, query url.Values, in, out any) error {
	u := p.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	req.Header.Set("User-Agent", "tenarium-paddle/"+version)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("paddle: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("paddle: %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var env struct {
			Error *APIError `json:"error"`
		}
		ae := &APIError{}
		if json.Unmarshal(raw, &env) == nil && env.Error != nil {
			ae = env.Error
		}
		ae.Status = resp.StatusCode
		return fmt.Errorf("%s %s: %w", method, path, ae)
	}
	if out == nil {
		return nil
	}
	env := struct {
		Data any `json:"data"`
	}{Data: out}
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("paddle: %s %s: decode response: %w", method, path, err)
	}
	return nil
}

// findCustomer returns the customer with the tenant's billing email if it
// belongs to the tenant or to no tenant yet (custom_data without
// tenarium_tenant_id), or nil. Paddle cannot filter by custom_data, but
// customer emails are unique per account, so the email lookup returns at
// most one customer.
func (p *Plugin) findCustomer(ctx context.Context, t sdk.Tenant, email string) (*Customer, error) {
	if email == "" {
		return nil, nil
	}
	var res []Customer
	q := url.Values{"email": {email}, "per_page": {"200"}}
	if err := p.call(ctx, http.MethodGet, "/customers", q, nil, &res); err != nil {
		return nil, err
	}
	var unclaimed *Customer
	for i, c := range res {
		switch tenantIDOf(c.CustomData) {
		case t.ID:
			return &res[i], nil
		case "":
			unclaimed = cmp.Or(unclaimed, &res[i])
		default:
			p.log.Warn("Paddle customer with the tenant's billing email belongs to another tenant",
				"tenant", t.ID, "customer", c.ID, "owner", tenantIDOf(c.CustomData))
		}
	}
	return unclaimed, nil
}

// conflictID extracts the existing customer's ID from a
// customer_already_exists error.
var conflictID = regexp.MustCompile(`ctm_[A-Za-z0-9]+`)

// createCustomer creates the tenant's customer. If Paddle reports that a
// customer with the email exists (e.g. created by a redelivery of the same
// event or archived), that customer is returned instead.
func (p *Plugin) createCustomer(ctx context.Context, t sdk.Tenant, email string) (*Customer, error) {
	in := map[string]any{
		"email":       email,
		"name":        cmp.Or(t.Name, t.Slug),
		"custom_data": map[string]any{CustomDataTenantID: t.ID, CustomDataSlug: t.Slug},
	}
	var c Customer
	err := p.call(ctx, http.MethodPost, "/customers", nil, in, &c)
	if err == nil {
		return &c, nil
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusConflict {
		return nil, err
	}
	id := conflictID.FindString(ae.Detail)
	if id == "" {
		return nil, err
	}
	return p.getCustomer(ctx, id)
}

func (p *Plugin) getCustomer(ctx context.Context, id string) (*Customer, error) {
	var c Customer
	if err := p.call(ctx, http.MethodGet, "/customers/"+url.PathEscape(id), nil, nil, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// updateCustomer sets the customer's name, email (if not empty) and tenant
// custom_data, keeping other custom_data keys (PATCH replaces the object).
func (p *Plugin) updateCustomer(ctx context.Context, c *Customer, t sdk.Tenant, email string) error {
	cd := maps.Clone(c.CustomData)
	if cd == nil {
		cd = map[string]any{}
	}
	cd[CustomDataTenantID], cd[CustomDataSlug] = t.ID, t.Slug
	in := map[string]any{"name": cmp.Or(t.Name, t.Slug), "custom_data": cd}
	if email != "" && email != c.Email {
		in["email"] = email
	}
	return p.call(ctx, http.MethodPatch, "/customers/"+url.PathEscape(c.ID), nil, in, nil)
}

// liveSubscriptions lists the customer's subscriptions that are not
// canceled, newest first.
func (p *Plugin) liveSubscriptions(ctx context.Context, customerID string) ([]Subscription, error) {
	q := url.Values{
		"customer_id": {customerID},
		"status":      {liveStatuses},
		"order_by":    {"id[DESC]"},
		"per_page":    {"200"},
	}
	var res []Subscription
	if err := p.call(ctx, http.MethodGet, "/subscriptions", q, nil, &res); err != nil {
		return nil, err
	}
	return slices.DeleteFunc(res, func(s Subscription) bool { return !s.live() }), nil
}

func (p *Plugin) getSubscription(ctx context.Context, id string) (*Subscription, error) {
	var s Subscription
	if err := p.call(ctx, http.MethodGet, "/subscriptions/"+url.PathEscape(id), nil, nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// changePrice replaces the subscription's plan item with price, keeping
// other items (e.g. add-ons), and tags the subscription with the tenant.
// Paddle replaces the whole item list on update.
func (p *Plugin) changePrice(ctx context.Context, s Subscription, tenantID, price string) error {
	items := []map[string]any{}
	replaced := false
	for _, it := range s.Items {
		id, qty := it.Price.ID, max(it.Quantity, 1)
		if _, plan := p.planOf[id]; plan || id == "" {
			if replaced {
				continue
			}
			id, qty, replaced = price, 1, true
		}
		items = append(items, map[string]any{"price_id": id, "quantity": qty})
	}
	if !replaced {
		items = append([]map[string]any{{"price_id": price, "quantity": 1}}, items...)
	}
	in := map[string]any{"items": items, "proration_billing_mode": p.cfg.ProrationBillingMode}
	if tenantIDOf(s.CustomData) != tenantID {
		cd := maps.Clone(s.CustomData)
		if cd == nil {
			cd = map[string]any{}
		}
		cd[CustomDataTenantID] = tenantID
		in["custom_data"] = cd
	}
	return p.call(ctx, http.MethodPatch, "/subscriptions/"+url.PathEscape(s.ID), nil, in, nil)
}

// cancelSubscription cancels immediately or at the end of the billing
// period. A missing subscription is not an error.
func (p *Plugin) cancelSubscription(ctx context.Context, id, effectiveFrom string) error {
	err := p.call(ctx, http.MethodPost, "/subscriptions/"+url.PathEscape(id)+"/cancel", nil,
		map[string]any{"effective_from": effectiveFrom}, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}
