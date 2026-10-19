package stripe

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// MetadataTenantID is the metadata key linking Stripe customers and
// subscriptions to a tenant.
const MetadataTenantID = "tenarium_tenant_id"

// MetadataSlug is the metadata key holding the tenant slug on customers.
const MetadataSlug = "tenarium_slug"

// Customer is the subset of a Stripe customer the plugin uses.
type Customer struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Deleted  bool              `json:"deleted"`
	Metadata map[string]string `json:"metadata"`
}

// Subscription is the subset of a Stripe subscription the plugin uses.
type Subscription struct {
	ID                string            `json:"id"`
	Customer          json.RawMessage   `json:"customer"`
	Status            string            `json:"status"`
	Metadata          map[string]string `json:"metadata"`
	CancelAtPeriodEnd bool              `json:"cancel_at_period_end"`
	// CurrentPeriodEnd is set by API versions before 2025-03-31; newer
	// versions carry it on the items.
	CurrentPeriodEnd int64 `json:"current_period_end"`
	Items            struct {
		Data []SubscriptionItem `json:"data"`
	} `json:"items"`
}

// SubscriptionItem is one price on a subscription.
type SubscriptionItem struct {
	ID    string `json:"id"`
	Price struct {
		ID string `json:"id"`
	} `json:"price"`
	CurrentPeriodEnd int64 `json:"current_period_end"`
}

// live reports whether the subscription still bills or may bill again.
func (s Subscription) live() bool {
	return s.Status != "canceled" && s.Status != "incomplete_expired"
}

// price returns the first item's price ID.
func (s Subscription) price() string {
	if len(s.Items.Data) == 0 {
		return ""
	}
	return s.Items.Data[0].Price.ID
}

func (s Subscription) periodEnd() int64 {
	if s.CurrentPeriodEnd != 0 || len(s.Items.Data) == 0 {
		return s.CurrentPeriodEnd
	}
	return s.Items.Data[0].CurrentPeriodEnd
}

// APIError is an error response from the Stripe API.
type APIError struct {
	Status  int
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	msg := cmp.Or(e.Message, http.StatusText(e.Status))
	if e.Code != "" {
		return fmt.Sprintf("stripe: %d %s: %s", e.Status, e.Code, msg)
	}
	return fmt.Sprintf("stripe: %d: %s", e.Status, msg)
}

func isNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.Status == http.StatusNotFound || ae.Code == "resource_missing")
}

// maxResponse bounds Stripe response bodies.
const maxResponse = 8 << 20

// call sends a form-encoded request to the Stripe API and decodes the JSON
// response into out (if non-nil). For GET and DELETE, form is sent as the
// query string. idemKey, if set, is sent as the Idempotency-Key header.
func (p *Plugin) call(ctx context.Context, method, path string, form url.Values, idemKey string, out any) error {
	u := p.base + path
	var body io.Reader
	if method == http.MethodGet || method == http.MethodDelete {
		if len(form) > 0 {
			u += "?" + form.Encode()
		}
	} else {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	req.Header.Set("User-Agent", "tenarium-stripe/"+version)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("stripe: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("stripe: %s %s: %w", method, path, err)
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
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("stripe: %s %s: decode response: %w", method, path, err)
	}
	return nil
}

// findCustomer returns the customer whose metadata links it to tenantID, or
// nil. Stripe search is eventually consistent; creation relies on
// idempotency keys to stay unique while a new customer is not searchable.
func (p *Plugin) findCustomer(ctx context.Context, tenantID string) (*Customer, error) {
	q := url.Values{"query": {fmt.Sprintf("metadata['%s']:'%s'", MetadataTenantID, searchEscape(tenantID))}}
	var res struct {
		Data []Customer `json:"data"`
	}
	if err := p.call(ctx, http.MethodGet, "/v1/customers/search", q, "", &res); err != nil {
		return nil, err
	}
	for _, c := range res.Data {
		if !c.Deleted && c.Metadata[MetadataTenantID] == tenantID {
			return &c, nil
		}
	}
	return nil, nil
}

// searchEscape escapes a value for a Stripe search query string literal.
func searchEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
}

func (p *Plugin) createCustomer(ctx context.Context, tenantID, slug, name string) (*Customer, error) {
	form := url.Values{
		"name":                               {name},
		"metadata[" + MetadataTenantID + "]": {tenantID},
		"metadata[" + MetadataSlug + "]":     {slug},
	}
	var c Customer
	if err := p.call(ctx, http.MethodPost, "/v1/customers", form, "tenarium-customer-"+tenantID, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (p *Plugin) getCustomer(ctx context.Context, id string) (*Customer, error) {
	var c Customer
	if err := p.call(ctx, http.MethodGet, "/v1/customers/"+url.PathEscape(id), nil, "", &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// updateCustomer sets the customer's name and slug metadata.
func (p *Plugin) updateCustomer(ctx context.Context, id, name, slug string) error {
	form := url.Values{"name": {name}, "metadata[" + MetadataSlug + "]": {slug}}
	return p.call(ctx, http.MethodPost, "/v1/customers/"+url.PathEscape(id), form, "", nil)
}

// liveSubscriptions lists the customer's subscriptions that are not
// canceled. Listing (unlike search) is strongly consistent.
func (p *Plugin) liveSubscriptions(ctx context.Context, customerID string) ([]Subscription, error) {
	q := url.Values{"customer": {customerID}, "status": {"all"}, "limit": {"100"}}
	var res struct {
		Data []Subscription `json:"data"`
	}
	if err := p.call(ctx, http.MethodGet, "/v1/subscriptions", q, "", &res); err != nil {
		return nil, err
	}
	var out []Subscription
	for _, s := range res.Data {
		if s.live() {
			out = append(out, s)
		}
	}
	return out, nil
}

func (p *Plugin) getSubscription(ctx context.Context, id string) (*Subscription, error) {
	var s Subscription
	if err := p.call(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(id), nil, "", &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (p *Plugin) createSubscription(ctx context.Context, customerID, tenantID, price, idemKey string) (*Subscription, error) {
	form := url.Values{
		"customer":                           {customerID},
		"items[0][price]":                    {price},
		"metadata[" + MetadataTenantID + "]": {tenantID},
		"collection_method":                  {p.cfg.CollectionMethod},
	}
	if p.cfg.CollectionMethod == collectionSendInvoice {
		form.Set("days_until_due", strconv.Itoa(p.cfg.DaysUntilDue))
	}
	if p.cfg.TrialDays > 0 {
		form.Set("trial_period_days", strconv.Itoa(p.cfg.TrialDays))
	}
	var s Subscription
	if err := p.call(ctx, http.MethodPost, "/v1/subscriptions", form, idemKey, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// changePrice replaces the price of the subscription's first item.
func (p *Plugin) changePrice(ctx context.Context, s Subscription, price string) error {
	if len(s.Items.Data) == 0 {
		return fmt.Errorf("stripe: subscription %s has no items", s.ID)
	}
	form := url.Values{
		"items[0][id]":       {s.Items.Data[0].ID},
		"items[0][price]":    {price},
		"proration_behavior": {"create_prorations"},
	}
	return p.call(ctx, http.MethodPost, "/v1/subscriptions/"+url.PathEscape(s.ID), form, "", nil)
}

// cancelSubscription cancels immediately or, with atPeriodEnd, when the
// current period ends. An already canceled subscription is not an error.
func (p *Plugin) cancelSubscription(ctx context.Context, id string, atPeriodEnd bool) error {
	path := "/v1/subscriptions/" + url.PathEscape(id)
	var err error
	if atPeriodEnd {
		err = p.call(ctx, http.MethodPost, path, url.Values{"cancel_at_period_end": {"true"}}, "", nil)
	} else {
		err = p.call(ctx, http.MethodDelete, path, nil, "", nil)
	}
	if isNotFound(err) {
		return nil
	}
	return err
}
