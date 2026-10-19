package chargebee

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// MetadataTenantID is the meta_data key linking Chargebee customers and
// subscriptions to a tenant.
const MetadataTenantID = "tenarium_tenant_id"

// MetadataSlug is the meta_data key holding the tenant slug on customers.
const MetadataSlug = "tenarium_slug"

// liveStatuses are the subscription statuses that bill or may bill again.
var liveStatuses = []string{"active", "in_trial", "non_renewing", "paused", "future"}

// Customer is the subset of a Chargebee customer the plugin uses.
type Customer struct {
	ID       string         `json:"id"`
	Company  string         `json:"company"`
	Deleted  bool           `json:"deleted"`
	MetaData map[string]any `json:"meta_data"`
	// Custom holds the string custom fields (cf_...).
	Custom map[string]string `json:"-"`
}

func (c *Customer) UnmarshalJSON(b []byte) error {
	type plain Customer
	if err := json.Unmarshal(b, (*plain)(c)); err != nil {
		return err
	}
	c.Custom = customFields(b)
	return nil
}

// Subscription is the subset of a Chargebee subscription the plugin uses.
type Subscription struct {
	ID               string             `json:"id"`
	CustomerID       string             `json:"customer_id"`
	Status           string             `json:"status"`
	CurrentTermEnd   int64              `json:"current_term_end"`
	DueInvoicesCount int                `json:"due_invoices_count"`
	MetaData         map[string]any     `json:"meta_data"`
	Items            []SubscriptionItem `json:"subscription_items"`
	// Custom holds the string custom fields (cf_...).
	Custom map[string]string `json:"-"`
}

func (s *Subscription) UnmarshalJSON(b []byte) error {
	type plain Subscription
	if err := json.Unmarshal(b, (*plain)(s)); err != nil {
		return err
	}
	s.Custom = customFields(b)
	return nil
}

// SubscriptionItem is one item price on a subscription.
type SubscriptionItem struct {
	ItemPriceID string `json:"item_price_id"`
	ItemType    string `json:"item_type"`
}

// live reports whether the subscription still bills or may bill again.
func (s Subscription) live() bool {
	return s.Status != "cancelled" && s.Status != "transferred"
}

// healthy reports whether the subscription is in good standing.
func (s Subscription) healthy() bool {
	return s.Status == "active" || s.Status == "in_trial" || s.Status == "non_renewing"
}

// settled reports whether the subscription is healthy and has no unpaid
// invoices. Chargebee keeps subscriptions active during dunning, so the due
// invoice count is what tells a recovered subscription apart.
func (s Subscription) settled() bool {
	return s.healthy() && s.DueInvoicesCount == 0
}

// planPrice returns the item price of the subscription's plan item (or its
// first item when none is typed "plan").
func (s Subscription) planPrice() string {
	for _, it := range s.Items {
		if it.ItemType == "plan" {
			return it.ItemPriceID
		}
	}
	if len(s.Items) == 0 {
		return ""
	}
	return s.Items[0].ItemPriceID
}

func customFields(b []byte) map[string]string {
	var all map[string]json.RawMessage
	if json.Unmarshal(b, &all) != nil {
		return nil
	}
	var out map[string]string
	for k, v := range all {
		if !strings.HasPrefix(k, "cf_") {
			continue
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = s
		}
	}
	return out
}

func metaString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// APIError is an error response from the Chargebee API.
type APIError struct {
	Status       int    `json:"http_status_code"`
	Message      string `json:"message"`
	Type         string `json:"type"`
	APIErrorCode string `json:"api_error_code"`
	ErrorCode    string `json:"error_code"`
}

func (e *APIError) Error() string {
	msg := cmp.Or(e.Message, http.StatusText(e.Status))
	if e.APIErrorCode != "" {
		return fmt.Sprintf("chargebee: %d %s: %s", e.Status, e.APIErrorCode, msg)
	}
	return fmt.Sprintf("chargebee: %d: %s", e.Status, msg)
}

func isNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.Status == http.StatusNotFound || ae.APIErrorCode == "resource_not_found")
}

func isDuplicate(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && (ae.APIErrorCode == "duplicate_entry" || ae.ErrorCode == "duplicate_entry")
}

// maxResponse bounds Chargebee response bodies.
const maxResponse = 8 << 20

// call sends a request to the Chargebee API and decodes the JSON response
// into out (if non-nil). For GET, form is sent as the query string;
// otherwise as a form-encoded body.
func (p *Plugin) call(ctx context.Context, method, path string, form url.Values, out any) error {
	u := p.base + path
	var body io.Reader
	if method == http.MethodGet {
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
	req.SetBasicAuth(p.cfg.APIKey, "")
	req.Header.Set("User-Agent", "tenarium-chargebee/"+version)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("chargebee: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("chargebee: %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{}
		_ = json.Unmarshal(raw, ae)
		ae.Status = resp.StatusCode
		return fmt.Errorf("%s %s: %w", method, path, ae)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("chargebee: %s %s: decode response: %w", method, path, err)
	}
	return nil
}

func encodeMeta(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}

func (p *Plugin) getCustomer(ctx context.Context, id string) (*Customer, error) {
	var res struct {
		Customer *Customer `json:"customer"`
	}
	if err := p.call(ctx, http.MethodGet, "/customers/"+url.PathEscape(id), nil, &res); err != nil {
		return nil, err
	}
	if res.Customer == nil {
		return nil, fmt.Errorf("chargebee: GET /customers/%s: response has no customer", id)
	}
	return res.Customer, nil
}

// createCustomer creates the tenant's customer with the tenant ID as its ID.
func (p *Plugin) createCustomer(ctx context.Context, tenantID, slug, name string) (*Customer, error) {
	form := url.Values{
		"id":        {tenantID},
		"company":   {name},
		"meta_data": {encodeMeta(map[string]any{MetadataTenantID: tenantID, MetadataSlug: slug})},
	}
	if f := p.cfg.TenantIDField; f != "" {
		form.Set(f, tenantID)
	}
	var res struct {
		Customer *Customer `json:"customer"`
	}
	if err := p.call(ctx, http.MethodPost, "/customers", form, &res); err != nil {
		return nil, err
	}
	if res.Customer == nil {
		return nil, errors.New("chargebee: POST /customers: response has no customer")
	}
	return res.Customer, nil
}

// updateCustomer sets the customer's company and meta_data. Chargebee
// replaces meta_data as a whole, so the caller passes the merged value.
func (p *Plugin) updateCustomer(ctx context.Context, id, company string, meta map[string]any) error {
	form := url.Values{"company": {company}, "meta_data": {encodeMeta(meta)}}
	return p.call(ctx, http.MethodPost, "/customers/"+url.PathEscape(id), form, nil)
}

// maxListPages bounds subscription list pagination.
const maxListPages = 10

// liveSubscriptions lists the customer's subscriptions that are not
// cancelled.
func (p *Plugin) liveSubscriptions(ctx context.Context, customerID string) ([]Subscription, error) {
	statuses, _ := json.Marshal(liveStatuses)
	q := url.Values{
		"customer_id[is]": {customerID},
		"status[in]":      {string(statuses)},
		"limit":           {"100"},
	}
	var out []Subscription
	for range maxListPages {
		var res struct {
			List []struct {
				Subscription *Subscription `json:"subscription"`
			} `json:"list"`
			NextOffset string `json:"next_offset"`
		}
		if err := p.call(ctx, http.MethodGet, "/subscriptions", q, &res); err != nil {
			return nil, err
		}
		for _, e := range res.List {
			if e.Subscription != nil && e.Subscription.live() {
				out = append(out, *e.Subscription)
			}
		}
		if res.NextOffset == "" {
			break
		}
		q.Set("offset", res.NextOffset)
	}
	return out, nil
}

// getSubscription returns the subscription and, when the API includes it,
// its customer.
func (p *Plugin) getSubscription(ctx context.Context, id string) (*Subscription, *Customer, error) {
	var res struct {
		Subscription *Subscription `json:"subscription"`
		Customer     *Customer     `json:"customer"`
	}
	if err := p.call(ctx, http.MethodGet, "/subscriptions/"+url.PathEscape(id), nil, &res); err != nil {
		return nil, nil, err
	}
	if res.Subscription == nil {
		return nil, nil, fmt.Errorf("chargebee: GET /subscriptions/%s: response has no subscription", id)
	}
	return res.Subscription, res.Customer, nil
}

// createSubscription creates the tenant's plan subscription with the tenant
// ID as its ID.
func (p *Plugin) createSubscription(ctx context.Context, customerID, tenantID, price string) error {
	form := url.Values{
		"id":                                   {tenantID},
		"subscription_items[item_price_id][0]": {price},
		"meta_data":                            {encodeMeta(map[string]any{MetadataTenantID: tenantID})},
	}
	return p.call(ctx, http.MethodPost, "/customers/"+url.PathEscape(customerID)+"/subscription_for_items", form, nil)
}

// changeItems replaces the subscription's items with price. With
// reactivate, a cancelled subscription is activated again.
func (p *Plugin) changeItems(ctx context.Context, id, price string, reactivate bool) error {
	form := url.Values{
		"subscription_items[item_price_id][0]": {price},
		"replace_items_list":                   {"true"},
	}
	if reactivate {
		form.Set("reactivate", "true")
	}
	return p.call(ctx, http.MethodPost, "/subscriptions/"+url.PathEscape(id)+"/update_for_items", form, nil)
}

// cancelSubscription cancels immediately or at the end of the current
// term. A missing subscription is not an error.
func (p *Plugin) cancelSubscription(ctx context.Context, id string, endOfTerm bool) error {
	form := url.Values{"end_of_term": {fmt.Sprint(endOfTerm)}}
	err := p.call(ctx, http.MethodPost, "/subscriptions/"+url.PathEscape(id)+"/cancel_for_items", form, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}
