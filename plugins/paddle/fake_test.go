package paddle

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakePaddle is an in-memory Paddle Billing API covering the endpoints the
// plugin calls. It checks the bearer key, enforces unique customer emails
// like Paddle and records every call.
type fakePaddle struct {
	srv *httptest.Server
	key string

	mu        sync.Mutex
	n         int
	customers map[string]*fakeCustomer
	custOrder []string
	subs      map[string]*fakeSub
	subOrder  []string
	calls     []fakeCall
	// hideFromList makes GET /customers find nothing (e.g. archived).
	hideFromList bool
	// failNext answers the next n requests with 500.
	failNext int
}

type fakeCustomer struct {
	ID         string         `json:"id"`
	Email      string         `json:"email"`
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	CustomData map[string]any `json:"custom_data"`
}

type fakeItem struct {
	Price    string
	Quantity int
}

type fakeSub struct {
	ID              string
	Customer        string
	Status          string
	CustomData      map[string]any
	Items           []fakeItem
	ScheduledCancel bool
}

type fakeCall struct {
	Method, Path string
	Query        string
	Body         map[string]any
}

func newFakePaddle(t *testing.T) *fakePaddle {
	f := &fakePaddle{
		key:       "pdl_test_key",
		customers: map[string]*fakeCustomer{},
		subs:      map[string]*fakeSub{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /event-types", func(w http.ResponseWriter, r *http.Request) {
		f.data(w, 200, []any{map[string]any{"name": "subscription.created"}})
	})
	mux.HandleFunc("GET /customers", f.listCustomers)
	mux.HandleFunc("POST /customers", f.createCustomer)
	mux.HandleFunc("GET /customers/{id}", f.getCustomer)
	mux.HandleFunc("PATCH /customers/{id}", f.updateCustomer)
	mux.HandleFunc("GET /subscriptions", f.listSubs)
	mux.HandleFunc("GET /subscriptions/{id}", f.getSub)
	mux.HandleFunc("PATCH /subscriptions/{id}", f.updateSub)
	mux.HandleFunc("POST /subscriptions/{id}/cancel", f.cancelSub)
	f.srv = httptest.NewServer(f.wrap(mux))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakePaddle) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+f.key {
			f.error(w, 403, "forbidden", "authentication_malformed")
			return
		}
		var body map[string]any
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			if len(raw) > 0 {
				if r.Header.Get("Content-Type") != "application/json" || json.Unmarshal(raw, &body) != nil {
					f.error(w, 400, "bad_request", "invalid JSON body")
					return
				}
			}
		}
		f.mu.Lock()
		f.calls = append(f.calls, fakeCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: body})
		if f.failNext > 0 {
			f.failNext--
			f.mu.Unlock()
			f.error(w, 500, "internal_error", "simulated outage")
			return
		}
		f.mu.Unlock()
		next.ServeHTTP(w, r.WithContext(withBody(r.Context(), body)))
	})
}

func (f *fakePaddle) data(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": v, "meta": map[string]any{"request_id": "req_1"}})
}

func (f *fakePaddle) list(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"data": v, "meta": map[string]any{
		"request_id": "req_1", "pagination": map[string]any{"per_page": 200, "has_more": false},
	}})
}

func (f *fakePaddle) error(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"type": "request_error", "code": code, "detail": detail}})
}

func (f *fakePaddle) id(prefix string) string {
	f.n++
	return fmt.Sprintf("%s%04d", prefix, f.n)
}

func (f *fakePaddle) listCustomers(w http.ResponseWriter, r *http.Request) {
	emails := strings.Split(r.URL.Query().Get("email"), ",")
	f.mu.Lock()
	defer f.mu.Unlock()
	data := []any{}
	for _, id := range f.custOrder {
		if c := f.customers[id]; !f.hideFromList && slices.Contains(emails, c.Email) {
			data = append(data, c)
		}
	}
	f.list(w, data)
}

func (f *fakePaddle) createCustomer(w http.ResponseWriter, r *http.Request) {
	body := bodyOf(r)
	email, _ := body["email"].(string)
	if email == "" {
		f.error(w, 400, "invalid_field", "email is required")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.customers {
		if strings.EqualFold(c.Email, email) {
			f.error(w, 409, "customer_already_exists", "customer email conflicts with customer of id "+c.ID)
			return
		}
	}
	name, _ := body["name"].(string)
	cd, _ := body["custom_data"].(map[string]any)
	c := &fakeCustomer{ID: f.id("ctm_"), Email: email, Name: name, Status: "active", CustomData: cd}
	f.customers[c.ID] = c
	f.custOrder = append(f.custOrder, c.ID)
	f.data(w, 201, c)
}

func (f *fakePaddle) getCustomer(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.customers[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "not_found", "Entity not found")
		return
	}
	f.data(w, 200, c)
}

func (f *fakePaddle) updateCustomer(w http.ResponseWriter, r *http.Request) {
	body := bodyOf(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.customers[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "not_found", "Entity not found")
		return
	}
	if v, ok := body["name"].(string); ok {
		c.Name = v
	}
	if v, ok := body["email"].(string); ok {
		c.Email = v
	}
	if v, ok := body["custom_data"].(map[string]any); ok {
		c.CustomData = v // replaced, like Paddle
	}
	f.data(w, 200, c)
}

func (s *fakeSub) object() map[string]any {
	items := []any{}
	for _, it := range s.Items {
		items = append(items, map[string]any{"status": "active", "quantity": it.Quantity, "price": map[string]any{"id": it.Price}})
	}
	var sc any
	if s.ScheduledCancel {
		sc = map[string]any{"action": "cancel", "effective_at": "2030-01-01T00:00:00Z"}
	}
	return map[string]any{
		"id": s.ID, "status": s.Status, "customer_id": s.Customer, "custom_data": s.CustomData,
		"items": items, "next_billed_at": "2030-01-01T00:00:00Z", "scheduled_change": sc,
		"current_billing_period": map[string]any{"starts_at": "2029-12-01T00:00:00Z", "ends_at": "2030-01-01T00:00:00Z"},
	}
}

func (f *fakePaddle) listSubs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("status") != liveStatuses || q.Get("order_by") != "id[DESC]" {
		f.error(w, 400, "invalid_field", "test expects live statuses newest first")
		return
	}
	statuses := strings.Split(q.Get("status"), ",")
	f.mu.Lock()
	defer f.mu.Unlock()
	data := []any{}
	for _, id := range slices.Backward(f.subOrder) {
		s := f.subs[id]
		if s.Customer == q.Get("customer_id") && slices.Contains(statuses, s.Status) {
			data = append(data, s.object())
		}
	}
	f.list(w, data)
}

func (f *fakePaddle) getSub(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subs[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "not_found", "Entity not found")
		return
	}
	f.data(w, 200, s.object())
}

func (f *fakePaddle) updateSub(w http.ResponseWriter, r *http.Request) {
	body := bodyOf(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subs[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "not_found", "Entity not found")
		return
	}
	if s.Status == "canceled" {
		f.error(w, 400, "subscription_update_when_canceled", "subscription is canceled")
		return
	}
	if raw, ok := body["items"].([]any); ok {
		if body["proration_billing_mode"] == nil {
			f.error(w, 400, "invalid_field", "proration_billing_mode is required")
			return
		}
		s.Items = nil
		for _, it := range raw {
			m := it.(map[string]any)
			s.Items = append(s.Items, fakeItem{Price: m["price_id"].(string), Quantity: int(m["quantity"].(float64))})
		}
	}
	if cd, ok := body["custom_data"].(map[string]any); ok {
		s.CustomData = cd
	}
	f.data(w, 200, s.object())
}

func (f *fakePaddle) cancelSub(w http.ResponseWriter, r *http.Request) {
	body := bodyOf(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subs[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "not_found", "Entity not found")
		return
	}
	switch body["effective_from"] {
	case "immediately":
		s.Status = "canceled"
	case "next_billing_period":
		s.ScheduledCancel = true
	default:
		f.error(w, 400, "invalid_field", "effective_from")
		return
	}
	f.data(w, 200, s.object())
}

// addCustomer adds a customer; tenantID may be empty (unclaimed).
func (f *fakePaddle) addCustomer(email, tenantID string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &fakeCustomer{ID: f.id("ctm_"), Email: email, Name: "Seeded", Status: "active", CustomData: map[string]any{}}
	if tenantID != "" {
		c.CustomData[CustomDataTenantID] = tenantID
	}
	f.customers[c.ID] = c
	f.custOrder = append(f.custOrder, c.ID)
	return c.ID
}

// addSub adds a subscription (as a checkout would) to the customer.
func (f *fakePaddle) addSub(customer, tenantID, price, status string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &fakeSub{ID: f.id("sub_"), Customer: customer, Status: status, CustomData: map[string]any{},
		Items: []fakeItem{{Price: price, Quantity: 1}}}
	if tenantID != "" {
		s.CustomData[CustomDataTenantID] = tenantID
	}
	f.subs[s.ID] = s
	f.subOrder = append(f.subOrder, s.ID)
	return s.ID
}

// seed adds a customer for tenantID with a subscription to price.
func (f *fakePaddle) seed(tenantID, email, price, status string) (cus, sub string) {
	cus = f.addCustomer(email, tenantID)
	return cus, f.addSub(cus, tenantID, price, status)
}

func (f *fakePaddle) setSub(id string, fn func(s *fakeSub)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.subs[id])
}

func (f *fakePaddle) sub(id string) fakeSub {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := *f.subs[id]
	s.Items = slices.Clone(s.Items)
	s.CustomData = maps.Clone(s.CustomData)
	return s
}

func (f *fakePaddle) subObject(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subs[id].object()
}

func (f *fakePaddle) customer(id string) fakeCustomer {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := *f.customers[id]
	c.CustomData = maps.Clone(c.CustomData)
	return c
}

// customersOf returns the customers tagged with tenantID.
func (f *fakePaddle) customersOf(tenantID string) []fakeCustomer {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeCustomer
	for _, id := range f.custOrder {
		if c := f.customers[id]; c.CustomData[CustomDataTenantID] == tenantID {
			out = append(out, *c)
		}
	}
	return out
}

// callsTo returns the recorded calls matching method and path prefix.
func (f *fakePaddle) callsTo(method, pathPrefix string) []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeCall
	for _, c := range f.calls {
		if c.Method == method && strings.HasPrefix(c.Path, pathPrefix) {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakePaddle) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strconv.Itoa(len(f.customers)) + " customers, " + strconv.Itoa(len(f.subs)) + " subscriptions, " +
		strconv.Itoa(len(f.calls)) + " calls"
}

type bodyKey struct{}

func withBody(ctx context.Context, body map[string]any) context.Context {
	return context.WithValue(ctx, bodyKey{}, body)
}

// bodyOf returns the decoded JSON request body.
func bodyOf(r *http.Request) map[string]any {
	b, _ := r.Context().Value(bodyKey{}).(map[string]any)
	return b
}
