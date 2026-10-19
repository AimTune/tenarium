package chargebee

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeChargebee is an in-memory Chargebee API v2 covering the endpoints the
// plugin calls. It checks the basic auth API key, parses form bodies,
// enforces unique IDs (duplicate_entry) and records every call.
type fakeChargebee struct {
	srv *httptest.Server
	key string

	mu        sync.Mutex
	customers map[string]*fakeCustomer
	subs      map[string]*fakeSub
	subOrder  []string
	calls     []fakeCall
	// failNext answers the next n requests with 500.
	failNext int
	// hideCustomerOnce makes the next n customer GETs answer 404, as if an
	// earlier attempt's creation had not been seen yet.
	hideCustomer int
}

type fakeCustomer struct {
	ID       string
	Company  string
	Deleted  bool
	MetaData map[string]any
	Custom   map[string]string
}

type fakeSub struct {
	ID          string
	Customer    string
	Status      string
	Price       string
	MetaData    map[string]any
	DueInvoices int
	TermEnd     int64
	Form        map[string]string
}

type fakeCall struct {
	Method, Path string
	Form         map[string]string
}

func newFakeChargebee(t *testing.T) *fakeChargebee {
	f := &fakeChargebee{key: "test_key", customers: map[string]*fakeCustomer{}, subs: map[string]*fakeSub{}}
	mux := http.NewServeMux()
	const b = "/api/v2"
	mux.HandleFunc("GET "+b+"/customers", f.listCustomers)
	mux.HandleFunc("POST "+b+"/customers", f.createCustomer)
	mux.HandleFunc("GET "+b+"/customers/{id}", f.getCustomer)
	mux.HandleFunc("POST "+b+"/customers/{id}", f.updateCustomer)
	mux.HandleFunc("POST "+b+"/customers/{id}/subscription_for_items", f.createSub)
	mux.HandleFunc("GET "+b+"/subscriptions", f.listSubs)
	mux.HandleFunc("GET "+b+"/subscriptions/{id}", f.getSub)
	mux.HandleFunc("POST "+b+"/subscriptions/{id}/update_for_items", f.updateSub)
	mux.HandleFunc("POST "+b+"/subscriptions/{id}/cancel_for_items", f.cancelSub)
	f.srv = httptest.NewServer(f.wrap(mux))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeChargebee) base() string { return f.srv.URL + "/api/v2" }

func (f *fakeChargebee) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != f.key || pass != "" {
			f.error(w, 401, "api_authentication_failed", "Sorry, authentication failed. Invalid api key")
			return
		}
		if r.Method == http.MethodPost && r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			f.error(w, 400, "invalid_request", "expected a form body")
			return
		}
		_ = r.ParseForm()
		form := map[string]string{}
		for k, v := range r.Form {
			form[k] = v[0]
		}
		f.mu.Lock()
		f.calls = append(f.calls, fakeCall{Method: r.Method, Path: strings.TrimPrefix(r.URL.Path, "/api/v2"), Form: form})
		if f.failNext > 0 {
			f.failNext--
			f.mu.Unlock()
			f.error(w, 500, "internal_error", "simulated outage")
			return
		}
		f.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (f *fakeChargebee) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeChargebee) error(w http.ResponseWriter, status int, code, msg string) {
	f.json(w, status, map[string]any{
		"message": msg, "type": "invalid_request", "api_error_code": code, "error_code": code, "http_status_code": status,
	})
}

func metaFrom(r *http.Request) (map[string]any, error) {
	md := map[string]any{}
	if s := r.Form.Get("meta_data"); s != "" {
		if err := json.Unmarshal([]byte(s), &md); err != nil {
			return nil, err
		}
	}
	return md, nil
}

func (c *fakeCustomer) object() map[string]any {
	o := map[string]any{"id": c.ID, "object": "customer", "company": c.Company, "deleted": c.Deleted, "meta_data": c.MetaData}
	for k, v := range c.Custom {
		o[k] = v
	}
	return o
}

func (s *fakeSub) object() map[string]any {
	return map[string]any{
		"id": s.ID, "object": "subscription", "customer_id": s.Customer, "status": s.Status,
		"meta_data": s.MetaData, "due_invoices_count": s.DueInvoices, "current_term_end": s.TermEnd,
		"subscription_items": []any{map[string]any{"item_price_id": s.Price, "item_type": "plan", "quantity": 1}},
	}
}

func (f *fakeChargebee) listCustomers(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("limit") != "1" {
		f.error(w, 400, "invalid_request", "test expects limit=1")
		return
	}
	f.json(w, 200, map[string]any{"list": []any{}})
}

func (f *fakeChargebee) createCustomer(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := r.Form.Get("id")
	if _, dup := f.customers[id]; dup {
		f.error(w, 400, "duplicate_entry", "The value "+id+" is already present.")
		return
	}
	md, err := metaFrom(r)
	if err != nil {
		f.error(w, 400, "invalid_request", "bad meta_data")
		return
	}
	c := &fakeCustomer{ID: id, Company: r.Form.Get("company"), MetaData: md, Custom: map[string]string{}}
	for k, v := range r.Form {
		if strings.HasPrefix(k, "cf_") {
			c.Custom[k] = v[0]
		}
	}
	f.customers[id] = c
	f.json(w, 200, map[string]any{"customer": c.object()})
}

func (f *fakeChargebee) getCustomer(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.customers[r.PathValue("id")]
	if f.hideCustomer > 0 {
		f.hideCustomer--
		ok = false
	}
	if !ok {
		f.error(w, 404, "resource_not_found", "Sorry, we couldn't find that resource")
		return
	}
	f.json(w, 200, map[string]any{"customer": c.object()})
}

func (f *fakeChargebee) updateCustomer(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.customers[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "resource_not_found", "Sorry, we couldn't find that resource")
		return
	}
	if r.Form.Has("company") {
		c.Company = r.Form.Get("company")
	}
	if r.Form.Has("meta_data") {
		md, err := metaFrom(r)
		if err != nil {
			f.error(w, 400, "invalid_request", "bad meta_data")
			return
		}
		c.MetaData = md // replaced as a whole, like Chargebee
	}
	f.json(w, 200, map[string]any{"customer": c.object()})
}

func (f *fakeChargebee) createSub(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.customers[r.PathValue("id")]; !ok {
		f.error(w, 404, "resource_not_found", "customer not found")
		return
	}
	id := r.Form.Get("id")
	if _, dup := f.subs[id]; dup {
		f.error(w, 400, "duplicate_entry", "The value "+id+" is already present.")
		return
	}
	md, err := metaFrom(r)
	if err != nil {
		f.error(w, 400, "invalid_request", "bad meta_data")
		return
	}
	form := map[string]string{}
	for k, v := range r.Form {
		form[k] = v[0]
	}
	s := &fakeSub{ID: id, Customer: r.PathValue("id"), Status: "active", Price: r.Form.Get("subscription_items[item_price_id][0]"),
		MetaData: md, TermEnd: 1893456000, Form: form}
	f.subs[id] = s
	f.subOrder = append(f.subOrder, id)
	f.json(w, 200, map[string]any{"subscription": s.object(), "customer": f.customers[s.Customer].object()})
}

func (f *fakeChargebee) listSubs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var statuses []string
	if err := json.Unmarshal([]byte(q.Get("status[in]")), &statuses); err != nil || len(statuses) == 0 {
		f.error(w, 400, "invalid_request", "test expects status[in]")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	list := []any{}
	for _, id := range slices.Backward(f.subOrder) {
		s := f.subs[id]
		if s.Customer == q.Get("customer_id[is]") && slices.Contains(statuses, s.Status) {
			list = append(list, map[string]any{"subscription": s.object()})
		}
	}
	f.json(w, 200, map[string]any{"list": list})
}

func (f *fakeChargebee) getSub(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subs[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "resource_not_found", "Sorry, we couldn't find that resource")
		return
	}
	res := map[string]any{"subscription": s.object()}
	if c, ok := f.customers[s.Customer]; ok {
		res["customer"] = c.object()
	}
	f.json(w, 200, res)
}

func (f *fakeChargebee) updateSub(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subs[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "resource_not_found", "Sorry, we couldn't find that resource")
		return
	}
	if r.Form.Get("replace_items_list") != "true" {
		f.error(w, 400, "invalid_request", "test expects replace_items_list")
		return
	}
	if s.Status == "cancelled" && r.Form.Get("reactivate") != "true" {
		f.error(w, 400, "invalid_state_for_request", "subscription is cancelled")
		return
	}
	s.Price = r.Form.Get("subscription_items[item_price_id][0]")
	if r.Form.Get("reactivate") == "true" {
		s.Status = "active"
	}
	f.json(w, 200, map[string]any{"subscription": s.object()})
}

func (f *fakeChargebee) cancelSub(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subs[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "resource_not_found", "Sorry, we couldn't find that resource")
		return
	}
	if s.Status == "cancelled" {
		f.error(w, 400, "invalid_state_for_request", "already cancelled")
		return
	}
	if r.Form.Get("end_of_term") == "true" {
		s.Status = "non_renewing"
	} else {
		s.Status = "cancelled"
	}
	f.json(w, 200, map[string]any{"subscription": s.object()})
}

// seedCustomer adds a customer.
func (f *fakeChargebee) seedCustomer(id string, meta map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if meta == nil {
		meta = map[string]any{}
	}
	f.customers[id] = &fakeCustomer{ID: id, Company: "Seeded", MetaData: meta, Custom: map[string]string{}}
}

// seed adds a customer with ID tenantID and a subscription with the same
// ID to price.
func (f *fakeChargebee) seed(tenantID, price, status string) string {
	f.seedCustomer(tenantID, map[string]any{"tenarium_tenant_id": tenantID})
	f.mu.Lock()
	defer f.mu.Unlock()
	s := &fakeSub{ID: tenantID, Customer: tenantID, Status: status, Price: price,
		MetaData: map[string]any{"tenarium_tenant_id": tenantID}, TermEnd: 1893456000}
	f.subs[s.ID] = s
	f.subOrder = append(f.subOrder, s.ID)
	return s.ID
}

func (f *fakeChargebee) setSub(id string, fn func(s *fakeSub)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.subs[id])
}

func (f *fakeChargebee) subObject(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subs[id].object()
}

func (f *fakeChargebee) customer(id string) *fakeCustomer {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.customers[id]; ok {
		cp := *c
		return &cp
	}
	return nil
}

// subsOf returns copies of the customer's subscriptions, oldest first.
func (f *fakeChargebee) subsOf(customer string) []fakeSub {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeSub
	for _, id := range f.subOrder {
		if s := f.subs[id]; s.Customer == customer {
			out = append(out, *s)
		}
	}
	return out
}

// callsTo returns the recorded calls matching method and a path prefix
// (relative to /api/v2).
func (f *fakeChargebee) callsTo(method, pathPrefix string) []fakeCall {
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

func (f *fakeChargebee) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprintf("%d customers, %d subscriptions, %d calls", len(f.customers), len(f.subs), len(f.calls))
}
