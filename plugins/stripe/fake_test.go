package stripe

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeStripe is an in-memory Stripe API covering the endpoints the plugin
// calls. It checks the bearer key, replays responses for repeated
// Idempotency-Keys and records every call.
type fakeStripe struct {
	srv *httptest.Server
	key string

	mu        sync.Mutex
	n         int
	customers map[string]*fakeCustomer
	subs      map[string]*fakeSub
	subOrder  []string
	idem      map[string]recorded
	calls     []fakeCall
	// hideFromSearch simulates search lag: search never finds anything.
	hideFromSearch bool
	// failNext answers the next n requests with 500.
	failNext int
}

type fakeCustomer struct {
	ID       string            `json:"id"`
	Object   string            `json:"object"`
	Name     string            `json:"name"`
	Metadata map[string]string `json:"metadata"`
}

type fakeSub struct {
	ID                string
	Customer          string
	Status            string
	Metadata          map[string]string
	ItemID            string
	Price             string
	CancelAtPeriodEnd bool
	PeriodEnd         int64
	Form              map[string]string // creation parameters
}

type fakeCall struct {
	Method, Path, IdemKey string
	Form                  map[string]string
}

type recorded struct {
	status int
	body   []byte
}

func newFakeStripe(t *testing.T) *fakeStripe {
	f := &fakeStripe{
		key:       "sk_test_key",
		customers: map[string]*fakeCustomer{},
		subs:      map[string]*fakeSub{},
		idem:      map[string]recorded{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/balance", func(w http.ResponseWriter, r *http.Request) {
		f.json(w, 200, map[string]any{"object": "balance"})
	})
	mux.HandleFunc("GET /v1/customers/search", f.searchCustomers)
	mux.HandleFunc("POST /v1/customers", f.createCustomer)
	mux.HandleFunc("GET /v1/customers/{id}", f.getCustomer)
	mux.HandleFunc("POST /v1/customers/{id}", f.updateCustomer)
	mux.HandleFunc("GET /v1/subscriptions", f.listSubs)
	mux.HandleFunc("POST /v1/subscriptions", f.createSub)
	mux.HandleFunc("GET /v1/subscriptions/{id}", f.getSub)
	mux.HandleFunc("POST /v1/subscriptions/{id}", f.updateSub)
	mux.HandleFunc("DELETE /v1/subscriptions/{id}", f.cancelSub)
	mux.HandleFunc("POST /v1/billing/meter_events", func(w http.ResponseWriter, r *http.Request) {
		f.json(w, 200, map[string]any{"object": "billing.meter_event", "identifier": r.PostForm.Get("identifier")})
	})
	f.srv = httptest.NewServer(f.wrap(mux))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeStripe) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+f.key {
			f.error(w, 401, "", "Invalid API Key provided")
			return
		}
		_ = r.ParseForm()
		form := map[string]string{}
		for k, v := range r.Form {
			form[k] = v[0]
		}
		key := r.Header.Get("Idempotency-Key")
		f.mu.Lock()
		f.calls = append(f.calls, fakeCall{Method: r.Method, Path: r.URL.Path, IdemKey: key, Form: form})
		if f.failNext > 0 {
			f.failNext--
			f.mu.Unlock()
			f.error(w, 500, "", "simulated outage")
			return
		}
		if rec, ok := f.idem[key]; ok && key != "" {
			f.mu.Unlock()
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(rec.status)
			_, _ = w.Write(rec.body)
			return
		}
		f.mu.Unlock()
		rr := httptest.NewRecorder()
		next.ServeHTTP(rr, r)
		if key != "" && r.Method == http.MethodPost {
			f.mu.Lock()
			f.idem[key] = recorded{rr.Code, rr.Body.Bytes()}
			f.mu.Unlock()
		}
		for k, v := range rr.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rr.Code)
		_, _ = w.Write(rr.Body.Bytes())
	})
}

func (f *fakeStripe) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeStripe) error(w http.ResponseWriter, status int, code, msg string) {
	f.json(w, status, map[string]any{"error": map[string]string{"type": "invalid_request_error", "code": code, "message": msg}})
}

func (f *fakeStripe) id(prefix string) string {
	f.n++
	return prefix + strconv.Itoa(f.n)
}

func metadataFrom(r *http.Request) map[string]string {
	md := map[string]string{}
	for k, v := range r.Form {
		if name, ok := strings.CutPrefix(k, "metadata["); ok {
			md[strings.TrimSuffix(name, "]")] = v[0]
		}
	}
	return md
}

var searchQuery = regexp.MustCompile(`^metadata\['tenarium_tenant_id'\]:'([^']*)'$`)

func (f *fakeStripe) searchCustomers(w http.ResponseWriter, r *http.Request) {
	m := searchQuery.FindStringSubmatch(r.URL.Query().Get("query"))
	if m == nil {
		f.error(w, 400, "parameter_invalid", "unsupported query")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data := []*fakeCustomer{}
	if !f.hideFromSearch {
		for _, c := range f.customers {
			if c.Metadata["tenarium_tenant_id"] == m[1] {
				data = append(data, c)
			}
		}
	}
	f.json(w, 200, map[string]any{"object": "search_result", "data": data})
}

func (f *fakeStripe) createCustomer(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &fakeCustomer{ID: f.id("cus_"), Object: "customer", Name: r.Form.Get("name"), Metadata: metadataFrom(r)}
	f.customers[c.ID] = c
	f.json(w, 200, c)
}

func (f *fakeStripe) getCustomer(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.customers[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "resource_missing", "No such customer")
		return
	}
	f.json(w, 200, c)
}

func (f *fakeStripe) updateCustomer(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.customers[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "resource_missing", "No such customer")
		return
	}
	if r.Form.Has("name") {
		c.Name = r.Form.Get("name")
	}
	for k, v := range metadataFrom(r) {
		c.Metadata[k] = v
	}
	f.json(w, 200, c)
}

func (s *fakeSub) object() map[string]any {
	return map[string]any{
		"id": s.ID, "object": "subscription", "customer": s.Customer, "status": s.Status,
		"metadata": s.Metadata, "cancel_at_period_end": s.CancelAtPeriodEnd,
		"items": map[string]any{"object": "list", "data": []any{map[string]any{
			"id": s.ItemID, "price": map[string]any{"id": s.Price}, "current_period_end": s.PeriodEnd,
		}}},
	}
}

func (f *fakeStripe) listSubs(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("status") != "all" {
		f.error(w, 400, "parameter_invalid", "test expects status=all")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data := []any{}
	for _, id := range slices.Backward(f.subOrder) { // newest first, like Stripe
		s := f.subs[id]
		if s.Customer == r.URL.Query().Get("customer") {
			data = append(data, s.object())
		}
	}
	f.json(w, 200, map[string]any{"object": "list", "data": data})
}

func (f *fakeStripe) createSub(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.customers[r.Form.Get("customer")]; !ok {
		f.error(w, 400, "resource_missing", "No such customer")
		return
	}
	form := map[string]string{}
	for k, v := range r.Form {
		form[k] = v[0]
	}
	s := &fakeSub{
		ID: f.id("sub_"), ItemID: f.id("si_"), Customer: r.Form.Get("customer"), Status: "active",
		Price: r.Form.Get("items[0][price]"), Metadata: metadataFrom(r), PeriodEnd: 1893456000, Form: form,
	}
	if r.Form.Get("trial_period_days") != "" {
		s.Status = "trialing"
	}
	f.subs[s.ID] = s
	f.subOrder = append(f.subOrder, s.ID)
	f.json(w, 200, s.object())
}

func (f *fakeStripe) getSub(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subs[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "resource_missing", "No such subscription")
		return
	}
	f.json(w, 200, s.object())
}

func (f *fakeStripe) updateSub(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subs[r.PathValue("id")]
	if !ok {
		f.error(w, 404, "resource_missing", "No such subscription")
		return
	}
	if id := r.Form.Get("items[0][id]"); id != "" {
		if id != s.ItemID {
			f.error(w, 400, "resource_missing", "No such subscription item")
			return
		}
		s.Price = r.Form.Get("items[0][price]")
	}
	if r.Form.Get("cancel_at_period_end") == "true" {
		s.CancelAtPeriodEnd = true
	}
	f.json(w, 200, s.object())
}

func (f *fakeStripe) cancelSub(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.subs[r.PathValue("id")]
	if !ok || s.Status == "canceled" {
		f.error(w, 404, "resource_missing", "No such subscription")
		return
	}
	s.Status = "canceled"
	f.json(w, 200, s.object())
}

// seed adds a customer for tenantID with a subscription to price.
func (f *fakeStripe) seed(tenantID, price, status string) (cus, sub string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &fakeCustomer{ID: f.id("cus_"), Object: "customer", Name: "Seeded", Metadata: map[string]string{"tenarium_tenant_id": tenantID}}
	f.customers[c.ID] = c
	if price == "" {
		return c.ID, ""
	}
	s := &fakeSub{ID: f.id("sub_"), ItemID: f.id("si_"), Customer: c.ID, Status: status, Price: price,
		Metadata: map[string]string{"tenarium_tenant_id": tenantID}, PeriodEnd: 1893456000}
	f.subs[s.ID] = s
	f.subOrder = append(f.subOrder, s.ID)
	return c.ID, s.ID
}

func (f *fakeStripe) setSub(id string, fn func(s *fakeSub)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.subs[id])
}

func (f *fakeStripe) subObject(id string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subs[id].object()
}

// customersOf returns the customers tagged with tenantID.
func (f *fakeStripe) customersOf(tenantID string) []fakeCustomer {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeCustomer
	for _, c := range f.customers {
		if c.Metadata["tenarium_tenant_id"] == tenantID {
			out = append(out, *c)
		}
	}
	return out
}

// subsOf returns copies of the customer's subscriptions, oldest first.
func (f *fakeStripe) subsOf(customer string) []fakeSub {
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

// callsTo returns the recorded calls matching "METHOD /path" prefixes.
func (f *fakeStripe) callsTo(method, pathPrefix string) []fakeCall {
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

func (f *fakeStripe) String() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprintf("%d customers, %d subscriptions, %d calls", len(f.customers), len(f.subs), len(f.calls))
}
