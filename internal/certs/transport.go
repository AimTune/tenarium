package certs

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// orderLocationTransport works around an interoperability gap between
// golang.org/x/crypto/acme and CAs that finalize orders asynchronously.
//
// After POSTing the CSR to an order's finalize URL, acme.Client.CreateOrderCert
// polls the order at the finalize response's Location header. RFC 8555 does
// not require that header there, and some CAs (Pebble, notably) answer
// "processing" without it, so the client polls an empty URL and issuance
// fails with `Post "": unsupported protocol scheme ""`.
//
// The shim remembers, from new-order responses, which order URL each finalize
// URL belongs to, and adds the missing Location to finalize responses. It
// changes nothing for CAs that already send the header (Let's Encrypt does).
type orderLocationTransport struct {
	base http.RoundTripper

	mu     sync.Mutex
	orders map[string]string // finalize URL -> order URL
}

const maxTrackedOrders = 1000

func withOrderLocation(c *http.Client) *http.Client {
	cp := *c
	base := cp.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	cp.Transport = &orderLocationTransport{base: base, orders: map[string]string{}}
	return &cp
}

func (t *orderLocationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.base.RoundTrip(req)
	if err != nil || req.Method != http.MethodPost || res.StatusCode >= 300 ||
		!strings.Contains(res.Header.Get("Content-Type"), "json") {
		return res, err
	}
	reqURL := req.URL.String()

	if res.Header.Get("Location") == "" {
		t.mu.Lock()
		order, ok := t.orders[reqURL]
		t.mu.Unlock()
		if ok {
			res.Header.Set("Location", order)
		}
		return res, nil
	}

	// A response carrying an order object: remember finalize -> order.
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	var o struct {
		Finalize string `json:"finalize"`
	}
	if json.Unmarshal(body, &o) == nil && o.Finalize != "" {
		t.mu.Lock()
		if len(t.orders) >= maxTrackedOrders {
			t.orders = map[string]string{}
		}
		t.orders[o.Finalize] = res.Header.Get("Location")
		t.mu.Unlock()
	}
	return res, nil
}
