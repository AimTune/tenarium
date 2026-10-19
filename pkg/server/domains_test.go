package server_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

// fakeDNS serves TXT records set by the test.
type fakeDNS struct {
	mu      sync.Mutex
	records map[string][]string
}

func (d *fakeDNS) lookup(_ context.Context, name string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.records[name], nil
}

func TestCustomDomains(t *testing.T) {
	dns := &fakeDNS{records: map[string][]string{}}
	cfg := baseConfig()
	cfg.Tenants.ReservedDomains = []string{"tenarium.example"}
	base := startServerWith(t, cfg, server.WithTXTResolver(dns.lookup))
	c := client{t: t, base: base}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	c.do("POST", "/v1/tenants", map[string]any{"slug": "globex", "name": "Globex"})

	for _, bad := range []string{"localhost", "10.0.0.1", "acme.tenarium.example", "bad_label.example.com"} {
		if code, _ := c.do("POST", "/v1/tenants/acme/domains", map[string]any{"hostname": bad}); code != 400 {
			t.Errorf("hostname %q: %d", bad, code)
		}
	}
	code, added := c.do("POST", "/v1/tenants/acme/domains", map[string]any{"hostname": "App.Acme.COM."})
	if code != 201 {
		t.Fatalf("add: %d %v", code, added)
	}
	instr := added["instructions"].(map[string]any)
	if instr["name"] != "_tenarium-challenge.app.acme.com" {
		t.Fatalf("instructions: %v", instr)
	}
	if code, _ := c.do("POST", "/v1/tenants/globex/domains", map[string]any{"hostname": "app.acme.com"}); code != 409 {
		t.Fatalf("hostname claimed twice: %d", code)
	}

	check := func(host string) int {
		resp, err := http.Get(base + "/v1/domains/check?domain=" + host)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if check("app.acme.com") != 404 {
		t.Fatal("unverified domain passed the TLS check")
	}
	if code, _ := c.do("POST", "/v1/tenants/acme/domains/app.acme.com/verify", nil); code != 422 {
		t.Fatalf("verify without TXT: %d", code)
	}
	if code, _ := c.do("POST", "/v1/tenants/globex/domains/app.acme.com/verify", nil); code != 404 {
		t.Fatalf("verify through another tenant: %d", code)
	}
	dns.mu.Lock()
	dns.records[instr["name"].(string)] = []string{"something else", instr["value"].(string)}
	dns.mu.Unlock()
	if code, d := c.do("POST", "/v1/tenants/acme/domains/app.acme.com/verify", nil); code != 200 || d["verified"] != true {
		t.Fatalf("verify: %d %v", code, d)
	}
	if check("app.acme.com") != 200 || check("APP.acme.com:443") != 200 {
		t.Fatal("verified domain failed the TLS check")
	}
	if code, r := c.do("GET", "/v1/domains/resolve?host=app.acme.com", nil); code != 200 || r["slug"] != "acme" {
		t.Fatalf("resolve: %d %v", code, r)
	}

	// Suspension does not break the domain; deletion does.
	c.do("POST", "/v1/tenants/acme/suspend", nil)
	if check("app.acme.com") != 200 {
		t.Fatal("suspended tenant lost its certificate eligibility")
	}
	if code, _ := c.do("DELETE", "/v1/tenants/acme/domains/app.acme.com", nil); code != 204 {
		t.Fatalf("remove: %d", code)
	}
	if check("app.acme.com") != 404 {
		t.Fatal("removed domain still passes")
	}
}
