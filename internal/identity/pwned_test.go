package identity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPwnedPasswords(t *testing.T) {
	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	var gotPath, padding string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, padding = r.URL.Path, r.Header.Get("Add-Padding")
		fmt.Fprint(w, "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n")
	}))
	defer srv.Close()
	p := PwnedPasswords{BaseURL: srv.URL}
	if bad, err := p.Breached(context.Background(), "password"); err != nil || !bad {
		t.Fatalf("breached: %v %v", bad, err)
	}
	if gotPath != "/range/5BAA6" || padding != "true" {
		t.Fatalf("request: %s padding=%q", gotPath, padding)
	}
	if bad, err := p.Breached(context.Background(), "correct horse battery staple 42"); err != nil || bad {
		t.Fatalf("clean: %v %v", bad, err)
	}
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer down.Close()
	if _, err := (PwnedPasswords{BaseURL: down.URL}).Breached(context.Background(), "x"); err == nil {
		t.Fatal("no error on outage")
	}
}
