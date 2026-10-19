package certs

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOrderLocationShim(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/new-order":
			w.Header().Set("Location", srv.URL+"/order/1")
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"status":"pending","finalize":"`+srv.URL+`/finalize/1"}`)
		case "/finalize/1", "/finalize/2": // async finalize without Location, like Pebble
			_, _ = io.WriteString(w, `{"status":"processing"}`)
		}
	}))
	defer srv.Close()
	c := withOrderLocation(srv.Client())

	res, err := c.Post(srv.URL+"/new-order", "application/jose+json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := io.ReadAll(res.Body); !strings.Contains(string(body), "finalize") {
		t.Fatalf("body not preserved: %q", body)
	}
	res, _ = c.Post(srv.URL+"/finalize/1", "application/jose+json", nil)
	if got := res.Header.Get("Location"); got != srv.URL+"/order/1" {
		t.Fatalf("Location = %q", got)
	}
	res, _ = c.Post(srv.URL+"/finalize/2", "application/jose+json", nil)
	if got := res.Header.Get("Location"); got != "" {
		t.Fatalf("unknown order got Location %q", got)
	}
}
