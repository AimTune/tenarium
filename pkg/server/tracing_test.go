package server_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

// TestTracingExportsRouteSpans runs a server against a fake OTLP/HTTP
// collector and checks spans arrive named after routes and deliveries.
func TestTracingExportsRouteSpans(t *testing.T) {
	var (
		mu       sync.Mutex
		payloads []byte
	)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		payloads = append(payloads, b...)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer collector.Close()

	cfg := baseConfig()
	cfg.Plugins = append(cfg.Plugins, server.PluginSpec{Plugin: "mailbox"})
	cfg.Tracing = server.TracingConfig{Enabled: true, Endpoint: strings.TrimPrefix(collector.URL, "http://"), Insecure: true, ServiceName: "tenarium-test"}

	ctx, cancel := context.WithCancel(context.Background())
	app, err := server.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, ln) }()
	c := client{t: t, base: "http://" + ln.Addr().String()}
	c.do("POST", "/v1/tenants", map[string]any{"slug": "acme", "name": "Acme"})
	c.do("GET", "/v1/tenants/acme", nil)
	waitFor(t, "delivery", func() bool {
		_, got := c.do("GET", "/v1/events", nil)
		return len(got["items"].([]any)) > 0
	})
	cancel() // shutdown flushes the batch
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"tenarium-test", "GET /v1/tenants/{id}", "POST /v1/tenants", "http.route"} {
		if !bytes.Contains(payloads, []byte(want)) {
			t.Errorf("exported spans lack %q", want)
		}
	}
}
