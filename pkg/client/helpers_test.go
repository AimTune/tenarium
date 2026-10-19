package client_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/server"
)

const apiKey = "client-test-key"

// --- test plugins (IDs are unique to this package) --------------------------

// flakyFail makes the clienttest-flaky subscriber fail.
var flakyFail atomic.Bool

type flakyPlugin struct{}

func (flakyPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "clienttest-flaky", Name: "Client test flaky", Version: "0"}
}

func (flakyPlugin) Init(_ context.Context, r sdk.Registrar) error {
	r.Subscribe("sink", sdk.EventFilter{Types: []string{sdk.EventTenantCreated}}, func(context.Context, sdk.Event) error {
		if flakyFail.Load() {
			return errors.New("sink down")
		}
		return nil
	}, sdk.WithMaxAttempts(1))
	return nil
}

// mailbox captures outgoing email so tests can read invitation and reset tokens.
type mailbox struct {
	mu   sync.Mutex
	sent []sdk.Message
}

var testMailbox = &mailbox{}

func (m *mailbox) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "clienttest-mailbox", Name: "Client test mailbox", Version: "0"}
}
func (m *mailbox) Init(_ context.Context, r sdk.Registrar) error { r.Mailer(m); return nil }
func (m *mailbox) Name() string                                  { return "clienttest-mailbox" }
func (m *mailbox) Send(_ context.Context, msg sdk.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

var mailLink = regexp.MustCompile(`/ui/#/(?:accept|reset)/([A-Za-z0-9_-]+)`)

func (m *mailbox) token(t *testing.T, to, tag string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if msg := m.sent[i]; msg.Tag == tag && msg.To[0] == to {
			if mm := mailLink.FindStringSubmatch(msg.Text); mm != nil {
				return mm[1]
			}
		}
	}
	t.Fatalf("no %s email to %s", tag, to)
	return ""
}

func init() {
	sdk.Register("clienttest-flaky", func() sdk.Plugin { return flakyPlugin{} })
	sdk.Register("clienttest-mailbox", func() sdk.Plugin { return testMailbox })
}

// --- server ----------------------------------------------------------------------

const (
	rootEmail    = "root@example.com"
	rootPassword = "root password long enough"
)

func baseConfig() server.Config {
	cfg := server.DefaultConfig()
	cfg.Server.APIKeys = []string{apiKey}
	cfg.Events.PollInterval = 20 * time.Millisecond
	cfg.Events.LeaseTTL = time.Second
	cfg.Auth.RateLimit = 0
	cfg.Users.PublicURL = "https://tenarium.example.com"
	cfg.Bootstrap.Users = []server.BootstrapUser{{Email: rootEmail, Password: rootPassword, Roles: []string{"admin"}}}
	cfg.Plugins = []server.PluginSpec{{Plugin: "clienttest-mailbox"}}
	return cfg
}

// startServer runs a real in-process Tenarium server and returns its URL.
func startServer(t *testing.T, cfg server.Config) string {
	t.Helper()
	curT = t
	ctx, cancel := context.WithCancel(context.Background())
	app, err := server.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return "http://" + ln.Addr().String()
}

func newClient(t *testing.T, base string, opts ...client.Option) *client.Client {
	t.Helper()
	c, err := client.New(base, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// curT is the running test (set by startServer); tests in this package do
// not run in parallel.
var curT *testing.T

// must fails the current test on error.
func must[T any](v T, err error) T {
	curT.Helper()
	if err != nil {
		curT.Fatal(err)
	}
	return v
}
