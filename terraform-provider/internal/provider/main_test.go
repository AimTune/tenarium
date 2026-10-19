package provider

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/server"
)

// testAPIKey is the static platform API key of the in-process test server.
const testAPIKey = "tf-acc-test-key"

// verifiableSuffix marks hostnames whose verification TXT record the fake
// DNS resolver "publishes".
const verifiableSuffix = ".ok.example.com"

var testAccProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"tenarium": providerserver.NewProtocol6WithError(New("test")()),
}

// testServerURL is the base URL of the in-process server started by TestMain.
var testServerURL string

// TestMain starts a real Tenarium server (memory store) on a random port and
// points the provider at it through the environment.
func TestMain(m *testing.M) {
	ctx, cancel := context.WithCancel(context.Background())
	stop, err := startTestServer(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start tenarium:", err)
		os.Exit(1)
	}
	code := m.Run()
	cancel()
	stop()
	os.Exit(code)
}

func startTestServer(ctx context.Context) (func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	base := "http://" + ln.Addr().String()

	cfg := server.DefaultConfig()
	cfg.Server.APIKeys = []string{testAPIKey}
	cfg.Events.PollInterval = 20 * time.Millisecond
	cfg.Events.LeaseTTL = time.Second
	cfg.UI.Enabled = false
	cfg.Users.PublicURL = base
	cfg.Auth.RateLimit = 0
	cfg.Auth.SSO.AllowPrivateIssuers = true
	cfg.Webhooks.MaxPerTenant = 10

	app, err := server.New(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)),
		server.WithTXTResolver(fakeTXT(base)))
	if err != nil {
		ln.Close()
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- app.Serve(ctx, ln) }()

	testServerURL = base
	os.Setenv(EnvURL, base)
	os.Setenv(EnvAPIKey, testAPIKey)
	return func() { <-done }, nil
}

// fakeTXT answers TXT lookups for _tenarium-challenge.<host> with the
// domain's verification token when host ends in verifiableSuffix, by asking
// the server itself. Other names have no records.
func fakeTXT(base string) func(ctx context.Context, name string) ([]string, error) {
	return func(ctx context.Context, name string) ([]string, error) {
		host, ok := strings.CutPrefix(name, challengePrefix)
		if !ok || !strings.HasSuffix(host, verifiableSuffix) {
			return nil, nil
		}
		c, err := client.New(base, client.WithAPIKey(testAPIKey))
		if err != nil {
			return nil, err
		}
		for t, err := range c.Tenants.All(ctx, client.TenantListOptions{}) {
			if err != nil {
				return nil, err
			}
			var out struct {
				Items []apiDomain `json:"items"`
			}
			if err := c.Do(ctx, http.MethodGet, domainsPath(t.ID), nil, nil, &out); err != nil {
				continue
			}
			for _, d := range out.Items {
				if d.Hostname == host {
					return []string{d.Token}, nil
				}
			}
		}
		return nil, nil
	}
}

// testClient returns an API client for checks.
func testClient(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.New(testServerURL, client.WithAPIKey(testAPIKey))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// uniq returns a lowercase name unique to this test run.
func uniq(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1_000_000_000)
}
