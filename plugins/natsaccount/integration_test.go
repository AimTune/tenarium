package natsaccount

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// Integration tests run against a NATS server in operator mode with the
// full account resolver, named by TENARIUM_TEST_NATS_URL. They also need:
//
//   - TENARIUM_TEST_NATS_SIGNING_KEY: an operator signing seed (SO...)
//     trusted by the server's operator.
//   - TENARIUM_TEST_NATS_CREDS: a creds file of a system account user.
//   - TENARIUM_TEST_NATS_OPERATOR_JWT (optional): the operator JWT.
//
// The delete test expects allow_delete: true on the resolver; without it
// the plugin falls back to disabling, which the test accepts too.

func natsEnv(t *testing.T) (url, seed, creds string) {
	t.Helper()
	url = os.Getenv("TENARIUM_TEST_NATS_URL")
	if url == "" {
		t.Skip("TENARIUM_TEST_NATS_URL not set")
	}
	seed, creds = os.Getenv("TENARIUM_TEST_NATS_SIGNING_KEY"), os.Getenv("TENARIUM_TEST_NATS_CREDS")
	if seed == "" || creds == "" {
		t.Fatal("TENARIUM_TEST_NATS_SIGNING_KEY and TENARIUM_TEST_NATS_CREDS are required with TENARIUM_TEST_NATS_URL")
	}
	return url, seed, creds
}

func newNATSPlugin(t *testing.T, extra map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	url, seed, creds := natsEnv(t)
	cfg := map[string]any{
		"operator_signing_key": seed,
		// A fresh secret per test run gives fresh accounts.
		"account_seed_secret": "integration-" + time.Now().Format(time.RFC3339Nano),
		"resolver":            map[string]any{"mode": "nats", "urls": []any{url}, "credentials_file": creds},
	}
	if op := os.Getenv("TENARIUM_TEST_NATS_OPERATOR_JWT"); op != "" {
		cfg["operator_jwt"] = op
	}
	for k, v := range extra {
		cfg[k] = v
	}
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}
	return p, reg
}

// connectAsTenant connects with a user JWT signed by the tenant's derived
// account key, as an application would.
func connectAsTenant(t *testing.T, p *Plugin, tenantID string, opts ...nats.Option) (*nats.Conn, error) {
	t.Helper()
	url, _, _ := natsEnv(t)
	akp, err := AccountKeyPair(p.cfg.AccountSeedSecret, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := nkeys.CreateUser()
	upub, _ := u.PublicKey()
	useed, _ := u.Seed()
	uc := jwt.NewUserClaims(upub)
	uc.Name = "app"
	tok, err := uc.Encode(akp)
	if err != nil {
		t.Fatal(err)
	}
	opts = append([]nats.Option{
		nats.UserJWTAndSeed(tok, string(useed)), nats.MaxReconnects(0), nats.Timeout(3 * time.Second),
		nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}),
	}, opts...)
	return nats.Connect(url, opts...)
}

// waitFor polls cond for a few seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestIntegrationProvisionAndConnect(t *testing.T) {
	ctx := context.Background()
	p, reg := newNATSPlugin(t, map[string]any{
		"limits":         map[string]any{"conn": "connections", "streams": "streams"},
		"jetstream":      true,
		"on_deprovision": "disable",
	})
	reg.HostImpl.AddPlan(sdk.Plan{ID: "small", Limits: map[string]int64{"connections": 1, "streams": 2}})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "small"})

	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatalf("second provision: %v", err)
	}

	// The resolver holds the JWT, visible through the route.
	req := httptest.NewRequest(http.MethodGet, "/tenants/acme", nil)
	req = req.WithContext(sdk.WithPrincipal(req.Context(), &sdk.Principal{Subject: "admin", Kind: "user"}))
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	var info TenantInfo
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if rec.Code != http.StatusOK || !info.Provisioned {
		t.Fatalf("route %d %s", rec.Code, rec.Body)
	}
	ac, err := jwt.DecodeAccountClaims(info.AccountJWT)
	if err != nil || ac.Limits.Conn != 1 || ac.Limits.Streams != 2 || !ac.Tags.Contains(TenantTag(tn.ID)) {
		t.Fatalf("stored claims %+v %v", ac, err)
	}

	// An application can connect and use the account.
	nc, err := connectAsTenant(t, p, tn.ID)
	if err != nil {
		t.Fatalf("connect as tenant: %v", err)
	}
	defer nc.Close()
	sub, err := nc.SubscribeSync("hello")
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Publish("hello", []byte("world")); err != nil {
		t.Fatal(err)
	}
	if m, err := sub.NextMsg(3 * time.Second); err != nil || string(m.Data) != "world" {
		t.Fatalf("message %v %v", m, err)
	}
	js, err := nc.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AccountInfo(); err != nil {
		t.Fatalf("JetStream not enabled: %v", err)
	}

	// The connection limit is enforced.
	if nc2, err := connectAsTenant(t, p, tn.ID); err == nil {
		nc2.Close()
		t.Fatal("second connection accepted despite conn limit 1")
	}

	// Disabling drops the connection and refuses new ones.
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "connection to be dropped", func() bool { return !nc.IsConnected() })
	if nc3, err := connectAsTenant(t, p, tn.ID); err == nil {
		nc3.Close()
		t.Fatal("connection accepted to a disabled account")
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatalf("second deprovision: %v", err)
	}
}

func TestIntegrationDelete(t *testing.T) {
	ctx := context.Background()
	p, reg := newNATSPlugin(t, map[string]any{"on_deprovision": "delete"})
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "doomed"})
	// Deprovisioning a never-provisioned tenant is a no-op.
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	nc, err := connectAsTenant(t, p, tn.ID)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer nc.Close()
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	pub, _ := TenantAccountPublicKey(p.cfg.AccountSeedSecret, tn.ID)
	cur, _, err := p.current(ctx, pub)
	if err != nil {
		t.Fatal(err)
	}
	if cur != nil && !cur.Tags.Contains(TagDisabled) {
		t.Fatalf("account neither deleted nor disabled: %v", cur.Tags)
	}
	if cur != nil {
		t.Log("resolver refused delete; plugin disabled the account instead")
	}
	waitFor(t, "connection to be dropped", func() bool { return !nc.IsConnected() })
	if nc2, err := connectAsTenant(t, p, tn.ID); err == nil {
		nc2.Close()
		t.Fatal("connection accepted to a deleted account")
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatalf("second deprovision: %v", err)
	}
}

func TestIntegrationOwnership(t *testing.T) {
	ctx := context.Background()
	p, reg := newNATSPlugin(t, nil)
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "contested"})
	pub, _ := TenantAccountPublicKey(p.cfg.AccountSeedSecret, tn.ID)

	foreign := jwt.NewAccountClaims(pub)
	foreign.Name = "foreign"
	foreign.Tags.Add(TenantTag("someone-else"))
	tok, err := foreign.Encode(p.signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.res.Push(ctx, pub, tok); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, tn); !errors.Is(err, errForeign) {
		t.Fatalf("provision over foreign account: %v", err)
	}
	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	cur, _, err := p.current(ctx, pub)
	if err != nil || cur == nil || cur.Name != "foreign" {
		t.Fatalf("foreign account touched: %v %v", cur, err)
	}
	// Clean up the foreign account directly.
	if err := p.deleteAccount(ctx, pub); err != nil && !strings.Contains(err.Error(), "delete") {
		t.Fatal(err)
	}
}
