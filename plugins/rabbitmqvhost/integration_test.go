package rabbitmqvhost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// Integration tests run against a RabbitMQ Management API named by
// TENARIUM_TEST_RABBITMQ_URL (e.g. http://localhost:15672). Credentials
// default to guest/guest and can be overridden with
// TENARIUM_TEST_RABBITMQ_USER / TENARIUM_TEST_RABBITMQ_PASSWORD.

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func randHex(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func newIntegrationPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	u := os.Getenv("TENARIUM_TEST_RABBITMQ_URL")
	if u == "" {
		t.Skip("TENARIUM_TEST_RABBITMQ_URL not set")
	}
	full := map[string]any{
		"url":             u,
		"username":        envOr("TENARIUM_TEST_RABBITMQ_USER", "guest"),
		"password":        envOr("TENARIUM_TEST_RABBITMQ_PASSWORD", "guest"),
		"password_secret": testSecret,
	}
	for k, v := range cfg {
		full[k] = v
	}
	reg := sdktest.NewRegistrar(full)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}
	return p, reg
}

// cleanup removes the tenant's vhost and user at the end of the test.
func cleanup(t *testing.T, p *Plugin, tg target) {
	t.Cleanup(func() {
		ctx := context.Background()
		_ = p.api.deleteIgnoreMissing(ctx, "/api/users/"+esc(tg.User))
		_ = p.api.deleteIgnoreMissing(ctx, "/api/vhosts/"+esc(tg.Vhost))
	})
}

// canLogin checks the tenant credentials against the management API's
// authentication endpoint (GET /api/whoami needs the management tag).
func canLogin(t *testing.T, p *Plugin, user, pass string) bool {
	t.Helper()
	c := *p.api
	c.user, c.pass = user, pass
	err := c.do(context.Background(), http.MethodGet, "/api/whoami", nil, nil)
	if err == nil {
		return true
	}
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
		return false
	}
	t.Fatalf("whoami: %v", err)
	return false
}

func TestIntegrationProvisionLifecycle(t *testing.T) {
	p, reg := newIntegrationPlugin(t, map[string]any{
		"user_tags":          []any{"management"},
		"default_queue_type": "quorum",
		"permissions":        map[string]any{"configure": "^tenant\\..*"},
		"limits":             map[string]any{"max-connections": "amqp_connections", "max-queues": "amqp_queues"},
	})
	ctx := context.Background()
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"amqp_connections": 7, "amqp_queues": 9}})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "it-" + randHex(t), Plan: "pro"})
	tg, err := p.target(ten)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(t, p, tg)

	for range 2 {
		if err := p.Provision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	vh, err := p.api.getVhost(ctx, tg.Vhost)
	if err != nil || vh == nil {
		t.Fatalf("vhost %v %v", vh, err)
	}
	if !slices.Contains(vh.tags(), TagTenantID+ten.ID) || vh.DefaultQueueType != "quorum" {
		t.Fatalf("vhost %+v", vh)
	}
	u, err := p.api.getUser(ctx, tg.User)
	if err != nil || u == nil || !slices.Contains(u.Tags, TagTenantID+ten.ID) || !slices.Contains(u.Tags, "management") {
		t.Fatalf("user %+v %v", u, err)
	}
	var perm permissionBody
	if err := p.api.do(ctx, http.MethodGet, "/api/permissions/"+esc(tg.Vhost)+"/"+esc(tg.User), nil, &perm); err != nil {
		t.Fatal(err)
	}
	if perm != (permissionBody{Configure: "^tenant\\..*", Write: ".*", Read: ".*"}) {
		t.Fatalf("perm %+v", perm)
	}
	var limits []struct {
		Value map[string]int64 `json:"value"`
	}
	if err := p.api.do(ctx, http.MethodGet, "/api/vhost-limits/"+esc(tg.Vhost), nil, &limits); err != nil {
		t.Fatal(err)
	}
	if len(limits) != 1 || limits[0].Value["max-connections"] != 7 || limits[0].Value["max-queues"] != 9 {
		t.Fatalf("limits %+v", limits)
	}
	if !canLogin(t, p, tg.User, TenantPassword(testSecret, ten.ID)) {
		t.Fatal("tenant cannot log in with derived password")
	}
	if canLogin(t, p, tg.User, "wrong") {
		t.Fatal("wrong password accepted")
	}

	// Unlimited: limits are removed.
	ten.Plan = ""
	reg.HostImpl.AddTenant(ten)
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	limits = nil
	if err := p.api.do(ctx, http.MethodGet, "/api/vhost-limits/"+esc(tg.Vhost), nil, &limits); err != nil {
		t.Fatal(err)
	}
	if len(limits) != 0 && len(limits[0].Value) != 0 {
		t.Fatalf("limits not removed: %+v", limits)
	}

	// A second tenant mapping to the same names is refused.
	intruder := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "intruder-" + randHex(t)})
	intruder.Slug = ten.Slug
	if err := p.Provision(ctx, intruder); err == nil || !strings.Contains(err.Error(), "belongs to tenant") {
		t.Fatalf("intruder: %v", err)
	}
	if err := p.Deprovision(ctx, intruder); err != nil {
		t.Fatal(err)
	}
	if vh, _ := p.api.getVhost(ctx, tg.Vhost); vh == nil {
		t.Fatal("intruder deprovision deleted the vhost")
	}

	for range 2 {
		if err := p.Deprovision(ctx, ten); err != nil {
			t.Fatal(err)
		}
	}
	if vh, err := p.api.getVhost(ctx, tg.Vhost); err != nil || vh != nil {
		t.Fatalf("vhost not deleted: %v %v", vh, err)
	}
	if u, err := p.api.getUser(ctx, tg.User); err != nil || u != nil {
		t.Fatalf("user not deleted: %v %v", u, err)
	}
}

func TestIntegrationUnmanagedAndRetain(t *testing.T) {
	p, reg := newIntegrationPlugin(t, map[string]any{"on_deprovision": "retain"})
	ctx := context.Background()

	// An unmarked existing vhost is not adopted.
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "it-" + randHex(t)})
	tg, _ := p.target(ten)
	cleanup(t, p, tg)
	if err := p.api.putVhost(ctx, tg.Vhost, vhostBody{Description: "manual"}); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, ten); err == nil || !strings.Contains(err.Error(), "not managed by tenarium") {
		t.Fatalf("err %v", err)
	}
	if u, _ := p.api.getUser(ctx, tg.User); u != nil {
		t.Fatal("user created despite conflict")
	}

	// Retain keeps the vhost but releases ownership and deletes the user.
	ten2 := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "it-" + randHex(t)})
	tg2, _ := p.target(ten2)
	cleanup(t, p, tg2)
	if err := p.Provision(ctx, ten2); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := p.Deprovision(ctx, ten2); err != nil {
			t.Fatal(err)
		}
	}
	vh, err := p.api.getVhost(ctx, tg2.Vhost)
	if err != nil || vh == nil {
		t.Fatalf("vhost gone: %v", err)
	}
	if ownerID, retained := owner(vh.tags()); ownerID != "" || retained != ten2.ID {
		t.Fatalf("tags %v", vh.tags())
	}
	if u, _ := p.api.getUser(ctx, tg2.User); u != nil {
		t.Fatal("user not deleted")
	}
	if err := p.Provision(ctx, ten2); err == nil || !strings.Contains(err.Error(), "retained data") {
		t.Fatalf("reprovision over retained: %v", err)
	}
}
