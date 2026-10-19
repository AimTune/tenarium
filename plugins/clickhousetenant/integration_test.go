package clickhousetenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// Integration tests run against a ClickHouse server whose HTTP interface is
// named by TENARIUM_TEST_CLICKHOUSE_URL (e.g. http://localhost:8123). The
// admin account comes from TENARIUM_TEST_CLICKHOUSE_USER (default
// "default") and TENARIUM_TEST_CLICKHOUSE_PASSWORD and must have access
// management, e.g. the clickhouse/clickhouse-server image started with
// CLICKHOUSE_USER, CLICKHOUSE_PASSWORD and
// CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1.

func integrationURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TENARIUM_TEST_CLICKHOUSE_URL")
	if u == "" {
		t.Skip("TENARIUM_TEST_CLICKHOUSE_URL not set")
	}
	return u
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func newIntegrationPlugin(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	full := map[string]any{
		"url":             integrationURL(t),
		"username":        os.Getenv("TENARIUM_TEST_CLICKHOUSE_USER"),
		"password":        os.Getenv("TENARIUM_TEST_CLICKHOUSE_PASSWORD"),
		"password_secret": "integration-test-secret",
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

// as returns a client authenticated as user.
func (p *Plugin) as(user, password string) *client {
	return &client{url: p.cfg.URL, user: user, password: password, http: &http.Client{Timeout: 30 * time.Second}}
}

func chCode(err error) int {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Code
	}
	return 0
}

func TestIntegrationLifecycle(t *testing.T) {
	ctx := context.Background()
	p, reg := newIntegrationPlugin(t, map[string]any{
		"settings_profile": map[string]any{
			"settings":    map[string]any{"max_execution_time": 60},
			"from_limits": map[string]any{"max_memory_usage": "ch_memory"},
		},
		"quota": map[string]any{
			"interval":    "1 hour",
			"limits":      map[string]any{"queries": 10000},
			"from_limits": map[string]any{"read_bytes": "ch_read_bytes"},
		},
	})
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"ch_memory": 2000000000, "ch_read_bytes": 1 << 30}})
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "it-" + randSuffix(t), Plan: "pro"})
	other := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "it-" + randSuffix(t)})
	t.Cleanup(func() {
		_ = p.Deprovision(context.Background(), ten)
		_ = p.Deprovision(context.Background(), other)
	})
	tg, _ := p.target(ten)
	og, _ := p.target(other)

	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	if err := p.Provision(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, comment, err := p.databaseComment(ctx, tg.Database); err != nil || comment != ownerMark(ten) {
		t.Fatalf("comment %q, %v", comment, err)
	}

	// The tenant user logs in and works in its own database only.
	tc := p.as(tg.User, TenantPassword("integration-test-secret", ten.ID))
	if _, err := tc.exec(ctx, "CREATE TABLE events (id UInt64, at DateTime) ENGINE = MergeTree ORDER BY id", nil); err != nil {
		t.Fatalf("create table in own (default) database: %v", err)
	}
	if _, err := tc.exec(ctx, "INSERT INTO "+quoteIdent(tg.Database)+".events VALUES (1, now())", nil); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if body, err := tc.exec(ctx, "SELECT count() FROM events", nil); err != nil || strings.TrimSpace(string(body)) != "1" {
		t.Fatalf("select: %q %v", body, err)
	}
	if _, err := tc.exec(ctx, "CREATE TABLE "+quoteIdent(og.Database)+".x (id UInt64) ENGINE = MergeTree ORDER BY id", nil); chCode(err) != 497 {
		t.Fatalf("create table in other tenant's database: want ACCESS_DENIED (497), got %v", err)
	}
	if _, err := tc.exec(ctx, "CREATE TABLE default.x (id UInt64) ENGINE = MergeTree ORDER BY id", nil); chCode(err) != 497 {
		t.Fatalf("create table in default: want 497, got %v", err)
	}
	if _, err := tc.exec(ctx, "DROP DATABASE "+quoteIdent(tg.Database), nil); chCode(err) != 497 {
		t.Fatalf("drop own database: want 497, got %v", err)
	}
	_, err := tc.exec(ctx, "ALTER DATABASE "+quoteIdent(tg.Database)+" MODIFY COMMENT 'x'", nil)
	if c := chCode(err); c != 497 && c != codeSyntaxError {
		t.Fatalf("modify marker: want ACCESS_DENIED (or SYNTAX_ERROR on servers without MODIFY COMMENT), got %v", err)
	}
	// Settings come from the profile and are locked.
	if body, err := tc.exec(ctx, "SELECT getSetting('max_memory_usage')", nil); err != nil || strings.TrimSpace(string(body)) != "2000000000" {
		t.Fatalf("max_memory_usage = %q, %v", body, err)
	}
	if _, err := tc.exec(ctx, "SELECT 1 SETTINGS max_memory_usage = 1", nil); err == nil {
		t.Fatal("locked setting changed")
	}
	// The quota applies to the user, with the entitlement limit.
	if exists, to, err := p.appliesTo(ctx, "system.quotas", tg.User); err != nil || !exists || len(to) != 1 || to[0] != tg.User {
		t.Fatalf("quota applies to %v (exists %v), %v", to, exists, err)
	}
	body, err := p.ch.exec(ctx, "SELECT max_read_bytes, max_queries FROM system.quota_limits WHERE quota_name = {n:String} FORMAT TSV", map[string]string{"n": tg.User})
	if err != nil || strings.TrimSpace(string(body)) != "1073741824\t10000" {
		t.Fatalf("quota limits %q, %v", body, err)
	}
	// A wrong password is rejected.
	if _, err := p.as(tg.User, "wrong").exec(ctx, "SELECT 1", nil); chCode(err) != 516 {
		t.Fatalf("wrong password: %v", err)
	}

	// Rotation: a new secret changes the password.
	p.cfg.PasswordSecret = "integration-test-secret-rotated"
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if _, err := tc.exec(ctx, "SELECT 1", nil); chCode(err) != 516 {
		t.Fatalf("old password still works: %v", err)
	}
	tc = p.as(tg.User, TenantPassword("integration-test-secret-rotated", ten.ID))
	if _, err := tc.exec(ctx, "SELECT 1", nil); err != nil {
		t.Fatalf("new password: %v", err)
	}

	// Another tenant whose name collides cannot adopt the database.
	thief := sdk.Tenant{ID: "thief", Slug: ten.Slug}
	if err := p.Provision(ctx, thief); err == nil || !strings.Contains(err.Error(), "someone else") {
		t.Fatalf("thief: %v", err)
	}
	if err := p.Deprovision(ctx, thief); err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := p.databaseComment(ctx, tg.Database); !exists {
		t.Fatal("thief dropped the database")
	}

	// Delete drops everything; the user can no longer log in.
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if exists, _, _ := p.databaseComment(ctx, tg.Database); exists {
		t.Fatal("database not dropped")
	}
	for _, table := range []string{"system.quotas", "system.settings_profiles"} {
		if exists, _, err := p.appliesTo(ctx, table, tg.User); err != nil || exists {
			t.Fatalf("%s left: %v", table, err)
		}
	}
	if _, err := tc.exec(ctx, "SELECT 1", nil); chCode(err) != 516 {
		t.Fatalf("dropped user can log in: %v", err)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatalf("second deprovision: %v", err)
	}
}

func TestIntegrationAdoptAndRetain(t *testing.T) {
	ctx := context.Background()
	p, reg := newIntegrationPlugin(t, map[string]any{"on_deprovision": "retain", "grants": []any{"SELECT", "INSERT", "CREATE TABLE"}})
	if !supportsModifyComment(t, p) {
		t.Skip("server does not support ALTER DATABASE ... MODIFY COMMENT (needed for adoption and retain)")
	}
	ten := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "it-" + randSuffix(t)})
	tg, _ := p.target(ten)
	t.Cleanup(func() {
		_, _ = p.ch.exec(context.Background(), "DROP DATABASE IF EXISTS "+quoteIdent(tg.Database)+" SYNC", nil)
		_, _ = p.ch.exec(context.Background(), "DROP USER IF EXISTS "+quoteIdent(tg.User), nil)
	})

	// An unmarked, non-empty database is refused; once empty it is adopted.
	if _, err := p.ch.exec(ctx, "CREATE DATABASE "+quoteIdent(tg.Database), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ch.exec(ctx, "CREATE TABLE "+quoteIdent(tg.Database)+".t (id UInt64) ENGINE = MergeTree ORDER BY id", nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, ten); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("unmarked non-empty: %v", err)
	}
	if _, err := p.ch.exec(ctx, "DROP TABLE "+quoteIdent(tg.Database)+".t SYNC", nil); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, ten); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if _, comment, _ := p.databaseComment(ctx, tg.Database); comment != ownerMark(ten) {
		t.Fatalf("not claimed: %q", comment)
	}
	tc := p.as(tg.User, TenantPassword("integration-test-secret", ten.ID))
	if _, err := tc.exec(ctx, "CREATE TABLE keep (id UInt64) ENGINE = MergeTree ORDER BY id", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tc.exec(ctx, "DROP TABLE keep", nil); chCode(err) != 497 {
		t.Fatalf("custom grants not applied: %v", err)
	}

	// Retain keeps the data, releases ownership and removes access.
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	exists, comment, err := p.databaseComment(ctx, tg.Database)
	if err != nil || !exists || !strings.HasPrefix(comment, "tenarium:deleted-tenant="+ten.ID+" deleted-at=") {
		t.Fatalf("retained: %v %q %v", exists, comment, err)
	}
	if empty, _ := p.databaseEmpty(ctx, tg.Database); empty {
		t.Fatal("retained data lost")
	}
	if _, err := tc.exec(ctx, "SELECT 1", nil); chCode(err) != 516 {
		t.Fatalf("user not dropped: %v", err)
	}
	if err := p.Deprovision(ctx, ten); err != nil {
		t.Fatal(err)
	}
	if err := p.Provision(ctx, ten); err == nil || !strings.Contains(err.Error(), "retained") {
		t.Fatalf("re-provision over retained data: %v", err)
	}
}

// supportsModifyComment probes ALTER DATABASE ... MODIFY COMMENT on a
// scratch database.
func supportsModifyComment(t *testing.T, p *Plugin) bool {
	t.Helper()
	ctx := context.Background()
	db := "tenarium_probe_" + randSuffix(t)
	if _, err := p.ch.exec(ctx, "CREATE DATABASE "+quoteIdent(db), nil); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = p.ch.exec(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(db)+" SYNC", nil) }()
	err := p.setComment(ctx, db, "probe")
	if chCode(err) == codeSyntaxError {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}
