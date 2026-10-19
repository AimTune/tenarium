package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func TestLifecycleCommands(t *testing.T) {
	cfg := baseConfig()
	cfg.Tenants.Regions = []string{"eu", "us"}
	h := newHarness(t, "--url", startServer(t, cfg), "--api-key", apiKey)

	h.ok("plans", "create", "--id", "pro", "--name", "Pro", "--quota", "seats=5")
	h.ok("plans", "create", "--id", "seats", "--name", "Seats", "--quota", "seats=5")
	tpl := filepath.Join(t.TempDir(), "agency.json")
	if err := os.WriteFile(tpl, []byte(`{"name":"Agency","plan":"pro","roles":[{"name":"auditor","actions":["tenants:read"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.ok("templates", "put", "agency", "--file", tpl)
	if out := h.ok("templates", "list"); !strings.Contains(out, "agency") {
		t.Fatalf("templates: %s", out)
	}
	tn := decodeJSON[sdk.Tenant](t, h.ok("-o", "json", "tenants", "create", "--slug", "acme", "--name", "Acme",
		"--template", "agency", "--region", "eu", "--add-on", "seats"))
	if tn.Plan != "pro" || tn.Region != "eu" || len(tn.AddOns) != 1 {
		t.Fatalf("create: %+v", tn)
	}
	h.ok("plans", "update", "pro", "--quota", "seats=3", "--grandfather")
	if out := h.ok("plans", "revisions", "pro"); strings.Count(out, "\n") != 3 {
		t.Fatalf("revisions: %q", out)
	}
	if out := h.ok("tenants", "get", "acme"); !strings.Contains(out, "Plan revision:") || !strings.Contains(out, "Region:") {
		t.Fatalf("get: %s", out)
	}
	h.ok("tenants", "pin-revision", "acme", "--revision", "0")
	h.ok("tenants", "update", "acme", "--clear-add-ons", "--billing-anchor", "2026-01-31T00:00:00Z")

	h.ok("rollouts", "set", "beta", "--percent", "100", "--region", "us")
	if out := h.ok("rollouts", "list"); !strings.Contains(out, "beta") {
		t.Fatalf("rollouts: %s", out)
	}
	if moved := decodeJSON[sdk.Tenant](t, h.ok("-o", "json", "tenants", "move", "acme", "--region", "us")); moved.Region != "us" {
		t.Fatalf("move: %+v", moved)
	}
	h.ok("rollouts", "delete", "beta")

	if out := h.ok("tenants", "maintenance", "acme", "start", "--message", "upgrade", "--for", "1h"); !strings.Contains(out, "upgrade") {
		t.Fatalf("maintenance: %s", out)
	}
	h.ok("tenants", "maintenance", "acme", "end")
	if out := h.ok("tenants", "health", "acme"); !strings.Contains(out, "Score:") {
		t.Fatalf("health: %s", out)
	}
	if cl := decodeJSON[sdk.Tenant](t, h.ok("-o", "json", "tenants", "clone", "acme", "--slug", "acme-2", "--name", "Acme 2")); cl.Plan != "pro" {
		t.Fatalf("clone: %+v", cl)
	}
	h.ok("templates", "delete", "agency")
}
