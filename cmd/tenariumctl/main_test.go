package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/server"
)

const (
	apiKey       = "ctl-test-key"
	rootEmail    = "root@example.com"
	rootPassword = "root password long enough"
)

var flakyFail atomic.Bool

type flakyPlugin struct{}

func (flakyPlugin) Manifest() sdk.Manifest {
	return sdk.Manifest{ID: "ctltest-flaky", Name: "CLI test flaky", Version: "0"}
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

func init() { sdk.Register("ctltest-flaky", func() sdk.Plugin { return flakyPlugin{} }) }

func baseConfig() server.Config {
	cfg := server.DefaultConfig()
	cfg.Server.APIKeys = []string{apiKey}
	cfg.Events.PollInterval = 20 * time.Millisecond
	cfg.Events.LeaseTTL = time.Second
	cfg.Auth.RateLimit = 0
	cfg.Bootstrap.Users = []server.BootstrapUser{{Email: rootEmail, Password: rootPassword, Roles: []string{"admin"}}}
	return cfg
}

func startServer(t *testing.T, cfg server.Config) string {
	t.Helper()
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

// harness runs tenariumctl in-process with an isolated config directory.
type harness struct {
	t       *testing.T
	env     map[string]string
	baseArg []string
}

func newHarness(t *testing.T, baseArgs ...string) *harness {
	dir := t.TempDir()
	return &harness{t: t, baseArg: baseArgs, env: map[string]string{
		"XDG_CONFIG_HOME": dir, "APPDATA": dir, "HOME": dir,
	}}
}

type result struct {
	code        int
	out, stderr string
}

func (h *harness) runIn(stdin string, args ...string) result {
	h.t.Helper()
	var out, errOut strings.Builder
	code := run(append(append([]string{}, h.baseArg...), args...), strings.NewReader(stdin), &out, &errOut,
		func(k string) string { return h.env[k] })
	return result{code, out.String(), errOut.String()}
}

func (h *harness) run(args ...string) result {
	h.t.Helper()
	return h.runIn("", args...)
}

// ok runs a command that must succeed.
func (h *harness) ok(args ...string) string {
	h.t.Helper()
	r := h.run(args...)
	if r.code != 0 {
		h.t.Fatalf("tenariumctl %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), r.code, r.out, r.stderr)
	}
	return r.out
}

// fails runs a command that must exit with code and mention want on stderr.
func (h *harness) fails(code int, want string, args ...string) {
	h.t.Helper()
	r := h.run(args...)
	if r.code != code || !strings.Contains(r.stderr, want) {
		h.t.Fatalf("tenariumctl %s: exit %d (want %d), stderr %q (want %q)", strings.Join(args, " "), r.code, code, r.stderr, want)
	}
}

func decodeJSON[T any](t *testing.T, s string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return v
}

func (h *harness) configFile() config {
	h.t.Helper()
	p := strings.TrimSpace(h.ok("config", "path"))
	b, err := os.ReadFile(p)
	if err != nil {
		h.t.Fatal(err)
	}
	return decodeJSON[config](h.t, string(b))
}

func TestUsageAndExitCodes(t *testing.T) {
	h := newHarness(t)
	if r := h.run(); r.code != exitUsage || !strings.Contains(r.stderr, "Commands:") {
		t.Fatalf("no args: %+v", r)
	}
	if r := h.run("help"); r.code != 0 || !strings.Contains(r.out, "dead-letters") {
		t.Fatalf("help: %+v", r)
	}
	if r := h.run("tenants", "--help"); r.code != 0 || !strings.Contains(r.out, "entitlements") {
		t.Fatalf("tenants --help: %+v", r)
	}
	if r := h.run("tenants", "create", "--help"); r.code != 0 || !strings.Contains(r.out, "--slug") || strings.Contains(r.out, "--api-key string") {
		t.Fatalf("tenants create --help: %+v", r)
	}
	if r := h.run("help", "users", "invite"); r.code != 0 || !strings.Contains(r.out, "invitation") {
		t.Fatalf("help users invite: %+v", r)
	}
	if r := h.run("--version"); r.code != 0 || !strings.Contains(r.out, version) {
		t.Fatalf("version: %+v", r)
	}
	h.fails(exitUsage, "unknown command", "bogus")
	h.fails(exitUsage, "unknown verb", "tenants", "bogus")
	h.fails(exitUsage, "missing verb", "tenants")
	h.fails(exitUsage, "missing arguments", "tenants", "get")
	h.fails(exitUsage, "unexpected arguments", "tenants", "get", "a", "b")
	h.fails(exitUsage, "flag provided but not defined", "tenants", "list", "--bogus")
	h.fails(exitUsage, "invalid --output", "-o", "yaml", "tenants", "list")
	h.fails(exitUsage, "--slug and --name are required", "tenants", "create", "--slug", "x")
	h.fails(exitUsage, "want key=value", "tenants", "create", "--label", "nope")
	h.fails(exitError, "no server URL", "tenants", "list")
	h.fails(exitError, "invalid base URL", "--url", "localhost:1", "tenants", "list")
}

func TestTenantCommands(t *testing.T) {
	base := startServer(t, baseConfig())
	h := newHarness(t, "--url", base, "--api-key", apiKey)

	if out := h.ok("tenants", "create", "--slug", "acme", "--name", "Acme Inc", "--label", "env=prod", "--settings", `{"theme":"dark"}`); !strings.Contains(out, "acme") || !strings.Contains(out, "env=prod") {
		t.Fatalf("create: %s", out)
	}
	h.ok("tenants", "create", "--slug", "globex", "--name", "Globex")
	h.ok("tenants", "create", "--slug", "ws1", "--name", "Workspace 1", "--parent", "acme")
	h.fails(exitError, "already_exists", "tenants", "create", "--slug", "acme", "--name", "Dup")

	// JSON vs table output; global flags after the verb.
	list := decodeJSON[[]sdk.Tenant](t, h.ok("tenants", "list", "-o", "json"))
	if len(list) != 3 {
		t.Fatalf("list: %+v", list)
	}
	table := h.ok("tenants", "list")
	if !strings.HasPrefix(table, "ID ") || !strings.Contains(table, "SLUG") || strings.Count(table, "\n") != 4 {
		t.Fatalf("table: %q", table)
	}
	if l := decodeJSON[[]sdk.Tenant](t, h.ok("tenants", "list", "--limit", "2", "--output", "json")); len(l) != 2 {
		t.Fatalf("limited list: %d", len(l))
	}
	if l := decodeJSON[[]sdk.Tenant](t, h.ok("tenants", "list", "--label", "env=prod", "-o", "json")); len(l) != 1 || l[0].Slug != "acme" {
		t.Fatalf("label filter: %+v", l)
	}

	acme := decodeJSON[sdk.Tenant](t, h.ok("-o", "json", "tenants", "get", "acme"))
	if acme.Name != "Acme Inc" || acme.Version != 1 || acme.Settings["theme"] != "dark" {
		t.Fatalf("get: %+v", acme)
	}
	if out := h.ok("tenants", "get", "acme"); !strings.Contains(out, "Slug:") || !strings.Contains(out, `{"theme":"dark"}`) {
		t.Fatalf("get table: %s", out)
	}
	upd := decodeJSON[sdk.Tenant](t, h.ok("tenants", "update", "acme", "--name", "Acme Corp", "--if-match", "1", "-o", "json"))
	if upd.Name != "Acme Corp" || upd.Version != 2 {
		t.Fatalf("update: %+v", upd)
	}
	h.fails(exitError, "version_conflict", "tenants", "update", "acme", "--name", "Stale", "--if-match", "1")
	h.fails(exitUsage, "nothing to update", "tenants", "update", "acme")

	if out := h.ok("tenants", "suspend", "acme", "--reason", "unpaid"); !strings.Contains(out, "suspended") || !strings.Contains(out, "unpaid") {
		t.Fatalf("suspend: %s", out)
	}
	h.fails(exitError, "invalid_transition", "tenants", "suspend", "acme")
	if out := h.ok("tenants", "resume", "acme"); !strings.Contains(out, "active") {
		t.Fatalf("resume: %s", out)
	}
	kids := decodeJSON[[]sdk.Tenant](t, h.ok("tenants", "children", "acme", "-o", "json"))
	if len(kids) != 1 || kids[0].Slug != "ws1" {
		t.Fatalf("children: %+v", kids)
	}
	ent := decodeJSON[sdk.Entitlements](t, h.ok("tenants", "entitlements", "acme", "-o", "json"))
	if ent.TenantID != acme.ID {
		t.Fatalf("entitlements: %+v", ent)
	}
	if out := h.ok("tenants", "entitlements", "acme"); !strings.Contains(out, "KIND") {
		t.Fatalf("entitlements table: %s", out)
	}
	if d := decodeJSON[sdk.Tenant](t, h.ok("tenants", "delete", "globex", "-o", "json")); d.IsLive() {
		t.Fatalf("delete: %+v", d)
	}
	h.fails(exitError, "not_found", "tenants", "get", "nope")

	// Credentials from the environment.
	envH := newHarness(t)
	envH.env["TENARIUM_URL"], envH.env["TENARIUM_API_KEY"] = base, apiKey
	if l := decodeJSON[[]sdk.Tenant](t, envH.ok("tenants", "list", "-o", "json", "--include-deleted")); len(l) != 3 {
		t.Fatalf("env credentials: %d", len(l))
	}
	h2 := newHarness(t, "--url", base, "--api-key", "wrong")
	h2.fails(exitError, "unauthorized", "tenants", "list")
}

func TestPlansMembersUsageUsers(t *testing.T) {
	cfg := baseConfig()
	cfg.Bootstrap.Plans = []server.BootstrapPlan{{ID: "free", Limits: map[string]int64{"api_calls": 3}}}
	h := newHarness(t, "--url", startServer(t, cfg), "--api-key", apiKey)

	// Plans.
	if out := h.ok("plans", "create", "--id", "pro", "--name", "Pro", "--feature", "sso", "--quota", "members=50"); !strings.Contains(out, "members=50") || !strings.Contains(out, "sso") {
		t.Fatalf("plan create: %s", out)
	}
	if ps := decodeJSON[[]sdk.Plan](t, h.ok("plans", "list", "-o", "json")); len(ps) != 2 {
		t.Fatalf("plans: %+v", ps)
	}
	p := decodeJSON[sdk.Plan](t, h.ok("plans", "update", "pro", "--description", "Teams", "--if-match", "1", "-o", "json"))
	if p.Description != "Teams" || p.Version != 2 {
		t.Fatalf("plan update: %+v", p)
	}
	h.fails(exitError, "version_conflict", "plans", "update", "pro", "--name", "x", "--if-match", "1")
	if g := decodeJSON[sdk.Plan](t, h.ok("plans", "get", "pro", "-o", "json")); g.Limits["members"] != 50 {
		t.Fatalf("plan get: %+v", g)
	}
	h.ok("plans", "create", "--id", "tmp", "--name", "Tmp")
	if out := h.ok("plans", "delete", "tmp"); !strings.Contains(out, "Deleted plan tmp") {
		t.Fatalf("plan delete: %s", out)
	}
	h.fails(exitError, "not_found", "plans", "get", "tmp")

	// Members.
	h.ok("tenants", "create", "--slug", "acme", "--name", "Acme", "--plan", "free")
	m := decodeJSON[sdk.Member](t, h.ok("members", "add", "acme", "--email", "ada@example.com", "--role", "viewer", "--name", "Ada", "-o", "json"))
	if m.Status != sdk.MemberInvited {
		t.Fatalf("member add: %+v", m)
	}
	if out := h.ok("members", "list", "acme"); !strings.Contains(out, "ada@example.com") || !strings.Contains(out, "Roles:") {
		t.Fatalf("members list: %s", out)
	}
	if u := decodeJSON[sdk.Member](t, h.ok("members", "set-role", "acme", "ada@example.com", "admin", "-o", "json")); u.Role != "admin" {
		t.Fatalf("set-role: %+v", u)
	}
	h.fails(exitError, "not a member", "members", "remove", "acme", "nobody@example.com")
	h.fails(exitUsage, "--role", "members", "add", "acme", "--email", "x@example.com")
	h.ok("members", "remove", "acme", "ada@example.com")
	if l := decodeJSON[client.MemberList](t, h.ok("members", "list", "acme", "-o", "json")); len(l.Items) != 0 {
		t.Fatalf("members after remove: %+v", l.Items)
	}

	// Usage and quotas.
	if it := decodeJSON[client.UsageItem](t, h.ok("usage", "record", "acme", "api_calls", "2", "-o", "json")); it.Value != 2 {
		t.Fatalf("record: %+v", it)
	}
	h.fails(exitError, "quota_exceeded", "usage", "record", "acme", "api_calls", "5")
	h.ok("usage", "record", "acme", "api_calls", "--delta", "-1")
	if out := h.ok("usage", "get", "acme"); !strings.Contains(out, "api_calls") || !strings.Contains(out, "unlimited") && !strings.Contains(out, "3") {
		t.Fatalf("usage get: %s", out)
	}
	items := decodeJSON[[]client.UsageItem](t, h.ok("usage", "get", "acme", "-o", "json"))
	for _, it := range items {
		if it.Metric == "api_calls" && (it.Value != 1 || it.Limit == nil || *it.Limit != 3) {
			t.Fatalf("usage: %+v", it)
		}
	}

	// Users.
	r := h.runIn("bob's long passphrase\n", "users", "create", "--email", "bob@example.com", "--name", "Bob", "--password-stdin", "-o", "json")
	if r.code != 0 {
		t.Fatalf("user create: %+v", r)
	}
	bob := decodeJSON[sdk.User](t, r.out)
	if bob.Status != sdk.UserActive {
		t.Fatalf("user create: %+v", bob)
	}
	if out := h.ok("users", "list"); !strings.Contains(out, "bob@example.com") || !strings.Contains(out, "ada@example.com") {
		t.Fatalf("users list: %s", out)
	}
	if l := decodeJSON[[]sdk.User](t, h.ok("users", "list", "--q", "bob", "-o", "json")); len(l) != 1 {
		t.Fatalf("users search: %+v", l)
	}
	if u := decodeJSON[sdk.User](t, h.ok("users", "disable", "bob@example.com", "-o", "json")); u.Status != sdk.UserDisabled {
		t.Fatalf("disable: %+v", u)
	}
	if u := decodeJSON[sdk.User](t, h.ok("users", "enable", bob.ID, "-o", "json")); u.Status != sdk.UserActive {
		t.Fatalf("enable: %+v", u)
	}
	if r := h.runIn("bob's newer passphrase\n", "users", "set-password", "bob@example.com"); r.code != 0 || !strings.Contains(r.out, "Password set") {
		t.Fatalf("set-password: %+v", r)
	}
	h.fails(exitError, "empty password", "users", "set-password", "bob@example.com")
	if u := decodeJSON[sdk.User](t, h.ok("users", "get", "bob@example.com", "-o", "json")); u.Name != "Bob" {
		t.Fatalf("get: %+v", u)
	}
	if out := h.ok("users", "invite", "ada@example.com"); !strings.Contains(out, "Invitation sent") {
		t.Fatalf("resend invite: %s", out)
	}
	if u := decodeJSON[sdk.User](t, h.ok("users", "invite", "carol@example.com", "--name", "Carol", "-o", "json")); u.Status != sdk.UserInvited {
		t.Fatalf("invite new: %+v", u)
	}
	h.fails(exitError, "invalid_transition", "users", "invite", "bob@example.com")
	h.ok("users", "delete", "bob@example.com")
	h.fails(exitError, "not_found", "users", "get", "bob@example.com")
}

func TestLoginAndProfiles(t *testing.T) {
	cfg := baseConfig()
	cfg.Auth.Tokens.AccessTTL = 2 * time.Second
	base := startServer(t, cfg)
	h := newHarness(t)

	h.fails(exitUsage, "--url is required", "login", "--email", rootEmail)
	if r := h.runIn("wrong password\n", "login", "--url", base, "--email", rootEmail, "--password-stdin"); r.code != exitError || !strings.Contains(r.stderr, "invalid_credentials") {
		t.Fatalf("bad login: %+v", r)
	}
	if r := h.runIn(rootPassword+"\n", "login", "--url", base, "--email", rootEmail, "--password-stdin"); r.code != 0 || !strings.Contains(r.out, `profile "default"`) {
		t.Fatalf("login: %+v", r)
	}
	// Non-terminal stdin is read without --password-stdin too.
	if r := h.runIn(rootPassword+"\n", "login", "--url", base, "--email", rootEmail); r.code != 0 {
		t.Fatalf("login from piped stdin: %+v", r)
	}

	// The config lives under the injected config dir.
	path := strings.TrimSpace(h.ok("config", "path"))
	if !strings.HasPrefix(path, h.env["APPDATA"]) || filepath.Base(path) != "config.json" || filepath.Base(filepath.Dir(path)) != "tenarium" {
		t.Fatalf("config path: %s", path)
	}
	c := h.configFile()
	prof := c.Profiles["default"]
	if c.CurrentProfile != "default" || prof == nil || prof.URL != base || prof.Tokens == nil || prof.Tokens.RefreshToken == "" {
		t.Fatalf("config: %+v", c)
	}

	me := decodeJSON[sdk.Principal](t, h.ok("me", "-o", "json"))
	if me.Authenticator != "core/token" {
		t.Fatalf("me: %+v", me)
	}

	// The 2s access token is refreshed automatically and the rotated refresh
	// token is saved.
	time.Sleep(1200 * time.Millisecond)
	h.ok("tenants", "list")
	if c2 := h.configFile(); c2.Profiles["default"].Tokens.RefreshToken == prof.Tokens.RefreshToken {
		t.Fatal("refresh token not rotated in config")
	}
	h.ok("me")

	// A second profile with an API key becomes current.
	if out := h.ok("--profile", "ci", "login", "--url", base, "--api-key", apiKey); !strings.Contains(out, "api-key-0") {
		t.Fatalf("api key login: %s", out)
	}
	h.fails(exitError, "unauthorized", "--profile", "bad", "login", "--url", base, "--api-key", "nope")
	if me := decodeJSON[sdk.Principal](t, h.ok("me", "-o", "json")); me.Kind != "service" {
		t.Fatalf("ci profile: %+v", me)
	}
	list := h.ok("config", "list")
	if !regexp.MustCompile(`(?m)^\*\s+ci\s`).MatchString(list) || !strings.Contains(list, "user "+rootEmail) || !strings.Contains(list, "api-key") {
		t.Fatalf("config list: %s", list)
	}
	h.ok("config", "use-profile", "default")
	if me := decodeJSON[sdk.Principal](t, h.ok("me", "-o", "json")); me.Authenticator != "core/token" {
		t.Fatalf("back to default: %+v", me)
	}
	// --profile and TENARIUM_PROFILE select a profile for one command.
	if me := decodeJSON[sdk.Principal](t, h.ok("--profile", "ci", "me", "-o", "json")); me.Kind != "service" {
		t.Fatalf("--profile: %+v", me)
	}
	h.env["TENARIUM_PROFILE"] = "ci"
	if me := decodeJSON[sdk.Principal](t, h.ok("me", "-o", "json")); me.Kind != "service" {
		t.Fatalf("TENARIUM_PROFILE: %+v", me)
	}
	delete(h.env, "TENARIUM_PROFILE")
	h.fails(exitError, "does not exist", "config", "use-profile", "nope")

	// Logout revokes the session and forgets the tokens.
	refresh := h.configFile().Profiles["default"].Tokens.RefreshToken
	if out := h.ok("logout"); !strings.Contains(out, "Logged out") {
		t.Fatalf("logout: %s", out)
	}
	if h.configFile().Profiles["default"].Tokens != nil {
		t.Fatal("tokens kept after logout")
	}
	pub, _ := client.New(base)
	if _, err := pub.Auth.Refresh(context.Background(), refresh); err == nil {
		t.Fatal("refresh token still valid after logout")
	}
	h.fails(exitError, "unauthorized", "me")
	h.fails(exitError, "no stored credentials", "logout")
	h.ok("config", "delete-profile", "ci")
	if cl := decodeJSON[[]map[string]any](t, h.ok("config", "list", "-o", "json")); len(cl) != 1 {
		t.Fatalf("profiles after delete: %+v", cl)
	}
}

func TestEventsDeadLettersPlugins(t *testing.T) {
	flakyFail.Store(true)
	defer flakyFail.Store(false)
	cfg := baseConfig()
	cfg.Plugins = []server.PluginSpec{{Plugin: "ctltest-flaky"}}
	h := newHarness(t, "--url", startServer(t, cfg), "--api-key", apiKey)

	h.ok("tenants", "create", "--slug", "acme", "--name", "Acme")
	h.ok("tenants", "suspend", "acme")
	h.ok("tenants", "create", "--slug", "globex", "--name", "Globex")

	evs := decodeJSON[[]sdk.Event](t, h.ok("events", "list", "--type", "tenant.created", "-o", "json"))
	if len(evs) != 2 {
		t.Fatalf("events: %+v", evs)
	}
	if evs := decodeJSON[[]sdk.Event](t, h.ok("events", "list", "--tenant", "acme", "-o", "json")); len(evs) != 2 {
		t.Fatalf("tenant events: %+v", evs)
	}
	if out := h.ok("events", "list", "--type", "tenant.*", "--limit", "1"); strings.Count(out, "\n") != 2 || !strings.Contains(out, "tenant.created") {
		t.Fatalf("events table: %q", out)
	}

	out := h.ok("events", "tail", "--from-start", "--type", "tenant.created", "--max", "2", "--interval", "20ms", "-o", "json")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || decodeJSON[sdk.Event](t, lines[1]).Seq != evs[1].Seq {
		t.Fatalf("tail json: %q", out)
	}
	// Tailing from the end shows only new events.
	done := make(chan result, 1)
	go func() { done <- h.run("events", "tail", "--max", "1", "--interval", "20ms", "--timeout", "10s") }()
	time.Sleep(300 * time.Millisecond)
	h.ok("tenants", "resume", "acme")
	r := <-done
	if r.code != 0 || !strings.Contains(r.out, "tenant.resumed") || strings.Contains(r.out, "tenant.created") {
		t.Fatalf("tail from end: %+v", r)
	}
	if r := h.run("events", "tail", "--timeout", "100ms", "--interval", "20ms"); r.code != 0 {
		t.Fatalf("tail timeout: %+v", r)
	}

	// Dead letters.
	var dls client.DeadLetterList
	deadline := time.Now().Add(5 * time.Second)
	for len(dls.Items) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no dead letters")
		}
		time.Sleep(20 * time.Millisecond)
		dls = decodeJSON[client.DeadLetterList](t, h.ok("dead-letters", "list", "--subscription", "ctltest-flaky/sink", "-o", "json"))
	}
	if out := h.ok("dead-letters", "list"); !strings.Contains(out, "sink down") {
		t.Fatalf("dead letters table: %s", out)
	}
	id1, id2 := dls.Items[0].ID, dls.Items[1].ID
	if out := h.ok("dead-letters", "get", id1); !strings.Contains(out, "Event data:") {
		t.Fatalf("dead letter get: %s", out)
	}
	h.fails(exitError, "could not be replayed", "dead-letters", "replay", id1)
	flakyFail.Store(false)
	res := decodeJSON[[]map[string]string](t, h.ok("dead-letters", "replay", id1, "-o", "json"))
	if res[0]["status"] != "replayed" {
		t.Fatalf("replay: %+v", res)
	}
	h.ok("dead-letters", "discard", id2)
	if l := decodeJSON[client.DeadLetterList](t, h.ok("dead-letters", "list", "-o", "json")); len(l.Items) != 0 {
		t.Fatalf("dead letters left: %+v", l.Items)
	}
	h.fails(exitError, "not_found", "dead-letters", "get", id1)

	if out := h.ok("plugins", "list"); !strings.Contains(out, "ctltest-flaky") || !strings.Contains(out, "1 subscriptions") {
		t.Fatalf("plugins: %s", out)
	}
	if l := decodeJSON[client.PluginList](t, h.ok("plugins", "list", "-o", "json")); len(l.Items) != 1 {
		t.Fatalf("plugins json: %+v", l)
	}
	if out := h.ok("me"); !strings.Contains(out, "service") {
		t.Fatalf("me: %s", out)
	}
}
