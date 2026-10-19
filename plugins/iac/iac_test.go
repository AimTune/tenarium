package iac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// fakeRunner records commands and answers them with handle.
type fakeRunner struct {
	mu     sync.Mutex
	calls  []Command
	handle func(ctx context.Context, c Command) (RunResult, error)
}

func (f *fakeRunner) Run(ctx context.Context, c Command) (RunResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	h := f.handle
	f.mu.Unlock()
	if h == nil {
		return RunResult{}, nil
	}
	return h(ctx, c)
}

func (f *fakeRunner) Calls() []Command {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeRunner) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// subcommands returns the first argument of each call.
func subcommands(calls []Command) []string {
	var out []string
	for _, c := range calls {
		out = append(out, strings.Join(firstWords(c.Args), " "))
	}
	return out
}

func firstWords(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") || len(out) == 2 {
			break
		}
		out = append(out, a)
	}
	return out
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

var fakeEnviron = []string{
	"PATH=/usr/bin", "HOME=/home/tenarium",
	"AWS_ACCESS_KEY_ID=AKIA", "AWS_SECRET_ACCESS_KEY=secret",
	"DATABASE_PASSWORD=do-not-leak", "TF_LOG=debug",
}

type env struct {
	p      *Plugin
	reg    *sdktest.Registrar
	runner *fakeRunner
}

func setup(t *testing.T, cfg map[string]any) *env {
	t.Helper()
	e, err := trySetup(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func trySetup(cfg map[string]any) (*env, error) {
	runner := &fakeRunner{}
	p := New(runner, nil)
	p.environ = func() []string { return slices.Clone(fakeEnviron) }
	p.lookPath = func(s string) (string, error) {
		if s == "missing" {
			return "", errors.New("executable file not found")
		}
		return "/bin/" + s, nil
	}
	p.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	reg := sdktest.NewRegistrar(cfg)
	reg.HostImpl.AddPlan(sdk.Plan{ID: "pro", Limits: map[string]int64{"cpu": 4}, Features: map[string]bool{"sso": true}})
	if err := p.Init(context.Background(), reg); err != nil {
		return nil, err
	}
	return &env{p: p, reg: reg, runner: runner}, nil
}

func (e *env) addTenant(slug string) sdk.Tenant {
	return e.reg.HostImpl.AddTenant(sdk.Tenant{
		Slug: slug, Name: "Acme Corp", Plan: "pro",
		Labels:   map[string]string{"region": "eu"},
		Settings: map[string]any{"color": "blue"},
		Limits:   map[string]int64{"cpu": 8},
		Version:  1,
	})
}

func (e *env) get(t *testing.T, p *sdk.Principal, path string) *httptest.ResponseRecorder {
	t.Helper()
	return serve(e.reg, p, path)
}

func serve(reg *sdktest.Registrar, p *sdk.Principal, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if p != nil {
		req = req.WithContext(sdk.WithPrincipal(req.Context(), p))
	}
	rec := httptest.NewRecorder()
	reg.Mux.ServeHTTP(rec, req)
	return rec
}

// moduleDir writes a small Terraform module.
func moduleDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "main.tf"), `output "x" { value = 1 }`)
	write(t, filepath.Join(dir, "modules", "net", "main.tf"), `# nested`)
	write(t, filepath.Join(dir, "terraform.tfstate"), `{"never":"copied"}`)
	write(t, filepath.Join(dir, ".terraform", "junk"), `x`)
	return dir
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func terraformConfig(t *testing.T) map[string]any {
	return map[string]any{
		"engine":          "terraform",
		"state_dir":       t.TempDir(),
		"env_passthrough": []any{"AWS_*"},
		"env":             map[string]any{"TF_CLI_ARGS_init": "-upgrade=false"},
		"vars": map[string]any{
			"region":   "{{index .Labels \"region\"}}",
			"cpu":      "{{index .Entitlements.Limits \"cpu\"}}",
			"replicas": 3,
			"tags":     map[string]any{"tenant": "{{.Slug}}"},
		},
		"terraform": map[string]any{
			"binary":     "/opt/terraform",
			"module_dir": moduleDir(t),
		},
	}
}

// terraformHandler simulates the CLI: apply writes local state, output
// prints outputs.
func terraformHandler(outputs string) func(ctx context.Context, c Command) (RunResult, error) {
	return func(_ context.Context, c Command) (RunResult, error) {
		switch c.Args[0] {
		case "apply":
			if err := os.WriteFile(filepath.Join(c.Dir, "terraform.tfstate"), []byte(`{"version":4}`), 0o600); err != nil {
				return RunResult{}, err
			}
		case "output":
			return RunResult{Stdout: []byte(outputs)}, nil
		}
		return RunResult{Output: []byte("ok")}, nil
	}
}

const tfOutputs = `{
  "endpoint": {"sensitive": false, "type": "string", "value": "db.acme.internal"},
  "ports": {"sensitive": false, "type": ["list", "number"], "value": [5432, 6432]},
  "password": {"sensitive": true, "type": "string", "value": "hunter2"}
}`

func TestTerraformProvision(t *testing.T) {
	ctx := context.Background()
	cfg := terraformConfig(t)
	e := setup(t, cfg)
	e.runner.handle = terraformHandler(tfOutputs)
	if len(e.reg.Provisioners) != 1 || e.reg.Provisioners[0].Name() != "terraform" {
		t.Fatalf("provisioners = %v", e.reg.Provisioners)
	}
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}

	stateDir := cfg["state_dir"].(string)
	dir := filepath.Join(stateDir, tn.ID)
	calls := e.runner.Calls()
	if got := subcommands(calls); !slices.Equal(got, []string{"init", "apply", "output"}) {
		t.Fatalf("commands = %v", got)
	}
	varsPath := filepath.Join(dir, metaDir, tfVarsFile)
	wantArgs := [][]string{
		{"init", "-input=false", "-no-color"},
		{"apply", "-auto-approve", "-input=false", "-no-color", "-var-file=" + varsPath},
		{"output", "-json", "-no-color"},
	}
	for i, c := range calls {
		if c.Path != "/opt/terraform" || c.Dir != dir || !slices.Equal(c.Args, wantArgs[i]) {
			t.Errorf("call %d = %s in %s, want %v in %s", i, c, c.Dir, wantArgs[i], dir)
		}
		env := envMap(c.Env)
		for k, v := range map[string]string{
			"AWS_ACCESS_KEY_ID": "AKIA", "AWS_SECRET_ACCESS_KEY": "secret", "PATH": "/usr/bin",
			"TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "TF_CLI_ARGS_init": "-upgrade=false",
		} {
			if env[k] != v {
				t.Errorf("call %d: env %s = %q, want %q", i, k, env[k], v)
			}
		}
		for _, k := range []string{"DATABASE_PASSWORD", "TF_LOG"} {
			if _, ok := env[k]; ok {
				t.Errorf("call %d: %s passed through", i, k)
			}
		}
	}

	// The module was copied without its state and .terraform directory.
	if _, err := os.Stat(filepath.Join(dir, "main.tf")); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "modules", "net", "main.tf")); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".terraform", "junk")); err == nil {
		t.Error(".terraform copied from the module")
	}

	var vars map[string]any
	b, err := os.ReadFile(varsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &vars); err != nil {
		t.Fatal(err)
	}
	var ent sdk.Entitlements
	if err := json.Unmarshal([]byte(vars[VarTenantEntitlements].(string)), &ent); err != nil {
		t.Fatal(err)
	}
	if ent.Limits["cpu"] != 8 || !ent.Features["sso"] || ent.Plan != "pro" {
		t.Errorf("entitlements = %+v", ent)
	}
	for k, want := range map[string]any{
		VarTenantID: tn.ID, VarTenantSlug: "acme", VarTenantName: "Acme Corp", VarTenantPlan: "pro",
		VarTenantSettings: `{"color":"blue"}`, "region": "eu", "cpu": "8", "replicas": float64(3),
	} {
		if vars[k] != want {
			t.Errorf("var %s = %#v, want %#v", k, vars[k], want)
		}
	}
	if l := vars[VarTenantLabels].(map[string]any); l["region"] != "eu" {
		t.Errorf("labels = %v", l)
	}
	if tags := vars["tags"].(map[string]any); tags["tenant"] != "acme" {
		t.Errorf("tags = %v", tags)
	}

	// The cached outputs never contain the sensitive value.
	raw, err := os.ReadFile(filepath.Join(dir, metaDir, outputsFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "hunter2") {
		t.Fatalf("sensitive value cached: %s", raw)
	}

	rec := e.get(t, &sdk.Principal{Subject: "admin"}, "/tenants/acme/outputs")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET outputs = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("sensitive value served: %s", rec.Body)
	}
	var resp OutputsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TenantID != tn.ID || resp.Engine != "terraform" || !resp.UpdatedAt.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("response = %+v", resp)
	}
	if resp.Outputs["endpoint"].Value != "db.acme.internal" || resp.Outputs["endpoint"].Sensitive {
		t.Errorf("endpoint = %+v", resp.Outputs["endpoint"])
	}
	if pw := resp.Outputs["password"]; !pw.Sensitive || !pw.Redacted || pw.Value != nil {
		t.Errorf("password = %+v", pw)
	}
	if ports, _ := resp.Outputs["ports"].Value.([]any); len(ports) != 2 {
		t.Errorf("ports = %+v", resp.Outputs["ports"])
	}

	// Another tenant's caller and anonymous callers see nothing.
	other := e.addTenant("other")
	if rec := e.get(t, &sdk.Principal{Subject: "u", TenantID: other.ID}, "/tenants/acme/outputs"); rec.Code != http.StatusNotFound {
		t.Errorf("foreign caller = %d", rec.Code)
	}
	if rec := e.get(t, nil, "/tenants/acme/outputs"); rec.Code != http.StatusNotFound {
		t.Errorf("anonymous caller = %d", rec.Code)
	}
	// A tenant that was not provisioned has no outputs.
	if rec := e.get(t, &sdk.Principal{Subject: "admin"}, "/tenants/other/outputs"); rec.Code != http.StatusNotFound {
		t.Errorf("unprovisioned tenant = %d", rec.Code)
	}
	if rec := e.get(t, &sdk.Principal{Subject: "admin"}, "/tenants/nope/outputs"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown tenant = %d", rec.Code)
	}
}

func TestTerraformRefreshesModule(t *testing.T) {
	ctx := context.Background()
	cfg := terraformConfig(t)
	e := setup(t, cfg)
	e.runner.handle = terraformHandler(`{}`)
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cfg["state_dir"].(string), tn.ID)
	// A file left over from an old module version and provider caches.
	write(t, filepath.Join(dir, "old.tf"), "# removed upstream")
	write(t, filepath.Join(dir, ".terraform", "providers", "p"), "cached")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "old.tf")); err == nil {
		t.Error("stale module file kept")
	}
	for _, keep := range []string{"terraform.tfstate", ".terraform/providers/p", "main.tf"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("%s: %v", keep, err)
		}
	}
}

func TestTerraformRemoteBackendAndSource(t *testing.T) {
	ctx := context.Background()
	state := t.TempDir()
	e := setup(t, map[string]any{
		"engine":    "opentofu",
		"state_dir": state,
		"terraform": map[string]any{
			"module_source":    "git::https://example.com/infra.git//tenant?ref=v1.2.0",
			"plugin_cache_dir": filepath.Join(state, "cache"),
			"backend_config": map[string]any{
				"bucket": "tf-state",
				"key":    "tenants/{{.ID}}.tfstate",
			},
		},
	})
	// The fetch step populates an empty temporary directory.
	tf := terraformHandler(`{}`)
	var fetchDir string
	e.runner.handle = func(ctx context.Context, c Command) (RunResult, error) {
		if slices.ContainsFunc(c.Args, func(a string) bool { return strings.HasPrefix(a, "-from-module=") }) {
			entries, _ := os.ReadDir(c.Dir)
			if len(entries) != 0 {
				return RunResult{Output: []byte("Can't populate non-empty directory")}, errors.New("exit status 1")
			}
			fetchDir = c.Dir
			write(t, filepath.Join(c.Dir, "main.tf"), "# fetched")
			write(t, filepath.Join(c.Dir, ".terraform", "modules", "x"), "junk")
		}
		return tf(ctx, c)
	}
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, tn.ID)
	calls := e.runner.Calls()
	if got := subcommands(calls); !slices.Equal(got, []string{"init", "init", "apply", "output"}) {
		t.Fatalf("commands = %v", got)
	}
	fetch := []string{"init", "-input=false", "-no-color", "-backend=false",
		"-from-module=git::https://example.com/infra.git//tenant?ref=v1.2.0"}
	if calls[0].Path != "tofu" || calls[0].Dir == dir || !slices.Equal(calls[0].Args, fetch) {
		t.Fatalf("fetch = %s in %s", calls[0], calls[0].Dir)
	}
	want := []string{"init", "-input=false", "-no-color",
		"-backend-config=bucket=tf-state", "-backend-config=key=tenants/" + tn.ID + ".tfstate"}
	if calls[1].Dir != dir || !slices.Equal(calls[1].Args, want) {
		t.Fatalf("init = %s in %s", calls[1], calls[1].Dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "main.tf")); err != nil {
		t.Error("fetched module not copied:", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".terraform", "modules", "x")); err == nil {
		t.Error(".terraform copied from the fetch directory")
	}
	if _, err := os.Stat(fetchDir); err == nil {
		t.Error("fetch directory kept")
	}
	if got := envMap(calls[0].Env)["TF_PLUGIN_CACHE_DIR"]; got != filepath.Join(state, "cache") {
		t.Errorf("TF_PLUGIN_CACHE_DIR = %q", got)
	}
	// A second run fetches again into a fresh directory.
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}

	// Deprovisioning a tenant whose working directory is gone still
	// destroys the remote state.
	other := e.addTenant("ghost")
	e.runner.reset()
	if err := e.p.Deprovision(ctx, other); err != nil {
		t.Fatal(err)
	}
	if got := subcommands(e.runner.Calls()); !slices.Equal(got, []string{"init", "init", "destroy"}) {
		t.Fatalf("commands = %v", got)
	}
}

func TestTerraformDeprovision(t *testing.T) {
	ctx := context.Background()
	cfg := terraformConfig(t)
	e := setup(t, cfg)
	e.runner.handle = terraformHandler(`{}`)
	tn := e.addTenant("acme")

	// Never provisioned with local state: nothing to do.
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if n := len(e.runner.Calls()); n != 0 {
		t.Fatalf("%d commands for an unprovisioned tenant", n)
	}

	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	e.runner.reset()
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	calls := e.runner.Calls()
	dir := filepath.Join(cfg["state_dir"].(string), tn.ID)
	if got := subcommands(calls); !slices.Equal(got, []string{"init", "destroy"}) {
		t.Fatalf("commands = %v", got)
	}
	want := []string{"destroy", "-auto-approve", "-input=false", "-no-color", "-var-file=" + filepath.Join(dir, metaDir, tfVarsFile)}
	if !slices.Equal(calls[1].Args, want) {
		t.Errorf("destroy = %v", calls[1].Args)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("working directory kept after destroy")
	}
	// Idempotent.
	e.runner.reset()
	if err := e.p.Deprovision(ctx, tn); err != nil || len(e.runner.Calls()) != 0 {
		t.Fatalf("second deprovision: %v, %d calls", err, len(e.runner.Calls()))
	}
}

func TestDeprovisionKeep(t *testing.T) {
	ctx := context.Background()
	cfg := terraformConfig(t)
	cfg["on_deprovision"] = "keep"
	e := setup(t, cfg)
	e.runner.handle = terraformHandler(`{}`)
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	e.runner.reset()
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if n := len(e.runner.Calls()); n != 0 {
		t.Fatalf("%d commands with keep", n)
	}
	if _, err := os.Stat(filepath.Join(cfg["state_dir"].(string), tn.ID, "terraform.tfstate")); err != nil {
		t.Error(err)
	}
}

func TestFailureLogIsTruncated(t *testing.T) {
	cfg := terraformConfig(t)
	cfg["log_limit"] = 300
	e := setup(t, cfg)
	var big strings.Builder
	big.WriteString("BEGINNING-OF-LOG\n")
	for i := range 200 {
		fmt.Fprintf(&big, "line %d of noisy provider output\n", i)
	}
	big.WriteString("Error: creating bucket: AccessDenied\n")
	e.runner.handle = func(_ context.Context, c Command) (RunResult, error) {
		if c.Args[0] == "apply" {
			return RunResult{Output: []byte(big.String())}, errors.New("exit status 1")
		}
		return RunResult{}, nil
	}
	err := e.p.Provision(context.Background(), e.addTenant("acme"))
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "AccessDenied") || !strings.Contains(msg, "exit status 1") ||
		!strings.Contains(msg, "truncated") || strings.Contains(msg, "BEGINNING-OF-LOG") {
		t.Fatalf("error = %s", msg)
	}
	if len(msg) > 600 {
		t.Fatalf("error is %d bytes", len(msg))
	}
}

func TestRunsAreSerializedPerTenant(t *testing.T) {
	cfg := terraformConfig(t)
	e := setup(t, cfg)
	var mu sync.Mutex
	active := map[string]int{}
	maxActive := map[string]int{}
	total, maxTotal := 0, 0
	e.runner.handle = func(_ context.Context, c Command) (RunResult, error) {
		mu.Lock()
		active[c.Dir]++
		total++
		maxActive[c.Dir] = max(maxActive[c.Dir], active[c.Dir])
		maxTotal = max(maxTotal, total)
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		active[c.Dir]--
		total--
		mu.Unlock()
		if c.Args[0] == "output" {
			return RunResult{Stdout: []byte(`{}`)}, nil
		}
		return RunResult{}, nil
	}
	a, b := e.addTenant("a"), e.addTenant("b")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 4 {
		for _, tn := range []sdk.Tenant{a, b} {
			wg.Go(func() { errs <- e.p.Provision(context.Background(), tn) })
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for dir, n := range maxActive {
		if n != 1 {
			t.Errorf("%s: %d concurrent runs", dir, n)
		}
	}
	if maxTotal < 2 {
		t.Logf("tenants never ran concurrently (max %d); timing dependent", maxTotal)
	}
}

func TestTimeout(t *testing.T) {
	cfg := terraformConfig(t)
	cfg["timeout"] = "50ms"
	e := setup(t, cfg)
	e.runner.handle = func(ctx context.Context, c Command) (RunResult, error) {
		if c.Args[0] == "apply" {
			<-ctx.Done()
			return RunResult{Output: []byte("Interrupt received.")}, ctx.Err()
		}
		return RunResult{}, nil
	}
	err := e.p.Provision(context.Background(), e.addTenant("acme"))
	if err == nil || !strings.Contains(err.Error(), "timed out after 50ms") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestReapply(t *testing.T) {
	ctx := context.Background()
	e := setup(t, terraformConfig(t))
	e.runner.handle = terraformHandler(`{}`)
	if len(e.reg.Subscriptions) != 1 {
		t.Fatalf("subscriptions = %+v", e.reg.Subscriptions)
	}
	sub := e.reg.Subscriptions[0]
	if !slices.Equal(sub.Filter.Types, DefaultReapplyOn) || !sub.Options.StartAtEnd || sub.Options.Timeout <= DefaultTimeout {
		t.Fatalf("subscription = %+v", sub)
	}
	tn := e.addTenant("acme")
	if err := e.reg.Deliver(ctx, "reapply", sdktest.TenantEvent(sdk.EventTenantPlanChanged, tn)); err != nil {
		t.Fatal(err)
	}
	if got := subcommands(e.runner.Calls()); !slices.Equal(got, []string{"init", "apply", "output"}) {
		t.Fatalf("commands = %v", got)
	}
	// A replay of an already applied version does nothing.
	e.runner.reset()
	if err := e.reg.Deliver(ctx, "reapply", sdktest.TenantEvent(sdk.EventTenantUpdated, tn)); err != nil {
		t.Fatal(err)
	}
	if n := len(e.runner.Calls()); n != 0 {
		t.Fatalf("%d commands for a replay", n)
	}
	// Events not in reapply_on are ignored.
	if err := e.reg.Deliver(ctx, "reapply", sdktest.TenantEvent(sdk.EventTenantSuspended, tn)); err != nil {
		t.Fatal(err)
	}
	// Tenants that are not provisioned are left to the provisioner.
	failed := e.reg.HostImpl.AddTenant(sdk.Tenant{Slug: "failed", Status: sdk.StatusFailed, Version: 3})
	if err := e.reg.Deliver(ctx, "reapply", sdktest.TenantEvent(sdk.EventTenantUpdated, failed)); err != nil {
		t.Fatal(err)
	}
	if n := len(e.runner.Calls()); n != 0 {
		t.Fatalf("%d commands for ignored events", n)
	}
	// Deleted tenants are ignored.
	if err := e.reg.Deliver(ctx, "reapply", sdktest.TenantEvent(sdk.EventTenantUpdated, sdk.Tenant{ID: "gone"})); err != nil {
		t.Fatal(err)
	}

	cfg := terraformConfig(t)
	cfg["reapply_on"] = []any{}
	if e := setup(t, cfg); len(e.reg.Subscriptions) != 0 {
		t.Fatalf("subscriptions with reapply_on [] = %+v", e.reg.Subscriptions)
	}
}

func TestHealth(t *testing.T) {
	e := setup(t, terraformConfig(t))
	if err := e.p.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg := terraformConfig(t)
	cfg["terraform"].(map[string]any)["binary"] = "missing"
	e = setup(t, cfg)
	if err := e.p.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "missing not found") {
		t.Fatalf("health = %v", err)
	}
}

func TestInitValidation(t *testing.T) {
	mod := moduleDir(t)
	tf := func(extra map[string]any, tfExtra map[string]any) map[string]any {
		c := map[string]any{"engine": "terraform", "state_dir": t.TempDir(),
			"terraform": map[string]any{"module_dir": mod}}
		for k, v := range extra {
			c[k] = v
		}
		for k, v := range tfExtra {
			c["terraform"].(map[string]any)[k] = v
		}
		return c
	}
	for name, cfg := range map[string]map[string]any{
		"no engine":          {},
		"bad engine":         {"engine": "ansible"},
		"unknown field":      tf(map[string]any{"nope": 1}, nil),
		"missing block":      {"engine": "terraform", "state_dir": t.TempDir()},
		"foreign block":      tf(map[string]any{"pulumi": map[string]any{"project_dir": mod}}, nil),
		"no state dir":       tf(map[string]any{"state_dir": ""}, nil),
		"no module":          {"engine": "terraform", "state_dir": t.TempDir(), "terraform": map[string]any{}},
		"both modules":       tf(nil, map[string]any{"module_source": "git::x"}),
		"missing module":     tf(nil, map[string]any{"module_dir": filepath.Join(mod, "nope")}),
		"shared backend":     tf(nil, map[string]any{"backend_config": map[string]any{"key": "state.tfstate"}}),
		"bad backend tmpl":   tf(nil, map[string]any{"backend_config": map[string]any{"key": "{{.Nope}}"}}),
		"bad backend key":    tf(nil, map[string]any{"backend_config": map[string]any{"a=b": "{{.ID}}"}}),
		"reserved var":       tf(map[string]any{"vars": map[string]any{"tenant_id": "x"}}, nil),
		"bad var template":   tf(map[string]any{"vars": map[string]any{"x": "{{.Missing}}"}}, nil),
		"bad timeout":        tf(map[string]any{"timeout": "soon"}, nil),
		"bad deprovision":    tf(map[string]any{"on_deprovision": "archive"}, nil),
		"bad reapply event":  tf(map[string]any{"reapply_on": []any{"tenant.deleted"}}, nil),
		"bad env name":       tf(map[string]any{"env": map[string]any{"A-B": "x"}}, nil),
		"bad passthrough":    tf(map[string]any{"env_passthrough": []any{"*"}}, nil),
		"small log limit":    tf(map[string]any{"log_limit": 10}, nil),
		"pulumi no yaml":     {"engine": "pulumi", "state_dir": t.TempDir(), "pulumi": map[string]any{"project_dir": t.TempDir()}},
		"pulumi same stack":  {"engine": "pulumi", "state_dir": t.TempDir(), "pulumi": map[string]any{"project_dir": pulumiProject(t), "stack_template": "prod"}},
		"crossplane shared":  {"engine": "crossplane", "crossplane": map[string]any{"resource": "xs", "manifest": "apiVersion: a/v1\nkind: X\nmetadata: {name: shared}\n"}},
		"crossplane no kind": {"engine": "crossplane", "crossplane": map[string]any{"resource": "xs", "manifest": "metadata: {name: t-{{.Slug}}}\n"}},
		"crossplane yaml":    {"engine": "crossplane", "crossplane": map[string]any{"resource": "xs", "manifest": "a: [\n"}},
		"crossplane none":    {"engine": "crossplane", "crossplane": map[string]any{"resource": "xs"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := trySetup(cfg); err == nil {
				t.Fatal("expected an error")
			} else {
				t.Log(err)
			}
		})
	}
}

func TestConfigSchema(t *testing.T) {
	s, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	for name, good := range map[string]map[string]any{
		"terraform": terraformConfig(t),
		"pulumi": {"engine": "pulumi", "state_dir": "/var/lib/iac", "pulumi": map[string]any{
			"project_dir": "/srv/infra", "backend_url": "file:///var/lib/pulumi", "keep_stack": true}},
		"crossplane": {"engine": "crossplane", "reapply_on": []any{}, "crossplane": map[string]any{
			"manifest": "x", "resource": "xs", "wait": false, "poll_interval": "1s"}},
	} {
		if err := s.Validate(good); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bad := range map[string]map[string]any{
		"no engine":       {"state_dir": "/x"},
		"unknown field":   {"engine": "crossplane", "crossplane": map[string]any{"manifest": "x"}, "nope": 1},
		"tf no block":     {"engine": "terraform", "state_dir": "/x"},
		"tf no state":     {"engine": "terraform", "terraform": map[string]any{"module_dir": "/m"}},
		"tf two modules":  {"engine": "terraform", "state_dir": "/x", "terraform": map[string]any{"module_dir": "/m", "module_source": "git::x"}},
		"tf unknown":      {"engine": "terraform", "state_dir": "/x", "terraform": map[string]any{"module_dir": "/m", "workspace": "x"}},
		"pulumi no dir":   {"engine": "pulumi", "state_dir": "/x", "pulumi": map[string]any{}},
		"xp no manifest":  {"engine": "crossplane", "crossplane": map[string]any{}},
		"bad reapply":     {"engine": "crossplane", "crossplane": map[string]any{"manifest": "x"}, "reapply_on": []any{"tenant.created"}},
		"bad passthrough": {"engine": "crossplane", "crossplane": map[string]any{"manifest": "x"}, "env_passthrough": []any{"A B"}},
	} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%s: expected schema error", name)
		}
	}
}

func TestBuildEnv(t *testing.T) {
	e := setup(t, terraformConfig(t))
	e.p.environ = func() []string {
		return []string{"=C:=C:\\", "PATH=/bin", "AWS_REGION=eu-west-1", "AWSX=no", "TF_CLI_ARGS_init=from-process"}
	}
	env := envMap(e.p.buildEnv(map[string]string{"TF_INPUT": "0"}))
	if env["AWS_REGION"] != "eu-west-1" || env["PATH"] != "/bin" || env["TF_INPUT"] != "0" {
		t.Errorf("env = %v", env)
	}
	if _, ok := env["AWSX"]; ok {
		t.Error("AWSX matched AWS_*")
	}
	// Configured env wins over the process environment.
	if env["TF_CLI_ARGS_init"] != "-upgrade=false" {
		t.Errorf("TF_CLI_ARGS_init = %q", env["TF_CLI_ARGS_init"])
	}
}

func TestTail(t *testing.T) {
	if got := tail([]byte("  short \n"), 100); got != "short" {
		t.Errorf("tail = %q", got)
	}
	got := tail([]byte("first line\nsecond line\nthird line"), 15)
	if got != truncatedMark+"third line" {
		t.Errorf("tail = %q", got)
	}
	b := &tailBuffer{max: 10}
	for range 10 {
		_, _ = b.Write([]byte("0123456789"))
	}
	if out := string(b.Bytes()); out != truncatedMark+"0123456789" {
		t.Errorf("tailBuffer = %q", out)
	}
}

func TestTenantDirRejectsTraversal(t *testing.T) {
	for _, id := range []string{"../x", "a/b", `a\b`, "", ".."} {
		if _, err := tenantDir(t.TempDir(), id); err == nil {
			t.Errorf("%q accepted", id)
		}
	}
}
