package iac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// TestHelperProcess is not a real test: ExecRunner tests run the test
// binary as a child process that behaves as instructed by IAC_HELPER.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("IAC_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "echo":
		fmt.Fprintln(os.Stdout, `{"ok":true}`)
		fmt.Fprintln(os.Stderr, "to stderr")
		wd, _ := os.Getwd()
		fmt.Fprintln(os.Stderr, "dir="+wd)
		fmt.Fprintln(os.Stderr, "secret="+os.Getenv("NOT_PASSED"))
		os.Exit(0)
	case "fail":
		fmt.Fprintln(os.Stderr, "Error: something broke")
		os.Exit(3)
	case "hang":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

func helperEnv(mode string) []string {
	env := []string{"IAC_HELPER=" + mode}
	for _, k := range []string{"SYSTEMROOT", "PATH", "TEMP", "TMP", "HOME"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func TestExecRunner(t *testing.T) {
	t.Setenv("NOT_PASSED", "leaked")
	dir := t.TempDir()
	cmd := Command{Path: os.Args[0], Args: []string{"-test.run=^TestHelperProcess$"}, Dir: dir, Env: helperEnv("echo")}
	res, err := ExecRunner{}.Run(context.Background(), cmd)
	if err != nil {
		t.Fatal(err, string(res.Output))
	}
	if !strings.HasPrefix(string(res.Stdout), `{"ok":true}`) {
		t.Errorf("stdout = %q", res.Stdout)
	}
	out := string(res.Output)
	if !strings.Contains(out, "to stderr") || !strings.Contains(out, `{"ok":true}`) {
		t.Errorf("output = %q", out)
	}
	if strings.Contains(out, "leaked") {
		t.Error("environment not isolated")
	}
	real, _ := filepath.EvalSymlinks(dir)
	if !strings.Contains(out, "dir="+dir) && !strings.Contains(out, "dir="+real) {
		t.Errorf("working directory not set: %q", out)
	}

	cmd.Env = helperEnv("fail")
	res, err = ExecRunner{}.Run(context.Background(), cmd)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 || !strings.Contains(string(res.Output), "something broke") {
		t.Errorf("fail: %v %q", err, res.Output)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cmd.Env = helperEnv("hang")
	start := time.Now()
	if _, err = (ExecRunner{}).Run(ctx, cmd); err == nil {
		t.Error("hang: no error")
	}
	if time.Since(start) > 40*time.Second {
		t.Error("hang: not cancelled")
	}
}

// TestTerraformIntegration runs the real CLI on a module without external
// providers (terraform_data is built in) and local state. Set
// TENARIUM_TEST_TERRAFORM_BIN to a terraform or tofu binary to run it.
func TestTerraformIntegration(t *testing.T) {
	bin := os.Getenv("TENARIUM_TEST_TERRAFORM_BIN")
	if bin == "" {
		t.Skip("TENARIUM_TEST_TERRAFORM_BIN not set")
	}
	engine := EngineTerraform
	if strings.Contains(strings.ToLower(filepath.Base(bin)), "tofu") {
		engine = EngineOpenTofu
	}
	module := t.TempDir()
	write(t, filepath.Join(module, "main.tf"), `
variable "tenant_slug" { type = string }
variable "tenant_labels" { type = map(string) }
variable "greeting" { type = string }

resource "terraform_data" "tenant" {
  input = "${var.greeting}, ${var.tenant_slug}"
}

output "message" { value = terraform_data.tenant.output }
output "region" { value = lookup(var.tenant_labels, "region", "none") }
output "token" {
  value     = "s3cr3t-${var.tenant_slug}"
  sensitive = true
}
`)
	for _, key := range []string{"module_dir", "module_source"} {
		t.Run(key, func(t *testing.T) { runTerraformIntegration(t, engine, bin, key, module) })
	}
}

func runTerraformIntegration(t *testing.T, engine, bin, key, module string) {
	state := t.TempDir()
	reg := sdktest.NewRegistrar(map[string]any{
		"engine":    engine,
		"state_dir": state,
		"timeout":   "5m",
		"vars":      map[string]any{"greeting": "hello from {{.Plan}}"},
		"terraform": map[string]any{"binary": bin, key: module},
	})
	p := &Plugin{}
	ctx := context.Background()
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	tn := reg.HostImpl.AddTenant(sdk.Tenant{Slug: "acme", Plan: "pro", Labels: map[string]string{"region": "eu"}})
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	// Idempotent.
	if err := p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, tn.ID, "terraform.tfstate")); err != nil {
		t.Fatal(err)
	}

	rec := serve(reg, &sdk.Principal{Subject: "admin"}, "/tenants/acme/outputs")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET outputs = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "s3cr3t") {
		t.Fatalf("sensitive output served: %s", rec.Body)
	}
	var resp OutputsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Outputs["message"].Value != "hello from pro, acme" || resp.Outputs["region"].Value != "eu" || !resp.Outputs["token"].Redacted {
		t.Fatalf("outputs = %s", rec.Body)
	}

	if err := p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, tn.ID)); err == nil {
		t.Fatal("working directory kept after destroy")
	}
}
