package wasm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// buildModule compiles a Go program to WASI.
func buildModule(t *testing.T, pkgOrFile string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("compiles a wasm module")
	}
	out := filepath.Join(t.TempDir(), "m.wasm")
	cmd := exec.Command("go", "build", "-o", out, pkgOrFile)
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build wasm: %v\n%s", err, b)
	}
	return out
}

func writeGuest(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "main.go")
	if err := os.WriteFile(f, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func load(t *testing.T, cfg map[string]any) (*Plugin, *sdktest.Registrar) {
	t.Helper()
	reg := sdktest.NewRegistrar(cfg)
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop(context.Background()) })
	return p, reg
}

func TestPolicyModule(t *testing.T) {
	mod := buildModule(t, "github.com/AimTune/tenarium/examples/wasm-policy")
	_, reg := load(t, map[string]any{
		"module": mod,
		"hooks":  []string{"tenant.before_create"},
		"config": map[string]any{"blocked_words": []string{"admin"}, "require_label": "owner"},
	})
	ctx := context.Background()
	run := func(t sdk.Tenant) (*sdk.Tenant, error) {
		req := &sdk.HookRequest{Point: sdk.HookBeforeTenantCreate, Tenant: &t}
		return req.Tenant, reg.RunHooks(ctx, req)
	}

	if _, err := run(sdk.Tenant{Slug: "my-admin", Name: "x", Labels: map[string]string{"owner": "a"}}); !isReject(err, "admin") {
		t.Fatalf("blocked word: %v", err)
	}
	if _, err := run(sdk.Tenant{Slug: "acme", Name: "x"}); !isReject(err, "owner") {
		t.Fatalf("missing label: %v", err)
	}
	tn, err := run(sdk.Tenant{Slug: "acme", Name: "x", Labels: map[string]string{"owner": "a"}})
	if err != nil || tn.Labels["policy"] != "wasm-checked" {
		t.Fatalf("accepted tenant: %+v %v", tn, err)
	}
}

func isReject(err error, contains string) bool {
	re, ok := sdk.IsReject(err)
	return ok && strings.Contains(re.Reason, contains)
}

const spinGuest = `package main

func main() {
	for {
	}
}
`

const hogGuest = `package main

var keep [][]byte

func main() {
	for {
		keep = append(keep, make([]byte, 1<<20))
	}
}
`

const escapeGuest = `package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	_, err := os.ReadFile("/etc/passwd")
	fmt.Printf("{\"reject\": %q}", fmt.Sprintf("fs=%v year=%d", err != nil, time.Now().Year()))
}
`

func TestSandboxLimits(t *testing.T) {
	ctx := context.Background()
	hook := func(reg *sdktest.Registrar) error {
		return reg.RunHooks(ctx, &sdk.HookRequest{Point: sdk.HookBeforeTenantCreate, Tenant: &sdk.Tenant{Slug: "a", Name: "a"}})
	}

	_, reg := load(t, map[string]any{"module": buildModule(t, writeGuest(t, spinGuest)), "hooks": []string{"tenant.before_create"}, "timeout": "200ms"})
	if err := hook(reg); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("infinite loop: %v", err)
	}

	_, reg = load(t, map[string]any{"module": buildModule(t, writeGuest(t, hogGuest)), "hooks": []string{"tenant.before_create"}, "memory_limit_mb": 32})
	if err := hook(reg); err == nil {
		t.Fatal("memory hog succeeded")
	}

	// No filesystem and a fake clock inside the sandbox.
	_, reg = load(t, map[string]any{"module": buildModule(t, writeGuest(t, escapeGuest)), "hooks": []string{"tenant.before_create"}})
	err := hook(reg)
	if !isReject(err, "fs=true") || isReject(err, fmt.Sprintf("year=%d", time.Now().Year())) {
		t.Fatalf("sandbox escape check: %v", err)
	}
}

func TestEventsAndConfigErrors(t *testing.T) {
	failing := `package main

import "os"

func main() { os.Stderr.WriteString("boom"); os.Exit(3) }
`
	_, reg := load(t, map[string]any{"module": buildModule(t, writeGuest(t, failing)), "events": []string{"tenant.*"}})
	err := reg.Deliver(context.Background(), "events", sdktest.TenantEvent(sdk.EventTenantCreated, sdk.Tenant{ID: "1"}))
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("event failure not surfaced: %v", err)
	}

	for _, cfg := range []map[string]any{
		{"module": "missing.wasm", "hooks": []string{"tenant.before_create"}},
		{"module": "x.wasm"},
	} {
		if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
			t.Errorf("config %v accepted", cfg)
		}
	}
}

func BenchmarkHookInvocation(b *testing.B) {
	out := filepath.Join(b.TempDir(), "m.wasm")
	cmd := exec.Command("go", "build", "-o", out, "github.com/AimTune/tenarium/examples/wasm-policy")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm")
	if o, err := cmd.CombinedOutput(); err != nil {
		b.Fatalf("%v %s", err, o)
	}
	reg := sdktest.NewRegistrar(map[string]any{"module": out, "hooks": []string{"tenant.before_create"}})
	p := &Plugin{}
	if err := p.Init(context.Background(), reg); err != nil {
		b.Fatal(err)
	}
	defer func() { _ = p.Stop(context.Background()) }()
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		tn := sdk.Tenant{Slug: "acme", Name: "x"}
		_ = reg.RunHooks(ctx, &sdk.HookRequest{Point: sdk.HookBeforeTenantCreate, Tenant: &tn})
	}
}

const floodGuest = `package main

import "os"

func main() {
	chunk := make([]byte, 64<<10)
	for {
		if _, err := os.Stdout.Write(chunk); err != nil {
			os.Exit(1)
		}
	}
}
`

func TestOutputIsBounded(t *testing.T) {
	_, reg := load(t, map[string]any{"module": buildModule(t, writeGuest(t, floodGuest)), "hooks": []string{"tenant.before_create"}, "timeout": "5s"})
	err := reg.RunHooks(context.Background(), &sdk.HookRequest{Point: sdk.HookBeforeTenantCreate, Tenant: &sdk.Tenant{Slug: "a", Name: "a"}})
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("flooding module: %v", err)
	}
}
