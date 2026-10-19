package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParsePlugins(t *testing.T) {
	ps, err := parsePlugins([]string{"a.com/x@v1.2.0", "b.com/y", "c.com/z=./dir"})
	if err != nil {
		t.Fatal(err)
	}
	if ps[0].version != "v1.2.0" || ps[1].version != "latest" || ps[2].replace == "" || ps[2].module != "c.com/z" {
		t.Fatalf("%+v", ps)
	}
	src := mainSource(ps, false)
	if strings.Contains(src, "plugins/all") || !strings.Contains(src, `_ "c.com/z"`) {
		t.Fatalf("source:\n%s", src)
	}
}

// TestBuildWithLocalPlugin builds a real binary containing a plugin from a
// separate local module, against this checkout.
func TestBuildWithLocalPlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go build")
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")

	pluginDir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(pluginDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/hello\n\ngo 1.26\n\nrequire github.com/AimTune/tenarium v0.0.0\n\nreplace github.com/AimTune/tenarium => "+filepath.ToSlash(root)+"\n")
	write("hello.go", `package hello

import (
	"context"

	"github.com/AimTune/tenarium/pkg/sdk"
)

type plugin struct{}

func (plugin) Manifest() sdk.Manifest                     { return sdk.Manifest{ID: "hello", Name: "Hello", Version: "1"} }
func (plugin) Init(context.Context, sdk.Registrar) error { return nil }

func init() { sdk.Register("hello", func() sdk.Plugin { return plugin{} }) }
`)

	bin := filepath.Join(t.TempDir(), "tenarium-custom")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if err := build([]plugin{{module: "example.com/hello", replace: pluginDir}}, bin, root, "v9.9.9-test", false, false); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-list-plugins").Output()
	if err != nil || strings.TrimSpace(string(out)) != "hello" {
		t.Fatalf("plugins in custom binary: %q %v", out, err)
	}
	ver, _ := exec.Command(bin, "-version").Output()
	if strings.TrimSpace(string(ver)) != "v9.9.9-test" {
		t.Fatalf("version: %q", ver)
	}
}
