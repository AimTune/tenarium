package external

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

// The TypeScript and Python SDK examples implement the same guard plugin as
// the Go one, so they must pass the same conformance checks.

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func runManaged(t *testing.T, command []string) {
	t.Helper()
	runManagedWith(t, command, exercise)
}

func runManagedWith(t *testing.T, command []string, check func(*testing.T, *sdktest.Registrar)) {
	t.Helper()
	reg := sdktest.NewRegistrar(map[string]any{
		"command": command,
		"dir":     repoRoot(t),
		"config":  map[string]any{"forbidden_prefix": "nope-"},
	})
	p := &Plugin{}
	ctx := context.Background()
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Stop(ctx) }()
	check(t, reg)
}

func TestTypeScriptSDK(t *testing.T) {
	runManaged(t, []string{lookNode(t), "sdks/typescript/examples/guard.ts"})
}

// The SDK directory examples implement the memdir conformance plugin (see
// directory_test.go).
func TestTypeScriptSDKDirectory(t *testing.T) {
	runManagedWith(t, []string{lookNode(t), "sdks/typescript/examples/directory.ts"}, exerciseDirectory)
}

func TestPythonSDK(t *testing.T) {
	runManaged(t, []string{lookPython(t), "sdks/python/examples/guard.py"})
}

func TestPythonSDKDirectory(t *testing.T) {
	runManagedWith(t, []string{lookPython(t), "sdks/python/examples/directory.py"}, exerciseDirectory)
}

func lookNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	return node
}

func lookPython(t *testing.T) string {
	t.Helper()
	var python string
	for _, name := range []string{os.Getenv("TENARIUM_TEST_PYTHON"), "python3", "python"} {
		if name == "" {
			continue
		}
		if p, err := exec.LookPath(name); err == nil && exec.Command(p, "--version").Run() == nil {
			python = p
			break
		}
	}
	if python == "" {
		t.Skip("python not installed")
	}
	return python
}

// TestRemoteSDK runs the conformance checks against an already running
// plugin, e.g. the Python example in a container:
//
//	docker run --rm -p 9555:9555 -v "$PWD/sdks/python:/p" -e TENARIUM_PLUGIN_ADDR=0.0.0.0:9555 \
//	  -e TENARIUM_PLUGIN_SECRET=s python:3.13-slim python /p/examples/guard.py
//	TENARIUM_TEST_REMOTE_PLUGIN_URL=http://127.0.0.1:9555 TENARIUM_TEST_REMOTE_PLUGIN_SECRET=s go test -run RemoteSDK ./plugins/external/
func TestRemoteSDK(t *testing.T) {
	url := os.Getenv("TENARIUM_TEST_REMOTE_PLUGIN_URL")
	if url == "" {
		t.Skip("TENARIUM_TEST_REMOTE_PLUGIN_URL not set")
	}
	reg := sdktest.NewRegistrar(map[string]any{
		"url": url, "secret": os.Getenv("TENARIUM_TEST_REMOTE_PLUGIN_SECRET"),
		"config": map[string]any{"forbidden_prefix": "nope-"},
	})
	if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	exercise(t, reg)
}
