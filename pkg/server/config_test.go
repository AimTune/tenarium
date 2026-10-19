package server_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/AimTune/tenarium/pkg/server"
)

func repoFile(parts ...string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(append([]string{filepath.Dir(file), "..", ".."}, parts...)...)
}

// TestShippedConfigs keeps the example configurations valid.
func TestShippedConfigs(t *testing.T) {
	t.Setenv("TENARIUM_API_KEY", "x")
	example, err := server.LoadConfig(repoFile("config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.New(context.Background(), example, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("config.example.yaml does not start: %v", err)
	}

	if _, err := server.LoadConfig(repoFile("deploy", "compose", "config.yaml")); err != nil {
		t.Fatal(err)
	}
}
