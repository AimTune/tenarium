package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/AimTune/tenarium/internal/secrets"
	"github.com/AimTune/tenarium/pkg/server"
)

func TestReencryptCommand(t *testing.T) {
	cfg := baseConfig()
	var out bytes.Buffer
	if err := server.Reencrypt(context.Background(), cfg, &out); err == nil {
		t.Fatal("ran without a secrets provider")
	}
	key, err := secrets.GenerateLocalKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Secrets = secrets.Config{Provider: "local", Local: secrets.LocalConfig{Keys: map[string]string{"k1": key}, Primary: "k1"}}
	if err := server.Reencrypt(context.Background(), cfg, &out); err != nil {
		t.Fatal(err)
	}
	var rep map[string]any
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep["rewritten"] == nil {
		t.Fatalf("report: %s %v", out.String(), err)
	}
}
