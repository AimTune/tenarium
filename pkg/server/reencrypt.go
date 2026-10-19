package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/AimTune/tenarium/internal/secrets"
	"github.com/AimTune/tenarium/internal/store/encrypted"
)

// Reencrypt rewrites every stored secret under the current `secrets`
// provider and key, then prints a report (`tenarium -reencrypt`). Run it
// after rotating a key or switching provider, before removing the old one.
func Reencrypt(ctx context.Context, cfg Config, out io.Writer) error {
	if cfg.Secrets.Provider == "" || cfg.Secrets.Provider == "none" {
		return errors.New("secrets.provider is not configured; nothing to re-encrypt with")
	}
	st, err := openStore(ctx, cfg.Store)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	kr, err := secrets.New(ctx, cfg.Secrets)
	if err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	rep, err := encrypted.Wrap(st, kr).(interface {
		Reencrypt(context.Context) (encrypted.Report, error)
	}).Reencrypt(ctx)
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if encErr := enc.Encode(rep); encErr != nil && err == nil {
		err = encErr
	}
	return err
}

func reencryptMain(configPath string) error {
	if configPath == "" {
		return errors.New("-reencrypt needs -config")
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return Reencrypt(context.Background(), cfg, os.Stdout)
}
