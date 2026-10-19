// Command testserver runs Tenarium for the admin UI tests: the same server as
// cmd/tenarium (all built-in plugins), except that DNS TXT lookups for domain
// verification are answered by the tests' fake DNS (see tests/ui/fakes/idp.ts),
// so tests can verify tenant domains and configure SSO connections.
//
// TENARIUM_UI_TEST_DNS is the URL of the fake: GET <url>?name=<name> answers a
// JSON array of TXT values. Without it, the system resolver is used.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AimTune/tenarium/pkg/server"
	_ "github.com/AimTune/tenarium/plugins/all"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	flag.Parse()
	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	lv := new(slog.LevelVar)
	if err := lv.UnmarshalText([]byte(cmp.Or(cfg.Log.Level, "info"))); err != nil {
		return fmt.Errorf("log level: %w", err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	opts := []server.Option{server.WithLevelVar(lv), server.WithConfigPath(configPath)}
	if dns := os.Getenv("TENARIUM_UI_TEST_DNS"); dns != "" {
		opts = append(opts, server.WithTXTResolver(fakeTXT(dns)))
	}
	app, err := server.New(ctx, cfg, log, opts...)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Server.Addr)
	if err != nil {
		return err
	}
	return app.Serve(ctx, ln)
}

// fakeTXT resolves TXT records through the fake DNS at base.
func fakeTXT(base string) func(ctx context.Context, name string) ([]string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(ctx context.Context, name string) ([]string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?"+url.Values{"name": {name}}.Encode(), nil)
		if err != nil {
			return nil, err
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = res.Body.Close() }()
		var records []string
		if err := json.NewDecoder(res.Body).Decode(&records); err != nil {
			return nil, fmt.Errorf("fake dns: %w", err)
		}
		if len(records) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		return records, nil
	}
}
