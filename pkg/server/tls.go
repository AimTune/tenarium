package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/AimTune/tenarium/internal/certs"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/internal/tenant"
)

// TLSConfig serves the API over TLS, with a static certificate or with
// certificates issued by ACME (Let's Encrypt) for the platform's hostnames
// and every verified custom domain of a live tenant.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	ACME     struct {
		Enabled      bool `yaml:"enabled"`
		certs.Config `yaml:",inline"`
		// HTTPAddr serves http-01 challenges and redirects to https
		// (default ":80"; empty string disables it, leaving tls-alpn-01).
		HTTPAddr *string `yaml:"http_addr"`
	} `yaml:"acme"`
}

// kvAdapter exposes the store's key-value space to the certs package.
type kvAdapter struct{ s store.Store }

func (k kvAdapter) Get(ctx context.Context, key string) ([]byte, error) {
	v, err := k.s.KVGet(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil, certs.ErrNotFound
	}
	return v, err
}

func (k kvAdapter) Put(ctx context.Context, key string, data []byte) error {
	return k.s.KVPut(ctx, key, data)
}

func (k kvAdapter) PutIfAbsent(ctx context.Context, key string, data []byte) (bool, error) {
	return k.s.KVPutIfAbsent(ctx, key, data)
}

func (k kvAdapter) Delete(ctx context.Context, key string) error { return k.s.KVDelete(ctx, key) }

// newCertManager builds the ACME manager; certificates of tenant domains
// are issued only for verified domains of live tenants.
func newCertManager(cfg TLSConfig, st store.Store, tenants *tenant.Service, log *slog.Logger) (*certs.Manager, error) {
	return certs.New(cfg.ACME.Config, certs.Options{
		KV: kvAdapter{st},
		Checker: func(ctx context.Context, host string) error {
			if _, err := tenants.ResolveDomain(ctx, host); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					return certs.ErrHostNotAllowed
				}
				return err
			}
			return nil
		},
		Logger: log,
	})
}

// serverTLS returns the TLS configuration to serve with, or nil for plain
// HTTP, and starts the http-01 listener when ACME needs it.
func (a *App) serverTLS() (*tls.Config, *http.Server, error) {
	t := a.cfg.Server.TLS
	switch {
	case a.certs != nil:
		var challenge *http.Server
		addr := ":80"
		if t.ACME.HTTPAddr != nil {
			addr = *t.ACME.HTTPAddr
		}
		if addr != "" {
			challenge = &http.Server{Addr: addr, Handler: a.certs.HTTPHandler(nil), ReadHeaderTimeout: 10 * time.Second}
		}
		return a.certs.TLSConfig(), challenge, nil
	case t.CertFile != "" || t.KeyFile != "":
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil, nil
	}
	return nil, nil, nil
}
