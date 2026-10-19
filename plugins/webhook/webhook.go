// Package webhook delivers events to an HTTP endpoint as CloudEvents JSON,
// signed according to the Standard Webhooks specification
// (https://www.standardwebhooks.com). Configure one instance per endpoint.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("webhook", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	URL string `json:"url"`
	// Secret signs requests. A "whsec_" prefix denotes a base64 secret as
	// used by Standard Webhooks libraries; otherwise the raw bytes are used.
	Secret  string            `json:"secret"`
	Events  []string          `json:"events"`
	Headers map[string]string `json:"headers"`
	// Timeout per request, e.g. "10s".
	Timeout     string `json:"timeout"`
	MaxAttempts int    `json:"max_attempts"`
}

type Plugin struct {
	cfg    Config
	secret []byte
	client *http.Client
	now    func() time.Time
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:          "webhook",
		Name:        "Webhook",
		Version:     "0.1.0",
		Description: "Delivers signed CloudEvents to an HTTP endpoint.",
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.setup(); err != nil {
		return err
	}
	p.now = time.Now

	var opts []sdk.SubscribeOption
	if p.cfg.MaxAttempts > 0 {
		opts = append(opts, sdk.WithMaxAttempts(p.cfg.MaxAttempts))
	}
	r.Subscribe("deliver", sdk.EventFilter{Types: p.cfg.Events}, p.deliver, opts...)
	return nil
}

func decodeSecret(s string) ([]byte, error) {
	if b64, ok := strings.CutPrefix(s, "whsec_"); ok {
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("secret: invalid whsec_ base64: %w", err)
		}
		return b, nil
	}
	return []byte(s), nil
}

func (p *Plugin) deliver(ctx context.Context, e sdk.Event) error {
	if n := p.next.Load(); n != nil {
		return n.deliver(ctx, e)
	}
	body, err := json.Marshal(e.CloudEvent())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range p.cfg.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/cloudevents+json")
	req.Header.Set("User-Agent", "tenarium-webhook/0.1")
	if len(p.secret) > 0 {
		ts := strconv.FormatInt(p.now().Unix(), 10)
		req.Header.Set("webhook-id", e.ID)
		req.Header.Set("webhook-timestamp", ts)
		req.Header.Set("webhook-signature", "v1,"+Sign(p.secret, e.ID, ts, body))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("endpoint responded " + resp.Status)
	}
	return nil
}

// Sign computes the Standard Webhooks signature (base64 HMAC-SHA256 over
// "id.timestamp.body"). Receivers can use it to verify requests.
func Sign(secret []byte, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// setup checks the endpoint settings and builds the client.
func (p *Plugin) setup() error {
	u, err := url.Parse(p.cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url must be an absolute http(s) URL, got %q", p.cfg.URL)
	}
	if p.secret, err = decodeSecret(p.cfg.Secret); err != nil {
		return err
	}
	timeout := 10 * time.Second
	if p.cfg.Timeout != "" {
		if timeout, err = time.ParseDuration(p.cfg.Timeout); err != nil {
			return fmt.Errorf("timeout: %w", err)
		}
	}
	p.client = &http.Client{Timeout: timeout}
	return nil
}

// Reconfigure applies a new URL, secret, headers or timeout without a
// restart (e.g. secret rotation). The event filter and attempts are fixed
// at startup.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{now: p.now}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if !slices.Equal(n.cfg.Events, p.cfg.Events) || n.cfg.MaxAttempts != p.cfg.MaxAttempts {
		return errors.New("events and max_attempts take effect after a restart")
	}
	if err := n.setup(); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}
