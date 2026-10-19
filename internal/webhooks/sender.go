package webhooks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/AimTune/tenarium/internal/netguard"
)

type sender struct {
	client *http.Client
}

func newSender(cfg Config) *sender {
	return &sender{client: netguard.NewClient(netguard.Options{Timeout: cfg.Timeout, AllowPrivate: cfg.AllowPrivateNetworks})}
}

// post sends body and returns the status code and an error message ("" on
// a 2xx answer).
func (s *sender) post(ctx context.Context, url string, headers map[string]string, body []byte) (int, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err.Error()
	}
	req.Header.Set("Content-Type", "application/cloudevents+json")
	req.Header.Set("User-Agent", "tenarium-webhooks/1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return 0, "timeout"
		}
		return 0, err.Error()
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, "endpoint responded " + resp.Status
	}
	return resp.StatusCode, ""
}
