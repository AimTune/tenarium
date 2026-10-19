package openmeter

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// APIError is an error response from the OpenMeter API (RFC 7807 problem
// details: {"type":...,"title":"...","status":400,"detail":"..."}).
type APIError struct {
	Status int    `json:"status"`
	Type   string `json:"type"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

func (e *APIError) Error() string {
	msg := cmp.Or(e.Title, http.StatusText(e.Status))
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	return fmt.Sprintf("openmeter: %d %s", e.Status, msg)
}

// maxResponse bounds OpenMeter response bodies.
const maxResponse = 8 << 20

// call sends body (if non-nil) with the given content type to the
// OpenMeter API. Non-2xx responses are returned as *APIError; successful
// response bodies are discarded.
func (p *Plugin) call(ctx context.Context, method, path, contentType string, body []byte) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, rd)
	if err != nil {
		return err
	}
	if p.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	}
	req.Header.Set("User-Agent", "tenarium-openmeter/"+version)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("openmeter: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("openmeter: %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{}
		_ = json.Unmarshal(raw, ae)
		ae.Status = resp.StatusCode
		return fmt.Errorf("%s %s: %w", method, path, ae)
	}
	return nil
}
