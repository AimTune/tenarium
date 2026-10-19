package orb

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// APIError is an error response from the Orb API (RFC 7807 style:
// {"type":...,"status":400,"title":"...","detail":"..."}).
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
	return fmt.Sprintf("orb: %d %s", e.Status, msg)
}

// maxResponse bounds Orb response bodies.
const maxResponse = 8 << 20

// call sends a JSON request to the Orb API and decodes the JSON response
// into out (if non-nil). Non-2xx responses are returned as *APIError.
func (p *Plugin) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)
	req.Header.Set("User-Agent", "tenarium-orb/"+version)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("orb: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("orb: %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{}
		_ = json.Unmarshal(raw, ae)
		ae.Status = resp.StatusCode
		return fmt.Errorf("%s %s: %w", method, path, ae)
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("orb: %s %s: decode response: %w", method, path, err)
	}
	return nil
}
