package hubspot

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxResponse bounds HubSpot response bodies.
const maxResponse = 8 << 20

// APIError is an error response from the HubSpot API.
type APIError struct {
	Status     int
	Category   string `json:"category"`
	Message    string `json:"message"`
	RetryAfter string `json:"-"`
}

func (e *APIError) Error() string {
	msg := cmp.Or(e.Message, http.StatusText(e.Status))
	s := fmt.Sprintf("hubspot: %d", e.Status)
	if e.Category != "" {
		s += " " + e.Category
	}
	s += ": " + msg
	if e.RetryAfter != "" {
		s += " (retry after " + e.RetryAfter + "s)"
	}
	return s
}

func isNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// call sends a JSON request and decodes the JSON response into out (if
// non-nil). Every non-2xx response is an error, so the delivery is retried;
// that includes 429 (rate limited) and 5xx.
func (p *Plugin) call(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := p.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tenarium-hubspot/"+version)
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("hubspot: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("hubspot: %s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{}
		_ = json.Unmarshal(raw, ae)
		ae.Status = resp.StatusCode
		if resp.StatusCode == http.StatusTooManyRequests {
			ae.RetryAfter = resp.Header.Get("Retry-After")
		}
		return fmt.Errorf("%s %s: %w", method, path, ae)
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("hubspot: %s %s: decode response: %w", method, path, err)
	}
	return nil
}

// batchResult is the response of a batch upsert.
type batchResult struct {
	Status  string `json:"status"`
	Results []struct {
		ID         string            `json:"id"`
		Properties map[string]string `json:"properties"`
	} `json:"results"`
	Errors []struct {
		Category string `json:"category"`
		Message  string `json:"message"`
	} `json:"errors"`
}

// upsert creates or updates one object of objectType identified by the
// unique property idProperty = id, and returns its HubSpot ID.
func (p *Plugin) upsert(ctx context.Context, objectType, idProperty, id string, props map[string]string) (string, error) {
	body := map[string]any{"inputs": []any{map[string]any{"idProperty": idProperty, "id": id, "properties": props}}}
	var res batchResult
	if err := p.call(ctx, http.MethodPost, "/crm/v3/objects/"+objectType+"/batch/upsert", nil, body, &res); err != nil {
		return "", err
	}
	if len(res.Errors) > 0 {
		var msgs []string
		for _, e := range res.Errors {
			msgs = append(msgs, cmp.Or(e.Category, "ERROR")+": "+e.Message)
		}
		return "", fmt.Errorf("hubspot: upsert %s %s: %s", objectType, id, strings.Join(msgs, "; "))
	}
	if len(res.Results) == 0 || res.Results[0].ID == "" {
		return "", fmt.Errorf("hubspot: upsert %s %s: no result", objectType, id)
	}
	return res.Results[0].ID, nil
}

// lookup returns the HubSpot ID of the object whose unique property
// idProperty is id, or "" if there is none.
func (p *Plugin) lookup(ctx context.Context, objectType, idProperty, id string) (string, error) {
	var obj struct {
		ID string `json:"id"`
	}
	err := p.call(ctx, http.MethodGet, "/crm/v3/objects/"+objectType+"/"+url.PathEscape(id),
		url.Values{"idProperty": {idProperty}}, nil, &obj)
	if isNotFound(err) {
		return "", nil
	}
	return obj.ID, err
}
