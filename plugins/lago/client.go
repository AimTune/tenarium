package lago

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
)

// APIError is an error response from the Lago API, e.g.
// {"status":422,"error":"Unprocessable Entity","code":"validation_errors",
// "error_details":{"transaction_id":["value_already_exist"]}}.
type APIError struct {
	Status  int             `json:"status"`
	Message string          `json:"error"`
	Code    string          `json:"code"`
	Details json.RawMessage `json:"error_details"`
}

func (e *APIError) Error() string {
	msg := cmp.Or(e.Message, http.StatusText(e.Status))
	if e.Code != "" {
		msg += " (" + e.Code + ")"
	}
	if len(e.Details) > 0 && string(e.Details) != "null" {
		msg += ": " + string(e.Details)
	}
	return fmt.Sprintf("lago: %d %s", e.Status, msg)
}

// fieldErrors returns the validation errors Lago reported for field.
func (e *APIError) fieldErrors(field string) []string {
	var details map[string]json.RawMessage
	if json.Unmarshal(e.Details, &details) != nil {
		return nil
	}
	var errs []string
	if json.Unmarshal(details[field], &errs) != nil {
		return nil
	}
	return errs
}

// isDuplicate reports whether err is Lago rejecting an event whose
// transaction_id was already ingested.
func isDuplicate(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusUnprocessableEntity &&
		slices.Contains(ae.fieldErrors("transaction_id"), "value_already_exist")
}

func isNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// maxResponse bounds Lago response bodies.
const maxResponse = 8 << 20

// call sends a JSON request to the Lago API and decodes the JSON response
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
	req.Header.Set("User-Agent", "tenarium-lago/"+version)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("lago: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("lago: %s %s: %w", method, path, err)
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
		return fmt.Errorf("lago: %s %s: decode response: %w", method, path, err)
	}
	return nil
}
