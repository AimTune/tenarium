package opensearchtenant

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// client is a minimal REST client for OpenSearch and Elasticsearch. It
// speaks JSON over net/http, authenticates with basic auth or an API key and
// fails over between the configured URLs on transport errors.
type client struct {
	urls     []*url.URL
	next     atomic.Uint32
	http     *http.Client
	username string
	password string
	apiKey   string
}

func newClient(c *Config, timeout time.Duration) (*client, error) {
	cl := &client{username: c.Username, password: c.Password, apiKey: c.APIKey}
	for _, raw := range c.URLs {
		u, err := parseURL(raw)
		if err != nil {
			return nil, err
		}
		cl.urls = append(cl.urls, u)
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected default transport")
	}
	tr = tr.Clone()
	if c.TLS != nil {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		// The operator explicitly opts in, typically for self-signed
		// development clusters.
		tlsCfg.InsecureSkipVerify = c.TLS.InsecureSkipVerify
		if c.TLS.CAFile != "" {
			pem, err := os.ReadFile(c.TLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("tls.ca_file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("tls.ca_file: no certificates found in %s", c.TLS.CAFile)
			}
			tlsCfg.RootCAs = pool
		}
		tr.TLSClientConfig = tlsCfg
	}
	cl.http = &http.Client{Transport: tr, Timeout: timeout}
	return cl, nil
}

// parseURL checks that raw is an absolute http(s) URL without query or
// fragment and strips a trailing slash from its path.
func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("url %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("url %q: missing host", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("url %q: must not contain credentials, query or fragment (use username/password)", raw)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// apiError is a non-2xx response.
type apiError struct {
	Method string
	Path   string
	Status int
	Type   string // error.type of the response, if any
	Reason string
}

func (e *apiError) Error() string {
	msg := fmt.Sprintf("%s %s: HTTP %d", e.Method, e.Path, e.Status)
	if e.Type != "" {
		msg += ": " + e.Type
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

// statusOf returns the HTTP status of an apiError (0 otherwise).
func statusOf(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

func isNotFound(err error) bool { return statusOf(err) == http.StatusNotFound }

// errorType returns error.type of an apiError ("" otherwise).
func errorType(err error) string {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Type
	}
	return ""
}

// do sends a request with an optional JSON body and decodes a 2xx JSON
// response into out (if non-nil). Non-2xx responses return *apiError.
func (c *client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
		if string(payload) == "null" { // a nil map or slice: no body
			payload = nil
		}
	}
	start := int(c.next.Load())
	var lastErr error
	for i := range c.urls {
		base := c.urls[(start+i)%len(c.urls)]
		resp, err := c.send(ctx, base, method, path, query, payload)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			// Transport error: try the next node and prefer it from now on.
			lastErr = err
			c.next.Store(uint32((start + i + 1) % len(c.urls))) //nolint:gosec // small index
			continue
		}
		return decodeResponse(resp, method, path, out)
	}
	return lastErr
}

func (c *client) send(ctx context.Context, base *url.URL, method, path string, query url.Values, payload []byte) (*http.Response, error) {
	u := *base
	u.Path = base.Path + path
	u.RawQuery = query.Encode()
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch {
	case c.apiKey != "":
		req.Header.Set("Authorization", "ApiKey "+c.apiKey)
	case c.username != "":
		req.SetBasicAuth(c.username, c.password)
	}
	return c.http.Do(req)
}

func decodeResponse(resp *http.Response, method, path string, out any) error {
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &apiError{Method: method, Path: path, Status: resp.StatusCode}
		parseErrorBody(data, ae)
		return ae
	}
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: decode response: %w", method, path, err)
	}
	return nil
}

// parseErrorBody extracts the error type and reason from the error formats
// of Elasticsearch/OpenSearch ({"error": {"type", "reason"}}) and of the
// OpenSearch security API ({"status", "message"}).
func parseErrorBody(data []byte, ae *apiError) {
	var body struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
		Status  any             `json:"status"`
	}
	if json.Unmarshal(data, &body) != nil {
		ae.Reason = truncate(strings.TrimSpace(string(data)), 300)
		return
	}
	var e struct {
		Type      string `json:"type"`
		Reason    string `json:"reason"`
		RootCause []struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"root_cause"`
	}
	if len(body.Error) > 0 && json.Unmarshal(body.Error, &e) == nil {
		ae.Type, ae.Reason = e.Type, e.Reason
		if ae.Type == "" && len(e.RootCause) > 0 {
			ae.Type, ae.Reason = e.RootCause[0].Type, e.RootCause[0].Reason
		}
		return
	}
	if len(body.Error) > 0 {
		var s string
		if json.Unmarshal(body.Error, &s) == nil {
			ae.Reason = s
			return
		}
	}
	ae.Reason = body.Message
}
