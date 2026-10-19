package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// maxResponseBytes bounds how much of a Vault response is read.
const maxResponseBytes = 4 << 20

// APIError is a non-2xx response from Vault.
type APIError struct {
	Method string
	Path   string
	Status int
	Errors []string
}

func (e *APIError) Error() string {
	msg := strings.Join(e.Errors, "; ")
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("vault %s /v1/%s: %d %s", e.Method, e.Path, e.Status, msg)
}

// statusOf returns the HTTP status of a Vault API error, 0 for other errors.
func statusOf(err error) int {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

func isNotFound(err error) bool { return statusOf(err) == http.StatusNotFound }

// client is a minimal Vault HTTP API client.
type client struct {
	base      string // e.g. https://vault.example.com:8200
	namespace string
	http      *http.Client
	token     string             // static token auth
	approle   *AuthAppRoleConfig // approle auth, nil with a static token
	now       func() time.Time

	mu      sync.Mutex
	cached  string    // approle login token
	expires time.Time // zero: no expiry
}

// authToken returns the token to send, logging in with AppRole when there
// is no cached token or it is about to expire.
func (c *client) authToken(ctx context.Context) (string, error) {
	if c.approle == nil {
		return c.token, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != "" && (c.expires.IsZero() || c.now().Before(c.expires)) {
		return c.cached, nil
	}
	var out struct {
		Auth *struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	body := map[string]string{"role_id": c.approle.RoleID, "secret_id": c.approle.SecretID}
	if err := c.raw(ctx, http.MethodPost, "auth/"+c.approle.Mount+"/login", nil, "", body, &out); err != nil {
		return "", fmt.Errorf("approle login: %w", err)
	}
	if out.Auth == nil || out.Auth.ClientToken == "" {
		return "", errors.New("approle login: response carries no token")
	}
	c.cached = out.Auth.ClientToken
	c.expires = time.Time{}
	if d := time.Duration(out.Auth.LeaseDuration) * time.Second; d > 0 {
		// Log in again well before the token expires.
		c.expires = c.now().Add(d * 8 / 10)
	}
	return c.cached, nil
}

// invalidate drops tok from the cache so the next request logs in again.
func (c *client) invalidate(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached == tok {
		c.cached = ""
	}
}

// do sends an authenticated request to /v1/<path>. body (if not nil) is
// sent as JSON and the response decoded into out (if not nil). With AppRole
// auth, a 403 answer triggers one new login and a retry, in case the cached
// token was revoked or expired early.
func (c *client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	tok, err := c.authToken(ctx)
	if err != nil {
		return err
	}
	err = c.raw(ctx, method, path, query, tok, body, out)
	if statusOf(err) == http.StatusForbidden && c.approle != nil {
		c.invalidate(tok)
		if tok, err = c.authToken(ctx); err != nil {
			return err
		}
		err = c.raw(ctx, method, path, query, tok, body, out)
	}
	return err
}

func (c *client) raw(ctx context.Context, method, path string, query url.Values, token string, body, out any) error {
	u := c.base + "/v1/" + path
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
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	req.Header.Set("X-Vault-Request", "true")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		ae := &APIError{Method: method, Path: path, Status: resp.StatusCode}
		var eb struct {
			Errors []string `json:"errors"`
		}
		if json.Unmarshal(data, &eb) == nil {
			ae.Errors = eb.Errors
		}
		return ae
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("vault %s /v1/%s: decode response: %w", method, path, err)
		}
	}
	return nil
}

// health checks /v1/sys/health. Active nodes (200), standbys (429) and
// performance standbys (473) can serve requests; DR secondaries (472),
// uninitialized (501) and sealed (503) nodes cannot.
func (c *client) health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v1/sys/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusTooManyRequests, 473:
		return nil
	case 472:
		return errors.New("vault node is a disaster recovery secondary and cannot serve requests")
	case http.StatusNotImplemented:
		return errors.New("vault is not initialized")
	case http.StatusServiceUnavailable:
		return errors.New("vault is sealed")
	default:
		return fmt.Errorf("vault health: unexpected status %d", resp.StatusCode)
	}
}
