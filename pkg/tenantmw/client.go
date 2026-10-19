package tenantmw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a minimal Tenarium REST API client for the calls an
// application needs at request time. It authenticates with an API key.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient sets the HTTP client (default: 10s timeout).
func WithHTTPClient(c *http.Client) ClientOption { return func(cl *Client) { cl.http = c } }

// NewClient returns a client for the Tenarium API at baseURL.
func NewClient(baseURL, apiKey string, opts ...ClientOption) *Client {
	c := &Client{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, http: &http.Client{Timeout: 10 * time.Second}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// APIError is a non-2xx response of the Tenarium API.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("tenarium api: %d %s: %s", e.Status, e.Code, e.Message)
}

// Is maps 404 to ErrNotFound and 429 quota_exceeded to ErrQuotaExceeded.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Status == http.StatusNotFound
	case ErrQuotaExceeded:
		return e.Status == http.StatusTooManyRequests
	}
	return false
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &APIError{Status: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
		var env struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		if json.Unmarshal(raw, &env) == nil && env.Error.Code != "" {
			e.Code, e.Message = env.Error.Code, env.Error.Message
		}
		return e
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// Entitlements are a tenant's effective features and limits.
type Entitlements struct {
	TenantID string           `json:"tenant_id"`
	Plan     string           `json:"plan,omitempty"`
	Features map[string]bool  `json:"features"`
	Limits   map[string]int64 `json:"limits"`
}

// GetTenant returns a tenant by ID or slug without entitlements (Features
// and Limits hold only the tenant's overrides). Use Tenant for the
// effective state.
func (c *Client) GetTenant(ctx context.Context, idOrSlug string) (*Tenant, error) {
	var t Tenant
	if err := c.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(idOrSlug), nil, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Entitlements returns the effective features and limits of a tenant.
func (c *Client) Entitlements(ctx context.Context, idOrSlug string) (*Entitlements, error) {
	var e Entitlements
	if err := c.do(ctx, http.MethodGet, "/v1/tenants/"+url.PathEscape(idOrSlug)+"/entitlements", nil, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// Tenant returns the tenant with its effective entitlements. It
// implements Source.
func (c *Client) Tenant(ctx context.Context, idOrSlug string) (*Tenant, error) {
	t, err := c.GetTenant(ctx, idOrSlug)
	if err != nil {
		return nil, err
	}
	e, err := c.Entitlements(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	t.Features, t.Limits = e.Features, e.Limits
	if e.Plan != "" {
		t.Plan = e.Plan
	}
	return t, nil
}

// Domain is a custom hostname mapped to a tenant.
type Domain struct {
	TenantID string `json:"tenant_id"`
	Slug     string `json:"slug"`
	Hostname string `json:"hostname"`
}

// ResolveDomain maps a custom hostname to its tenant with
// GET /v1/domains/resolve. Unknown hosts yield ErrNotFound.
func (c *Client) ResolveDomain(ctx context.Context, host string) (Domain, error) {
	var d Domain
	err := c.do(ctx, http.MethodGet, "/v1/domains/resolve?host="+url.QueryEscape(host), nil, &d)
	return d, err
}

// Usage is the value of a metered metric after recording usage.
type Usage struct {
	Metric string `json:"metric"`
	Value  int64  `json:"value"`
	// Limit is nil when the metric is unlimited.
	Limit *int64 `json:"limit,omitempty"`
}

// RecordUsage atomically adds delta to the tenant's metric. An increment
// beyond the tenant's limit fails with an error matching ErrQuotaExceeded.
func (c *Client) RecordUsage(ctx context.Context, tenantID, metric string, delta int64) (Usage, error) {
	var u Usage
	path := "/v1/tenants/" + url.PathEscape(tenantID) + "/usage/" + url.PathEscape(metric)
	err := c.do(ctx, http.MethodPost, path, map[string]int64{"delta": delta}, &u)
	return u, err
}

// UsageRecorder records metered usage of the current tenant.
type UsageRecorder struct {
	client *Client
}

// NewUsageRecorder returns a recorder posting usage through c.
func NewUsageRecorder(c *Client) *UsageRecorder { return &UsageRecorder{client: c} }

// Record adds delta to metric for tenantID. It returns an error matching
// ErrQuotaExceeded (errors.Is) when the tenant's limit would be exceeded.
func (u *UsageRecorder) Record(ctx context.Context, tenantID, metric string, delta int64) (Usage, error) {
	return u.client.RecordUsage(ctx, tenantID, metric, delta)
}

// RecordFor adds delta to metric for the tenant stored in ctx by
// Middleware.
func (u *UsageRecorder) RecordFor(ctx context.Context, metric string, delta int64) (Usage, error) {
	t := FromContext(ctx)
	if t == nil {
		return Usage{}, ErrNoTenant
	}
	return u.Record(ctx, t.ID, metric, delta)
}
