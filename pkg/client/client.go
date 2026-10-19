// Package client is the official Go client for the Tenarium REST API.
//
//	c, err := client.New("https://tenarium.example.com", client.WithAPIKey(key))
//	t, err := c.Tenants.Create(ctx, client.CreateTenantRequest{Slug: "acme", Name: "Acme"})
//	for t, err := range c.Tenants.All(ctx, client.TenantListOptions{Status: sdk.StatusActive}) { ... }
//
// Every call takes a context. A Client holds no global state and is safe
// for concurrent use.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultUserAgent is sent unless WithUserAgent overrides it.
const DefaultUserAgent = "tenarium-go-client/1"

// maxResponseBytes bounds how much of a response body is read.
const maxResponseBytes = 32 << 20

// Client talks to one Tenarium server. Create it with New.
type Client struct {
	base      *url.URL
	hc        *http.Client
	userAgent string
	tokens    TokenProvider
	retry     retryPolicy

	Tenants     *TenantsService
	Members     *MembersService
	Usage       *UsageService
	Plans       *PlansService
	Users       *UsersService
	Auth        *AuthService
	Events      *EventsService
	DeadLetters *DeadLettersService
	Plugins     *PluginsService
	Rollouts    *RolloutsService
	Templates   *TemplatesService
}

// Option configures a Client.
type Option func(*Client)

// WithAPIKey authenticates with a static API key (sent as a bearer token).
func WithAPIKey(key string) Option { return WithTokenSource(StaticToken(key)) }

// WithToken authenticates with a fixed bearer token, e.g. an access token
// from an external identity provider.
func WithToken(token string) Option { return WithTokenSource(StaticToken(token)) }

// WithTokenSource authenticates with tokens from p. If p also implements
// Reauthenticator, a 401 response triggers one token refresh and retry.
func WithTokenSource(p TokenProvider) Option { return func(c *Client) { c.tokens = p } }

// WithHTTPClient sets the underlying HTTP client (timeouts, transport, proxies).
func WithHTTPClient(hc *http.Client) Option { return func(c *Client) { c.hc = hc } }

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option { return func(c *Client) { c.userAgent = ua } }

// WithRetry retries failed requests up to max additional times with
// exponential backoff starting at backoff. Only requests that are safe to
// repeat are retried: GET/HEAD/PUT/DELETE/OPTIONS, and POSTs carrying an
// Idempotency-Key. Network errors, 502/503/504 and 429 with Retry-After are
// retried; Retry-After is honored. With retries enabled, Create calls get
// an Idempotency-Key automatically.
func WithRetry(max int, backoff time.Duration) Option {
	return func(c *Client) { c.retry = retryPolicy{max: max, backoff: backoff} }
}

type retryPolicy struct {
	max     int
	backoff time.Duration
}

// New returns a client for the server at baseURL (e.g. "http://localhost:8080").
func New(baseURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("tenarium: invalid base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("tenarium: invalid base URL %q: want http(s)://host[:port]", baseURL)
	}
	c := &Client{base: u, hc: http.DefaultClient, userAgent: DefaultUserAgent}
	for _, o := range opts {
		o(c)
	}
	c.bind()
	return c, nil
}

// With returns a copy of c with opts applied, e.g. to switch credentials
// after a login: c.With(client.WithTokenSource(ts)).
func (c *Client) With(opts ...Option) *Client {
	n := &Client{base: c.base, hc: c.hc, userAgent: c.userAgent, tokens: c.tokens, retry: c.retry}
	for _, o := range opts {
		o(n)
	}
	n.bind()
	return n
}

// BaseURL returns the server URL the client talks to.
func (c *Client) BaseURL() string { return c.base.String() }

func (c *Client) bind() {
	c.Tenants = &TenantsService{c}
	c.Members = &MembersService{c}
	c.Usage = &UsageService{c}
	c.Plans = &PlansService{c}
	c.Rollouts = &RolloutsService{c}
	c.Templates = &TemplatesService{c}
	c.Users = &UsersService{c}
	c.Auth = &AuthService{c}
	c.Events = &EventsService{c}
	c.DeadLetters = &DeadLettersService{c}
	c.Plugins = &PluginsService{c}
}

// --- call options ---------------------------------------------------------------

// CallOption tunes a single API call.
type CallOption func(*callConfig)

type callConfig struct {
	ifMatch  *int64
	idemKey  string
	header   http.Header
	autoIdem bool // generate an Idempotency-Key when retries are on
	noAuth   bool // public endpoint: never send or refresh credentials
}

// IfMatch makes an update conditional on the resource still being at
// version; otherwise the call fails with a 412 (see IsVersionConflict).
func IfMatch(version int64) CallOption {
	return func(cc *callConfig) { cc.ifMatch = &version }
}

// WithIdempotencyKey sends an Idempotency-Key so a POST can be retried
// safely: the server replays the first response for the same key and body.
func WithIdempotencyKey(key string) CallOption {
	return func(cc *callConfig) { cc.idemKey = key }
}

// WithHeader adds a request header to one call.
func WithHeader(key, value string) CallOption {
	return func(cc *callConfig) {
		if cc.header == nil {
			cc.header = http.Header{}
		}
		cc.header.Add(key, value)
	}
}

func autoIdempotency() CallOption { return func(cc *callConfig) { cc.autoIdem = true } }
func public() CallOption          { return func(cc *callConfig) { cc.noAuth = true } }

// --- request execution ---------------------------------------------------------

// Do performs a request against an API path (e.g. "/v1/tenants") and decodes
// the JSON response into out (if non-nil). It is the building block of the
// typed services and can be used for endpoints they do not cover yet.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, in, out any, opts ...CallOption) error {
	err := c.do(ctx, method, path, query, in, out, opts...)
	return err
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any, opts ...CallOption) error {
	var cc callConfig
	for _, o := range opts {
		o(&cc)
	}
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return fmt.Errorf("tenarium: encode request: %w", err)
		}
	}
	if cc.idemKey == "" && cc.autoIdem && c.retry.max > 0 {
		cc.idemKey = newIdempotencyKey()
	}
	u := *c.base
	u.Path = c.base.Path + path
	u.RawQuery = query.Encode()

	retryable := isIdempotent(method) || (method == http.MethodPost && cc.idemKey != "")
	reauthed := false
	for attempt := 0; ; attempt++ {
		token := ""
		if c.tokens != nil && !cc.noAuth {
			var err error
			if token, err = c.tokens.Token(ctx); err != nil {
				return fmt.Errorf("tenarium: get token: %w", err)
			}
		}
		resp, err := c.send(ctx, method, u.String(), body, token, &cc)
		if err != nil {
			if ctx.Err() == nil && retryable && attempt < c.retry.max {
				if werr := sleep(ctx, c.backoff(attempt, 0)); werr != nil {
					return werr
				}
				continue
			}
			return err
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		resp.Body.Close()
		if rerr != nil {
			return fmt.Errorf("tenarium: read response: %w", rerr)
		}
		if resp.StatusCode == http.StatusUnauthorized && !reauthed && token != "" {
			if ra, ok := c.tokens.(Reauthenticator); ok {
				reauthed = true
				if _, err := ra.Reauth(ctx, token); err == nil {
					attempt-- // a credential refresh is not a retry
					continue
				}
			}
		}
		if resp.StatusCode >= 400 {
			apiErr := parseError(resp, raw)
			if retryable && attempt < c.retry.max && retryableStatus(resp.StatusCode, apiErr.RetryAfter) {
				if werr := sleep(ctx, c.backoff(attempt, apiErr.RetryAfter)); werr != nil {
					return werr
				}
				continue
			}
			return apiErr
		}
		if out != nil && resp.StatusCode != http.StatusNoContent && len(raw) > 0 {
			if err := json.Unmarshal(raw, out); err != nil {
				return fmt.Errorf("tenarium: decode %s %s response: %w", method, path, err)
			}
		}
		return nil
	}
}

func (c *Client) send(ctx context.Context, method, u string, body []byte, token string, cc *callConfig) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, fmt.Errorf("tenarium: build request: %w", err)
	}
	for k, vs := range cc.header {
		req.Header[k] = vs
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if cc.ifMatch != nil {
		req.Header.Set("If-Match", `"`+strconv.FormatInt(*cc.ifMatch, 10)+`"`)
	}
	if cc.idemKey != "" {
		req.Header.Set("Idempotency-Key", cc.idemKey)
	}
	return c.hc.Do(req)
}

func isIdempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions:
		return true
	}
	return false
}

func retryableStatus(status int, retryAfter time.Duration) bool {
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case http.StatusTooManyRequests:
		return retryAfter > 0
	}
	return false
}

// backoff returns the delay before retry attempt+1: the server's
// Retry-After if given, else exponential backoff with jitter.
func (c *Client) backoff(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}
	d := c.retry.backoff << min(attempt, 16)
	if d <= 0 || d > 30*time.Second {
		d = 30 * time.Second
	}
	return d/2 + rand.N(d/2+1) //nolint:gosec // jitter needs no cryptographic randomness
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// --- small helpers -------------------------------------------------------------

// Ptr returns a pointer to v, for the optional fields of update requests.
func Ptr[T any](v T) *T { return &v }

func esc(s string) string { return url.PathEscape(s) }

func setLimit(q url.Values, v int) {
	if v > 0 {
		q.Set("limit", strconv.Itoa(v))
	}
}

func setStr(q url.Values, key, v string) {
	if v != "" {
		q.Set(key, v)
	}
}

var errEmptyID = errors.New("tenarium: empty identifier")

func checkIDs(ids ...string) error {
	for _, id := range ids {
		if id == "" {
			return errEmptyID
		}
	}
	return nil
}
