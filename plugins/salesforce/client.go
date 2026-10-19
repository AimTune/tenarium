package salesforce

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/jwt"
)

// maxResponse bounds API response bodies.
const maxResponse = 8 << 20

// session is a cached access token and the API host it belongs to.
type session struct {
	token    string
	instance string
}

// tokenCache reuses a token for ttl, since Salesforce tokens report no
// expiry, and lets callers force a refresh after a 401.
type tokenCache struct {
	fetch func(ctx context.Context) (*oauth2.Token, error)
	ttl   time.Duration
	now   func() time.Time

	mu      sync.Mutex
	cur     *session
	fetched time.Time
}

// get returns the cached session or fetches a new one. stale, if non-nil,
// is a session the API rejected: it is replaced unless another caller
// already did.
func (c *tokenCache) get(ctx context.Context, stale *session) (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur != nil && c.cur != stale && c.now().Sub(c.fetched) < c.ttl {
		return c.cur, nil
	}
	tok, err := c.fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("salesforce: get token: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("salesforce: token response has no access_token")
	}
	instance, _ := tok.Extra("instance_url").(string)
	c.cur, c.fetched = &session{token: tok.AccessToken, instance: strings.TrimRight(instance, "/")}, c.now()
	return c.cur, nil
}

// tokenSource builds the token fetcher of the configured flow.
func (p *Plugin) tokenSource() (func(ctx context.Context) (*oauth2.Token, error), error) {
	a := p.cfg.Auth
	if a.ClientID == "" {
		return nil, errors.New("auth.client_id is required")
	}
	tokenURL := p.loginURL + "/services/oauth2/token"
	withClient := func(ctx context.Context) context.Context {
		return context.WithValue(ctx, oauth2.HTTPClient, p.client)
	}
	switch a.Flow {
	case FlowClientCredentials:
		if a.ClientSecret == "" {
			return nil, errors.New("auth.client_secret is required for client_credentials")
		}
		if a.Username != "" || a.PrivateKey != "" || a.PrivateKeyFile != "" {
			return nil, errors.New("auth: username and private keys only apply to jwt_bearer")
		}
		cc := &clientcredentials.Config{
			ClientID: a.ClientID, ClientSecret: a.ClientSecret, TokenURL: tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		}
		return func(ctx context.Context) (*oauth2.Token, error) { return cc.Token(withClient(ctx)) }, nil
	case FlowJWTBearer:
		if a.Username == "" {
			return nil, errors.New("auth.username is required for jwt_bearer")
		}
		if a.ClientSecret != "" {
			return nil, errors.New("auth.client_secret does not apply to jwt_bearer")
		}
		key, err := readKey(a)
		if err != nil {
			return nil, err
		}
		if err := parseRSAKey(key); err != nil {
			return nil, fmt.Errorf("auth: private key: %w", err)
		}
		jc := &jwt.Config{
			Email: a.ClientID, Subject: a.Username, PrivateKey: key, TokenURL: tokenURL,
			Audience: p.loginURL, Expires: 3 * time.Minute,
		}
		return func(ctx context.Context) (*oauth2.Token, error) { return jc.TokenSource(withClient(ctx)).Token() }, nil
	}
	return nil, fmt.Errorf("auth.flow must be client_credentials or jwt_bearer, got %q", a.Flow)
}

// APIError is an error response from the Salesforce REST API.
type APIError struct {
	Status int
	Errors []struct {
		ErrorCode string   `json:"errorCode"`
		Message   string   `json:"message"`
		Fields    []string `json:"fields"`
	}
}

func (e *APIError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("salesforce: %d %s", e.Status, http.StatusText(e.Status))
	}
	msgs := make([]string, len(e.Errors))
	for i, x := range e.Errors {
		msgs[i] = x.ErrorCode + ": " + x.Message
		if len(x.Fields) > 0 {
			msgs[i] += " (" + strings.Join(x.Fields, ", ") + ")"
		}
	}
	return fmt.Sprintf("salesforce: %d: %s", e.Status, strings.Join(msgs, "; "))
}

func isNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// api calls {instance}/services/data/{version}{path}. On 401 the token is
// refreshed and the request retried once.
func (p *Plugin) api(ctx context.Context, method, path string, body any) ([]byte, error) {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	var stale *session
	for attempt := 0; ; attempt++ {
		s, err := p.tokens.get(ctx, stale)
		if err != nil {
			return nil, err
		}
		instance := p.cfg.InstanceURL
		if instance == "" {
			instance = s.instance
		}
		if instance == "" {
			return nil, errors.New("salesforce: token response has no instance_url; set instance_url")
		}
		status, raw, err := p.do(ctx, method, instance+"/services/data/"+p.cfg.APIVersion+path, s.token, payload)
		if err != nil {
			return nil, err
		}
		if status == http.StatusUnauthorized && attempt == 0 {
			stale = s
			continue
		}
		if status < 200 || status > 299 {
			ae := &APIError{Status: status}
			_ = json.Unmarshal(raw, &ae.Errors)
			return nil, fmt.Errorf("%s %s: %w", method, path, ae)
		}
		return raw, nil
	}
}

func (p *Plugin) do(ctx context.Context, method, u, token string, payload []byte) (int, []byte, error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tenarium-salesforce/"+version)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("salesforce: %s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return 0, nil, fmt.Errorf("salesforce: %s: %w", method, err)
	}
	return resp.StatusCode, raw, nil
}
