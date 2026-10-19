package tenantmw

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Claims are the claims of a verified Tenarium access token.
type Claims struct {
	jwt.Claims
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	TenantID string   `json:"tid,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	// Region is the tenant's region (tenant tokens), for routing.
	Region string `json:"region,omitempty"`
}

// ErrForeignToken means a bearer token is not a JWT or was issued by
// someone else; FromToken ignores such tokens.
var ErrForeignToken = errors.New("tenantmw: not a tenarium token")

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	// JWKSURL is Tenarium's key set, "<base>/.well-known/jwks.json".
	JWKSURL string
	// Issuer is the expected iss claim (Tenarium's users.public_url or
	// auth.tokens.issuer). Required.
	Issuer string
	// Audience is the expected aud claim (default "tenarium").
	Audience string
	// HTTPClient fetches the key set (default: 10s timeout client).
	HTTPClient *http.Client
	// KeysTTL is how long a fetched key set is used before it is fetched
	// again (default 1h). Unknown key IDs trigger an earlier refresh.
	KeysTTL time.Duration
	// MinRefreshInterval limits refreshes caused by unknown key IDs
	// (default 30s), so forged kids cannot hammer the JWKS endpoint.
	MinRefreshInterval time.Duration
	// Leeway tolerates clock skew in exp/nbf/iat (default 30s).
	Leeway time.Duration
}

// Verifier verifies ES256 access tokens issued by Tenarium against its
// JWKS. Keys are cached and refreshed when a token names an unknown key.
type Verifier struct {
	cfg VerifierConfig
	now func() time.Time

	fetchMu sync.Mutex // serializes fetches
	mu      sync.RWMutex
	keys    map[string]*jose.JSONWebKey
	fetched time.Time
}

// NewVerifier returns a Verifier. Keys are fetched lazily on first use.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.JWKSURL == "" || cfg.Issuer == "" {
		return nil, errors.New("tenantmw: verifier needs JWKSURL and Issuer")
	}
	cfg.Audience = cmp.Or(cfg.Audience, "tenarium")
	cfg.KeysTTL = cmp.Or(cfg.KeysTTL, time.Hour)
	cfg.MinRefreshInterval = cmp.Or(cfg.MinRefreshInterval, 30*time.Second)
	cfg.Leeway = cmp.Or(cfg.Leeway, 30*time.Second)
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{cfg: cfg, now: time.Now}, nil
}

// DiscoverVerifier reads "<baseURL>/.well-known/openid-configuration" and
// returns a Verifier for its issuer and jwks_uri.
func DiscoverVerifier(ctx context.Context, baseURL string, client *http.Client) (*Verifier, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := getJSON(ctx, client, strings.TrimRight(baseURL, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("tenantmw: discovery: %w", err)
	}
	return NewVerifier(VerifierConfig{JWKSURL: doc.JWKSURI, Issuer: doc.Issuer, HTTPClient: client})
}

// Verify checks the token's signature, issuer, audience and lifetime. It
// returns ErrForeignToken for non-JWTs and tokens of other issuers, and an
// error wrapping ErrInvalidToken when a Tenarium token is not valid.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		if strings.Count(raw, ".") == 2 {
			// A JWT with another algorithm: foreign unless it claims our issuer.
			if iss := unverifiedIssuer(raw); iss == v.cfg.Issuer {
				return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
			}
		}
		return nil, ErrForeignToken
	}
	var unverified jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&unverified); err != nil || unverified.Issuer != v.cfg.Issuer {
		return nil, ErrForeignToken
	}
	if len(tok.Headers) != 1 {
		return nil, fmt.Errorf("%w: unexpected headers", ErrInvalidToken)
	}
	key, err := v.key(ctx, tok.Headers[0].KeyID)
	if err != nil {
		return nil, err
	}
	var c Claims
	if err := tok.Claims(key.Key, &c); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	exp := jwt.Expected{Issuer: v.cfg.Issuer, AnyAudience: jwt.Audience{v.cfg.Audience}, Time: v.now()}
	if err := c.ValidateWithLeeway(exp, v.cfg.Leeway); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if c.Expiry == nil {
		return nil, fmt.Errorf("%w: no expiry", ErrInvalidToken)
	}
	return &c, nil
}

// key returns the public key for kid, refreshing the key set when it is
// stale or does not contain kid.
func (v *Verifier) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	if k, fresh := v.lookup(kid); k != nil && fresh {
		return k, nil
	}
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	// Another goroutine may have refreshed while we waited.
	k, fresh := v.lookup(kid)
	if k != nil && fresh {
		return k, nil
	}
	v.mu.RLock()
	since := v.now().Sub(v.fetched)
	never := v.fetched.IsZero()
	v.mu.RUnlock()
	if never || !fresh || since >= v.cfg.MinRefreshInterval {
		if err := v.refresh(ctx); err != nil {
			if k != nil {
				return k, nil // serve the stale key rather than fail
			}
			return nil, fmt.Errorf("tenantmw: fetch jwks: %w", err)
		}
		k, _ = v.lookup(kid)
	}
	if k == nil {
		return nil, fmt.Errorf("%w: unknown signing key %q", ErrInvalidToken, kid)
	}
	return k, nil
}

func (v *Verifier) lookup(kid string) (k *jose.JSONWebKey, fresh bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keys[kid], !v.fetched.IsZero() && v.now().Sub(v.fetched) < v.cfg.KeysTTL
}

func (v *Verifier) refresh(ctx context.Context) error {
	var set jose.JSONWebKeySet
	if err := getJSON(ctx, v.cfg.HTTPClient, v.cfg.JWKSURL, &set); err != nil {
		return err
	}
	keys := make(map[string]*jose.JSONWebKey, len(set.Keys))
	for i := range set.Keys {
		k := set.Keys[i]
		if k.IsPublic() && (k.Use == "" || k.Use == "sig") {
			keys[k.KeyID] = &k
		}
	}
	v.mu.Lock()
	v.keys, v.fetched = keys, v.now()
	v.mu.Unlock()
	return nil
}

func unverifiedIssuer(raw string) string {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{
		jose.HS256, jose.HS384, jose.HS512, jose.RS256, jose.RS384, jose.RS512,
		jose.ES384, jose.ES512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA,
	})
	if err != nil {
		return ""
	}
	var c jwt.Claims
	if tok.UnsafeClaimsWithoutVerification(&c) != nil {
		return ""
	}
	return c.Issuer
}

func getJSON(ctx context.Context, client *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
