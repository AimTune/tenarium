// Package oidc authenticates API callers with OIDC/JWT bearer tokens issued
// by an identity provider such as Keycloak, Auth0, Entra ID, Okta or Dex.
//
// Signing keys are discovered from the issuer's
// /.well-known/openid-configuration (or taken from jwks_url). Discovery is
// lazy: an unreachable IdP at startup does not prevent Tenarium from
// booting; it is retried on first use. Claims are mapped to a Principal:
// roles and groups (optionally renamed through role_mapping) become roles,
// and an optional tenant claim scopes the principal to one tenant.
//
// Several instances may coexist, one per issuer. Tokens whose iss does not
// match an instance are passed on to the next authenticator.
package oidc

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/coreos/go-oidc/v3/oidc"
)

func init() {
	sdk.Register("oidc", func() sdk.Plugin { return &Plugin{} })
}

type Config struct {
	Issuer string `json:"issuer"`
	// JWKSURL skips discovery and fetches signing keys from this URL.
	JWKSURL string `json:"jwks_url"`
	// Audience is the expected aud; ClientID is accepted as an alias.
	Audience     string `json:"audience"`
	ClientID     string `json:"client_id"`
	SubjectClaim string `json:"subject_claim"`
	EmailClaim   string `json:"email_claim"`
	// RolesClaim and GroupsClaim are dotted paths into the claims, holding
	// a string array or a space/comma separated string.
	RolesClaim  string `json:"roles_claim"`
	GroupsClaim string `json:"groups_claim"`
	// RoleMapping renames IdP roles/groups to Tenarium roles. When set,
	// unmapped values are dropped.
	RoleMapping map[string]string `json:"role_mapping"`
	// TenantClaim is a dotted path to a tenant ID or slug.
	TenantClaim string `json:"tenant_claim"`
	// AllowMissingTenant accepts tokens without the tenant claim as
	// platform-wide principals (e.g. staff in the same realm). By default a
	// missing claim is rejected, so a token can never fail open to
	// platform-wide access.
	AllowMissingTenant bool `json:"allow_missing_tenant"`
	// Kind is "user" (default) or "service".
	Kind string `json:"kind"`
	// ClockSkew tolerated on exp, e.g. "30s".
	ClockSkew string `json:"clock_skew"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "issuer": {"type": "string", "minLength": 1},
    "jwks_url": {"type": "string"},
    "audience": {"type": "string"},
    "client_id": {"type": "string"},
    "subject_claim": {"type": "string"},
    "email_claim": {"type": "string"},
    "roles_claim": {"type": "string"},
    "groups_claim": {"type": "string"},
    "role_mapping": {"type": "object", "additionalProperties": {"type": "string"}},
    "tenant_claim": {"type": "string"},
    "allow_missing_tenant": {"type": "boolean"},
    "kind": {"enum": ["user", "service"]},
    "clock_skew": {"type": "string"}
  },
  "required": ["issuer"],
  "additionalProperties": false
}`)

const (
	tenantCacheTTL = time.Minute
	httpTimeout    = 10 * time.Second
)

var signingAlgs = []string{
	oidc.RS256, oidc.RS384, oidc.RS512,
	oidc.ES256, oidc.ES384, oidc.ES512,
	oidc.PS256, oidc.PS384, oidc.PS512, oidc.EdDSA,
}

type Plugin struct {
	cfg      Config
	audience string
	skew     time.Duration
	host     sdk.Host
	log      *slog.Logger
	client   *http.Client
	now      func() time.Time
	// retryEvery throttles discovery attempts after a failure.
	retryEvery time.Duration

	mu          sync.Mutex
	verifier    *oidc.IDTokenVerifier
	lastAttempt time.Time
	lastErr     error

	tenantMu sync.Mutex
	tenants  map[string]tenantEntry
}

type tenantEntry struct {
	id      string
	err     error
	expires time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "oidc",
		Name:         "OIDC / JWT",
		Version:      "0.1.0",
		Description:  "Authenticates OIDC/JWT bearer tokens and maps claims to principals.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if p.cfg.Issuer == "" {
		return errors.New("issuer is required")
	}
	p.cfg.SubjectClaim = cmp.Or(p.cfg.SubjectClaim, "sub")
	p.cfg.EmailClaim = cmp.Or(p.cfg.EmailClaim, "email")
	p.cfg.RolesClaim = cmp.Or(p.cfg.RolesClaim, "realm_access.roles")
	p.cfg.Kind = cmp.Or(p.cfg.Kind, "user")
	if p.cfg.Kind != "user" && p.cfg.Kind != "service" {
		return fmt.Errorf("kind must be \"user\" or \"service\", got %q", p.cfg.Kind)
	}
	p.skew = 30 * time.Second
	if p.cfg.ClockSkew != "" {
		d, err := time.ParseDuration(p.cfg.ClockSkew)
		if err != nil || d < 0 {
			return fmt.Errorf("clock_skew: invalid duration %q", p.cfg.ClockSkew)
		}
		p.skew = d
	}
	p.audience = cmp.Or(p.cfg.Audience, p.cfg.ClientID)
	p.log = r.Logger()
	p.host = r.Host()
	p.client = &http.Client{Timeout: httpTimeout}
	if p.now == nil {
		p.now = time.Now
	}
	if p.retryEvery == 0 {
		p.retryEvery = 5 * time.Second
	}
	p.tenants = map[string]tenantEntry{}
	if p.audience == "" {
		p.log.Warn("no audience configured; tokens are accepted for any audience of this issuer", "issuer", p.cfg.Issuer)
	}

	// Best effort: an unreachable IdP must not abort startup.
	ictx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := p.getVerifier(ictx); err != nil {
		p.log.Warn("OIDC discovery failed; will retry on first use", "issuer", p.cfg.Issuer, "error", err)
	}
	r.Authenticator(p)
	return nil
}

func (p *Plugin) Name() string { return "jwt" }

func (p *Plugin) oidcConfig() *oidc.Config {
	c := &oidc.Config{
		ClientID:          p.audience,
		SkipClientIDCheck: p.audience == "",
		Now:               func() time.Time { return p.now().Add(-p.skew) },
	}
	if p.cfg.JWKSURL != "" {
		c.SupportedSigningAlgs = signingAlgs
	}
	return c
}

// getVerifier returns the token verifier, performing discovery if it has not
// succeeded yet. Failed attempts are throttled to one per retryEvery.
func (p *Plugin) getVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.verifier != nil {
		return p.verifier, nil
	}
	if !p.lastAttempt.IsZero() && p.now().Sub(p.lastAttempt) < p.retryEvery {
		return nil, fmt.Errorf("oidc discovery for %s unavailable: %w", p.cfg.Issuer, p.lastErr)
	}
	p.lastAttempt = p.now()
	if p.cfg.JWKSURL != "" {
		keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), p.client), p.cfg.JWKSURL)
		p.verifier = oidc.NewVerifier(p.cfg.Issuer, keys, p.oidcConfig())
		return p.verifier, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, p.client), p.cfg.Issuer)
	if err != nil {
		p.lastErr = err
		return nil, fmt.Errorf("oidc discovery for %s: %w", p.cfg.Issuer, err)
	}
	p.verifier = provider.Verifier(p.oidcConfig())
	p.lastErr = nil
	return p.verifier, nil
}

func (p *Plugin) Authenticate(ctx context.Context, r *http.Request) (*sdk.Principal, error) {
	raw, ok := bearer(r)
	if !ok {
		return nil, sdk.ErrNoCredentials
	}
	iss, ok := unverifiedIssuer(raw)
	if !ok || strings.TrimSuffix(iss, "/") != strings.TrimSuffix(p.cfg.Issuer, "/") {
		return nil, sdk.ErrNoCredentials
	}
	v, err := p.getVerifier(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := v.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("invalid token claims: %w", err)
	}

	sub, _ := lookup(claims, p.cfg.SubjectClaim).(string)
	if sub == "" {
		return nil, fmt.Errorf("token has no %q claim", p.cfg.SubjectClaim)
	}
	pr := &sdk.Principal{
		Subject: sub,
		Kind:    p.cfg.Kind,
		Roles:   p.roles(claims),
		Claims:  map[string]any{"iss": tok.Issuer},
	}
	if email, ok := lookup(claims, p.cfg.EmailClaim).(string); ok && email != "" {
		pr.Claims["email"] = email
	}
	for _, k := range []string{"name", "preferred_username", "azp", "client_id"} {
		if v, ok := claims[k].(string); ok && v != "" {
			pr.Claims[k] = v
		}
	}
	if p.cfg.TenantClaim != "" {
		raw := lookup(claims, p.cfg.TenantClaim)
		ref := claimString(raw)
		switch {
		case ref != "":
			id, err := p.resolveTenant(ctx, ref)
			if err != nil {
				return nil, err
			}
			pr.TenantID = id
		case raw == nil && p.cfg.AllowMissingTenant:
			// Platform-wide principal, explicitly allowed.
		default:
			return nil, fmt.Errorf("token claim %q must hold exactly one tenant", p.cfg.TenantClaim)
		}
	}
	return pr, nil
}

func (p *Plugin) roles(claims map[string]any) []string {
	values := claimStrings(lookup(claims, p.cfg.RolesClaim))
	if p.cfg.GroupsClaim != "" {
		values = append(values, claimStrings(lookup(claims, p.cfg.GroupsClaim))...)
	}
	var out []string
	for _, v := range values {
		if len(p.cfg.RoleMapping) > 0 {
			mapped, ok := p.cfg.RoleMapping[v]
			if !ok || mapped == "" {
				continue
			}
			v = mapped
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// resolveTenant turns a tenant ID or slug into a tenant ID, caching
// lookups for tenantCacheTTL.
func (p *Plugin) resolveTenant(ctx context.Context, ref string) (string, error) {
	now := p.now()
	p.tenantMu.Lock()
	e, ok := p.tenants[ref]
	p.tenantMu.Unlock()
	if ok && now.Before(e.expires) {
		return e.id, e.err
	}
	t, err := p.host.GetTenant(ctx, ref)
	switch {
	case errors.Is(err, sdk.ErrNotFound):
		e = tenantEntry{err: fmt.Errorf("token tenant %q does not exist", ref)}
	case err != nil:
		return "", fmt.Errorf("resolve token tenant %q: %w", ref, err)
	case !t.IsLive():
		e = tenantEntry{err: fmt.Errorf("token tenant %q is %s", ref, t.Status)}
	default:
		e = tenantEntry{id: t.ID}
	}
	e.expires = now.Add(tenantCacheTTL)
	p.tenantMu.Lock()
	p.tenants[ref] = e
	p.tenantMu.Unlock()
	return e.id, e.err
}

// Health reports whether signing keys can be obtained from the IdP.
func (p *Plugin) Health(ctx context.Context) error {
	if p.cfg.JWKSURL == "" {
		_, err := p.getVerifier(ctx)
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: %s responded %s", p.cfg.JWKSURL, resp.Status)
	}
	return nil
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	return tok, tok != ""
}

// unverifiedIssuer extracts iss from a compact JWS without verifying it. It
// reports false if raw is not shaped like a JWT.
func unverifiedIssuer(raw string) (string, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", false
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", false
	}
	return c.Iss, true
}

// lookup resolves a dotted path such as "realm_access.roles". A key that
// itself contains dots (e.g. a namespaced Auth0 claim) is matched first.
func lookup(claims map[string]any, path string) any {
	if path == "" {
		return nil
	}
	if v, ok := claims[path]; ok {
		return v
	}
	var cur any = claims
	for part := range strings.SplitSeq(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}

func claimStrings(v any) []string {
	switch v := v.(type) {
	case string:
		return strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' })
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func claimString(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprint(v)
	case []any:
		if len(v) == 1 {
			return claimString(v[0])
		}
	}
	return ""
}
