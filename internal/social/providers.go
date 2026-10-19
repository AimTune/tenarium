package social

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const providerTTL = time.Hour

// provider is a configured provider with its discovery cache.
type provider struct {
	cfg     ProviderConfig
	label   string
	domains []string // lower-case
	scopes  []string
	issuer  string // OIDC types: discovery URL

	mu      sync.Mutex
	op      *oidc.Provider
	fetched time.Time
	// tokenIssuer is the issuer ID tokens must carry (Microsoft: from
	// discovery; may contain the "{tenantid}" placeholder).
	tokenIssuer string
}

func newProvider(c ProviderConfig) *provider {
	p := &provider{cfg: c, label: defaultLabel(c)}
	for _, d := range c.AllowedDomains {
		p.domains = append(p.domains, strings.ToLower(strings.TrimSpace(d)))
	}
	p.scopes = slices.Clone(c.Scopes)
	switch c.Type {
	case TypeGitHub:
		if len(p.scopes) == 0 {
			p.scopes = []string{"read:user", "user:email"}
		}
		if p.cfg.AuthURL == "" {
			p.cfg.AuthURL = githubAuthURL
		}
		if p.cfg.TokenURL == "" {
			p.cfg.TokenURL = githubTokenURL
		}
		if p.cfg.APIURL == "" {
			p.cfg.APIURL = githubAPIURL
		}
		p.cfg.APIURL = strings.TrimRight(p.cfg.APIURL, "/")
		return p
	case TypeGoogle:
		p.issuer = c.Issuer
		if p.issuer == "" {
			p.issuer = googleIssuer
		}
	case TypeMicrosoft:
		p.issuer = c.Issuer
		if p.issuer == "" {
			p.issuer = microsoftBaseURL + "/" + c.Tenant + "/v2.0"
		}
	default:
		p.issuer = c.Issuer
	}
	if len(p.scopes) == 0 {
		p.scopes = []string{"email", "profile"}
	}
	if !slices.Contains(p.scopes, oidc.ScopeOpenID) {
		p.scopes = append([]string{oidc.ScopeOpenID}, p.scopes...)
	}
	return p
}

func (p *provider) isOIDC() bool { return p.cfg.Type != TypeGitHub }

// discover returns the (cached) OpenID provider.
func (p *provider) discover(ctx context.Context, client *http.Client) (*oidc.Provider, string, error) {
	p.mu.Lock()
	op, iss, fetched := p.op, p.tokenIssuer, p.fetched
	p.mu.Unlock()
	if op != nil && time.Since(fetched) < providerTTL {
		return op, iss, nil
	}
	ctx = oidc.ClientContext(ctx, client)
	if p.cfg.Type == TypeMicrosoft {
		// Microsoft's discovery documents for "common", "organizations",
		// "consumers" and domain names carry an issuer different from the
		// discovery URL ("https://login.microsoftonline.com/{tenantid}/v2.0"
		// or a tenant GUID); ID tokens are checked against it in verify.
		ctx = oidc.InsecureIssuerURLContext(ctx, p.issuer)
	}
	op, err := oidc.NewProvider(ctx, p.issuer)
	if err != nil {
		return nil, "", fmt.Errorf("discovery of %s: %w", p.issuer, err)
	}
	iss = p.issuer
	if p.cfg.Type == TypeMicrosoft {
		var meta struct {
			Issuer string `json:"issuer"`
		}
		if err := op.Claims(&meta); err != nil || meta.Issuer == "" {
			return nil, "", fmt.Errorf("discovery of %s: no issuer", p.issuer)
		}
		iss = meta.Issuer
	}
	p.mu.Lock()
	p.op, p.tokenIssuer, p.fetched = op, iss, time.Now()
	p.mu.Unlock()
	return op, iss, nil
}

// oauth returns the OAuth 2.0 client configuration.
func (p *provider) oauth(ctx context.Context, client *http.Client, redirect string) (*oauth2.Config, error) {
	c := &oauth2.Config{ClientID: p.cfg.ClientID, ClientSecret: p.cfg.ClientSecret, RedirectURL: redirect, Scopes: p.scopes}
	if !p.isOIDC() {
		c.Endpoint = oauth2.Endpoint{AuthURL: p.cfg.AuthURL, TokenURL: p.cfg.TokenURL, AuthStyle: oauth2.AuthStyleInParams}
		return c, nil
	}
	op, _, err := p.discover(ctx, client)
	if err != nil {
		return nil, err
	}
	c.Endpoint = op.Endpoint()
	return c, nil
}

// flexBool accepts true and "true" (some providers send strings).
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(data), `"`) {
	case "true":
		*b = true
	default:
		*b = false
	}
	return nil
}

// verifyIDToken checks the ID token of tok and returns the identity it
// asserts (email not yet checked for verification or domain).
func (p *provider) verifyIDToken(ctx context.Context, client *http.Client, tok *oauth2.Token, nonce string, now func() time.Time) (Identity, bool, error) {
	op, wantIss, err := p.discover(ctx, client)
	if err != nil {
		return Identity{}, false, err
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, false, errors.New("no id_token in token response")
	}
	ms := p.cfg.Type == TypeMicrosoft
	idt, err := op.Verifier(&oidc.Config{ClientID: p.cfg.ClientID, SkipIssuerCheck: ms, Now: now}).Verify(oidc.ClientContext(ctx, client), raw)
	if err != nil {
		return Identity{}, false, fmt.Errorf("id token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
		return Identity{}, false, errors.New("id token: nonce mismatch")
	}
	var claims struct {
		Email         string   `json:"email"`
		EmailVerified flexBool `json:"email_verified"`
		Name          string   `json:"name"`
		TenantID      string   `json:"tid"`
		// xms_edov: Microsoft's "email domain owner verified" optional claim.
		DomainVerified flexBool `json:"xms_edov"`
	}
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, false, fmt.Errorf("id token claims: %w", err)
	}
	verified := bool(claims.EmailVerified)
	if ms {
		if strings.Contains(wantIss, "{tenantid}") {
			if !tenantRe.MatchString(claims.TenantID) {
				return Identity{}, false, errors.New("id token: missing tid")
			}
			wantIss = strings.ReplaceAll(wantIss, "{tenantid}", claims.TenantID)
		}
		if idt.Issuer != wantIss {
			return Identity{}, false, fmt.Errorf("id token: issuer %q, want %q", idt.Issuer, wantIss)
		}
		// Entra ID does not emit email_verified; its email claim is only
		// trustworthy when the domain owner verified it (xms_edov).
		verified = verified || bool(claims.DomainVerified)
	}
	return Identity{Subject: idt.Subject, Email: claims.Email, Name: claims.Name}, verified, nil
}

const maxAPIResponse = 1 << 20

// githubIdentity reads the user and their primary verified email.
func (p *provider) githubIdentity(ctx context.Context, client *http.Client, tok *oauth2.Token) (Identity, bool, error) {
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := p.githubGet(ctx, client, tok, "/user", &user); err != nil {
		return Identity{}, false, err
	}
	if user.ID == 0 {
		return Identity{}, false, errors.New("github: user without id")
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := p.githubGet(ctx, client, tok, "/user/emails", &emails); err != nil {
		return Identity{}, false, err
	}
	id := Identity{Subject: strconv.FormatInt(user.ID, 10), Name: user.Name}
	if id.Name == "" {
		id.Name = user.Login
	}
	for _, e := range emails {
		if e.Primary {
			id.Email = e.Email
			return id, e.Verified, nil
		}
	}
	return id, false, nil
}

func (p *provider) githubGet(ctx context.Context, client *http.Client, tok *oauth2.Token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.APIURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("github %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github %s: %s", path, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAPIResponse)).Decode(out); err != nil {
		return fmt.Errorf("github %s: %w", path, err)
	}
	return nil
}
