package social

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/AimTune/tenarium/internal/netguard"
)

// Provider types.
const (
	TypeGoogle    = "google"
	TypeGitHub    = "github"
	TypeMicrosoft = "microsoft"
	TypeOIDC      = "oidc"
)

const (
	googleIssuer     = "https://accounts.google.com"
	microsoftBaseURL = "https://login.microsoftonline.com"
	githubAuthURL    = "https://github.com/login/oauth/authorize"
	githubTokenURL   = "https://github.com/login/oauth/access_token" //nolint:gosec // G101: a URL, not a credential
	githubAPIURL     = "https://api.github.com"
)

// Config configures platform social sign-in.
type Config struct {
	// PublicURL is where Tenarium is reachable. The redirect URI to
	// register at each provider is
	// PublicURL + "/v1/auth/social/{name}/callback".
	PublicURL string `yaml:"public_url"`
	// AllowedRedirects are extra origins return_to may point to (besides
	// PublicURL's), e.g. the application's frontend.
	AllowedRedirects []string `yaml:"allowed_redirects"`
	// AllowPrivateIssuers lets providers live on internal addresses and
	// plain http (development and tests only).
	AllowPrivateIssuers bool `yaml:"allow_private_issuers"`
	// Providers are the enabled providers, listed in this order.
	Providers []ProviderConfig `yaml:"providers"`
}

// ProviderConfig configures one provider.
type ProviderConfig struct {
	// Name identifies the provider in URLs ([a-z0-9_-], at most 32
	// characters), e.g. "google" or "okta".
	Name string `yaml:"name"`
	// Type is "google", "github", "microsoft" or "oidc".
	Type string `yaml:"type"`
	// Label is shown on the sign-in button (default: derived from Type).
	Label        string `yaml:"label"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// Issuer is the OpenID Connect issuer URL. Required for "oidc";
	// defaults to https://accounts.google.com for "google"; for
	// "microsoft" it overrides the discovery URL derived from Tenant
	// (e.g. for national clouds).
	Issuer string `yaml:"issuer"`
	// Tenant is the Microsoft Entra directory: a tenant ID or verified
	// domain (single-tenant, recommended) or "organizations", "common" or
	// "consumers" (multi-tenant: then any Microsoft account may
	// authenticate, so set AllowedDomains). Required for "microsoft"
	// unless Issuer is set.
	Tenant string `yaml:"tenant"`
	// Scopes requested (default: openid, email, profile; for GitHub:
	// read:user, user:email). "openid" is always added for OIDC types.
	Scopes []string `yaml:"scopes"`
	// AllowedDomains, when set, restricts sign-in to these email domains.
	AllowedDomains []string `yaml:"allowed_domains"`
	// AutoCreate lets the tenant service create a user that does not
	// exist yet.
	AutoCreate bool `yaml:"auto_create"`
	// AuthURL, TokenURL and APIURL override GitHub's endpoints (GitHub
	// Enterprise Server, tests).
	AuthURL  string `yaml:"auth_url"`
	TokenURL string `yaml:"token_url"`
	APIURL   string `yaml:"api_url"`
}

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	tenantRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
)

// Validate checks the configuration.
func (c Config) Validate() error {
	if err := c.checkURL(c.PublicURL, true); err != nil {
		return fmt.Errorf("social: public_url: %w", err)
	}
	for _, r := range c.AllowedRedirects {
		u, err := url.Parse(r)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("social: allowed_redirects: %q must be an absolute URL", r)
		}
	}
	seen := map[string]bool{}
	var errs []error
	for i, p := range c.Providers {
		if err := c.validateProvider(p); err != nil {
			errs = append(errs, fmt.Errorf("social: providers[%d] (%s): %w", i, p.Name, err))
			continue
		}
		if seen[p.Name] {
			errs = append(errs, fmt.Errorf("social: providers[%d]: duplicate name %q", i, p.Name))
		}
		seen[p.Name] = true
	}
	return errors.Join(errs...)
}

func (c Config) validateProvider(p ProviderConfig) error {
	if !nameRe.MatchString(p.Name) {
		return errors.New("name must match [a-z0-9][a-z0-9_-]{0,31}")
	}
	if p.ClientID == "" || p.ClientSecret == "" {
		return errors.New("client_id and client_secret are required")
	}
	for _, d := range p.AllowedDomains {
		d = strings.TrimSpace(d)
		if d == "" || strings.ContainsAny(d, "@/ ") {
			return fmt.Errorf("allowed_domains: invalid domain %q", d)
		}
	}
	switch p.Type {
	case TypeGoogle:
		if p.Issuer != "" {
			return c.checkURL(p.Issuer, false)
		}
	case TypeOIDC:
		if p.Issuer == "" {
			return errors.New("issuer is required")
		}
		return c.checkURL(p.Issuer, false)
	case TypeMicrosoft:
		if p.Issuer != "" {
			return c.checkURL(p.Issuer, false)
		}
		if !tenantRe.MatchString(p.Tenant) {
			return errors.New(`tenant is required (a tenant ID or domain, or "organizations", "common" or "consumers")`)
		}
	case TypeGitHub:
		for _, u := range []string{p.AuthURL, p.TokenURL, p.APIURL} {
			if u != "" {
				if err := c.checkURL(u, false); err != nil {
					return err
				}
			}
		}
	default:
		return fmt.Errorf("unknown type %q (want google, github, microsoft or oidc)", p.Type)
	}
	return nil
}

// checkURL requires an absolute https URL (http and internal hosts too
// when AllowPrivateIssuers; always http for public_url).
func (c Config) checkURL(raw string, public bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%q must be an absolute URL", raw)
	}
	if public || c.AllowPrivateIssuers {
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%q must use https", raw)
	}
	return netguard.CheckHost(u.Hostname())
}

func defaultLabel(p ProviderConfig) string {
	switch {
	case p.Label != "":
		return p.Label
	case p.Type == TypeGoogle:
		return "Google"
	case p.Type == TypeGitHub:
		return "GitHub"
	case p.Type == TypeMicrosoft:
		return "Microsoft"
	}
	return p.Name
}
