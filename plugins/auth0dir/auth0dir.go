// Package auth0dir keeps Tenarium's platform users in an Auth0 database
// connection, through the Auth0 Management API v2.
//
// The plugin registers an sdk.UserDirectory that creates, updates, blocks
// and deletes Auth0 users and sets their passwords. Every Auth0 user it
// manages carries app_metadata.tenarium.user_id, the ID of the owning
// Tenarium user; an existing Auth0 user with the same email and no owner is
// adopted. Optionally it:
//
//   - verifies passwords (sdk.PasswordVerifier) with the Resource Owner
//     Password grant ("password-realm") of an Auth0 application, and
//   - sends invitations (sdk.InvitationSender) through Auth0's own emails:
//     the "change password" email or the "verify email" email.
package auth0dir

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("auth0-directory", func() sdk.Plugin { return &Plugin{} })
}

// MetadataKey is the app_metadata key under which the plugin stores the
// owning Tenarium user ID and the user's attributes.
const MetadataKey = "tenarium"

// ErrInvalidCredentials is returned by VerifyPassword when Auth0 rejects the
// email and password.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrMFARequired is returned by VerifyPassword when the credentials are
// correct but Auth0 demands a second factor, which the password grant used
// by Tenarium cannot satisfy.
var ErrMFARequired = errors.New("multi-factor authentication required")

// Invitation modes.
const (
	InvitationNone           = "none"
	InvitationChangePassword = "change_password_email"
	InvitationVerifyEmail    = "verification_email"
)

// Config is the plugin's configuration block.
type Config struct {
	// Domain is the Auth0 tenant domain, e.g. "acme.eu.auth0.com" or a full
	// base URL such as "https://acme.eu.auth0.com".
	Domain string `json:"domain"`
	// ClientID and ClientSecret are a machine-to-machine application
	// authorized for the Management API with the read:users, create:users,
	// update:users and delete:users scopes.
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// Audience of the Management API; default "https://{domain}/api/v2/".
	// Set it when Domain is a custom domain.
	Audience string `json:"audience"`
	// Connection is the database connection holding the users, e.g.
	// "Username-Password-Authentication".
	Connection string `json:"connection"`
	// VerifyEmail makes Auth0 send its verification email when a user whose
	// email is not verified is created.
	VerifyEmail bool `json:"verify_email"`
	// Invitation selects how invitations are sent: "none" (default:
	// Tenarium sends its own), "change_password_email" (Auth0's password
	// reset email, which lets the user choose a password) or
	// "verification_email".
	Invitation string `json:"invitation"`
	// InvitationClientID is the application named in Auth0 emails; it must
	// be enabled for Connection. Default: password_login.client_id or
	// client_id.
	InvitationClientID string `json:"invitation_client_id"`
	// PasswordLogin, when set, enables password verification.
	PasswordLogin *PasswordLoginConfig `json:"password_login"`
	// Timeout per request; default "10s".
	Timeout string `json:"timeout"`
}

// PasswordLoginConfig configures password verification with the
// password-realm grant.
type PasswordLoginConfig struct {
	// ClientID and ClientSecret name an application with the "Password"
	// grant type enabled; default the Management API client.
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// Audience, if set, is requested for the token (only needed by some
	// tenant configurations).
	Audience string `json:"audience"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["domain", "client_id", "client_secret", "connection"],
  "additionalProperties": false,
  "properties": {
    "domain": {"type": "string", "minLength": 1},
    "client_id": {"type": "string", "minLength": 1},
    "client_secret": {"type": "string", "minLength": 1},
    "audience": {"type": "string"},
    "connection": {"type": "string", "minLength": 1},
    "verify_email": {"type": "boolean"},
    "invitation": {"enum": ["none", "change_password_email", "verification_email"]},
    "invitation_client_id": {"type": "string"},
    "password_login": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "client_id": {"type": "string"},
        "client_secret": {"type": "string"},
        "audience": {"type": "string"}
      }
    },
    "timeout": {"type": "string"}
  }
}`)

// Plugin is the Auth0 user directory plugin.
type Plugin struct {
	cfg    Config
	base   string       // e.g. https://acme.eu.auth0.com
	api    *http.Client // adds the Management API token
	client *http.Client // unauthenticated (token, login, emails)
	tokens oauth2.TokenSource
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "auth0-directory",
		Name:         "Auth0 user directory",
		Version:      "0.1.0",
		Description:  "Keeps platform users in an Auth0 database connection through the Management API.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.configure(); err != nil {
		return err
	}
	d := &directory{p: p}
	if p.cfg.PasswordLogin != nil {
		r.UserDirectory(verifyingDirectory{d})
	} else {
		r.UserDirectory(d)
	}
	return nil
}

// configure validates the configuration, applies defaults and builds the
// HTTP clients.
func (p *Plugin) configure() error {
	c := &p.cfg
	base := strings.TrimRight(strings.TrimSpace(c.Domain), "/")
	if base == "" {
		return errors.New("domain is required")
	}
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("domain must be a host name or an http(s) base URL, got %q", c.Domain)
	}
	p.base = base
	if c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("client_id and client_secret are required")
	}
	if c.Connection == "" {
		return errors.New("connection is required")
	}
	c.Audience = cmp.Or(c.Audience, base+"/api/v2/")
	c.Invitation = cmp.Or(c.Invitation, InvitationNone)
	switch c.Invitation {
	case InvitationNone, InvitationChangePassword, InvitationVerifyEmail:
	default:
		return fmt.Errorf("invitation must be none, change_password_email or verification_email, got %q", c.Invitation)
	}
	if pl := c.PasswordLogin; pl != nil {
		if pl.ClientID == "" {
			if pl.ClientSecret != "" {
				return errors.New("password_login.client_secret needs password_login.client_id")
			}
			pl.ClientID, pl.ClientSecret = c.ClientID, c.ClientSecret
		}
	}
	if c.InvitationClientID == "" {
		c.InvitationClientID = c.ClientID
		if c.PasswordLogin != nil {
			c.InvitationClientID = c.PasswordLogin.ClientID
		}
	}
	timeout := 10 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
	}
	p.client = &http.Client{Timeout: timeout}
	cc := &clientcredentials.Config{
		ClientID:       c.ClientID,
		ClientSecret:   c.ClientSecret,
		TokenURL:       base + "/oauth/token",
		EndpointParams: url.Values{"audience": {c.Audience}},
		AuthStyle:      oauth2.AuthStyleInParams,
	}
	// The token source outlives any request, so it gets its own context.
	tokenCtx := context.WithValue(context.Background(), oauth2.HTTPClient, p.client)
	p.tokens = cc.TokenSource(tokenCtx)
	p.api = &http.Client{
		Timeout:   timeout,
		Transport: &oauth2.Transport{Source: p.tokens, Base: http.DefaultTransport},
	}
	return nil
}

// Health obtains a Management API token (cached while valid) and makes a
// cheap users-by-email lookup, which needs the read:users scope the
// directory relies on.
func (p *Plugin) Health(ctx context.Context) error {
	q := url.Values{"email": {"healthcheck@tenarium.invalid"}, "fields": {"user_id"}}
	status, body, err := p.do(ctx, http.MethodGet, "/api/v2/users-by-email", q, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("health", status, body)
	}
	return nil
}

// do sends a Management API request and returns the status and body.
func (p *Plugin) do(ctx context.Context, method, path string, q url.Values, in any) (int, []byte, error) {
	target := p.base + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	return send(ctx, p.api, method, target, in)
}

func send(ctx context.Context, c *http.Client, method, target string, in any) (int, []byte, error) {
	var payload io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, nil, err
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("auth0: %s %s: %w", method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

func apiError(op string, status int, body []byte) error {
	return fmt.Errorf("auth0: %s: %s: %s", op, http.StatusText(status), errorMessage(body))
}

// errorMessage extracts Auth0's error text from a JSON error body. It never
// contains the submitted password.
func errorMessage(body []byte) string {
	var e struct {
		Message          string `json:"message"`
		ErrorDescription string `json:"error_description"`
		Error            string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil {
		if msg := cmp.Or(e.Message, e.ErrorDescription, e.Error); msg != "" {
			return msg
		}
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return msg
}

// randomPassword returns a password satisfying every Auth0 password policy
// level ("excellent": 4 character classes, no 3 identical characters in a
// row). Nobody knows it; it only exists because database connections
// require a password at creation.
func randomPassword() (string, error) {
	for {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		pw := base64.RawURLEncoding.EncodeToString(b) + "aA1!"
		if !hasTriple(pw) {
			return pw, nil
		}
	}
}

// hasTriple reports whether s contains three identical bytes in a row.
func hasTriple(s string) bool {
	for i := 2; i < len(s); i++ {
		if s[i-2] == s[i-1] && s[i-1] == s[i] {
			return true
		}
	}
	return false
}
