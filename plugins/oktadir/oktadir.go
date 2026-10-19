// Package oktadir keeps Tenarium's platform users in an Okta org, through
// the Okta Users API.
//
// The plugin authenticates with an SSWS API token or, preferably, as an
// OAuth 2.0 service app (client credentials with a private key JWT) and
// registers an sdk.UserDirectory. Users are created staged (activate=false)
// with their email as login; disabling a user suspends (or deactivates) it,
// deleting deactivates and then deletes it. Optionally it:
//
//   - sends invitations (sdk.InvitationSender) as Okta activation emails,
//     and
//   - verifies passwords (sdk.PasswordVerifier) with the Okta Authentication
//     API (POST /api/v1/authn).
package oktadir

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("okta-directory", func() sdk.Plugin { return &Plugin{} })
}

// ErrInvalidCredentials is returned by VerifyPassword when Okta rejects the
// login and password (or the user is locked out or not active).
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrMFARequired is returned by VerifyPassword when the password is correct
// but the Okta sign-on policy demands a second factor.
var ErrMFARequired = errors.New("multi-factor authentication required")

// Disable actions.
const (
	DisableSuspend    = "suspend"
	DisableDeactivate = "deactivate"
)

// Config is the plugin's configuration block.
type Config struct {
	// OrgURL is the Okta org, e.g. "https://acme.okta.com".
	OrgURL string `json:"org_url"`
	// APIToken is an SSWS API token. Either it or OAuth is required.
	APIToken string `json:"api_token"`
	// OAuth authenticates as an API service app with a private key JWT.
	OAuth *OAuthConfig `json:"oauth"`
	// UserIDAttribute is a custom string property of the Okta user profile
	// (it must exist in the profile schema) holding the owning Tenarium user
	// ID. Without it ownership is not recorded and an existing user with the
	// same login is always adopted.
	UserIDAttribute string `json:"user_id_attribute"`
	// AttributeMap copies Tenarium user attributes to Okta profile
	// properties, e.g. {"dept": "department"}. Others are ignored.
	AttributeMap map[string]string `json:"attribute_map"`
	// DisableAction is what disabling a user does: "suspend" (default; the
	// user keeps app assignments, only possible for active users, others
	// are deactivated) or "deactivate".
	DisableAction string `json:"disable_action"`
	// SendInvitation sends invitations as Okta activation emails, in which
	// the user chooses a password in Okta. Otherwise Tenarium sends its own.
	SendInvitation bool `json:"send_invitation"`
	// VerifyPasswords enables password verification with the Okta
	// Authentication API.
	VerifyPasswords bool `json:"verify_passwords"`
	// Timeout per request; default "10s".
	Timeout string `json:"timeout"`
}

// OAuthConfig configures OAuth 2.0 for Okta management APIs.
type OAuthConfig struct {
	ClientID string `json:"client_id"`
	// PrivateKey is the PEM-encoded RSA or EC private key registered with
	// the service app; PrivateKeyFile reads it from a file instead.
	PrivateKey     string `json:"private_key"`
	PrivateKeyFile string `json:"private_key_file"`
	// KeyID is the "kid" of the registered public key.
	KeyID string `json:"key_id"`
	// Scopes requested; default okta.users.read and okta.users.manage.
	Scopes []string `json:"scopes"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["org_url"],
  "additionalProperties": false,
  "properties": {
    "org_url": {"type": "string", "pattern": "^https?://"},
    "api_token": {"type": "string"},
    "oauth": {
      "type": "object",
      "required": ["client_id"],
      "additionalProperties": false,
      "properties": {
        "client_id": {"type": "string", "minLength": 1},
        "private_key": {"type": "string"},
        "private_key_file": {"type": "string"},
        "key_id": {"type": "string"},
        "scopes": {"type": "array", "items": {"type": "string", "minLength": 1}}
      }
    },
    "user_id_attribute": {"type": "string"},
    "attribute_map": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
    "disable_action": {"enum": ["suspend", "deactivate"]},
    "send_invitation": {"type": "boolean"},
    "verify_passwords": {"type": "boolean"},
    "timeout": {"type": "string"}
  }
}`)

// Plugin is the Okta user directory plugin.
type Plugin struct {
	cfg    Config
	base   string
	api    *http.Client // authenticated management requests
	client *http.Client // unauthenticated (token, authn)
	now    func() time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "okta-directory",
		Name:         "Okta user directory",
		Version:      "0.1.0",
		Description:  "Keeps platform users in an Okta org through the Users API.",
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
	if p.cfg.VerifyPasswords {
		r.UserDirectory(verifyingDirectory{d})
	} else {
		r.UserDirectory(d)
	}
	return nil
}

var profileProperty = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// reserved are profile properties the directory manages itself.
var reserved = map[string]bool{"login": true, "email": true, "firstname": true, "lastname": true}

func (p *Plugin) configure() error {
	c := &p.cfg
	u, err := url.Parse(c.OrgURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("org_url must be an http(s) base URL such as https://acme.okta.com, got %q", c.OrgURL)
	}
	p.base = strings.TrimRight(c.OrgURL, "/")
	if p.now == nil {
		p.now = time.Now
	}
	timeout := 10 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
	}
	p.client = &http.Client{Timeout: timeout}
	switch {
	case c.APIToken != "" && c.OAuth != nil:
		return errors.New("api_token and oauth are mutually exclusive")
	case c.APIToken != "":
		p.api = &http.Client{Timeout: timeout, Transport: sswsTransport{token: c.APIToken, base: http.DefaultTransport}}
	case c.OAuth != nil:
		src, err := p.newAssertionSource(c.OAuth)
		if err != nil {
			return err
		}
		p.api = &http.Client{Timeout: timeout, Transport: &oauth2.Transport{
			Source: oauth2.ReuseTokenSource(nil, src), Base: http.DefaultTransport,
		}}
	default:
		return errors.New("either api_token or oauth is required")
	}
	c.DisableAction = cmp.Or(c.DisableAction, DisableSuspend)
	if c.DisableAction != DisableSuspend && c.DisableAction != DisableDeactivate {
		return fmt.Errorf("disable_action must be suspend or deactivate, got %q", c.DisableAction)
	}
	if c.UserIDAttribute != "" && (!profileProperty.MatchString(c.UserIDAttribute) || reserved[strings.ToLower(c.UserIDAttribute)]) {
		return fmt.Errorf("user_id_attribute: invalid or reserved profile property %q", c.UserIDAttribute)
	}
	seen := map[string]bool{strings.ToLower(c.UserIDAttribute): c.UserIDAttribute != ""}
	for k, prop := range c.AttributeMap {
		if k == "" || !profileProperty.MatchString(prop) || reserved[strings.ToLower(prop)] {
			return fmt.Errorf("attribute_map[%q]: invalid or reserved profile property %q", k, prop)
		}
		if seen[strings.ToLower(prop)] {
			return fmt.Errorf("attribute_map[%q]: property %q is used twice", k, prop)
		}
		seen[strings.ToLower(prop)] = true
	}
	return nil
}

func (p *Plugin) newAssertionSource(o *OAuthConfig) (*assertionSource, error) {
	if o.ClientID == "" {
		return nil, errors.New("oauth.client_id is required")
	}
	pemData := o.PrivateKey
	switch {
	case o.PrivateKey != "" && o.PrivateKeyFile != "":
		return nil, errors.New("oauth.private_key and oauth.private_key_file are mutually exclusive")
	case o.PrivateKeyFile != "":
		raw, err := os.ReadFile(o.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("oauth.private_key_file: %w", err)
		}
		pemData = string(raw)
	case o.PrivateKey == "":
		return nil, errors.New("oauth.private_key or oauth.private_key_file is required")
	}
	key, alg, err := parsePrivateKey([]byte(pemData))
	if err != nil {
		return nil, fmt.Errorf("oauth private key: %w", err)
	}
	scopes := o.Scopes
	if len(scopes) == 0 {
		scopes = []string{"okta.users.read", "okta.users.manage"}
	}
	return &assertionSource{
		tokenURL: p.base + "/oauth2/v1/token", clientID: o.ClientID, keyID: o.KeyID,
		key: key, alg: alg, scopes: strings.Join(scopes, " "), client: p.client, now: p.now,
	}, nil
}

// sswsTransport authenticates with an Okta API token.
type sswsTransport struct {
	token string
	base  http.RoundTripper
}

func (t sswsTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "SSWS "+t.token)
	return t.base.RoundTrip(r)
}

// Health lists one user, which needs valid credentials and okta.users.read.
func (p *Plugin) Health(ctx context.Context) error {
	status, body, err := p.do(ctx, http.MethodGet, "/api/v1/users", url.Values{"limit": {"1"}}, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("health", status, body)
	}
	return nil
}

// do sends a management API request and returns the status and body.
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
		return 0, nil, fmt.Errorf("okta: %s %s: %w", method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

func apiError(op string, status int, body []byte) error {
	return fmt.Errorf("okta: %s: %s: %s", op, http.StatusText(status), errorMessage(body))
}

// oktaError is Okta's error body.
type oktaError struct {
	ErrorCode    string `json:"errorCode"`
	ErrorSummary string `json:"errorSummary"`
	ErrorCauses  []struct {
		ErrorSummary string `json:"errorSummary"`
	} `json:"errorCauses"`
	// OAuth errors.
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func parseError(body []byte) oktaError {
	var e oktaError
	_ = json.Unmarshal(body, &e)
	return e
}

// errorMessage extracts Okta's error text, including its causes. Okta
// never echoes passwords.
func errorMessage(body []byte) string {
	e := parseError(body)
	if e.ErrorSummary != "" {
		msg := e.ErrorCode + ": " + e.ErrorSummary
		for _, c := range e.ErrorCauses {
			msg += "; " + c.ErrorSummary
		}
		return msg
	}
	if msg := cmp.Or(e.ErrorDescription, e.Error); msg != "" {
		return msg
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return msg
}
