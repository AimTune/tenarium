// Package entradir keeps Tenarium's platform users in Microsoft Entra ID
// (Azure AD), through Microsoft Graph.
//
// The plugin authenticates as an app registration with the client
// credentials grant and registers an sdk.UserDirectory. It works in one of
// two modes:
//
//   - "member" (default): users are member accounts of the Entra tenant,
//     created with a random password. Tenarium sets their password
//     (SetPassword PATCHes passwordProfile), disables them through
//     accountEnabled and deletes them. Invitations are Tenarium's own.
//   - "guest": users are B2B guests who sign in with their home account.
//     They are created with the invitations API and Microsoft sends the
//     invitation email (sdk.InvitationSender). Passwords are not managed.
//
// Entra ID offers no API to check a password, so the directory does not
// implement sdk.PasswordVerifier: users sign in through OIDC/SSO (see the
// oidc plugin) with Entra as the identity provider.
package entradir

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
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("entra-directory", func() sdk.Plugin { return &Plugin{} })
}

// Modes.
const (
	ModeMember = "member"
	ModeGuest  = "guest"
)

// Config is the plugin's configuration block.
type Config struct {
	// TenantID is the Entra tenant (directory) ID or a verified domain.
	TenantID string `json:"tenant_id"`
	// ClientID and ClientSecret are an app registration with the
	// User.ReadWrite.All application permission (User.Invite.All in guest
	// mode). Setting passwords additionally needs the
	// User-PasswordProfile.ReadWrite.All permission or the User
	// Administrator role for the app.
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// AuthorityURL defaults to "https://login.microsoftonline.com"; use
	// "https://login.microsoftonline.us" etc. for national clouds.
	AuthorityURL string `json:"authority_url"`
	// GraphURL defaults to "https://graph.microsoft.com/v1.0".
	GraphURL string `json:"graph_url"`
	// Mode is "member" (default) or "guest".
	Mode string `json:"mode"`
	// UPNDomain, in member mode, is the domain of generated
	// userPrincipalNames: "ada@example.com" becomes
	// "ada_example.com@<upn_domain>". When empty the email itself is the
	// UPN, which requires its domain to be verified in the tenant.
	UPNDomain string `json:"upn_domain"`
	// ForceChangePassword makes users change a password set by Tenarium at
	// their next Entra sign-in.
	ForceChangePassword bool `json:"force_change_password"`
	// InviteRedirectURL is where guests land after redeeming the
	// invitation; default "https://myapps.microsoft.com".
	InviteRedirectURL string `json:"invite_redirect_url"`
	// UserIDAttribute is a string property of the Graph user holding the
	// owning Tenarium user ID, e.g. "employeeId" or a directory extension
	// "extension_<appId>_tenariumUserId". Without it ownership is not
	// recorded and an existing user with the same email is always adopted.
	UserIDAttribute string `json:"user_id_attribute"`
	// AttributeMap copies Tenarium user attributes to string properties of
	// the Graph user, e.g. {"dept": "department"}. Others are ignored.
	AttributeMap map[string]string `json:"attribute_map"`
	// HardDelete also removes deleted users from the recycle bin
	// ("deleted items"); otherwise Entra keeps them restorable for 30 days.
	HardDelete bool `json:"hard_delete"`
	// Timeout per request; default "15s".
	Timeout string `json:"timeout"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["tenant_id", "client_id", "client_secret"],
  "additionalProperties": false,
  "properties": {
    "tenant_id": {"type": "string", "minLength": 1},
    "client_id": {"type": "string", "minLength": 1},
    "client_secret": {"type": "string", "minLength": 1},
    "authority_url": {"type": "string", "pattern": "^https?://"},
    "graph_url": {"type": "string", "pattern": "^https?://"},
    "mode": {"enum": ["member", "guest"]},
    "upn_domain": {"type": "string"},
    "force_change_password": {"type": "boolean"},
    "invite_redirect_url": {"type": "string"},
    "user_id_attribute": {"type": "string"},
    "attribute_map": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
    "hard_delete": {"type": "boolean"},
    "timeout": {"type": "string"}
  }
}`)

// Plugin is the Entra ID user directory plugin.
type Plugin struct {
	cfg   Config
	graph string
	api   *http.Client
	// retryDelays are the waits before retrying a 404 for a user that may
	// not have replicated yet, and before retrying a throttled request.
	retryDelays []time.Duration
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "entra-directory",
		Name:         "Microsoft Entra ID user directory",
		Version:      "0.1.0",
		Description:  "Keeps platform users in Microsoft Entra ID (members or B2B guests) through Microsoft Graph.",
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
	r.UserDirectory(&directory{p: p})
	return nil
}

var graphProperty = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// reserved are Graph properties the directory manages itself.
var reserved = map[string]bool{
	"id": true, "accountenabled": true, "displayname": true, "mail": true, "mailnickname": true,
	"userprincipalname": true, "passwordprofile": true, "usertype": true,
}

func (p *Plugin) configure() error {
	c := &p.cfg
	if c.TenantID == "" || c.ClientID == "" || c.ClientSecret == "" {
		return errors.New("tenant_id, client_id and client_secret are required")
	}
	authority, err := baseURL("authority_url", cmp.Or(c.AuthorityURL, "https://login.microsoftonline.com"))
	if err != nil {
		return err
	}
	if p.graph, err = baseURL("graph_url", cmp.Or(c.GraphURL, "https://graph.microsoft.com/v1.0")); err != nil {
		return err
	}
	c.Mode = cmp.Or(c.Mode, ModeMember)
	switch c.Mode {
	case ModeMember:
		if c.InviteRedirectURL != "" {
			return errors.New("invite_redirect_url is only used in guest mode")
		}
	case ModeGuest:
		if c.UPNDomain != "" || c.ForceChangePassword {
			return errors.New("upn_domain and force_change_password are only used in member mode")
		}
		c.InviteRedirectURL = cmp.Or(c.InviteRedirectURL, "https://myapps.microsoft.com")
		if u, err := url.Parse(c.InviteRedirectURL); err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invite_redirect_url must be an absolute URL, got %q", c.InviteRedirectURL)
		}
	default:
		return fmt.Errorf("mode must be member or guest, got %q", c.Mode)
	}
	if c.UPNDomain != "" && (strings.ContainsAny(c.UPNDomain, "@/ ") || !strings.Contains(c.UPNDomain, ".")) {
		return fmt.Errorf("upn_domain must be a domain name, got %q", c.UPNDomain)
	}
	if c.UserIDAttribute != "" && (!graphProperty.MatchString(c.UserIDAttribute) || reserved[strings.ToLower(c.UserIDAttribute)]) {
		return fmt.Errorf("user_id_attribute: invalid or reserved Graph property %q", c.UserIDAttribute)
	}
	seen := map[string]bool{strings.ToLower(c.UserIDAttribute): c.UserIDAttribute != ""}
	for k, prop := range c.AttributeMap {
		if k == "" || !graphProperty.MatchString(prop) || reserved[strings.ToLower(prop)] {
			return fmt.Errorf("attribute_map[%q]: invalid or reserved Graph property %q", k, prop)
		}
		if seen[strings.ToLower(prop)] {
			return fmt.Errorf("attribute_map[%q]: property %q is used twice", k, prop)
		}
		seen[strings.ToLower(prop)] = true
	}
	timeout := 15 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
	}
	plain := &http.Client{Timeout: timeout}
	cc := &clientcredentials.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		TokenURL:     authority + "/" + url.PathEscape(c.TenantID) + "/oauth2/v2.0/token",
		Scopes:       []string{scopeFor(p.graph)},
		AuthStyle:    oauth2.AuthStyleInParams,
	}
	tokens := cc.TokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, plain))
	p.api = &http.Client{Timeout: timeout, Transport: &oauth2.Transport{Source: tokens, Base: http.DefaultTransport}}
	if p.retryDelays == nil {
		p.retryDelays = []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}
	}
	return nil
}

func baseURL(field, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("%s must be an absolute http(s) URL, got %q", field, raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

// scopeFor returns the ".default" scope of the Graph instance at graph,
// e.g. "https://graph.microsoft.com/.default".
func scopeFor(graph string) string {
	u, _ := url.Parse(graph)
	return u.Scheme + "://" + u.Host + "/.default"
}

// Health makes a minimal Graph query, which needs a token and the
// User.Read.All (or ReadWrite) permission.
func (p *Plugin) Health(ctx context.Context) error {
	status, body, err := p.do(ctx, http.MethodGet, "/users", url.Values{"$top": {"1"}, "$select": {"id"}}, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("health", status, body)
	}
	return nil
}

// do sends a Graph request. Throttled requests (429, 503) are retried after
// the server's Retry-After (capped) up to len(retryDelays) times.
func (p *Plugin) do(ctx context.Context, method, path string, q url.Values, in any) (int, []byte, error) {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return 0, nil, err
		}
	}
	target := p.graph + path
	if len(q) > 0 {
		target += "?" + strings.ReplaceAll(q.Encode(), "+", "%20")
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Accept", "application/json")
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := p.api.Do(req)
		if err != nil {
			return 0, nil, fmt.Errorf("entra: %s %s: %w", method, path, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return 0, nil, err
		}
		throttled := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable
		if !throttled || attempt >= len(p.retryDelays) {
			return resp.StatusCode, body, nil
		}
		wait := p.retryDelays[attempt]
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			wait = min(time.Duration(s)*time.Second, 10*time.Second)
		}
		if err := sleep(ctx, wait); err != nil {
			return 0, nil, err
		}
	}
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

func apiError(op string, status int, body []byte) error {
	return fmt.Errorf("entra: %s: %s: %s", op, http.StatusText(status), errorMessage(body))
}

// graphError is Graph's error body.
type graphError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func errorMessage(body []byte) string {
	var e graphError
	if json.Unmarshal(body, &e) == nil && (e.Error.Message != "" || e.Error.Code != "") {
		return strings.TrimSpace(e.Error.Code + ": " + e.Error.Message)
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return msg
}

// randomPassword returns a password meeting Entra's complexity rules (3 of
// 4 character classes, 8-256 characters). Nobody knows it; it only exists
// because member accounts need one at creation.
func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b) + "aA1!", nil
}
