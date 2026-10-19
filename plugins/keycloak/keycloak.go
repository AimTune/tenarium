// Package keycloak integrates Tenarium with Keycloak through its Admin REST
// API, in two independent ways.
//
// Realm per tenant (provision_realms, on by default): the "realm" provisioner
// creates the realm (and optionally an OIDC client in
// it) when a tenant is created and deletes or disables it when the tenant is
// deleted. Optional subscriptions keep the realm in step with the tenant:
// members become realm users, and suspending or resuming a tenant disables or
// enables its realm. The route GET /realms/{tenant} returns a tenant's realm
// and OIDC issuer URL.
//
// User directory (the users block): platform users live in one Keycloak
// realm. The plugin registers an sdk.UserDirectory that creates, updates and
// deletes them and sets their passwords, sends invitations with Keycloak's
// "execute actions" email and, when users.client_id is set, verifies
// passwords with that client's direct grant.
package keycloak

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("keycloak", func() sdk.Plugin { return &Plugin{} })
}

// RoleAttribute is the user attribute holding the member's Tenarium role.
// Keycloak 24+ only stores it when the realm's user profile allows unmanaged
// attributes (or declares this one).
const RoleAttribute = "tenarium_role"

type Config struct {
	// URL is the Keycloak base URL, e.g. http://keycloak:8080.
	URL string `json:"url"`
	// AdminRealm is the realm the admin credentials belong to; default "master".
	AdminRealm string `json:"admin_realm"`
	// ClientID and ClientSecret authenticate with the client_credentials
	// grant. If Username is set the password grant is used instead, with
	// ClientID defaulting to "admin-cli".
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	// RealmTemplate and DisplayNameTemplate are text/template strings over
	// sdk.Tenant; defaults "tenant-{{.Slug}}" and "{{.Name}}".
	RealmTemplate       string `json:"realm_template"`
	DisplayNameTemplate string `json:"display_name_template"`
	// Client, if set, is created in every tenant realm.
	Client *ClientConfig `json:"client"`
	// DeleteRealmOnDeprovision deletes the realm (default) instead of only
	// disabling it.
	DeleteRealmOnDeprovision *bool `json:"delete_realm_on_deprovision"`
	// SyncMembers mirrors tenant members as realm users (default true).
	SyncMembers *bool `json:"sync_members"`
	// SyncStatus disables the realm while the tenant is suspended (default true).
	SyncStatus *bool `json:"sync_status"`
	// Timeout per Admin API request, e.g. "10s".
	Timeout string `json:"timeout"`
	// ProvisionRealms enables the realm-per-tenant features: the provisioner,
	// the member and status subscriptions and the realm route (default true).
	ProvisionRealms *bool `json:"provision_realms"`
	// Users, if set, offers a user directory backed by a Keycloak realm.
	Users *UsersConfig `json:"users"`
}

// ClientConfig describes the OIDC client created in each realm.
type ClientConfig struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	WebOrigins   []string `json:"web_origins"`
	// Public creates a public client; default is confidential.
	Public bool `json:"public"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["url"],
  "additionalProperties": false,
  "properties": {
    "url": {"type": "string", "pattern": "^https?://"},
    "admin_realm": {"type": "string", "minLength": 1},
    "client_id": {"type": "string"},
    "client_secret": {"type": "string"},
    "username": {"type": "string"},
    "password": {"type": "string"},
    "realm_template": {"type": "string", "minLength": 1},
    "display_name_template": {"type": "string"},
    "client": {
      "type": "object",
      "required": ["client_id"],
      "additionalProperties": false,
      "properties": {
        "client_id": {"type": "string", "minLength": 1},
        "redirect_uris": {"type": "array", "items": {"type": "string"}},
        "web_origins": {"type": "array", "items": {"type": "string"}},
        "public": {"type": "boolean"}
      }
    },
    "delete_realm_on_deprovision": {"type": "boolean"},
    "sync_members": {"type": "boolean"},
    "sync_status": {"type": "boolean"},
    "timeout": {"type": "string"},
    "provision_realms": {"type": "boolean"},
    "users": {
      "type": "object",
      "required": ["realm"],
      "additionalProperties": false,
      "properties": {
        "realm": {"type": "string", "minLength": 1},
        "create_realm": {"type": "boolean"},
        "client_id": {"type": "string"},
        "client_secret": {"type": "string"},
        "send_invitation": {"type": "boolean"},
        "invitation_actions": {"type": "array", "items": {"type": "string", "minLength": 1}},
        "invitation_lifespan": {"type": "string"},
        "redirect_uri": {"type": "string"},
        "client_for_redirect": {"type": "string"}
      }
    }
  }
}`)

type Plugin struct {
	cfg         Config
	base        string
	realmTmpl   *template.Template
	displayTmpl *template.Template
	client      *http.Client
	host        sdk.Host
	log         *slog.Logger
	now         func() time.Time

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "keycloak",
		Name:         "Keycloak",
		Version:      "0.2.0",
		Description:  "Provisions a Keycloak realm per tenant and offers a Keycloak-backed user directory.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	c := &p.cfg
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url must be an absolute http(s) URL, got %q", c.URL)
	}
	p.base = strings.TrimRight(c.URL, "/")
	c.AdminRealm = cmp.Or(c.AdminRealm, "master")
	switch {
	case c.Username != "":
		if c.Password == "" {
			return errors.New("password is required with username")
		}
		c.ClientID = cmp.Or(c.ClientID, "admin-cli")
	case c.ClientID != "" && c.ClientSecret != "":
	default:
		return errors.New("either client_id and client_secret or username and password are required")
	}
	if c.Client != nil && c.Client.ClientID == "" {
		return errors.New("client.client_id is required")
	}
	var dir *directory
	if c.Users != nil {
		if dir, err = newDirectory(p, c.Users); err != nil {
			return err
		}
	}
	if p.realmTmpl, err = parseTemplate("realm_template", cmp.Or(c.RealmTemplate, "tenant-{{.Slug}}")); err != nil {
		return err
	}
	if p.displayTmpl, err = parseTemplate("display_name_template", cmp.Or(c.DisplayNameTemplate, "{{.Name}}")); err != nil {
		return err
	}
	if _, err := p.RealmName(sampleTenant); err != nil {
		return err
	}
	timeout := 10 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil {
			return fmt.Errorf("timeout: %w", err)
		}
	}
	p.client = &http.Client{Timeout: timeout}
	p.host = r.Host()
	p.log = r.Logger()
	if p.now == nil {
		p.now = time.Now
	}

	if dir != nil {
		if c.Users.CreateRealm {
			if err := p.ensureRealm(ctx, c.Users.Realm); err != nil {
				return fmt.Errorf("users.create_realm: %w", err)
			}
		}
		if c.Users.ClientID != "" {
			r.UserDirectory(verifyingDirectory{dir})
		} else {
			r.UserDirectory(dir)
		}
	}
	if !enabled(c.ProvisionRealms) {
		return nil
	}
	r.Provisioner(realmProvisioner{p})
	if enabled(c.SyncMembers) {
		r.Subscribe("members", sdk.EventFilter{Types: []string{
			sdk.EventMemberAdded, sdk.EventMemberUpdated, sdk.EventMemberRemoved,
		}}, p.syncMember)
	}
	if enabled(c.SyncStatus) {
		r.Subscribe("status", sdk.EventFilter{Types: []string{
			sdk.EventTenantSuspended, sdk.EventTenantResumed,
		}}, p.syncStatus)
	}
	r.Route("GET /realms/{tenant}", http.HandlerFunc(p.realmInfo))
	return nil
}

func enabled(b *bool) bool { return b == nil || *b }

// sampleTenant is used to validate templates at Init.
var sampleTenant = sdk.Tenant{
	ID: "00000000-0000-0000-0000-000000000000", Slug: "sample", Name: "Sample",
	Status: sdk.StatusActive, Labels: map[string]string{}, Settings: map[string]any{},
}

func parseTemplate(name, text string) (*template.Template, error) {
	t, err := template.New(name).Option("missingkey=zero").Parse(text)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if _, err := execTemplate(t, sampleTenant); err != nil {
		return nil, err
	}
	return t, nil
}

func execTemplate(t *template.Template, tenant sdk.Tenant) (string, error) {
	var b strings.Builder
	if err := t.Execute(&b, tenant); err != nil {
		return "", fmt.Errorf("%s: %w", t.Name(), err)
	}
	return strings.TrimSpace(b.String()), nil
}

// RealmName returns the realm that belongs to t.
func (p *Plugin) RealmName(t sdk.Tenant) (string, error) {
	name, err := execTemplate(p.realmTmpl, t)
	if err == nil && name == "" {
		err = fmt.Errorf("realm_template produced an empty name for tenant %s", t.ID)
	}
	return name, err
}

// Issuer returns the OIDC issuer URL of realm.
func (p *Plugin) Issuer(realm string) string {
	return p.base + "/realms/" + url.PathEscape(realm)
}

// --- provisioning ---

type realmProvisioner struct{ p *Plugin }

func (realmProvisioner) Name() string { return "realm" }

func (rp realmProvisioner) Provision(ctx context.Context, t sdk.Tenant) error {
	p := rp.p
	realm, err := p.RealmName(t)
	if err != nil {
		return err
	}
	display, err := execTemplate(p.displayTmpl, t)
	if err != nil {
		return err
	}
	rep := map[string]any{"realm": realm, "displayName": display, "enabled": true}
	status, body, err := p.do(ctx, http.MethodPost, "/admin/realms", nil, rep)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusCreated, http.StatusNoContent, http.StatusOK:
	case http.StatusConflict:
		// Already there (e.g. a retried provisioning): converge its state.
		update := map[string]any{"displayName": display, "enabled": true}
		if err := p.expect(ctx, http.MethodPut, realmPath(realm), update, http.StatusNoContent); err != nil {
			return err
		}
	default:
		return apiError("create realm "+realm, status, body)
	}
	if p.cfg.Client != nil {
		return p.ensureClient(ctx, realm)
	}
	return nil
}

func (rp realmProvisioner) Deprovision(ctx context.Context, t sdk.Tenant) error {
	p := rp.p
	realm, err := p.RealmName(t)
	if err != nil {
		return err
	}
	if !enabled(p.cfg.DeleteRealmOnDeprovision) {
		return p.setRealmEnabled(ctx, realm, false)
	}
	return p.expect(ctx, http.MethodDelete, realmPath(realm), nil, http.StatusNoContent, http.StatusNotFound)
}

func (p *Plugin) ensureClient(ctx context.Context, realm string) error {
	cc := p.cfg.Client
	q := url.Values{"clientId": {cc.ClientID}}
	status, body, err := p.do(ctx, http.MethodGet, realmPath(realm)+"/clients", q, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("list clients in "+realm, status, body)
	}
	var existing []struct {
		ClientID string `json:"clientId"`
	}
	if err := json.Unmarshal(body, &existing); err != nil {
		return fmt.Errorf("list clients in %s: %w", realm, err)
	}
	for _, c := range existing {
		if c.ClientID == cc.ClientID {
			return nil
		}
	}
	rep := map[string]any{
		"clientId":            cc.ClientID,
		"protocol":            "openid-connect",
		"enabled":             true,
		"publicClient":        cc.Public,
		"standardFlowEnabled": true,
		"redirectUris":        nonNil(cc.RedirectURIs),
		"webOrigins":          nonNil(cc.WebOrigins),
	}
	return p.expect(ctx, http.MethodPost, realmPath(realm)+"/clients", rep, http.StatusCreated, http.StatusConflict)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// setRealmEnabled toggles a realm. A missing realm is not an error.
func (p *Plugin) setRealmEnabled(ctx context.Context, realm string, on bool) error {
	return p.expect(ctx, http.MethodPut, realmPath(realm), map[string]any{"enabled": on},
		http.StatusNoContent, http.StatusNotFound)
}

func realmPath(realm string) string { return "/admin/realms/" + url.PathEscape(realm) }

// --- subscriptions ---

func (p *Plugin) syncStatus(ctx context.Context, e sdk.Event) error {
	var data sdk.TenantEventData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return fmt.Errorf("decode event: %w", err)
	}
	realm, err := p.RealmName(data.Tenant)
	if err != nil {
		return err
	}
	return p.setRealmEnabled(ctx, realm, e.Type == sdk.EventTenantResumed)
}

// errNoRealm reports that the tenant's realm does not exist.
var errNoRealm = errors.New("realm does not exist")

func (p *Plugin) syncMember(ctx context.Context, e sdk.Event) error {
	var data sdk.MemberEventData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return fmt.Errorf("decode event: %w", err)
	}
	m := data.Member
	if m.Email == "" {
		return nil
	}
	t, err := p.host.GetTenant(ctx, cmp.Or(m.TenantID, e.TenantID))
	if errors.Is(err, sdk.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	realm, err := p.RealmName(t)
	if err != nil {
		return err
	}
	switch e.Type {
	case sdk.EventMemberAdded, sdk.EventMemberUpdated:
		lookup := m.Email
		if data.Previous != nil && data.Previous.Email != "" {
			lookup = data.Previous.Email
		}
		err = p.ensureUser(ctx, realm, lookup, m)
	case sdk.EventMemberRemoved:
		err = p.deleteUser(ctx, realm, m.Email)
	}
	if errors.Is(err, errNoRealm) {
		if t.Status == sdk.StatusProvisioning {
			// The realm is still being created; retry later.
			return err
		}
		p.log.Debug("skipping member sync: realm missing", "realm", realm, "event", e.ID)
		return nil
	}
	return err
}

// ensureUser creates the member's user or updates its role attribute.
func (p *Plugin) ensureUser(ctx context.Context, realm, lookup string, m sdk.Member) error {
	user, err := p.findUser(ctx, realm, lookup)
	if err != nil {
		return err
	}
	usersPath := realmPath(realm) + "/users"
	if user == nil {
		rep := map[string]any{
			"username":        m.Email,
			"email":           m.Email,
			"enabled":         true,
			"requiredActions": []string{"VERIFY_EMAIL", "UPDATE_PASSWORD"},
			"attributes":      map[string][]string{RoleAttribute: {m.Role}},
		}
		status, body, err := p.do(ctx, http.MethodPost, usersPath, nil, rep)
		switch {
		case err != nil:
			return err
		case status == http.StatusCreated || status == http.StatusConflict:
			return nil
		case status == http.StatusNotFound:
			return errNoRealm
		default:
			return apiError("create user in "+realm, status, body)
		}
	}
	attrs, _ := user["attributes"].(map[string]any)
	if attrs == nil {
		attrs = map[string]any{}
	}
	if cur, _ := attrs[RoleAttribute].([]any); len(cur) == 1 && cur[0] == m.Role {
		return nil
	}
	attrs[RoleAttribute] = []string{m.Role}
	user["attributes"] = attrs
	id, _ := user["id"].(string)
	return p.expect(ctx, http.MethodPut, usersPath+"/"+url.PathEscape(id), user,
		http.StatusNoContent, http.StatusNotFound)
}

func (p *Plugin) deleteUser(ctx context.Context, realm, email string) error {
	user, err := p.findUser(ctx, realm, email)
	if err != nil || user == nil {
		return err
	}
	id, _ := user["id"].(string)
	return p.expect(ctx, http.MethodDelete, realmPath(realm)+"/users/"+url.PathEscape(id), nil,
		http.StatusNoContent, http.StatusNotFound)
}

// findUser returns the user whose username is email, or nil.
func (p *Plugin) findUser(ctx context.Context, realm, email string) (map[string]any, error) {
	q := url.Values{"username": {email}, "exact": {"true"}}
	status, body, err := p.do(ctx, http.MethodGet, realmPath(realm)+"/users", q, nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errNoRealm
	default:
		return nil, apiError("search users in "+realm, status, body)
	}
	var users []map[string]any
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("search users in %s: %w", realm, err)
	}
	for _, u := range users {
		if name, _ := u["username"].(string); strings.EqualFold(name, email) {
			return u, nil
		}
	}
	return nil, nil
}

// --- route ---

func (p *Plugin) realmInfo(w http.ResponseWriter, r *http.Request) {
	t, err := p.host.GetTenant(r.Context(), r.PathValue("tenant"))
	if pr, ok := sdk.PrincipalFrom(r.Context()); err == nil && ok && pr.TenantID != "" && pr.TenantID != t.ID {
		err = sdk.ErrNotFound // tenant-scoped callers only see their own tenant
	}
	if errors.Is(err, sdk.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
		return
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	realm, err := p.RealmName(t)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"realm": realm, "issuer": p.Issuer(realm)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// --- health ---

// Health obtains a fresh admin token.
func (p *Plugin) Health(ctx context.Context) error {
	_, err := p.fetchToken(ctx)
	return err
}

// --- Admin API client ---

// do sends an authenticated Admin API request and returns the status and
// body. A 401 drops the cached token and retries once.
func (p *Plugin) do(ctx context.Context, method, path string, q url.Values, in any) (int, []byte, error) {
	status, body, _, err := p.doHeader(ctx, method, path, q, in)
	return status, body, err
}

// doHeader is do that also returns the response headers.
func (p *Plugin) doHeader(ctx context.Context, method, path string, q url.Values, in any) (int, []byte, http.Header, error) {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return 0, nil, nil, err
		}
	}
	target := p.base + path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	for attempt := 0; ; attempt++ {
		tok, err := p.accessToken(ctx)
		if err != nil {
			return 0, nil, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := p.client.Do(req)
		if err != nil {
			return 0, nil, nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if err != nil {
			return 0, nil, nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			p.dropToken(tok)
			continue
		}
		return resp.StatusCode, body, resp.Header, nil
	}
}

// expect is do for requests whose response body is not needed.
func (p *Plugin) expect(ctx context.Context, method, path string, in any, ok ...int) error {
	status, body, err := p.do(ctx, method, path, nil, in)
	if err != nil {
		return err
	}
	for _, s := range ok {
		if status == s {
			return nil
		}
	}
	return apiError(method+" "+path, status, body)
}

func apiError(op string, status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return fmt.Errorf("keycloak: %s: %s: %s", op, http.StatusText(status), msg)
}

func (p *Plugin) accessToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	tok, exp := p.token, p.tokenExp
	p.mu.Unlock()
	if tok != "" && p.now().Before(exp) {
		return tok, nil
	}
	return p.fetchToken(ctx)
}

func (p *Plugin) dropToken(tok string) {
	p.mu.Lock()
	if p.token == tok {
		p.token = ""
	}
	p.mu.Unlock()
}

// fetchToken requests a new admin token and caches it until shortly before
// it expires.
func (p *Plugin) fetchToken(ctx context.Context) (string, error) {
	c := p.cfg
	form := url.Values{"client_id": {c.ClientID}}
	if c.ClientSecret != "" {
		form.Set("client_secret", c.ClientSecret)
	}
	if c.Username != "" {
		form.Set("grant_type", "password")
		form.Set("username", c.Username)
		form.Set("password", c.Password)
	} else {
		form.Set("grant_type", "client_credentials")
	}
	endpoint := p.base + "/realms/" + url.PathEscape(c.AdminRealm) + "/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak: token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", apiError("token", resp.StatusCode, body)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("keycloak: token: response has no access_token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	ttl -= min(30*time.Second, ttl/2)
	p.mu.Lock()
	p.token, p.tokenExp = tr.AccessToken, p.now().Add(ttl)
	p.mu.Unlock()
	return tr.AccessToken, nil
}
