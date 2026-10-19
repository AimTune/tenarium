// Package vault provisions per-tenant HashiCorp Vault resources through the
// Vault HTTP API (plugin ID "vault-tenant").
//
// For every tenant it maintains:
//
//   - a path prefix in an existing KV version 2 mount (kv.path_template,
//     default "tenants/{{.Slug}}"),
//   - an ACL policy (policy.name_template, default "tenant-{{.Slug}}")
//     granting the tenant's capabilities on that prefix and, when enabled, on
//     its transit key,
//   - optionally an AppRole role (approle) whose tokens carry that policy,
//   - optionally a transit encryption key (transit).
//
// Names come from text/template templates over sdk.Tenant and are sanitized:
// policy, role and key names to lowercase letters, digits, "_" and "-"; path
// prefixes segment by segment to lowercase letters, digits, ".", "_" and
// "-". Names that are too long are shortened and suffixed with a hash of the
// tenant ID. Templates should only use immutable tenant fields (ID, Slug),
// since names are recomputed on deprovision.
//
// # Ownership
//
// Vault policies, AppRole roles and transit keys carry no metadata, so
// ownership is recorded in a marker: the KV v2 key "<prefix>/.tenarium-owner"
// in the KV mount, which holds no secret versions, only custom_metadata:
//
//	tenarium_tenant_id     the owning tenant
//	tenarium_approle_role  "<mount>/<role>" of the role created for it
//	tenarium_transit_key   "<mount>/<key>" of the transit key created for it
//
// In addition every policy starts with the line "# tenarium-tenant-id: <id>".
// Provision refuses a prefix whose marker names another tenant, a prefix
// without a marker that already holds keys, a policy without that header or
// with another tenant's ID, and a role or transit key that exists but is not
// recorded in the tenant's marker. Deprovision only deletes what the marker
// records and policies whose header names the tenant. The tenant's policy
// denies access to the marker itself.
//
// # Deprovisioning
//
//   - delete (default): the AppRole role, the policy, the transit key (after
//     setting deletion_allowed) and every KV key under the prefix (all
//     versions and metadata) are deleted; the marker goes last so an
//     interrupted run is retried. Deleting a transit key irrecoverably
//     destroys the ability to decrypt anything encrypted with it.
//   - keep: nothing is touched; the marker stays, so a new tenant whose
//     names collide cannot take the data over.
//   - retain: the role and policy are deleted (access is revoked), the KV data
//     and the transit key are kept, and the marker's tenarium_tenant_id is
//     replaced by tenarium_deleted_tenant_id and tenarium_deleted_at.
//     Provisioning a tenant whose prefix holds retained data fails until an
//     operator removes it.
package vault

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// PluginID is the registered plugin ID.
const PluginID = "vault-tenant"

func init() {
	sdk.Register(PluginID, func() sdk.Plugin { return &Plugin{} })
}

// Deprovision actions.
const (
	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// Defaults.
const (
	DefaultKVMount         = "secret"
	DefaultPathTemplate    = "tenants/{{.Slug}}"
	DefaultPolicyTemplate  = "tenant-{{.Slug}}"
	DefaultAppRoleMount    = "approle"
	DefaultRoleTemplate    = "tenant-{{.Slug}}"
	DefaultTransitMount    = "transit"
	DefaultKeyTemplate     = "tenant-{{.Slug}}"
	DefaultTransitKeyType  = "aes256-gcm96"
	defaultTimeout         = 10 * time.Second
	maxNameLen             = 128
	maxPathLen             = 256
	policyHeaderPrefix     = "# tenarium-tenant-id:"
	ownerKey               = ".tenarium-owner"
	MetaTenantID           = "tenarium_tenant_id"
	MetaAppRoleRole        = "tenarium_approle_role"
	MetaTransitKey         = "tenarium_transit_key"
	MetaDeletedTenantID    = "tenarium_deleted_tenant_id"
	MetaDeletedAt          = "tenarium_deleted_at"
	metaSecretIDIssuedBy   = "tenarium_issued_by"               //nolint:gosec // G101: metadata key, not a credential
	metaSecretIDTenantID   = "tenarium_tenant_id"               //nolint:gosec // G101: metadata key, not a credential
	secretIDRoutePattern   = "POST /tenants/{tenant}/secret-id" //nolint:gosec // G101: an HTTP route pattern, not a credential
	tenantInfoRoutePattern = "GET /tenants/{tenant}"
)

// DefaultCapabilities are granted on the tenant's KV prefix by default.
var DefaultCapabilities = []string{"create", "read", "update", "delete", "list"}

var (
	validCapabilities = []string{"create", "read", "update", "patch", "delete", "list"}
	validKeyTypes     = []string{"aes128-gcm96", "aes256-gcm96", "chacha20-poly1305", "rsa-2048", "rsa-3072", "rsa-4096"}
	// reservedPolicies are built-in Vault policy names.
	reservedPolicies = []string{"root", "default", "default-ceiling", "response-wrapping", "control-group"}
	mountRe          = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)
)

type Config struct {
	// Address is the Vault base URL, e.g. https://vault.example.com:8200.
	Address string `json:"address"`
	// Namespace is sent as X-Vault-Namespace (Vault Enterprise).
	Namespace string     `json:"namespace"`
	Auth      AuthConfig `json:"auth"`
	TLS       TLSConfig  `json:"tls"`
	// Timeout per request, e.g. "10s".
	Timeout string       `json:"timeout"`
	KV      KVConfig     `json:"kv"`
	Policy  PolicyConfig `json:"policy"`
	// AppRole, when present, creates an AppRole role per tenant.
	AppRole *AppRoleConfig `json:"approle"`
	// Transit, when present, creates a transit key per tenant.
	Transit *TransitConfig `json:"transit"`
	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
}

// AuthConfig selects how the plugin authenticates: exactly one of Token and
// AppRole.
type AuthConfig struct {
	Token   string             `json:"token"`
	AppRole *AuthAppRoleConfig `json:"approle"`
}

type AuthAppRoleConfig struct {
	Mount    string `json:"mount"`
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

type TLSConfig struct {
	CAFile             string `json:"ca_file"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

type KVConfig struct {
	// Mount is an existing KV version 2 mount.
	Mount        string `json:"mount"`
	PathTemplate string `json:"path_template"`
}

type PolicyConfig struct {
	NameTemplate string   `json:"name_template"`
	Capabilities []string `json:"capabilities"`
	// ExtraRules is a template appended to the policy.
	ExtraRules string `json:"extra_rules"`
}

type AppRoleConfig struct {
	Mount        string `json:"mount"`
	RoleTemplate string `json:"role_template"`
	TokenTTL     string `json:"token_ttl"`
	TokenMaxTTL  string `json:"token_max_ttl"`
	SecretIDTTL  string `json:"secret_id_ttl"`
	// TokenPolicies are added to the tenant's policy on role tokens.
	TokenPolicies []string `json:"token_policies"`
}

type TransitConfig struct {
	Mount       string `json:"mount"`
	KeyTemplate string `json:"key_template"`
	Type        string `json:"type"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "address": {"type": "string", "minLength": 1},
    "namespace": {"type": "string"},
    "auth": {
      "type": "object",
      "properties": {
        "token": {"type": "string", "minLength": 1},
        "approle": {
          "type": "object",
          "properties": {
            "mount": {"type": "string"},
            "role_id": {"type": "string", "minLength": 1},
            "secret_id": {"type": "string", "minLength": 1}
          },
          "required": ["role_id", "secret_id"],
          "additionalProperties": false
        }
      },
      "oneOf": [{"required": ["token"]}, {"required": ["approle"]}],
      "additionalProperties": false
    },
    "tls": {
      "type": "object",
      "properties": {
        "ca_file": {"type": "string"},
        "insecure_skip_verify": {"type": "boolean"}
      },
      "additionalProperties": false
    },
    "timeout": {"type": "string"},
    "kv": {
      "type": "object",
      "properties": {
        "mount": {"type": "string"},
        "path_template": {"type": "string"}
      },
      "additionalProperties": false
    },
    "policy": {
      "type": "object",
      "properties": {
        "name_template": {"type": "string"},
        "capabilities": {
          "type": "array",
          "items": {"enum": ["create", "read", "update", "patch", "delete", "list"]},
          "minItems": 1,
          "uniqueItems": true
        },
        "extra_rules": {"type": "string"}
      },
      "additionalProperties": false
    },
    "approle": {
      "type": "object",
      "properties": {
        "mount": {"type": "string"},
        "role_template": {"type": "string"},
        "token_ttl": {"type": "string"},
        "token_max_ttl": {"type": "string"},
        "secret_id_ttl": {"type": "string"},
        "token_policies": {"type": "array", "items": {"type": "string", "minLength": 1}}
      },
      "additionalProperties": false
    },
    "transit": {
      "type": "object",
      "properties": {
        "mount": {"type": "string"},
        "key_template": {"type": "string"},
        "type": {"enum": ["aes128-gcm96", "aes256-gcm96", "chacha20-poly1305", "rsa-2048", "rsa-3072", "rsa-4096"]}
      },
      "additionalProperties": false
    },
    "on_deprovision": {"enum": ["delete", "keep", "retain"]}
  },
  "required": ["address", "auth"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg    Config
	path   *template.Template
	policy *template.Template
	role   *template.Template // nil without approle
	key    *template.Template // nil without transit
	extra  *template.Template // nil without policy.extra_rules
	client *client
	host   sdk.Host
	log    *slog.Logger
	now    func() time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           PluginID,
		Name:         "Vault Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions a HashiCorp Vault KV v2 path, ACL policy, and optionally an AppRole role and transit key per tenant.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	hc, err := p.httpClient()
	if err != nil {
		return err
	}
	p.now = time.Now
	p.client = &client{
		base:      p.cfg.Address,
		namespace: p.cfg.Namespace,
		http:      hc,
		token:     p.cfg.Auth.Token,
		approle:   p.cfg.Auth.AppRole,
		now:       func() time.Time { return p.now() },
	}
	p.host = r.Host()
	p.log = r.Logger()
	r.Provisioner(p)
	r.Route(tenantInfoRoutePattern, http.HandlerFunc(p.serveTenant))
	if p.cfg.AppRole != nil {
		r.Route(secretIDRoutePattern, http.HandlerFunc(p.serveSecretID))
	}
	return nil
}

func (p *Plugin) httpClient() (*http.Client, error) {
	timeout := defaultTimeout
	if p.cfg.Timeout != "" {
		var err error
		if timeout, err = time.ParseDuration(p.cfg.Timeout); err != nil || timeout <= 0 {
			return nil, fmt.Errorf("timeout must be a positive duration such as 10s, got %q", p.cfg.Timeout)
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if p.cfg.TLS.CAFile != "" || p.cfg.TLS.InsecureSkipVerify {
		tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: p.cfg.TLS.InsecureSkipVerify} //nolint:gosec // opt-in
		if p.cfg.TLS.CAFile != "" {
			pem, err := os.ReadFile(p.cfg.TLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("tls.ca_file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("tls.ca_file: no PEM certificates in %s", p.cfg.TLS.CAFile)
			}
			tc.RootCAs = pool
		}
		tr.TLSClientConfig = tc
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	if c.Address == "" {
		return errors.New("address is required")
	}
	u, err := url.Parse(c.Address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("address must be an http(s) URL such as https://vault.example.com:8200, got %q", c.Address)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return fmt.Errorf("address must not have a path or query, got %q", c.Address)
	}
	c.Address = strings.TrimSuffix(c.Address, "/")
	c.Namespace = strings.Trim(c.Namespace, "/")

	switch {
	case c.Auth.Token != "" && c.Auth.AppRole != nil:
		return errors.New("auth: set exactly one of token and approle")
	case c.Auth.Token == "" && c.Auth.AppRole == nil:
		return errors.New("auth: one of token and approle is required")
	case c.Auth.AppRole != nil:
		a := c.Auth.AppRole
		if a.RoleID == "" || a.SecretID == "" {
			return errors.New("auth.approle: role_id and secret_id are required")
		}
		if a.Mount, err = cleanMount("auth.approle.mount", a.Mount, DefaultAppRoleMount); err != nil {
			return err
		}
	}
	if c.Timeout != "" {
		if d, err := time.ParseDuration(c.Timeout); err != nil || d <= 0 {
			return fmt.Errorf("timeout must be a positive duration such as 10s, got %q", c.Timeout)
		}
	}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep, DeprovisionRetain:
	default:
		return fmt.Errorf("on_deprovision must be delete, keep or retain, got %q", c.OnDeprovision)
	}

	if c.KV.Mount, err = cleanMount("kv.mount", c.KV.Mount, DefaultKVMount); err != nil {
		return err
	}
	if c.KV.PathTemplate == "" {
		c.KV.PathTemplate = DefaultPathTemplate
	}
	if p.path, err = parseTemplate("kv.path_template", c.KV.PathTemplate, renderPath); err != nil {
		return err
	}

	if c.Policy.NameTemplate == "" {
		c.Policy.NameTemplate = DefaultPolicyTemplate
	}
	if p.policy, err = parseTemplate("policy.name_template", c.Policy.NameTemplate, renderName); err != nil {
		return err
	}
	if len(c.Policy.Capabilities) == 0 {
		c.Policy.Capabilities = slices.Clone(DefaultCapabilities)
	}
	for _, cp := range c.Policy.Capabilities {
		if !slices.Contains(validCapabilities, cp) {
			return fmt.Errorf("policy.capabilities: %q is not one of %s", cp, strings.Join(validCapabilities, ", "))
		}
	}

	if a := c.AppRole; a != nil {
		if a.Mount, err = cleanMount("approle.mount", a.Mount, DefaultAppRoleMount); err != nil {
			return err
		}
		if a.RoleTemplate == "" {
			a.RoleTemplate = DefaultRoleTemplate
		}
		if p.role, err = parseTemplate("approle.role_template", a.RoleTemplate, renderName); err != nil {
			return err
		}
		for k, v := range map[string]string{"token_ttl": a.TokenTTL, "token_max_ttl": a.TokenMaxTTL, "secret_id_ttl": a.SecretIDTTL} {
			if !validTTL(v) {
				return fmt.Errorf("approle.%s must be a duration such as 1h or a number of seconds, got %q", k, v)
			}
		}
		for _, tp := range a.TokenPolicies {
			if tp == "" || strings.ContainsAny(tp, "\"\n\r") {
				return fmt.Errorf("approle.token_policies: invalid policy name %q", tp)
			}
		}
	}

	if tc := c.Transit; tc != nil {
		if tc.Mount, err = cleanMount("transit.mount", tc.Mount, DefaultTransitMount); err != nil {
			return err
		}
		if tc.KeyTemplate == "" {
			tc.KeyTemplate = DefaultKeyTemplate
		}
		if p.key, err = parseTemplate("transit.key_template", tc.KeyTemplate, renderName); err != nil {
			return err
		}
		if tc.Type == "" {
			tc.Type = DefaultTransitKeyType
		}
		if !slices.Contains(validKeyTypes, tc.Type) {
			return fmt.Errorf("transit.type must be one of %s (an encryption key type), got %q", strings.Join(validKeyTypes, ", "), tc.Type)
		}
	}

	if c.Policy.ExtraRules != "" {
		if p.extra, err = template.New("extra_rules").Option("missingkey=error").Parse(c.Policy.ExtraRules); err != nil {
			return fmt.Errorf("policy.extra_rules: %w", err)
		}
		tg, err := p.target(sample1)
		if err != nil {
			return err
		}
		if _, err := p.renderExtra(sample1, tg); err != nil {
			return fmt.Errorf("policy.extra_rules: %w", err)
		}
	}
	return nil
}

// cleanMount trims slashes from a mount path, applies def when empty and
// checks the characters.
func cleanMount(field, v, def string) (string, error) {
	v = strings.Trim(v, "/")
	if v == "" {
		v = def
	}
	if !mountRe.MatchString(v) || strings.Contains("/"+v+"/", "/../") || strings.Contains("/"+v+"/", "/./") {
		return "", fmt.Errorf("%s: invalid mount path %q", field, v)
	}
	return v, nil
}

// validTTL accepts "" (Vault default), a number of seconds or a Go duration.
func validTTL(s string) bool {
	if s == "" {
		return true
	}
	if _, err := strconv.ParseUint(s, 10, 63); err == nil {
		return true
	}
	d, err := time.ParseDuration(s)
	return err == nil && d >= 0
}

// Sample tenants used to validate templates at Init.
var (
	sample1 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One"}
	sample2 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two"}
)

type renderFunc func(*template.Template, sdk.Tenant) (string, error)

// parseTemplate compiles a name template and checks that it renders distinct
// valid names for two sample tenants.
func parseTemplate(field, s string, render renderFunc) (*template.Template, error) {
	tmpl, err := template.New(field).Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	n1, err := render(tmpl, sample1)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	n2, err := render(tmpl, sample2)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if n1 == n2 {
		return nil, fmt.Errorf("%s must depend on the tenant (e.g. {{.Slug}} or {{.ID}})", field)
	}
	return tmpl, nil
}

func execute(tmpl *template.Template, t sdk.Tenant) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, t); err != nil {
		return "", err
	}
	return b.String(), nil
}

// hashSuffix is "-" plus the first 8 hex characters of sha256(tenant ID).
func hashSuffix(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "-" + hex.EncodeToString(sum[:4])
}

// renderName renders a policy, role or transit key name.
func renderName(tmpl *template.Template, t sdk.Tenant) (string, error) {
	s, err := execute(tmpl, t)
	if err != nil {
		return "", err
	}
	name := SanitizeName(s)
	if name == "" {
		return "", fmt.Errorf("renders an empty name for tenant %q", t.ID)
	}
	if len(name) > maxNameLen {
		sfx := hashSuffix(t.ID)
		name = strings.TrimRight(name[:maxNameLen-len(sfx)], "-_") + sfx
	}
	return name, nil
}

// renderPath renders a KV path prefix.
func renderPath(tmpl *template.Template, t sdk.Tenant) (string, error) {
	s, err := execute(tmpl, t)
	if err != nil {
		return "", err
	}
	path := SanitizePath(s)
	if path == "" {
		return "", fmt.Errorf("renders an empty path for tenant %q", t.ID)
	}
	if len(path) > maxPathLen {
		sfx := hashSuffix(t.ID)
		path = strings.TrimRight(path[:maxPathLen-len(sfx)], "/-_.") + sfx
	}
	return path, nil
}

// SanitizeName turns s into a Vault policy, AppRole role or transit key
// name: lowercase, characters other than [a-z0-9_-] replaced by "-", hyphen
// runs collapsed, and leading and trailing hyphens and underscores trimmed.
func SanitizeName(s string) string {
	return strings.Trim(sanitizeSegment(s, false), "_")
}

// SanitizePath turns s into a KV path prefix: each "/"-separated segment is
// lowercased, characters other than [a-z0-9._-] are replaced by "-", hyphen
// runs collapsed and leading and trailing "-" and "." trimmed (so "." and
// ".." cannot appear); empty segments are dropped.
func SanitizePath(s string) string {
	var segs []string
	for seg := range strings.SplitSeq(s, "/") {
		if seg = strings.Trim(sanitizeSegment(seg, true), "."); seg != "" {
			segs = append(segs, seg)
		}
	}
	return strings.Join(segs, "/")
}

func sanitizeSegment(s string, dots bool) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || (dots && r == '.'):
			b.WriteRune(r)
		case !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// target is what a tenant maps to in Vault.
type target struct {
	Prefix string // KV path prefix without leading or trailing slash
	Policy string
	Role   string // "" without approle
	Key    string // "" without transit
}

// roleRef and keyRef are how the role and key are recorded in the marker.
func (p *Plugin) roleRef(tg target) string {
	if tg.Role == "" {
		return ""
	}
	return p.cfg.AppRole.Mount + "/" + tg.Role
}

func (p *Plugin) keyRef(tg target) string {
	if tg.Key == "" {
		return ""
	}
	return p.cfg.Transit.Mount + "/" + tg.Key
}

func (p *Plugin) target(t sdk.Tenant) (target, error) {
	var tg target
	var err error
	if tg.Prefix, err = renderPath(p.path, t); err != nil {
		return tg, fmt.Errorf("kv.path_template: %w", err)
	}
	if tg.Policy, err = renderName(p.policy, t); err != nil {
		return tg, fmt.Errorf("policy.name_template: %w", err)
	}
	if slices.Contains(reservedPolicies, tg.Policy) {
		return tg, fmt.Errorf("policy.name_template renders the built-in policy name %q for tenant %s", tg.Policy, t.ID)
	}
	if p.role != nil {
		if tg.Role, err = renderName(p.role, t); err != nil {
			return tg, fmt.Errorf("approle.role_template: %w", err)
		}
	}
	if p.key != nil {
		if tg.Key, err = renderName(p.key, t); err != nil {
			return tg, fmt.Errorf("transit.key_template: %w", err)
		}
	}
	return tg, nil
}

func (p *Plugin) Name() string { return "vault" }

// Stop releases idle connections.
func (p *Plugin) Stop(context.Context) error {
	if p.client != nil {
		p.client.http.CloseIdleConnections()
	}
	return nil
}

// Health checks that Vault is unsealed and can serve requests (see
// client.health) and that the plugin's token is valid
// (auth/token/lookup-self, allowed by Vault's default policy).
func (p *Plugin) Health(ctx context.Context) error {
	if err := p.client.health(ctx); err != nil {
		return err
	}
	if err := p.client.do(ctx, http.MethodGet, "auth/token/lookup-self", nil, nil, nil); err != nil {
		return fmt.Errorf("token lookup: %w", err)
	}
	return nil
}
