// Package salesforce mirrors tenants into Salesforce as records of an
// sObject (Account by default) through the REST API.
//
// Records are upserted by an external ID field holding the tenant ID
// (external_id_field, default Tenarium_Tenant_Id__c, which must exist on the
// object and be marked "External ID", ideally also "Unique"). Upserts are
// idempotent, so redelivered events converge on the same record.
//
//   - tenant.created, tenant.updated, tenant.plan_changed, tenant.suspended
//     and tenant.resumed upsert the record with the fields rendered from
//     the fields templates.
//   - tenant.deleted keeps the record (on_delete "keep", the default),
//     deletes it ("delete"), or upserts it once more with deleted_fields
//     applied over fields ("update"), e.g. to set a status picklist.
//
// Authentication uses a connected app with either the OAuth 2.0 client
// credentials flow (client_id + client_secret) or the JWT bearer flow
// (client_id + username + an RSA private key whose certificate is uploaded
// to the connected app). The API host is the instance_url returned with the
// token unless instance_url is configured. Salesforce access tokens carry no
// expiry, so a token is reused for token_ttl and refreshed early when the
// API answers 401.
//
// Configuration:
//
//	plugins:
//	  - plugin: salesforce
//	    config:
//	      login_url: https://login.salesforce.com    # test.salesforce.com for sandboxes
//	      auth:
//	        flow: jwt_bearer
//	        client_id: 3MVG9...
//	        username: integration@acme.com
//	        private_key_file: /etc/tenarium/salesforce.key
//	      fields:
//	        Name: "{{.Name}}"
//	        Tenarium_Plan__c: "{{.Plan}}"
//	        Tenarium_Status__c: "{{.Status}}"
//	      on_delete: update
//	      deleted_fields:
//	        Tenarium_Status__c: deleted
package salesforce

import (
	"cmp"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

const version = "0.1.0"

func init() {
	sdk.Register("salesforce", func() sdk.Plugin { return &Plugin{} })
}

// Authentication flows.
const (
	FlowClientCredentials = "client_credentials"
	FlowJWTBearer         = "jwt_bearer"
)

// on_delete modes.
const (
	onDeleteKeep   = "keep"
	onDeleteDelete = "delete"
	onDeleteUpdate = "update"
)

// Config is the plugin configuration.
type Config struct {
	// LoginURL is the authorization server (default
	// https://login.salesforce.com; https://test.salesforce.com for
	// sandboxes, or the My Domain URL).
	LoginURL string `json:"login_url"`
	// InstanceURL overrides the API host returned with the token.
	InstanceURL string `json:"instance_url"`
	// APIVersion defaults to v62.0.
	APIVersion string     `json:"api_version"`
	Auth       AuthConfig `json:"auth"`
	// ExternalIDField is the external ID field holding the tenant ID
	// (default Tenarium_Tenant_Id__c).
	ExternalIDField string `json:"external_id_field"`
	// SObject defaults to Account.
	SObject string `json:"sobject"`
	// Fields maps field API names to templates rendered against the tenant.
	// Default: {"Name": "{{.Name}}"}.
	Fields map[string]string `json:"fields"`
	// OnDelete is "keep" (default), "delete" or "update".
	OnDelete string `json:"on_delete"`
	// DeletedFields are applied over fields when on_delete is "update".
	DeletedFields map[string]string `json:"deleted_fields"`
	// TokenTTL is how long an access token is reused, e.g. "1h" (default).
	// Set it below the connected app's session timeout.
	TokenTTL string `json:"token_ttl"`
	// Timeout per request, e.g. "15s" (default).
	Timeout string `json:"timeout"`
}

// AuthConfig selects the OAuth flow.
type AuthConfig struct {
	// Flow is "client_credentials" or "jwt_bearer".
	Flow     string `json:"flow"`
	ClientID string `json:"client_id"`
	// ClientSecret is for client_credentials.
	ClientSecret string `json:"client_secret"`
	// Username, and PrivateKey (PEM) or PrivateKeyFile, are for jwt_bearer.
	Username       string `json:"username"`
	PrivateKey     string `json:"private_key"`
	PrivateKeyFile string `json:"private_key_file"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["auth"],
  "additionalProperties": false,
  "properties": {
    "login_url": {"type": "string", "pattern": "^https?://"},
    "instance_url": {"type": "string", "pattern": "^https?://"},
    "api_version": {"type": "string", "pattern": "^v[0-9]+\\.[0-9]+$"},
    "auth": {
      "type": "object",
      "additionalProperties": false,
      "required": ["flow", "client_id"],
      "properties": {
        "flow": {"enum": ["client_credentials", "jwt_bearer"]},
        "client_id": {"type": "string", "minLength": 1},
        "client_secret": {"type": "string", "minLength": 1},
        "username": {"type": "string", "minLength": 1},
        "private_key": {"type": "string", "minLength": 1},
        "private_key_file": {"type": "string", "minLength": 1}
      },
      "if": {"properties": {"flow": {"const": "client_credentials"}}},
      "then": {"required": ["client_secret"]},
      "else": {
        "required": ["username"],
        "oneOf": [{"required": ["private_key"]}, {"required": ["private_key_file"]}]
      }
    },
    "external_id_field": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_]*__c$"},
    "sobject": {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_]*$"},
    "fields": {
      "type": "object",
      "propertyNames": {"pattern": "^[A-Za-z][A-Za-z0-9_]*$"},
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "on_delete": {"enum": ["keep", "delete", "update"]},
    "deleted_fields": {
      "type": "object",
      "propertyNames": {"pattern": "^[A-Za-z][A-Za-z0-9_]*$"},
      "additionalProperties": {"type": "string", "minLength": 1}
    },
    "token_ttl": {"type": "string"},
    "timeout": {"type": "string"}
  },
  "if": {"properties": {"on_delete": {"const": "update"}}, "required": ["on_delete"]},
  "then": {"required": ["deleted_fields"]}
}`)

var (
	fieldName    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	externalID   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*__c$`)
	apiVersionRe = regexp.MustCompile(`^v[0-9]+\.[0-9]+$`)
)

// Plugin is the Salesforce CRM plugin.
type Plugin struct {
	cfg           Config
	loginURL      string
	fields        map[string]*template.Template
	deletedFields map[string]*template.Template
	client        *http.Client
	tokens        *tokenCache
	log           *slog.Logger
	now           func() time.Time
	// next holds the configuration applied by Reconfigure.
	next atomic.Pointer[Plugin]
}

var _ sdk.Reconfigurer = (*Plugin)(nil)

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "salesforce",
		Name:         "Salesforce",
		Version:      version,
		Description:  "Upserts a Salesforce record (Account by default) per tenant through the REST API.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	p.log = r.Logger()
	if p.now == nil {
		p.now = time.Now
	}
	if err := p.applyConfig(); err != nil {
		return err
	}
	r.Subscribe("sync", sdk.EventFilter{Types: []string{
		sdk.EventTenantCreated, sdk.EventTenantUpdated, sdk.EventTenantPlanChanged,
		sdk.EventTenantSuspended, sdk.EventTenantResumed, sdk.EventTenantDeleted,
	}}, p.sync)
	return nil
}

func absURL(field, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("%s must be an absolute http(s) URL, got %q", field, raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

func (p *Plugin) applyConfig() error {
	c := &p.cfg
	var err error
	if p.loginURL, err = absURL("login_url", cmp.Or(c.LoginURL, "https://login.salesforce.com")); err != nil {
		return err
	}
	if c.InstanceURL != "" {
		if c.InstanceURL, err = absURL("instance_url", c.InstanceURL); err != nil {
			return err
		}
	}
	c.APIVersion = cmp.Or(c.APIVersion, "v62.0")
	if !apiVersionRe.MatchString(c.APIVersion) {
		return fmt.Errorf("api_version must look like v62.0, got %q", c.APIVersion)
	}
	c.ExternalIDField = cmp.Or(c.ExternalIDField, "Tenarium_Tenant_Id__c")
	if !externalID.MatchString(c.ExternalIDField) {
		return fmt.Errorf("external_id_field must be a custom field API name (..__c), got %q", c.ExternalIDField)
	}
	c.SObject = cmp.Or(c.SObject, "Account")
	if !fieldName.MatchString(c.SObject) {
		return fmt.Errorf("sobject: invalid API name %q", c.SObject)
	}

	timeout := 15 * time.Second
	if c.Timeout != "" {
		if timeout, err = time.ParseDuration(c.Timeout); err != nil || timeout <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
	}
	p.client = &http.Client{Timeout: timeout}
	ttl := time.Hour
	if c.TokenTTL != "" {
		if ttl, err = time.ParseDuration(c.TokenTTL); err != nil || ttl < time.Minute {
			return fmt.Errorf("token_ttl: invalid duration %q (minimum 1m)", c.TokenTTL)
		}
	}

	if c.Fields == nil {
		c.Fields = map[string]string{"Name": "{{.Name}}"}
	}
	if p.fields, err = p.compile("fields", c.Fields); err != nil {
		return err
	}
	c.OnDelete = cmp.Or(c.OnDelete, onDeleteKeep)
	switch c.OnDelete {
	case onDeleteKeep, onDeleteDelete:
		if len(c.DeletedFields) > 0 {
			return errors.New("deleted_fields only applies to on_delete update")
		}
	case onDeleteUpdate:
		if len(c.DeletedFields) == 0 {
			return errors.New("on_delete update requires deleted_fields")
		}
		if p.deletedFields, err = p.compile("deleted_fields", c.DeletedFields); err != nil {
			return err
		}
	default:
		return fmt.Errorf("on_delete must be keep, delete or update, got %q", c.OnDelete)
	}

	src, err := p.tokenSource()
	if err != nil {
		return err
	}
	p.tokens = &tokenCache{fetch: src, ttl: ttl, now: p.now}
	return nil
}

// compile parses one template per field.
func (p *Plugin) compile(field string, m map[string]string) (map[string]*template.Template, error) {
	out := make(map[string]*template.Template, len(m))
	for _, name := range slices.Sorted(maps.Keys(m)) {
		if !fieldName.MatchString(name) {
			return nil, fmt.Errorf("%s: invalid field API name %q", field, name)
		}
		if strings.EqualFold(name, p.cfg.ExternalIDField) {
			return nil, fmt.Errorf("%s: %s is the external ID field and is set to the tenant ID", field, name)
		}
		if strings.TrimSpace(m[name]) == "" {
			return nil, fmt.Errorf("%s.%s: template must not be empty", field, name)
		}
		t, err := template.New(name).Option("missingkey=error").Parse(m[name])
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", field, name, err)
		}
		out[name] = t
	}
	return out, nil
}

// parseRSAKey checks that pemData holds an unencrypted RSA private key
// (PKCS#1 or PKCS#8), as the JWT bearer flow signs with RS256.
func parseRSAKey(pemData []byte) error {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return errors.New("no PEM block found")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("not a PKCS#1 or PKCS#8 private key: %w", err)
	}
	if _, ok := key.(*rsa.PrivateKey); !ok {
		return errors.New("the key is not an RSA key")
	}
	return nil
}

func readKey(a AuthConfig) ([]byte, error) {
	switch {
	case a.PrivateKey != "" && a.PrivateKeyFile != "":
		return nil, errors.New("auth: set private_key or private_key_file, not both")
	case a.PrivateKey != "":
		return []byte(a.PrivateKey), nil
	case a.PrivateKeyFile != "":
		b, err := os.ReadFile(a.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("auth.private_key_file: %w", err)
		}
		return b, nil
	}
	return nil, errors.New("auth: jwt_bearer needs private_key or private_key_file")
}

// Health fetches the org limits, which checks authentication and the API.
func (p *Plugin) Health(ctx context.Context) error {
	if n := p.next.Load(); n != nil {
		return n.Health(ctx)
	}
	_, err := p.api(ctx, http.MethodGet, "/limits", nil)
	return err
}

// Reconfigure applies every setting without a restart (e.g. credential or
// key rotation, new field templates). The new configuration starts with an
// empty token cache, so the next request fetches a token with the new
// credentials; the subscribed events are fixed and not configurable.
func (p *Plugin) Reconfigure(_ context.Context, decode func(v any) error) error {
	n := &Plugin{log: p.log, now: p.now}
	if err := decode(&n.cfg); err != nil {
		return err
	}
	if err := n.applyConfig(); err != nil {
		return err
	}
	p.next.Store(n)
	return nil
}
