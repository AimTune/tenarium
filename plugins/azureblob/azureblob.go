// Package azureblob provisions one Azure Blob Storage container per tenant.
//
// It talks to the Blob service REST API directly (net/http) with Shared Key
// authorization, so it works against Azure Storage accounts and the Azurite
// emulator alike. The account is configured with connection_string (the
// usual "DefaultEndpointsProtocol=...;AccountName=...;AccountKey=..." form,
// or "UseDevelopmentStorage=true") or with account_name, account_key and an
// optional endpoint.
//
// The container name comes from name_template (a text/template over
// sdk.Tenant, default "tenant-{{.Slug}}"), sanitized to a valid container
// name: lowercase letters, digits and single hyphens, 3-63 characters,
// starting and ending with a letter or digit. Names that are too short or too
// long get a hash of the tenant ID, so two tenants never collide through
// truncation. Templates should only use immutable tenant fields (ID, Slug),
// since the name is recomputed on deprovision.
//
// # Ownership
//
// Containers carry the metadata tenarium_tenant_id=<id> (metadata names must
// be C# identifiers, hence underscores). New containers are created with the
// marker in the same request. Containers marked for another tenant are never
// adopted by Provision nor touched by Deprovision. An unmarked container is
// adopted only when it holds no blob.
//
// # Deprovisioning
//
// on_deprovision chooses what happens when a tenant is deleted:
//
//   - delete (default): the container is deleted with all its blobs. Azure
//     deletes containers asynchronously; while that runs, creating a
//     container of the same name fails with ContainerBeingDeleted, which
//     Provision waits out for a bounded time.
//   - keep: nothing is touched; the ownership marker stays.
//   - retain: the data stays, ownership is released (tenarium_tenant_id is
//     replaced by tenarium_deleted_at and tenarium_deleted_tenant_id) and
//     public access is turned off. Provisioning a tenant whose name collides
//     with retained data fails until an operator removes it.
package azureblob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("azure-blob-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Public access levels and deprovision actions.
const (
	PublicAccessNone      = "none"
	PublicAccessBlob      = "blob"
	PublicAccessContainer = "container"

	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// DefaultNameTemplate names tenant containers when name_template is unset.
const DefaultNameTemplate = "tenant-{{.Slug}}"

// Container name length limits.
const (
	minNameLen = 3
	maxNameLen = 63
)

// Metadata names (lowercase; Azure compares them case-insensitively).
const (
	MetaTenantID        = "tenarium_tenant_id"
	MetaQuotaGB         = "tenarium_quota_gb"
	MetaDeletedAt       = "tenarium_deleted_at"
	MetaDeletedTenantID = "tenarium_deleted_tenant_id"
)

// Defaults for waiting out a container that is still being deleted.
const (
	defaultBeingDeletedWait = 60 * time.Second
	defaultPollInterval     = 2 * time.Second
	requestTimeout          = 60 * time.Second
)

type Config struct {
	// ConnectionString is an Azure Storage connection string.
	ConnectionString string `json:"connection_string"`
	// AccountName, AccountKey and Endpoint are the alternative to
	// ConnectionString. Endpoint defaults to
	// https://<account>.blob.core.windows.net.
	AccountName string `json:"account_name"`
	AccountKey  string `json:"account_key"`
	Endpoint    string `json:"endpoint"`
	// NameTemplate renders the container name from an sdk.Tenant.
	NameTemplate string `json:"name_template"`
	// PublicAccess is "none" (default), "blob" or "container".
	PublicAccess string `json:"public_access"`
	// QuotaFromLimit is the entitlement limit recorded as tenarium_quota_gb.
	QuotaFromLimit string `json:"quota_from_limit"`
	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "connection_string": {"type": "string", "minLength": 1},
    "account_name": {"type": "string", "pattern": "^[a-z0-9]{3,24}$"},
    "account_key": {"type": "string", "minLength": 1},
    "endpoint": {"type": "string", "minLength": 1},
    "name_template": {"type": "string", "minLength": 1},
    "public_access": {"enum": ["none", "blob", "container"]},
    "quota_from_limit": {"type": "string"},
    "on_deprovision": {"enum": ["delete", "keep", "retain"]}
  },
  "oneOf": [
    {"required": ["connection_string"], "not": {"anyOf": [{"required": ["account_name"]}, {"required": ["account_key"]}, {"required": ["endpoint"]}]}},
    {"required": ["account_name", "account_key"], "not": {"required": ["connection_string"]}}
  ],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg    Config
	name   *template.Template
	client *client
	host   sdk.Host
	log    *slog.Logger
	now    func() time.Time

	// beingDeletedWait bounds how long Provision waits for a container
	// that is still being deleted; pollInterval is the retry interval.
	beingDeletedWait time.Duration
	pollInterval     time.Duration
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "azure-blob-tenant",
		Name:         "Azure Blob Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions an Azure Blob Storage container per tenant.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	creds, err := p.validate()
	if err != nil {
		return err
	}
	p.now = time.Now
	p.client = &client{http: &http.Client{Timeout: requestTimeout}, creds: creds, now: p.now}
	p.host = r.Host()
	p.log = r.Logger()
	p.beingDeletedWait = defaultBeingDeletedWait
	p.pollInterval = defaultPollInterval
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	return nil
}

// validate checks and defaults the configuration, compiles the name template
// and resolves the account credentials.
func (p *Plugin) validate() (credentials, error) {
	c := &p.cfg
	var creds credentials
	var err error
	switch {
	case c.ConnectionString != "":
		if c.AccountName != "" || c.AccountKey != "" || c.Endpoint != "" {
			return creds, errors.New("set either connection_string or account_name/account_key/endpoint, not both")
		}
		if creds, err = parseConnectionString(c.ConnectionString); err != nil {
			return creds, err
		}
	case c.AccountName != "" && c.AccountKey != "":
		endpoint := c.Endpoint
		if endpoint == "" {
			endpoint = "https://" + c.AccountName + ".blob.core.windows.net"
		}
		if creds, err = newCredentials(c.AccountName, c.AccountKey, endpoint); err != nil {
			return creds, err
		}
	default:
		return creds, errors.New("connection_string, or account_name and account_key, are required")
	}
	switch c.PublicAccess {
	case "":
		c.PublicAccess = PublicAccessNone
	case PublicAccessNone, PublicAccessBlob, PublicAccessContainer:
	default:
		return creds, fmt.Errorf("public_access must be none, blob or container, got %q", c.PublicAccess)
	}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep, DeprovisionRetain:
	default:
		return creds, fmt.Errorf("on_deprovision must be delete, keep or retain, got %q", c.OnDeprovision)
	}
	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	if p.name, err = parseNameTemplate(c.NameTemplate); err != nil {
		return creds, err
	}
	return creds, nil
}

// Sample tenants used to validate the name template at Init.
var (
	sample1 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One"}
	sample2 = sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two"}
)

// parseNameTemplate compiles a name template and checks that it renders
// distinct, valid names for two sample tenants.
func parseNameTemplate(s string) (*template.Template, error) {
	tmpl, err := template.New("name").Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("name_template: %w", err)
	}
	n1, err := renderName(tmpl, sample1)
	if err != nil {
		return nil, fmt.Errorf("name_template: %w", err)
	}
	n2, err := renderName(tmpl, sample2)
	if err != nil {
		return nil, fmt.Errorf("name_template: %w", err)
	}
	if n1 == n2 {
		return nil, errors.New("name_template must depend on the tenant (e.g. {{.Slug}} or {{.ID}})")
	}
	return tmpl, nil
}

func renderName(tmpl *template.Template, t sdk.Tenant) (string, error) {
	var b strings.Builder
	if err := tmpl.Execute(&b, t); err != nil {
		return "", err
	}
	name := sanitize(b.String())
	if name == "" {
		return "", fmt.Errorf("renders an empty name for tenant %q", t.ID)
	}
	if len(name) < minNameLen || len(name) > maxNameLen {
		// Truncating alone could map two tenants to one name; a hash of the
		// tenant ID keeps shortened names distinct.
		sum := sha256.Sum256([]byte(t.ID))
		suffix := "-" + hex.EncodeToString(sum[:4])
		name = strings.TrimRight(truncate(name, maxNameLen-len(suffix)), "-") + suffix
	}
	if !ValidContainerName(name) {
		return "", fmt.Errorf("renders invalid container name %q for tenant %s", name, t.ID)
	}
	return name, nil
}

// SanitizeName turns s into a container name candidate: lowercase,
// characters other than [a-z0-9] replaced by "-", hyphen runs collapsed and
// leading and trailing hyphens trimmed. It does not enforce the length
// limits, which need the tenant ID; see renderName.
func SanitizeName(s string) string { return sanitize(s) }

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// ValidContainerName reports whether s is a valid Blob container name:
// 3-63 lowercase letters, digits and hyphens, starting and ending with a
// letter or digit, without consecutive hyphens.
func ValidContainerName(s string) bool {
	if len(s) < minNameLen || len(s) > maxNameLen {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' || strings.Contains(s, "--") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// containerName returns the container of tenant t.
func (p *Plugin) containerName(t sdk.Tenant) (string, error) {
	name, err := renderName(p.name, t)
	if err != nil {
		return "", fmt.Errorf("name_template: %w", err)
	}
	return name, nil
}

func (p *Plugin) Name() string { return "azure-blob" }

// quota returns the tenant's quota_from_limit value as a metadata value, or
// "" when not configured or unlimited.
func (p *Plugin) quota(ctx context.Context, t sdk.Tenant) (string, error) {
	if p.cfg.QuotaFromLimit == "" {
		return "", nil
	}
	e, err := p.host.Entitlements(ctx, t.ID)
	if err != nil {
		return "", fmt.Errorf("entitlements: %w", err)
	}
	if v, ok := e.Limit(p.cfg.QuotaFromLimit); ok {
		return fmt.Sprint(v), nil
	}
	return "", nil
}

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	Container string `json:"container"`
	Account   string `json:"account"`
	URL       string `json:"url"`
}

func (p *Plugin) serveTenant(w http.ResponseWriter, r *http.Request) {
	t, err := p.host.GetTenant(r.Context(), r.PathValue("tenant"))
	if errors.Is(err, sdk.ErrNotFound) {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Answer "not found" rather than "forbidden" so callers cannot probe
	// other tenants' slugs.
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(r.Context(), sdk.ActionTenantsRead, res); err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}
	name, err := p.containerName(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(TenantInfo{
		Container: name,
		Account:   p.client.creds.Account,
		URL:       p.client.containerURL(name, nil).String(),
	})
}

// Health lists at most one container, which checks that the endpoint is
// reachable and the account key is accepted.
func (p *Plugin) Health(ctx context.Context) error {
	if err := p.client.listContainers(ctx); err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	return nil
}
