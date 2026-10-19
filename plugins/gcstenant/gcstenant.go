// Package gcstenant provisions per-tenant object storage on Google Cloud
// Storage, through the GCS JSON API.
//
// Two isolation modes are supported:
//
//   - bucket (default): one bucket per tenant, created in project.
//   - prefix: one object prefix ("<name>/") per tenant inside the shared
//     bucket named by bucket, which must already exist.
//
// The bucket or prefix name comes from name_template (a text/template over
// sdk.Tenant, default "tenant-{{.Slug}}"), sanitized to a valid GCS bucket
// name: lowercase letters, digits and hyphens, 3-63 characters, starting and
// ending with a letter or digit, not starting with "goog" and not
// containing "google". Names that are too long or too short are shortened
// or padded with a hash of the tenant ID, so two tenants never collide
// through truncation. Bucket names are global across all of GCS, so use a
// template with an organization-specific prefix in production.
//
// # Authentication
//
// Requests are authorized with golang.org/x/oauth2/google credentials, with
// the devstorage.full_control scope: credentials_file or credentials_json
// when set, Application Default Credentials otherwise. anonymous sends no
// credentials at all, for emulators such as fake-gcs-server (endpoint).
//
// # Ownership
//
// Every resource is marked with the tenant it belongs to. With ownership
// "labels" (the default in bucket mode) a bucket carries the label
// tenarium-tenant-id=<id>. With ownership "object", and always in prefix
// mode, the marker is an object ".tenarium-owner" (at the bucket root, or
// "<prefix>/.tenarium-owner") whose content is the tenant ID; it is created
// with ifGenerationMatch=0, so two tenants racing for one name cannot both
// win. Bucket updates are sent with ifMetagenerationMatch for the same
// reason. Resources marked for another tenant are never adopted by
// Provision nor touched by Deprovision. An unmarked bucket or prefix is
// adopted only when it is empty (what an interrupted Provision leaves
// behind); unmarked data is never claimed.
//
// # Deprovisioning
//
// on_deprovision chooses what happens when a tenant is deleted:
//
//   - delete (default): every object generation (live and noncurrent) is
//     removed, then the bucket. Owner markers go last so an interrupted
//     run is retried safely.
//   - keep: nothing is touched; the ownership marker remains.
//   - retain: the data stays, but ownership is released: the owner label
//     is replaced by tenarium-deleted-at / tenarium-deleted-tenant-id (or
//     the owner object by ".tenarium-retained"). Provisioning a new tenant
//     whose name collides with retained data fails until an operator
//     removes it.
package gcstenant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func init() {
	sdk.Register("gcs-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Isolation modes, ownership markers and deprovision actions.
const (
	ModeBucket = "bucket"
	ModePrefix = "prefix"

	OwnershipLabels = "labels"
	OwnershipObject = "object"

	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// DefaultEndpoint is the public GCS endpoint.
const DefaultEndpoint = "https://storage.googleapis.com"

// DefaultNameTemplate names tenant buckets/prefixes when name_template is
// unset.
const DefaultNameTemplate = "tenant-{{.Slug}}"

// Scope is the OAuth2 scope requested for the credentials.
const Scope = "https://www.googleapis.com/auth/devstorage.full_control"

// Bucket name length limits (without dots).
const (
	minNameLen = 3
	maxNameLen = 63
	// maxLabelLen is the maximum length of a label key or value.
	maxLabelLen = 63
	// maxLabels is the maximum number of labels on a bucket.
	maxLabels = 64
)

// Labels, metadata keys and marker objects.
const (
	LabelTenantID        = "tenarium-tenant-id"
	LabelQuotaGB         = "tenarium-quota-gb"
	LabelDeletedAt       = "tenarium-deleted-at"
	LabelDeletedTenantID = "tenarium-deleted-tenant-id"

	ownerObject    = ".tenarium-owner"
	retainedObject = ".tenarium-retained"
)

// Storage classes accepted by storage_class.
var storageClasses = []string{"STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"}

type Config struct {
	// Endpoint is the GCS base URL (default https://storage.googleapis.com);
	// set it to an emulator such as http://localhost:4443.
	Endpoint string `json:"endpoint"`
	// Anonymous sends unauthenticated requests (emulators only).
	Anonymous bool `json:"anonymous"`
	// CredentialsFile and CredentialsJSON hold a Google credentials JSON
	// (service account key, external account, ...). Default: ADC.
	CredentialsFile string `json:"credentials_file"`
	CredentialsJSON string `json:"credentials_json"`
	// Project owns the tenant buckets (required in bucket mode).
	Project string `json:"project"`
	// Mode is "bucket" (default) or "prefix".
	Mode string `json:"mode"`
	// Bucket is the shared bucket in prefix mode.
	Bucket string `json:"bucket"`
	// NameTemplate renders the bucket/prefix name from an sdk.Tenant.
	NameTemplate string `json:"name_template"`
	// Ownership is "labels" (default) or "object" (bucket mode only).
	Ownership string `json:"ownership"`
	// Location and StorageClass are used when creating a bucket.
	Location     string `json:"location"`
	StorageClass string `json:"storage_class"`
	Versioning   bool   `json:"versioning"`
	// LifecycleExpireDays deletes objects after this many days (0 = never).
	LifecycleExpireDays int `json:"lifecycle_expire_days"`
	// UniformBucketLevelAccess enables UBLA (default true); false leaves the
	// setting alone.
	UniformBucketLevelAccess *bool `json:"uniform_bucket_level_access"`
	// PublicAccessPrevention is "enforced", "inherited" or "" (unmanaged).
	PublicAccessPrevention string `json:"public_access_prevention"`
	// Labels are extra bucket labels; values are templates over sdk.Tenant.
	Labels map[string]string `json:"labels"`
	// QuotaFromLimit is the entitlement limit recorded as tenarium-quota-gb.
	QuotaFromLimit string `json:"quota_from_limit"`
	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "endpoint": {"type": "string", "minLength": 1},
    "anonymous": {"type": "boolean"},
    "credentials_file": {"type": "string"},
    "credentials_json": {"type": "string"},
    "project": {"type": "string"},
    "mode": {"enum": ["bucket", "prefix"]},
    "bucket": {"type": "string"},
    "name_template": {"type": "string", "minLength": 1},
    "ownership": {"enum": ["labels", "object"]},
    "location": {"type": "string"},
    "storage_class": {"enum": ["STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"]},
    "versioning": {"type": "boolean"},
    "lifecycle_expire_days": {"type": "integer", "minimum": 0},
    "uniform_bucket_level_access": {"type": "boolean"},
    "public_access_prevention": {"enum": ["", "enforced", "inherited"]},
    "labels": {"type": "object", "additionalProperties": {"type": "string"}},
    "quota_from_limit": {"type": "string"},
    "on_deprovision": {"enum": ["delete", "keep", "retain"]}
  },
  "additionalProperties": false
}`)

type Plugin struct {
	cfg    Config
	name   *template.Template
	labels map[string]*template.Template
	gcs    *client
	host   sdk.Host
	log    *slog.Logger
	now    func() time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "gcs-tenant",
		Name:         "GCS Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions a Google Cloud Storage bucket or object prefix per tenant.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.validate(); err != nil {
		return err
	}
	hc, err := p.httpClient(ctx)
	if err != nil {
		return err
	}
	p.gcs = &client{endpoint: p.cfg.Endpoint, http: hc}
	p.host = r.Host()
	p.log = r.Logger()
	p.now = time.Now
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	return nil
}

// httpClient returns an HTTP client carrying the configured credentials.
func (p *Plugin) httpClient(ctx context.Context) (*http.Client, error) {
	const timeout = 60 * time.Second
	if p.cfg.Anonymous {
		return &http.Client{Timeout: timeout}, nil
	}
	creds, err := p.credentials(ctx)
	if err != nil {
		return nil, err
	}
	// The token source outlives Init, so it must not use Init's context.
	hc := oauth2.NewClient(context.WithoutCancel(ctx), creds.TokenSource)
	hc.Timeout = timeout
	return hc, nil
}

// credentialTypes are the credential JSON types accepted from configuration.
var credentialTypes = map[string]google.CredentialsType{
	string(google.ServiceAccount):                google.ServiceAccount,
	string(google.AuthorizedUser):                google.AuthorizedUser,
	string(google.ExternalAccount):               google.ExternalAccount,
	string(google.ExternalAccountAuthorizedUser): google.ExternalAccountAuthorizedUser,
	string(google.ImpersonatedServiceAccount):    google.ImpersonatedServiceAccount,
}

func (p *Plugin) credentials(ctx context.Context) (*google.Credentials, error) {
	raw := []byte(p.cfg.CredentialsJSON)
	source := "credentials_json"
	if p.cfg.CredentialsFile != "" {
		b, err := os.ReadFile(p.cfg.CredentialsFile)
		if err != nil {
			return nil, fmt.Errorf("credentials_file: %w", err)
		}
		raw, source = b, "credentials_file"
	}
	if len(raw) == 0 {
		creds, err := google.FindDefaultCredentials(ctx, Scope)
		if err != nil {
			return nil, fmt.Errorf("application default credentials: %w (set credentials_file, credentials_json or anonymous)", err)
		}
		return creds, nil
	}
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	typ, ok := credentialTypes[head.Type]
	if !ok {
		return nil, fmt.Errorf("%s: unsupported credentials type %q", source, head.Type)
	}
	creds, err := google.CredentialsFromJSONWithType(ctx, raw, typ, Scope)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return creds, nil
}

var labelKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	if c.Endpoint == "" {
		c.Endpoint = DefaultEndpoint
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
		strings.Trim(u.Path, "/") != "" || u.RawQuery != "" {
		return fmt.Errorf("endpoint must be an http(s) URL without path, got %q", c.Endpoint)
	}
	c.Endpoint = strings.TrimRight(c.Endpoint, "/")
	if c.CredentialsFile != "" && c.CredentialsJSON != "" {
		return errors.New("set only one of credentials_file and credentials_json")
	}
	if c.Anonymous && (c.CredentialsFile != "" || c.CredentialsJSON != "") {
		return errors.New("anonymous cannot be combined with credentials_file or credentials_json")
	}
	switch c.Mode {
	case "":
		c.Mode = ModeBucket
	case ModeBucket, ModePrefix:
	default:
		return fmt.Errorf("mode must be bucket or prefix, got %q", c.Mode)
	}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep, DeprovisionRetain:
	default:
		return fmt.Errorf("on_deprovision must be delete, keep or retain, got %q", c.OnDeprovision)
	}
	if c.LifecycleExpireDays < 0 {
		return fmt.Errorf("lifecycle_expire_days must not be negative, got %d", c.LifecycleExpireDays)
	}
	if c.StorageClass != "" {
		c.StorageClass = strings.ToUpper(c.StorageClass)
		if !contains(storageClasses, c.StorageClass) {
			return fmt.Errorf("storage_class must be one of %s, got %q", strings.Join(storageClasses, ", "), c.StorageClass)
		}
	}
	switch c.PublicAccessPrevention {
	case "", "enforced", "inherited":
	default:
		return fmt.Errorf("public_access_prevention must be enforced or inherited, got %q", c.PublicAccessPrevention)
	}

	if c.Mode == ModePrefix {
		if c.Bucket == "" {
			return errors.New("bucket is required in prefix mode")
		}
		if err := checkBucketName(c.Bucket); err != nil {
			return fmt.Errorf("bucket: %w", err)
		}
		// These are bucket-wide settings; applying them per tenant to a
		// shared bucket would affect every tenant in it.
		for opt, set := range map[string]bool{
			"ownership":                   c.Ownership != "",
			"location":                    c.Location != "",
			"storage_class":               c.StorageClass != "",
			"versioning":                  c.Versioning,
			"lifecycle_expire_days":       c.LifecycleExpireDays > 0,
			"uniform_bucket_level_access": c.UniformBucketLevelAccess != nil,
			"public_access_prevention":    c.PublicAccessPrevention != "",
			"labels":                      len(c.Labels) > 0,
		} {
			if set {
				return fmt.Errorf("%s is only supported in bucket mode; configure the shared bucket directly", opt)
			}
		}
		c.Ownership = OwnershipObject
	} else {
		if c.Bucket != "" {
			return errors.New("bucket is only used in prefix mode")
		}
		if c.Project == "" {
			return errors.New("project is required in bucket mode")
		}
		switch c.Ownership {
		case "":
			c.Ownership = OwnershipLabels
		case OwnershipLabels, OwnershipObject:
		default:
			return fmt.Errorf("ownership must be labels or object, got %q", c.Ownership)
		}
		if c.UniformBucketLevelAccess == nil {
			on := true
			c.UniformBucketLevelAccess = &on
		}
	}

	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	if p.name, err = parseNameTemplate(c.NameTemplate); err != nil {
		return err
	}
	if len(c.Labels) > maxLabels-4 {
		return fmt.Errorf("labels: at most %d labels are allowed", maxLabels-4)
	}
	p.labels = map[string]*template.Template{}
	for k, v := range c.Labels {
		if !labelKeyRE.MatchString(k) {
			return fmt.Errorf("labels: invalid key %q (lowercase letter, then up to 62 of [a-z0-9_-])", k)
		}
		if strings.HasPrefix(k, "tenarium-") {
			return fmt.Errorf("labels: key %q uses the reserved prefix tenarium-", k)
		}
		tmpl, err := template.New(k).Option("missingkey=error").Parse(v)
		if err != nil {
			return fmt.Errorf("labels.%s: %w", k, err)
		}
		if err := tmpl.Execute(new(strings.Builder), sample1); err != nil {
			return fmt.Errorf("labels.%s: %w", k, err)
		}
		p.labels[k] = tmpl
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Sample tenants used to validate templates at Init.
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
		name = strings.TrimRight(truncate(name, maxNameLen-9), "-") + "-" + idHash(t.ID)[:8]
	}
	if err := checkBucketName(name); err != nil {
		return "", fmt.Errorf("renders invalid name %q for tenant %s: %w", name, t.ID, err)
	}
	return name, nil
}

func idHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// SanitizeName turns s into a valid GCS bucket name candidate: lowercase,
// characters other than [a-z0-9-] replaced by "-", hyphen runs collapsed,
// leading and trailing hyphens trimmed, "google" replaced by "ggl" and a
// "goog" prefix avoided. Dots and underscores are replaced too, so names
// stay DNS-compatible. It does not enforce the length limits, which need
// the tenant ID; see renderName.
func SanitizeName(s string) string { return sanitize(s) }

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	out := strings.ReplaceAll(strings.Trim(b.String(), "-"), "google", "ggl")
	if strings.HasPrefix(out, "goog") {
		out = "t-" + out
	}
	return out
}

var bucketNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)

// checkBucketName applies GCS bucket naming rules (names with dots, which
// may be up to 222 characters for domain-named buckets, are limited to 63).
func checkBucketName(s string) error {
	switch {
	case !bucketNameRE.MatchString(s):
		return fmt.Errorf("%q is not a valid bucket name (3-63 of [a-z0-9._-], starting and ending with a letter or digit)", s)
	case strings.HasPrefix(s, "goog") || strings.Contains(s, "google"):
		return fmt.Errorf("%q: bucket names must not start with goog or contain google", s)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

var labelValueRE = regexp.MustCompile(`^[a-z0-9_-]{0,63}$`)

// LabelValue turns a tenant ID into a label value. Values that are already
// valid (UUIDs are) are used as is; others become "sha256-" and 40 hex
// digits of their hash, which is still unique per tenant.
func LabelValue(id string) string {
	if labelValueRE.MatchString(id) {
		return id
	}
	return "sha256-" + idHash(id)[:40]
}

// sanitizeLabelValue turns arbitrary text (a rendered label template) into
// a label value: lowercase, invalid characters replaced by "_", truncated.
func sanitizeLabelValue(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return truncate(b.String(), maxLabelLen)
}

// target is what a tenant maps to in object storage.
type target struct {
	Bucket string
	// Prefix is "<name>/" in prefix mode and empty in bucket mode.
	Prefix string
}

func (p *Plugin) target(t sdk.Tenant) (target, error) {
	name, err := renderName(p.name, t)
	if err != nil {
		return target{}, fmt.Errorf("name_template: %w", err)
	}
	if p.cfg.Mode == ModePrefix {
		return target{Bucket: p.cfg.Bucket, Prefix: name + "/"}, nil
	}
	return target{Bucket: name}, nil
}

func (p *Plugin) Name() string { return "gcs" }

// Provision creates or claims the tenant's bucket or prefix and applies the
// configured settings. Every step is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	quota, err := p.quota(ctx, t)
	if err != nil {
		return err
	}
	if p.cfg.Mode == ModePrefix {
		return p.provisionMarker(ctx, tg.Bucket, tg.Prefix, t, quota, false)
	}
	return p.provisionBucket(ctx, tg.Bucket, t, quota)
}

// Deprovision applies on_deprovision. A tenant whose bucket or prefix does
// not exist is treated as already deprovisioned.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	tg, err := p.target(t)
	if err != nil {
		return err
	}
	if p.cfg.Mode == ModePrefix {
		_, err := p.deprovisionMarker(ctx, tg.Bucket, tg.Prefix, t)
		return err
	}
	return p.deprovisionBucket(ctx, tg.Bucket, t)
}

// quota returns the tenant's quota_from_limit value as a label value, or ""
// when not configured or unlimited.
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
	Mode    string `json:"mode"`
	Bucket  string `json:"bucket"`
	Prefix  string `json:"prefix,omitempty"`
	Project string `json:"project,omitempty"`
	// URL is the gs:// URL of the tenant's bucket or prefix.
	URL string `json:"url"`
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
	tg, err := p.target(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(TenantInfo{
		Mode: p.cfg.Mode, Bucket: tg.Bucket, Prefix: tg.Prefix, Project: p.cfg.Project,
		URL: "gs://" + tg.Bucket + "/" + tg.Prefix,
	})
}

// Health lists buckets of the project (bucket mode) or reads the shared
// bucket (prefix mode).
func (p *Plugin) Health(ctx context.Context) error {
	if p.cfg.Mode == ModePrefix {
		_, err := p.gcs.getBucket(ctx, p.cfg.Bucket)
		if isNotFound(err) {
			return fmt.Errorf("shared bucket %s does not exist", p.cfg.Bucket)
		}
		return err
	}
	return p.gcs.listBuckets(ctx, p.cfg.Project)
}
