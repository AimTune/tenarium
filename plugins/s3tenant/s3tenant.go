// Package s3tenant provisions per-tenant object storage on Amazon S3 or any
// S3-compatible store (MinIO, Ceph RGW, SeaweedFS, Cloudflare R2, ...).
//
// Two isolation modes are supported:
//
//   - bucket (default): one bucket per tenant.
//   - prefix: one key prefix ("<name>/") per tenant inside the shared bucket
//     named by bucket, which must already exist.
//
// The bucket or prefix name comes from name_template (a text/template over
// sdk.Tenant, default "tenant-{{.Slug}}"), sanitized to a valid S3 bucket
// name: lowercase letters, digits and hyphens, 3-63 characters, starting and
// ending with a letter or digit. Dots are replaced too, because they break
// virtual-hosted-style requests over TLS. Names that are too long are
// shortened and suffixed with a hash of the tenant ID, so two tenants never
// collide through truncation. Templates should only use immutable tenant
// fields (ID, Slug), since the name is recomputed on deprovision.
//
// # Ownership
//
// Every resource is marked with the tenant it belongs to: buckets carry the
// tag tenarium-tenant-id=<id>, prefixes the object "<prefix>/.tenarium-owner"
// whose content is the tenant ID. Resources marked for another tenant are
// never adopted by Provision nor touched by Deprovision. An unmarked bucket or
// prefix is adopted only when it is empty (what an interrupted Provision
// leaves behind); unmarked data is never claimed.
//
// # Bucket options
//
// In bucket mode, versioning enables versioning, object_lock creates the
// bucket with S3 Object Lock (only possible at creation, and it implies
// versioning), lifecycle_expire_days adds a lifecycle rule
// "tenarium-expire" that expires objects (and noncurrent versions) after N
// days, and policy_template renders a bucket policy, a text/template over
// {Tenant, Bucket, Prefix}, e.g. to grant a per-tenant IAM role access.
//
// S3 has no native storage quotas. With quota_from_limit, the tenant's
// entitlement limit of that name (interpreted as gigabytes) is recorded as
// the bucket tag tenarium-quota-gb (in prefix mode: as the user metadata
// tenarium-quota-gb of the owner marker object) so that downstream tooling
// (a usage scanner, a gateway) can enforce it. Unlimited tenants have no tag.
//
// # IAM users
//
// With iam.enabled, every tenant also gets an IAM user (path iam.path,
// default /tenarium/, tagged tenarium-tenant-id) with an inline policy
// "tenarium-s3" restricted to the tenant's bucket or prefix (or rendered
// from iam.policy_template). No access keys are created or stored: an admin
// creates them on demand with POST /tenants/{tenant}/access-keys, which
// returns the secret once. The user, its keys and policies are deleted on
// deprovision (delete and retain; keep leaves everything in place).
//
// # Deprovisioning
//
// on_deprovision chooses what happens when a tenant is deleted:
//
//   - delete (default): every object (and every version and delete marker)
//     is removed, then the bucket. In prefix mode the owner marker goes last,
//     so an interrupted run is retried safely.
//   - keep: nothing is touched. The bucket keeps its ownership marker, so a
//     new tenant with the same slug cannot adopt it.
//   - retain: the data stays, but ownership is released: the bucket's
//     tenarium-tenant-id tag is replaced by tenarium-deleted-at=<RFC3339>
//     and tenarium-deleted-tenant-id=<id> (in prefix mode the owner marker is
//     replaced by "<prefix>/.tenarium-retained"). Provisioning a new tenant
//     whose name collides with retained data fails with a clear error; an
//     operator must archive or remove the data first.
package s3tenant

import (
	"bytes"
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
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
)

func init() {
	sdk.Register("s3-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Isolation modes and deprovision actions.
const (
	ModeBucket = "bucket"
	ModePrefix = "prefix"

	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
	DeprovisionRetain = "retain"
)

// DefaultNameTemplate names tenant buckets/prefixes when name_template is
// unset.
const DefaultNameTemplate = "tenant-{{.Slug}}"

// Bucket name length limits.
const (
	minNameLen = 3
	maxNameLen = 63
)

// Tags and marker objects.
const (
	TagTenantID        = "tenarium-tenant-id"
	TagQuotaGB         = "tenarium-quota-gb"
	TagDeletedAt       = "tenarium-deleted-at"
	TagDeletedTenantID = "tenarium-deleted-tenant-id"

	ownerObject    = ".tenarium-owner"
	retainedObject = ".tenarium-retained"
	// quotaMetaKey is TagQuotaGB as minio-go reports user metadata.
	quotaMetaKey = "Tenarium-Quota-Gb"
)

type Config struct {
	// Endpoint is host[:port] of the S3 API, without scheme.
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	// Secure selects HTTPS (default true).
	Secure *bool `json:"secure"`
	// Mode is "bucket" (default) or "prefix".
	Mode string `json:"mode"`
	// Bucket is the shared bucket in prefix mode.
	Bucket string `json:"bucket"`
	// NameTemplate renders the bucket/prefix name from an sdk.Tenant.
	NameTemplate string `json:"name_template"`
	Versioning   bool   `json:"versioning"`
	ObjectLock   bool   `json:"object_lock"`
	// LifecycleExpireDays expires objects after this many days (0 = never).
	LifecycleExpireDays int `json:"lifecycle_expire_days"`
	// QuotaFromLimit is the entitlement limit recorded as tenarium-quota-gb.
	QuotaFromLimit string `json:"quota_from_limit"`
	// OnDeprovision is "delete" (default), "keep" or "retain".
	OnDeprovision string `json:"on_deprovision"`
	// PolicyTemplate renders a bucket policy (bucket mode only).
	PolicyTemplate string `json:"policy_template"`
	// IAM optionally gives each tenant an IAM user restricted to its
	// bucket or prefix (AWS IAM API).
	IAM IAMConfig `json:"iam"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "endpoint": {"type": "string", "minLength": 1},
    "region": {"type": "string"},
    "access_key": {"type": "string", "minLength": 1},
    "secret_key": {"type": "string", "minLength": 1},
    "secure": {"type": "boolean"},
    "mode": {"enum": ["bucket", "prefix"]},
    "bucket": {"type": "string"},
    "name_template": {"type": "string", "minLength": 1},
    "versioning": {"type": "boolean"},
    "object_lock": {"type": "boolean"},
    "lifecycle_expire_days": {"type": "integer", "minimum": 0},
    "quota_from_limit": {"type": "string"},
    "on_deprovision": {"enum": ["delete", "keep", "retain"]},
    "policy_template": {"type": "string"},
    "iam": {
      "type": "object",
      "properties": {
        "enabled": {"type": "boolean"},
        "endpoint": {"type": "string"},
        "region": {"type": "string"},
        "access_key": {"type": "string"},
        "secret_key": {"type": "string"},
        "partition": {"type": "string"},
        "path": {"type": "string", "maxLength": 512},
        "user_template": {"type": "string", "minLength": 1},
        "policy_template": {"type": "string"},
        "permissions_boundary": {"type": "string"}
      },
      "additionalProperties": false
    }
  },
  "required": ["endpoint", "access_key", "secret_key"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg    Config
	name   *template.Template
	policy *template.Template // nil without policy_template
	client *minio.Client
	// iam is set when iam.enabled.
	iam       iamAPI
	iamUser   *template.Template
	iamPolicy *template.Template // nil: default policy
	host      sdk.Host
	log       *slog.Logger
	now       func() time.Time
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "s3-tenant",
		Name:         "S3 Tenant Isolation",
		Version:      "0.1.0",
		Description:  "Provisions an S3 bucket or key prefix per tenant on S3-compatible object storage.",
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
	client, err := minio.New(p.cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(p.cfg.AccessKey, p.cfg.SecretKey, ""),
		Secure: *p.cfg.Secure,
		Region: p.cfg.Region,
	})
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	p.client = client
	p.host = r.Host()
	p.log = r.Logger()
	p.now = time.Now
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	if p.cfg.IAM.Enabled {
		p.iam = newIAMClient(p.cfg.IAM)
		r.Route("POST /tenants/{tenant}/access-keys", http.HandlerFunc(p.serveCreateAccessKey))
		r.Route("GET /tenants/{tenant}/access-keys", http.HandlerFunc(p.serveListAccessKeys))
		r.Route("DELETE /tenants/{tenant}/access-keys/{key}", http.HandlerFunc(p.serveDeleteAccessKey))
	}
	return nil
}

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	if c.Endpoint == "" {
		return errors.New("endpoint is required")
	}
	if strings.Contains(c.Endpoint, "://") || strings.Contains(c.Endpoint, "/") {
		return fmt.Errorf("endpoint must be host[:port] without scheme or path, got %q (use secure to choose TLS)", c.Endpoint)
	}
	if c.AccessKey == "" || c.SecretKey == "" {
		return errors.New("access_key and secret_key are required")
	}
	if c.Secure == nil {
		secure := true
		c.Secure = &secure
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
	if c.Mode == ModePrefix {
		if c.Bucket == "" {
			return errors.New("bucket is required in prefix mode")
		}
		if err := s3utils.CheckValidBucketNameStrict(c.Bucket); err != nil {
			return fmt.Errorf("bucket: %w", err)
		}
		// These are bucket-wide settings; applying them per tenant to a
		// shared bucket would affect every tenant in it.
		for opt, set := range map[string]bool{
			"versioning":            c.Versioning,
			"object_lock":           c.ObjectLock,
			"lifecycle_expire_days": c.LifecycleExpireDays > 0,
			"policy_template":       c.PolicyTemplate != "",
		} {
			if set {
				return fmt.Errorf("%s is only supported in bucket mode; configure the shared bucket directly", opt)
			}
		}
	} else if c.Bucket != "" {
		return errors.New("bucket is only used in prefix mode")
	}
	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	var err error
	if p.name, err = parseNameTemplate(c.NameTemplate); err != nil {
		return err
	}
	if c.PolicyTemplate != "" {
		if p.policy, err = parsePolicyTemplate(c.PolicyTemplate); err != nil {
			return err
		}
	}
	return p.validateIAM()
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

// policyData is the template data of policy_template.
type policyData struct {
	Tenant sdk.Tenant
	Bucket string
	Prefix string
}

// parsePolicyTemplate compiles policy_template and checks that it renders
// valid JSON.
func parsePolicyTemplate(s string) (*template.Template, error) {
	tmpl, err := template.New("policy").Option("missingkey=error").Parse(s)
	if err != nil {
		return nil, fmt.Errorf("policy_template: %w", err)
	}
	if _, err := renderPolicy(tmpl, policyData{Tenant: sample1, Bucket: "tenant-example-one"}); err != nil {
		return nil, fmt.Errorf("policy_template: %w", err)
	}
	return tmpl, nil
}

func renderPolicy(tmpl *template.Template, data policyData) (string, error) {
	var b bytes.Buffer
	if err := tmpl.Execute(&b, data); err != nil {
		return "", err
	}
	if !json.Valid(b.Bytes()) {
		return "", fmt.Errorf("renders invalid JSON for tenant %s", data.Tenant.ID)
	}
	return b.String(), nil
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
	if err := s3utils.CheckValidBucketNameStrict(name); err != nil {
		return "", fmt.Errorf("renders invalid name %q for tenant %s: %w", name, t.ID, err)
	}
	return name, nil
}

// reservedPrefixes and reservedSuffixes are bucket name affixes AWS
// rejects (after hyphen runs are collapsed).
var (
	reservedPrefixes = []string{"sthree-", "amzn-s3-demo-"}
	reservedSuffixes = []string{"-s3alias"}
)

// SanitizeName turns s into a valid S3 bucket name candidate: lowercase,
// characters other than [a-z0-9-] replaced by "-", hyphen runs collapsed,
// leading and trailing hyphens trimmed and reserved affixes avoided. It does
// not enforce the length limits, which need the tenant ID; see renderName.
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
	out := strings.Trim(b.String(), "-")
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(out, p) {
			out = "t-" + out
		}
	}
	for _, sfx := range reservedSuffixes {
		if strings.HasSuffix(out, sfx) {
			out += "-t"
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
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

func (p *Plugin) Name() string { return "s3" }

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
		err = p.provisionPrefix(ctx, tg, t, quota)
	} else {
		err = p.provisionBucket(ctx, tg, t, quota)
	}
	if err != nil || p.iam == nil {
		return err
	}
	return p.provisionIAM(ctx, t, tg)
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
	// Revoke access first: with retain the data stays, but the tenant's
	// credentials must not.
	if p.iam != nil {
		if err := p.deprovisionIAM(ctx, t, tg); err != nil {
			return err
		}
	}
	if p.cfg.Mode == ModePrefix {
		return p.deprovisionPrefix(ctx, tg, t)
	}
	return p.deprovisionBucket(ctx, tg, t)
}

// quota returns the tenant's quota_from_limit value as a tag value, or ""
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

// errCode returns the S3 error code of err ("" if none).
func errCode(err error) string { return minio.ToErrorResponse(err).Code }

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	Mode     string `json:"mode"`
	Bucket   string `json:"bucket"`
	Prefix   string `json:"prefix,omitempty"`
	Endpoint string `json:"endpoint"`
	// IAMUser is the tenant's IAM user when iam.enabled.
	IAMUser string `json:"iam_user,omitempty"`
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
	info := TenantInfo{Mode: p.cfg.Mode, Bucket: tg.Bucket, Prefix: tg.Prefix, Endpoint: p.cfg.Endpoint}
	if p.iam != nil {
		if info.IAMUser, err = p.iamUserName(t, tg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// Health lists buckets (bucket mode) or checks that the shared bucket
// exists (prefix mode). With iam.enabled it also lists IAM users.
func (p *Plugin) Health(ctx context.Context) error {
	if p.iam != nil {
		if _, err := p.iam.ListUsers(ctx, &iam.ListUsersInput{
			PathPrefix: aws.String(p.cfg.IAM.Path), MaxItems: aws.Int32(1),
		}); err != nil {
			return fmt.Errorf("iam: %w", err)
		}
	}
	if p.cfg.Mode == ModePrefix {
		ok, err := p.client.BucketExists(ctx, p.cfg.Bucket)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("shared bucket %s does not exist", p.cfg.Bucket)
		}
		return nil
	}
	_, err := p.client.ListBuckets(ctx)
	return err
}
