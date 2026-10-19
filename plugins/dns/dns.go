// Package dns provisions DNS records per tenant in an Amazon Route 53 hosted
// zone or a Cloudflare zone.
//
// Each entry of records renders a record set from text/templates over
// sdk.Tenant, e.g. name_template "{{.Slug}}" (relative to zone) or
// "{{.Slug}}.example.com", type CNAME and values ["ingress.example.com"].
// Supported types are A, AAAA, CNAME and TXT. Names are sanitized to DNS
// labels (lowercase letters, digits, hyphens; a leading underscore and a
// leading "*" label are kept); labels longer than 63 characters are
// shortened and suffixed with a hash of the tenant ID. Templates should
// only use immutable tenant fields (ID, Slug), since names are recomputed on
// deprovision.
//
// # Ownership
//
// Like the external-dns TXT registry, every record name the plugin manages
// has a sibling TXT marker at ownership_txt_prefix + name (default
// "_tenarium.<name>") whose value is "tenarium-owner=<tenant ID>". The
// marker cannot live at the record name itself because a CNAME cannot share
// its name with any other record. The marker is the source of truth on both
// providers:
//
//   - A name whose marker names another tenant is never written nor deleted.
//   - A record that already exists at a name without a marker is never taken
//     over; Provision fails with a clear error.
//   - Deprovision deletes the configured record types at a name only when
//     the marker names the tenant, and deletes the marker last.
//
// On Route 53 the marker and the records are written in one atomic change
// batch (CREATE for new sets, so a concurrent writer makes the batch fail,
// UPSERT for sets already owned) and deleted in one batch with the exact
// current values. Cloudflare has no transactions: the marker is created
// before the records and deleted after them, so an interrupted run is
// retried safely.
//
// # Deprovisioning
//
// on_deprovision is delete (default) or keep (records and markers stay; the
// marker still blocks other tenants from taking the names). There is no
// retain mode: DNS records hold no data worth keeping without their owner,
// and releasing the marker while keeping the records would leave live,
// unowned records that a new tenant could not reclaim.
package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("dns-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Providers, record types and deprovision actions.
const (
	ProviderRoute53    = "route53"
	ProviderCloudflare = "cloudflare"

	TypeA     = "A"
	TypeAAAA  = "AAAA"
	TypeCNAME = "CNAME"
	TypeTXT   = "TXT"

	DeprovisionDelete = "delete"
	DeprovisionKeep   = "keep"
)

// Defaults.
const (
	DefaultTTL                = 300
	DefaultOwnershipTXTPrefix = "_tenarium."
	DefaultCloudflareBaseURL  = "https://api.cloudflare.com/client/v4"
	DefaultRoute53Region      = "us-east-1"
	DefaultWaitTimeout        = 5 * time.Minute

	// OwnerValuePrefix starts the value of every ownership marker TXT.
	OwnerValuePrefix = "tenarium-owner="

	markerTTL = 300
)

type Config struct {
	// Provider is "route53" or "cloudflare"; the block of that name must be
	// set and the other one absent.
	Provider string `json:"provider"`
	// Zone is the DNS zone (domain), e.g. "example.com".
	Zone    string         `json:"zone"`
	Records []RecordConfig `json:"records"`
	// OwnershipTXTPrefix is prepended to a record name to form the name of
	// its ownership marker TXT. It must end with ".".
	OwnershipTXTPrefix string `json:"ownership_txt_prefix"`
	// OnDeprovision is "delete" (default) or "keep".
	OnDeprovision string            `json:"on_deprovision"`
	Route53       *Route53Config    `json:"route53"`
	Cloudflare    *CloudflareConfig `json:"cloudflare"`
}

type RecordConfig struct {
	// NameTemplate renders the record name, absolute or relative to zone.
	NameTemplate string `json:"name_template"`
	Type         string `json:"type"`
	// Values are templates too (static values are fine).
	Values []string `json:"values"`
	// TTL in seconds (default 300). On Cloudflare 1 means automatic.
	TTL int64 `json:"ttl"`
	// Proxied routes traffic through Cloudflare (A, AAAA, CNAME only).
	Proxied bool `json:"proxied"`
}

type Route53Config struct {
	// Region defaults to us-east-1 (Route 53 is a global service).
	Region string `json:"region"`
	// Static credentials; without them the default AWS credential chain
	// (environment, shared config, IAM role) is used.
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
	// Endpoint overrides the API URL, e.g. LocalStack.
	Endpoint string `json:"endpoint"`
	// HostedZoneID is looked up by zone name when empty.
	HostedZoneID string `json:"hosted_zone_id"`
	// Wait blocks Provision/Deprovision until the change is INSYNC.
	Wait bool `json:"wait"`
	// WaitTimeout bounds Wait (Go duration, default 5m).
	WaitTimeout string `json:"wait_timeout"`

	waitTimeout time.Duration
}

type CloudflareConfig struct {
	// APIToken needs Zone:Read and DNS:Edit on the zone.
	APIToken string `json:"api_token"`
	// BaseURL defaults to https://api.cloudflare.com/client/v4.
	BaseURL string `json:"base_url"`
	// ZoneID is looked up by zone name when empty.
	ZoneID string `json:"zone_id"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "provider": {"enum": ["route53", "cloudflare"]},
    "zone": {"type": "string", "minLength": 1},
    "records": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "properties": {
          "name_template": {"type": "string", "minLength": 1},
          "type": {"enum": ["A", "AAAA", "CNAME", "TXT"]},
          "values": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
          "ttl": {"type": "integer", "minimum": 1},
          "proxied": {"type": "boolean"}
        },
        "required": ["name_template", "type", "values"],
        "additionalProperties": false
      }
    },
    "ownership_txt_prefix": {"type": "string", "minLength": 1},
    "on_deprovision": {"enum": ["delete", "keep"]},
    "route53": {
      "type": "object",
      "properties": {
        "region": {"type": "string"},
        "access_key_id": {"type": "string"},
        "secret_access_key": {"type": "string"},
        "session_token": {"type": "string"},
        "endpoint": {"type": "string"},
        "hosted_zone_id": {"type": "string"},
        "wait": {"type": "boolean"},
        "wait_timeout": {"type": "string"}
      },
      "additionalProperties": false
    },
    "cloudflare": {
      "type": "object",
      "properties": {
        "api_token": {"type": "string", "minLength": 1},
        "base_url": {"type": "string"},
        "zone_id": {"type": "string"}
      },
      "required": ["api_token"],
      "additionalProperties": false
    }
  },
  "required": ["provider", "zone", "records"],
  "additionalProperties": false
}`)

// rrset is a record set: all records of one name and type.
type rrset struct {
	// Name is fully qualified, lowercase, without trailing dot.
	Name    string
	Type    string
	TTL     int64
	Values  []string // canonical, see normalizeValue
	Proxied bool
	// raw is the provider's representation of an existing set.
	raw any
}

// change is a set to write: want is the desired state, have the current one
// (nil when the set does not exist).
type change struct {
	want rrset
	have *rrset
}

// backend is a DNS provider.
type backend interface {
	// lookup returns the record sets at name, keyed by type.
	lookup(ctx context.Context, name string) (map[string]*rrset, error)
	// apply writes markers and records; markers are written first or in
	// the same atomic batch. Unchanged sets are skipped.
	apply(ctx context.Context, tenantID string, markers, records []change) error
	// remove deletes existing sets (as returned by lookup); markers last or
	// in the same atomic batch.
	remove(ctx context.Context, records, markers []*rrset) error
	health(ctx context.Context) error
}

type recordTemplate struct {
	name    *template.Template
	typ     string
	values  []*template.Template
	ttl     int64
	proxied bool
}

type Plugin struct {
	cfg     Config
	records []recordTemplate
	backend backend
	host    sdk.Host
	log     *slog.Logger
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "dns-tenant",
		Name:         "DNS Tenant Records",
		Version:      "0.1.0",
		Description:  "Creates DNS records per tenant in Amazon Route 53 or Cloudflare, with TXT ownership markers.",
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
	p.log = r.Logger()
	switch p.cfg.Provider {
	case ProviderRoute53:
		b, err := newRoute53(ctx, p.cfg.Zone, p.cfg.Route53)
		if err != nil {
			return fmt.Errorf("route53: %w", err)
		}
		p.backend = b
	case ProviderCloudflare:
		p.backend = newCloudflare(p.cfg.Zone, p.cfg.Cloudflare)
	}
	p.host = r.Host()
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	return nil
}

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	switch c.Provider {
	case ProviderRoute53:
		if c.Route53 == nil {
			return errors.New("provider route53 requires a route53 block")
		}
		if c.Cloudflare != nil {
			return errors.New("cloudflare block is set but provider is route53")
		}
		if err := c.Route53.validate(); err != nil {
			return fmt.Errorf("route53: %w", err)
		}
	case ProviderCloudflare:
		if c.Cloudflare == nil {
			return errors.New("provider cloudflare requires a cloudflare block")
		}
		if c.Route53 != nil {
			return errors.New("route53 block is set but provider is cloudflare")
		}
		if err := c.Cloudflare.validate(); err != nil {
			return fmt.Errorf("cloudflare: %w", err)
		}
	case "":
		return errors.New("provider is required (route53 or cloudflare)")
	default:
		return fmt.Errorf("provider must be route53 or cloudflare, got %q", c.Provider)
	}
	c.Zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.Zone)), ".")
	if err := validZone(c.Zone); err != nil {
		return fmt.Errorf("zone %q %w", c.Zone, err)
	}
	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDelete
	case DeprovisionDelete, DeprovisionKeep:
	case "retain":
		return errors.New("on_deprovision retain is not supported for DNS: records hold no data to retain; use keep or delete")
	default:
		return fmt.Errorf("on_deprovision must be delete or keep, got %q", c.OnDeprovision)
	}
	if c.OwnershipTXTPrefix == "" {
		c.OwnershipTXTPrefix = DefaultOwnershipTXTPrefix
	}
	if err := validPrefix(c.OwnershipTXTPrefix); err != nil {
		return err
	}
	if len(c.Records) == 0 {
		return errors.New("records must list at least one record")
	}
	p.records = nil
	for i := range c.Records {
		rt, err := p.compileRecord(&c.Records[i])
		if err != nil {
			return fmt.Errorf("records[%d]: %w", i, err)
		}
		p.records = append(p.records, rt)
	}
	// Cross-record checks (duplicates, CNAME exclusivity, marker clashes)
	// run on the rendered sets.
	for _, s := range []sdk.Tenant{sample1, sample2} {
		if _, err := p.render(s); err != nil {
			return err
		}
	}
	return nil
}

func validPrefix(prefix string) error {
	if !strings.HasSuffix(prefix, ".") {
		return fmt.Errorf("ownership_txt_prefix must end with \".\" (a separate label), got %q", prefix)
	}
	for _, l := range strings.Split(strings.TrimSuffix(prefix, "."), ".") {
		if l == "" || len(l) > maxLabelLen || SanitizeLabel(l) != l {
			return fmt.Errorf("ownership_txt_prefix %q has invalid label %q", prefix, l)
		}
	}
	return nil
}

func (c *Route53Config) validate() error {
	if c.Region == "" {
		c.Region = DefaultRoute53Region
	}
	if (c.AccessKeyID == "") != (c.SecretAccessKey == "") {
		return errors.New("access_key_id and secret_access_key must be set together")
	}
	if c.SessionToken != "" && c.AccessKeyID == "" {
		return errors.New("session_token requires access_key_id and secret_access_key")
	}
	if c.Endpoint != "" {
		if err := validHTTPURL(c.Endpoint); err != nil {
			return fmt.Errorf("endpoint: %w", err)
		}
	}
	c.HostedZoneID = strings.TrimPrefix(c.HostedZoneID, "/hostedzone/")
	c.waitTimeout = DefaultWaitTimeout
	if c.WaitTimeout != "" {
		d, err := time.ParseDuration(c.WaitTimeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("wait_timeout must be a positive duration, got %q", c.WaitTimeout)
		}
		c.waitTimeout = d
	}
	return nil
}

func (c *CloudflareConfig) validate() error {
	if c.APIToken == "" {
		return errors.New("api_token is required")
	}
	if c.BaseURL == "" {
		c.BaseURL = DefaultCloudflareBaseURL
	}
	c.BaseURL = strings.TrimSuffix(c.BaseURL, "/")
	if err := validHTTPURL(c.BaseURL); err != nil {
		return fmt.Errorf("base_url: %w", err)
	}
	return nil
}

func validHTTPURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("must be an http(s) URL, got %q", s)
	}
	return nil
}

func (p *Plugin) compileRecord(rc *RecordConfig) (recordTemplate, error) {
	switch rc.Type {
	case TypeA, TypeAAAA, TypeCNAME, TypeTXT:
	default:
		return recordTemplate{}, fmt.Errorf("type must be A, AAAA, CNAME or TXT, got %q", rc.Type)
	}
	if len(rc.Values) == 0 {
		return recordTemplate{}, errors.New("values must not be empty")
	}
	if rc.Type == TypeCNAME && len(rc.Values) != 1 {
		return recordTemplate{}, fmt.Errorf("a CNAME must have exactly one value, got %d", len(rc.Values))
	}
	if rc.TTL == 0 {
		rc.TTL = DefaultTTL
	}
	if rc.TTL < 0 {
		return recordTemplate{}, fmt.Errorf("ttl must be positive, got %d", rc.TTL)
	}
	if p.cfg.Provider == ProviderCloudflare && rc.TTL != 1 && (rc.TTL < 30 || rc.TTL > 86400) {
		return recordTemplate{}, fmt.Errorf("cloudflare ttl must be 1 (automatic) or between 30 and 86400, got %d", rc.TTL)
	}
	if p.cfg.Provider == ProviderRoute53 && rc.TTL > 2147483647 {
		return recordTemplate{}, fmt.Errorf("ttl %d is too large", rc.TTL)
	}
	if rc.Proxied {
		if p.cfg.Provider != ProviderCloudflare {
			return recordTemplate{}, errors.New("proxied is only supported by the cloudflare provider")
		}
		if rc.Type == TypeTXT {
			return recordTemplate{}, errors.New("TXT records cannot be proxied")
		}
	}
	if rc.NameTemplate == "" {
		return recordTemplate{}, errors.New("name_template is required")
	}
	rt := recordTemplate{typ: rc.Type, ttl: rc.TTL, proxied: rc.Proxied}
	var err error
	if rt.name, err = parseTemplate("name", rc.NameTemplate); err != nil {
		return recordTemplate{}, fmt.Errorf("name_template: %w", err)
	}
	n1, err := renderName(rt.name, sample1, p.cfg.Zone)
	if err != nil {
		return recordTemplate{}, fmt.Errorf("name_template: %w", err)
	}
	n2, err := renderName(rt.name, sample2, p.cfg.Zone)
	if err != nil {
		return recordTemplate{}, fmt.Errorf("name_template: %w", err)
	}
	if n1 == n2 {
		return recordTemplate{}, errors.New("name_template must depend on the tenant (e.g. {{.Slug}} or {{.ID}})")
	}
	for i, v := range rc.Values {
		vt, err := parseTemplate("value", v)
		if err != nil {
			return recordTemplate{}, fmt.Errorf("values[%d]: %w", i, err)
		}
		rt.values = append(rt.values, vt)
	}
	return rt, nil
}

// render returns the record sets of tenant t, in configuration order.
func (p *Plugin) render(t sdk.Tenant) ([]rrset, error) {
	sets := make([]rrset, 0, len(p.records))
	types := map[string][]string{} // name -> types
	for i, rt := range p.records {
		name, err := renderName(rt.name, t, p.cfg.Zone)
		if err != nil {
			return nil, fmt.Errorf("records[%d].name_template: %w", i, err)
		}
		s := rrset{Name: name, Type: rt.typ, TTL: rt.ttl, Proxied: rt.proxied}
		if rt.proxied {
			s.TTL = 1 // Proxied records always use automatic TTL.
		}
		for j, vt := range rt.values {
			raw, err := execute(vt, t)
			if err != nil {
				return nil, fmt.Errorf("records[%d].values[%d]: %w", i, j, err)
			}
			v, err := normalizeValue(rt.typ, raw)
			if err != nil {
				return nil, fmt.Errorf("records[%d].values[%d]: renders %w for tenant %s", i, j, err, t.ID)
			}
			if !slices.Contains(s.Values, v) {
				s.Values = append(s.Values, v)
			}
		}
		if rt.typ == TypeCNAME && s.Values[0] == name {
			return nil, fmt.Errorf("records[%d]: CNAME %s points to itself", i, name)
		}
		have := types[name]
		if slices.Contains(have, rt.typ) {
			return nil, fmt.Errorf("records[%d]: duplicate %s record %s (merge the values into one entry)", i, rt.typ, name)
		}
		if len(have) > 0 && (rt.typ == TypeCNAME || slices.Contains(have, TypeCNAME)) {
			return nil, fmt.Errorf("records[%d]: a CNAME cannot coexist with other records at %s", i, name)
		}
		types[name] = append(have, rt.typ)
		sets = append(sets, s)
	}
	for _, s := range sets {
		m, err := p.markerName(s.Name)
		if err != nil {
			return nil, err
		}
		if _, clash := types[m]; clash {
			return nil, fmt.Errorf("record %s clashes with the ownership marker of %s; change ownership_txt_prefix or the record name", m, s.Name)
		}
	}
	return sets, nil
}

// markerName is the name of the ownership TXT of a record name. A leading
// "*" label (wildcard) is replaced by "_wildcard", since a wildcard must be
// the leftmost label.
func (p *Plugin) markerName(name string) (string, error) {
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		name = "_wildcard." + rest
	}
	m := p.cfg.OwnershipTXTPrefix + name
	if len(m) > maxNameLen {
		return "", fmt.Errorf("ownership marker name %s is longer than %d characters; shorten the record name or ownership_txt_prefix", m, maxNameLen)
	}
	return m, nil
}

func markerSet(name, tenantID string) rrset {
	return rrset{Name: name, Type: TypeTXT, TTL: markerTTL, Values: []string{OwnerValuePrefix + tenantID}}
}

// errNotMarker reports a TXT set at a marker name that is not a tenarium
// ownership marker.
var errNotMarker = errors.New("not a tenarium ownership marker")

// markerOwner returns the tenant ID recorded in an existing marker set ("" if
// there is none).
func markerOwner(m *rrset) (string, error) {
	if m == nil {
		return "", nil
	}
	owner := ""
	for _, v := range m.Values {
		id, ok := strings.CutPrefix(v, OwnerValuePrefix)
		if !ok || id == "" || (owner != "" && id != owner) {
			return "", fmt.Errorf("TXT %s %w (values %q)", m.Name, errNotMarker, m.Values)
		}
		owner = id
	}
	return owner, nil
}

// group returns the distinct names of sets in order and the sets per name.
func group(sets []rrset) ([]string, map[string][]rrset) {
	var names []string
	by := map[string][]rrset{}
	for _, s := range sets {
		if _, ok := by[s.Name]; !ok {
			names = append(names, s.Name)
		}
		by[s.Name] = append(by[s.Name], s)
	}
	return names, by
}

func (p *Plugin) Name() string { return "dns" }

// Provision creates or updates the tenant's records and their ownership
// markers. It refuses names owned by another tenant and records it does not
// own.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	sets, err := p.render(t)
	if err != nil {
		return err
	}
	names, byName := group(sets)
	var markers, records []change
	for _, name := range names {
		mname, _ := p.markerName(name) // validated by render
		mhave, err := p.backend.lookup(ctx, mname)
		if err != nil {
			return fmt.Errorf("look up %s: %w", mname, err)
		}
		owner, err := markerOwner(mhave[TypeTXT])
		if err != nil {
			return fmt.Errorf("refusing to manage %s: %w", name, err)
		}
		if owner != "" && owner != t.ID {
			return fmt.Errorf("%s is owned by tenant %s (marker %s); refusing to take it over", name, owner, mname)
		}
		have, err := p.backend.lookup(ctx, name)
		if err != nil {
			return fmt.Errorf("look up %s: %w", name, err)
		}
		if owner == "" {
			if err := checkUnowned(name, mname, byName[name], have); err != nil {
				return err
			}
		}
		markers = append(markers, change{want: markerSet(mname, t.ID), have: mhave[TypeTXT]})
		for _, s := range byName[name] {
			records = append(records, change{want: s, have: have[s.Type]})
		}
	}
	if err := p.backend.apply(ctx, t.ID, markers, records); err != nil {
		return err
	}
	p.log.Info("dns records provisioned", "tenant", t.ID, "names", names)
	return nil
}

// checkUnowned fails if writing want at a name without an ownership marker
// would overwrite or conflict with existing records.
func checkUnowned(name, mname string, want []rrset, have map[string]*rrset) error {
	for _, s := range want {
		if have[s.Type] != nil {
			return fmt.Errorf("%s record %s already exists without a tenarium ownership marker (%s TXT); refusing to take it over", s.Type, name, mname)
		}
		if s.Type == TypeCNAME && len(have) > 0 {
			return fmt.Errorf("cannot create CNAME %s: other records exist at that name", name)
		}
		if have[TypeCNAME] != nil {
			return fmt.Errorf("cannot create %s %s: a CNAME exists at that name", s.Type, name)
		}
	}
	return nil
}

// Deprovision deletes the tenant's records (on_deprovision delete). Names
// not marked for the tenant are left alone, so a tenant that was never
// provisioned, is already deprovisioned or never owned a name is fine.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	sets, err := p.render(t)
	if err != nil {
		return err
	}
	names, byName := group(sets)
	var records, markers []*rrset
	for _, name := range names {
		mname, _ := p.markerName(name)
		mhave, err := p.backend.lookup(ctx, mname)
		if err != nil {
			return fmt.Errorf("look up %s: %w", mname, err)
		}
		owner, err := markerOwner(mhave[TypeTXT])
		if err != nil {
			p.log.Warn("skipping dns name without a valid ownership marker", "tenant", t.ID, "name", name, "error", err)
			continue
		}
		if owner != t.ID {
			if owner != "" {
				p.log.Warn("skipping dns name owned by another tenant", "tenant", t.ID, "name", name, "owner", owner)
			}
			continue
		}
		have, err := p.backend.lookup(ctx, name)
		if err != nil {
			return fmt.Errorf("look up %s: %w", name, err)
		}
		for _, s := range byName[name] {
			if h := have[s.Type]; h != nil {
				records = append(records, h)
			}
		}
		markers = append(markers, mhave[TypeTXT])
	}
	if len(records) == 0 && len(markers) == 0 {
		return nil
	}
	if err := p.backend.remove(ctx, records, markers); err != nil {
		return err
	}
	p.log.Info("dns records deleted", "tenant", t.ID, "names", names)
	return nil
}

// sameSet reports whether an existing set already matches the desired one.
func sameSet(want rrset, have *rrset) bool {
	if have == nil || want.TTL != have.TTL || want.Proxied != have.Proxied || len(want.Values) != len(have.Values) {
		return false
	}
	a, b := slices.Clone(want.Values), slices.Clone(have.Values)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	Provider string       `json:"provider"`
	Zone     string       `json:"zone"`
	Records  []RecordInfo `json:"records"`
}

// RecordInfo is a rendered record set.
type RecordInfo struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Values  []string `json:"values"`
	TTL     int64    `json:"ttl"`
	Proxied bool     `json:"proxied,omitempty"`
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
	sets, err := p.render(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info := TenantInfo{Provider: p.cfg.Provider, Zone: p.cfg.Zone, Records: []RecordInfo{}}
	for _, s := range sets {
		info.Records = append(info.Records, RecordInfo{Name: s.Name, Type: s.Type, Values: s.Values, TTL: s.TTL, Proxied: s.Proxied})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// Health checks that the zone is reachable with the configured credentials.
func (p *Plugin) Health(ctx context.Context) error { return p.backend.health(ctx) }
