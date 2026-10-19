// Package natsaccount provisions one NATS account per tenant for NATS
// decentralized JWT authentication (operator mode).
//
// For every tenant the plugin derives an account key pair from the tenant ID
// (see AccountKeyPair), builds an account JWT signed by the operator signing
// key, and pushes it to the account resolver: either the NATS servers
// themselves (resolver.mode nats, for the "full" or "cache" resolver, via
// $SYS.REQ.CLAIMS.UPDATE as a system account user) or an HTTP account server
// (resolver.mode http, the nats-account-server API).
//
// # Account keys
//
// Account keys are never stored. The 32 byte ed25519 seed of a tenant's
// account is HMAC-SHA256(account_seed_secret, "nats-account:" + tenant ID),
// so the same secret always yields the same account. Applications that know
// the secret can derive the account key with AccountKeyPair and sign user
// JWTs for the tenant. Changing the secret changes every account key: all
// tenants get new, empty accounts and existing user JWTs stop working, so
// treat the secret like the operator signing key.
//
// # Ownership
//
// Account JWTs carry the tag "tenarium-tenant-id:<id>". Since the account
// public key is derived from the tenant ID, two tenants cannot map to the
// same account; the tag is a second line of defense against JWTs that were
// pushed by someone else (another tool sharing the operator, or another
// installation using the same secret). Before pushing, the plugin looks up
// the current JWT: one tagged for another tenant, or not tagged at all, is
// never overwritten nor deleted.
//
// # Limits
//
// limits maps NATS account limits (conn, subs, data, payload, leaf, imports,
// exports, mem_storage, disk_storage, streams, consumers) to Tenarium limit
// names. Absent or negative entitlements are unlimited (-1, jwt.NoLimit);
// unmapped limits are unlimited too. JetStream is disabled unless jetstream
// is true (optionally only for tenants with jetstream_feature).
//
// # Deprovisioning
//
// on_deprovision chooses what happens when a tenant is deleted:
//
//   - delete (default in nats mode): the account JWT is removed from the
//     resolver with $SYS.REQ.CLAIMS.DELETE, a request signed by the operator
//     signing key. It needs a full resolver with allow_delete: true; when the
//     servers refuse ("delete must be enabled"), the plugin falls back to
//     disable and logs a warning. Not available in http mode.
//   - disable (default in http mode): the account JWT is re-pushed with all
//     limits set to 0, JetStream disabled and every user JWT issued so far
//     revoked, so existing connections are dropped and new ones refused. The
//     account (and its key) stays known to the resolver, tagged
//     "tenarium-disabled".
//   - keep: nothing is touched.
//
// There is no "retain" mode: the account key is derived from the tenant ID,
// so ownership cannot be released to another tenant.
package natsaccount

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func init() {
	sdk.Register("nats-tenant", func() sdk.Plugin { return &Plugin{} })
}

// Resolver modes and deprovision actions.
const (
	ModeNATS = "nats"
	ModeHTTP = "http"

	DeprovisionDelete  = "delete"
	DeprovisionDisable = "disable"
	DeprovisionKeep    = "keep"
)

// DefaultNameTemplate names tenant accounts when name_template is unset.
const DefaultNameTemplate = "tenant-{{.Slug}}"

// DefaultTimeout bounds every resolver request.
const DefaultTimeout = 5 * time.Second

// maxNameLen bounds account names (display only; NATS has no hard limit).
const maxNameLen = 64

// Tags set on account JWTs. Tag values are lower case (jwt.TagList).
const (
	TagTenantPrefix = "tenarium-tenant-id:"
	TagDisabled     = "tenarium-disabled"
)

// Limit names accepted as keys of the limits mapping.
const (
	LimitConn        = "conn"
	LimitSubs        = "subs"
	LimitData        = "data"
	LimitPayload     = "payload"
	LimitLeaf        = "leaf"
	LimitImports     = "imports"
	LimitExports     = "exports"
	LimitMemStorage  = "mem_storage"
	LimitDiskStorage = "disk_storage"
	LimitStreams     = "streams"
	LimitConsumers   = "consumers"
)

var (
	natsLimitKeys = []string{LimitConn, LimitSubs, LimitData, LimitPayload, LimitLeaf, LimitImports, LimitExports}
	jsLimitKeys   = []string{LimitMemStorage, LimitDiskStorage, LimitStreams, LimitConsumers}
)

type Config struct {
	// OperatorSigningKey is the operator seed ("SO...") that signs account
	// JWTs: the operator identity key or one of its signing keys.
	OperatorSigningKey string `json:"operator_signing_key"`
	// OperatorPublicKey is the operator identity ("O..."), for display and
	// validation.
	OperatorPublicKey string `json:"operator_public_key"`
	// OperatorJWT is the operator JWT, used to check that the signing key is
	// trusted by the operator.
	OperatorJWT string `json:"operator_jwt"`
	// AccountSeedSecret is the HMAC key account seeds are derived from.
	AccountSeedSecret string `json:"account_seed_secret"`
	// NameTemplate renders the account JWT name from an sdk.Tenant.
	NameTemplate string         `json:"name_template"`
	Resolver     ResolverConfig `json:"resolver"`
	// Limits maps a NATS account limit to a Tenarium limit name.
	Limits map[string]string `json:"limits"`
	// JetStream enables JetStream for tenant accounts.
	JetStream bool `json:"jetstream"`
	// JetStreamFeature restricts JetStream to tenants with this feature.
	JetStreamFeature string `json:"jetstream_feature"`
	// OnDeprovision is "delete", "disable" or "keep".
	OnDeprovision string `json:"on_deprovision"`
}

// ResolverConfig selects where account JWTs are pushed.
type ResolverConfig struct {
	// Mode is "nats" or "http".
	Mode string `json:"mode"`
	// URLs are the NATS servers (nats mode).
	URLs []string `json:"urls"`
	// URL is the account server base URL, e.g.
	// http://nats-account-server:9090/jwt/v1 (http mode).
	URL string `json:"url"`
	// CredentialsFile is a system account user creds file (nats mode).
	CredentialsFile string `json:"credentials_file"`
	// UserJWT and UserSeed are inline system account user credentials.
	UserJWT  string `json:"user_jwt"`
	UserSeed string `json:"user_seed"`
	// User and Password authenticate with username/password (nats mode).
	User     string `json:"user"`
	Password string `json:"password"`
	// Token is a NATS auth token (nats mode) or a bearer token sent to the
	// account server (http mode).
	Token string `json:"token"`
	// CAFile is a PEM file of CAs trusted for TLS.
	CAFile string `json:"ca_file"`
	// Timeout bounds each request, as a Go duration (default 5s).
	Timeout string `json:"timeout"`
}

var configSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "operator_signing_key": {"type": "string", "pattern": "^SO[A-Z2-7]+$"},
    "operator_public_key": {"type": "string", "pattern": "^O[A-Z2-7]+$"},
    "operator_jwt": {"type": "string", "minLength": 1},
    "account_seed_secret": {"type": "string", "minLength": 16},
    "name_template": {"type": "string", "minLength": 1},
    "resolver": {
      "type": "object",
      "properties": {
        "mode": {"enum": ["nats", "http"]},
        "urls": {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1},
        "url": {"type": "string", "minLength": 1},
        "credentials_file": {"type": "string", "minLength": 1},
        "user_jwt": {"type": "string", "minLength": 1},
        "user_seed": {"type": "string", "minLength": 1},
        "user": {"type": "string", "minLength": 1},
        "password": {"type": "string"},
        "token": {"type": "string", "minLength": 1},
        "ca_file": {"type": "string", "minLength": 1},
        "timeout": {"type": "string", "minLength": 1}
      },
      "required": ["mode"],
      "additionalProperties": false
    },
    "limits": {
      "type": "object",
      "properties": {
        "conn": {"type": "string", "minLength": 1},
        "subs": {"type": "string", "minLength": 1},
        "data": {"type": "string", "minLength": 1},
        "payload": {"type": "string", "minLength": 1},
        "leaf": {"type": "string", "minLength": 1},
        "imports": {"type": "string", "minLength": 1},
        "exports": {"type": "string", "minLength": 1},
        "mem_storage": {"type": "string", "minLength": 1},
        "disk_storage": {"type": "string", "minLength": 1},
        "streams": {"type": "string", "minLength": 1},
        "consumers": {"type": "string", "minLength": 1}
      },
      "additionalProperties": false
    },
    "jetstream": {"type": "boolean"},
    "jetstream_feature": {"type": "string", "minLength": 1},
    "on_deprovision": {"enum": ["delete", "disable", "keep"]}
  },
  "required": ["operator_signing_key", "account_seed_secret", "resolver"],
  "additionalProperties": false
}`)

type Plugin struct {
	cfg         Config
	name        *template.Template
	signer      nkeys.KeyPair
	signerPub   string
	operatorPub string
	timeout     time.Duration
	res         resolver
	host        sdk.Host
	log         *slog.Logger
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "nats-tenant",
		Name:         "NATS Tenant Accounts",
		Version:      "0.1.0",
		Description:  "Provisions a NATS account per tenant (decentralized JWT auth) and pushes it to the account resolver.",
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
	p.host = r.Host()
	p.log = r.Logger()
	if p.cfg.Resolver.Mode == ModeNATS {
		p.res = newNATSResolver(&p.cfg.Resolver, p.timeout)
	} else {
		res, err := newHTTPResolver(&p.cfg.Resolver, p.timeout)
		if err != nil {
			return err
		}
		p.res = res
	}
	r.Provisioner(p)
	r.Route("GET /tenants/{tenant}", http.HandlerFunc(p.serveTenant))
	return nil
}

// validate checks and defaults the configuration and compiles templates.
func (p *Plugin) validate() error {
	c := &p.cfg
	if c.OperatorSigningKey == "" {
		return errors.New("operator_signing_key is required")
	}
	prefix, _, err := nkeys.DecodeSeed([]byte(c.OperatorSigningKey))
	if err != nil {
		return fmt.Errorf("operator_signing_key: not a valid nkey seed: %w", err)
	}
	if prefix != nkeys.PrefixByteOperator {
		return fmt.Errorf("operator_signing_key must be an operator seed (SO...), got a %s seed", prefix)
	}
	if p.signer, err = nkeys.FromSeed([]byte(c.OperatorSigningKey)); err != nil {
		return fmt.Errorf("operator_signing_key: %w", err)
	}
	if p.signerPub, err = p.signer.PublicKey(); err != nil {
		return fmt.Errorf("operator_signing_key: %w", err)
	}
	if c.OperatorPublicKey != "" && !nkeys.IsValidPublicOperatorKey(c.OperatorPublicKey) {
		return fmt.Errorf("operator_public_key must be an operator public key (O...), got %q", c.OperatorPublicKey)
	}
	p.operatorPub = c.OperatorPublicKey
	if c.OperatorJWT != "" {
		oc, err := jwt.DecodeOperatorClaims(strings.TrimSpace(c.OperatorJWT))
		if err != nil {
			return fmt.Errorf("operator_jwt: %w", err)
		}
		if p.operatorPub != "" && oc.Subject != p.operatorPub {
			return fmt.Errorf("operator_jwt is for operator %s, not operator_public_key %s", oc.Subject, p.operatorPub)
		}
		p.operatorPub = oc.Subject
		switch {
		case p.signerPub == oc.Subject && oc.StrictSigningKeyUsage:
			return errors.New("operator_signing_key is the operator identity key, but the operator requires signing keys (strict_signing_key_usage)")
		case p.signerPub != oc.Subject && !oc.SigningKeys.Contains(p.signerPub):
			return fmt.Errorf("operator_signing_key %s is not a signing key of operator %s", p.signerPub, oc.Subject)
		}
	}
	if c.AccountSeedSecret == "" {
		return errors.New("account_seed_secret is required")
	}
	if len(c.AccountSeedSecret) < 16 {
		return errors.New("account_seed_secret must be at least 16 characters")
	}
	if err := p.validateResolver(); err != nil {
		return err
	}
	for k, v := range c.Limits {
		if !slices.Contains(natsLimitKeys, k) && !slices.Contains(jsLimitKeys, k) {
			return fmt.Errorf("limits: unknown NATS limit %q (want one of %s)", k, strings.Join(append(slices.Clone(natsLimitKeys), jsLimitKeys...), ", "))
		}
		if v == "" {
			return fmt.Errorf("limits.%s: Tenarium limit name must not be empty", k)
		}
		if slices.Contains(jsLimitKeys, k) && !c.JetStream {
			return fmt.Errorf("limits.%s is a JetStream limit; set jetstream: true", k)
		}
	}
	if c.JetStreamFeature != "" && !c.JetStream {
		return errors.New("jetstream_feature requires jetstream: true")
	}
	switch c.OnDeprovision {
	case "":
		if c.Resolver.Mode == ModeHTTP {
			c.OnDeprovision = DeprovisionDisable
		} else {
			c.OnDeprovision = DeprovisionDelete
		}
	case DeprovisionDelete:
		if c.Resolver.Mode == ModeHTTP {
			return errors.New("on_deprovision delete is not supported by the http resolver (the account server has no delete API); use disable or keep")
		}
	case DeprovisionDisable, DeprovisionKeep:
	default:
		return fmt.Errorf("on_deprovision must be delete, disable or keep, got %q", c.OnDeprovision)
	}
	if c.NameTemplate == "" {
		c.NameTemplate = DefaultNameTemplate
	}
	if p.name, err = parseNameTemplate(c.NameTemplate); err != nil {
		return err
	}
	return nil
}

func (p *Plugin) validateResolver() error {
	r := &p.cfg.Resolver
	p.timeout = DefaultTimeout
	if r.Timeout != "" {
		d, err := time.ParseDuration(r.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("resolver.timeout must be a positive duration such as 5s, got %q", r.Timeout)
		}
		p.timeout = d
	}
	if r.CAFile != "" {
		if _, err := os.Stat(r.CAFile); err != nil {
			return fmt.Errorf("resolver.ca_file: %w", err)
		}
	}
	switch r.Mode {
	case ModeNATS:
		if len(r.URLs) == 0 {
			return errors.New("resolver.urls is required in nats mode")
		}
		if r.URL != "" {
			return errors.New("resolver.url is only used in http mode; use resolver.urls")
		}
		for _, u := range r.URLs {
			pu, err := url.Parse(u)
			if err != nil || pu.Host == "" || !slices.Contains([]string{"nats", "tls", "ws", "wss"}, pu.Scheme) {
				return fmt.Errorf("resolver.urls: %q is not a nats://, tls://, ws:// or wss:// URL", u)
			}
		}
		methods := 0
		if r.CredentialsFile != "" {
			methods++
			if _, err := os.Stat(r.CredentialsFile); err != nil {
				return fmt.Errorf("resolver.credentials_file: %w", err)
			}
		}
		if r.UserJWT != "" || r.UserSeed != "" {
			methods++
			if r.UserJWT == "" || r.UserSeed == "" {
				return errors.New("resolver.user_jwt and resolver.user_seed must be set together")
			}
			uc, err := jwt.DecodeUserClaims(strings.TrimSpace(r.UserJWT))
			if err != nil {
				return fmt.Errorf("resolver.user_jwt: %w", err)
			}
			kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(r.UserSeed)))
			if err != nil {
				return fmt.Errorf("resolver.user_seed: %w", err)
			}
			if pub, _ := kp.PublicKey(); pub != uc.Subject || !nkeys.IsValidPublicUserKey(pub) {
				return errors.New("resolver.user_seed must be the user seed (SU...) of resolver.user_jwt")
			}
		}
		if r.User != "" || r.Password != "" {
			methods++
			if r.User == "" {
				return errors.New("resolver.password requires resolver.user")
			}
		}
		if r.Token != "" {
			methods++
		}
		if methods > 1 {
			return errors.New("resolver: use only one of credentials_file, user_jwt/user_seed, user/password or token")
		}
	case ModeHTTP:
		if r.URL == "" {
			return errors.New("resolver.url is required in http mode")
		}
		pu, err := url.Parse(r.URL)
		if err != nil || pu.Host == "" || (pu.Scheme != "http" && pu.Scheme != "https") {
			return fmt.Errorf("resolver.url must be an http(s) URL, got %q", r.URL)
		}
		r.URL = strings.TrimRight(r.URL, "/")
		if len(r.URLs) > 0 {
			return errors.New("resolver.urls is only used in nats mode; use resolver.url")
		}
		for opt, set := range map[string]bool{
			"credentials_file":   r.CredentialsFile != "",
			"user_jwt/user_seed": r.UserJWT != "" || r.UserSeed != "",
			"user/password":      r.User != "" || r.Password != "",
		} {
			if set {
				return fmt.Errorf("resolver.%s is only used in nats mode", opt)
			}
		}
	case "":
		return errors.New("resolver.mode is required (nats or http)")
	default:
		return fmt.Errorf("resolver.mode must be nats or http, got %q", r.Mode)
	}
	return nil
}

// AccountKeyPair derives the account key pair of a tenant: an ed25519 key
// whose seed is HMAC-SHA256(secret, "nats-account:" + tenantID). It is
// deterministic, so applications holding the secret can sign user JWTs for
// the tenant's account without any stored key.
func AccountKeyPair(secret, tenantID string) (nkeys.KeyPair, error) {
	if secret == "" || tenantID == "" {
		return nil, errors.New("secret and tenant ID are required")
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("nats-account:" + tenantID))
	return nkeys.FromRawSeed(nkeys.PrefixByteAccount, m.Sum(nil))
}

// TenantAccountPublicKey returns the public key ("A...") of a tenant's
// account, see AccountKeyPair.
func TenantAccountPublicKey(secret, tenantID string) (string, error) {
	kp, err := AccountKeyPair(secret, tenantID)
	if err != nil {
		return "", err
	}
	return kp.PublicKey()
}

// TenantTag is the ownership tag of a tenant's account JWT.
func TenantTag(tenantID string) string { return strings.ToLower(TagTenantPrefix + tenantID) }

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
	name := SanitizeName(b.String())
	if name == "" {
		return "", fmt.Errorf("renders an empty name for tenant %q", t.ID)
	}
	if len(name) > maxNameLen {
		// Truncating alone could map two tenants to one name; a hash of the
		// tenant ID keeps shortened names distinct.
		sum := sha256.Sum256([]byte(t.ID))
		suffix := "-" + hex.EncodeToString(sum[:4])
		name = strings.TrimRight(name[:maxNameLen-len(suffix)], "-_.") + suffix
	}
	return name, nil
}

// SanitizeName restricts s to the characters nsc and the NATS tooling
// handle without quoting: letters, digits, '-', '_' and '.'. Other
// characters become '-', runs of '-' are collapsed and leading or trailing
// separators trimmed. It does not enforce the length limit.
func SanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.':
			b.WriteRune(r)
		case !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-_.")
}

func (p *Plugin) accountName(t sdk.Tenant) (string, error) {
	name, err := renderName(p.name, t)
	if err != nil {
		return "", fmt.Errorf("name_template: %w", err)
	}
	return name, nil
}

// accountPub returns the public key of the tenant's account.
func (p *Plugin) accountPub(t sdk.Tenant) (string, error) {
	return TenantAccountPublicKey(p.cfg.AccountSeedSecret, t.ID)
}

// limits computes the account limits of a tenant from its entitlements.
func (p *Plugin) limits(ctx context.Context, t sdk.Tenant) (jwt.OperatorLimits, error) {
	l := jwt.NewAccountClaims("A").Limits // NATS defaults: unlimited, JetStream off
	if len(p.cfg.Limits) == 0 && p.cfg.JetStreamFeature == "" {
		if p.cfg.JetStream {
			setJetStream(&l, nil)
		}
		return l, nil
	}
	e, err := p.host.Entitlements(ctx, t.ID)
	if err != nil {
		return l, fmt.Errorf("entitlements: %w", err)
	}
	val := func(key string) int64 {
		name, ok := p.cfg.Limits[key]
		if !ok {
			return jwt.NoLimit
		}
		v, ok := e.Limit(name)
		if !ok || v < 0 {
			return jwt.NoLimit
		}
		return v
	}
	l.Conn = val(LimitConn)
	l.Subs = val(LimitSubs)
	l.Data = val(LimitData)
	l.Payload = val(LimitPayload)
	l.LeafNodeConn = val(LimitLeaf)
	l.Imports = val(LimitImports)
	l.Exports = val(LimitExports)
	if p.cfg.JetStream && (p.cfg.JetStreamFeature == "" || e.HasFeature(p.cfg.JetStreamFeature)) {
		setJetStream(&l, val)
	}
	return l, nil
}

// setJetStream enables JetStream with val's limits (unlimited when nil).
func setJetStream(l *jwt.OperatorLimits, val func(string) int64) {
	if val == nil {
		val = func(string) int64 { return jwt.NoLimit }
	}
	l.MemoryStorage = val(LimitMemStorage)
	l.DiskStorage = val(LimitDiskStorage)
	l.Streams = val(LimitStreams)
	l.Consumer = val(LimitConsumers)
}

// accountClaims builds the account JWT claims of a tenant.
func (p *Plugin) accountClaims(ctx context.Context, t sdk.Tenant, pub string) (*jwt.AccountClaims, error) {
	name, err := p.accountName(t)
	if err != nil {
		return nil, err
	}
	l, err := p.limits(ctx, t)
	if err != nil {
		return nil, err
	}
	ac := jwt.NewAccountClaims(pub)
	ac.Name = name
	ac.Limits = l
	ac.Tags.Add(TenantTag(t.ID))
	return ac, nil
}

func (p *Plugin) encode(ac *jwt.AccountClaims) (string, error) {
	token, err := ac.Encode(p.signer)
	if err != nil {
		return "", fmt.Errorf("sign account JWT: %w", err)
	}
	return token, nil
}

// errForeign is returned for account JWTs not tagged for the tenant.
var errForeign = errors.New("account JWT is not owned by this tenant")

// checkOwner verifies that ac is tagged for tenantID.
func checkOwner(ac *jwt.AccountClaims, tenantID string) error {
	want := TenantTag(tenantID)
	var others []string
	for _, tag := range ac.Tags {
		if tag == want {
			return nil
		}
		if strings.HasPrefix(tag, TagTenantPrefix) {
			others = append(others, strings.TrimPrefix(tag, TagTenantPrefix))
		}
	}
	if len(others) > 0 {
		return fmt.Errorf("%w: account %s is tagged for tenant %s", errForeign, ac.Subject, strings.Join(others, ", "))
	}
	return fmt.Errorf("%w: account %s exists without a %s tag (not created by Tenarium)", errForeign, ac.Subject, TagTenantPrefix+"<id>")
}

// current returns the account JWT the resolver holds for pub, or nil.
func (p *Plugin) current(ctx context.Context, pub string) (*jwt.AccountClaims, string, error) {
	token, err := p.res.Lookup(ctx, pub)
	if err != nil {
		return nil, "", fmt.Errorf("look up account %s: %w", pub, err)
	}
	if token == "" {
		return nil, "", nil
	}
	ac, err := jwt.DecodeAccountClaims(token)
	if err != nil {
		return nil, "", fmt.Errorf("decode current JWT of account %s: %w", pub, err)
	}
	if ac.Subject != pub {
		return nil, "", fmt.Errorf("resolver returned a JWT for account %s when asked for %s", ac.Subject, pub)
	}
	return ac, token, nil
}

func (p *Plugin) Name() string { return "nats-account" }

// Provision creates or updates the tenant's account JWT. It refuses to
// overwrite a JWT that is not tagged for the tenant.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	pub, err := p.accountPub(t)
	if err != nil {
		return err
	}
	ac, err := p.accountClaims(ctx, t, pub)
	if err != nil {
		return err
	}
	cur, _, err := p.current(ctx, pub)
	if err != nil {
		return err
	}
	if cur != nil {
		if err := checkOwner(cur, t.ID); err != nil {
			return fmt.Errorf("refusing to overwrite: %w", err)
		}
	}
	token, err := p.encode(ac)
	if err != nil {
		return err
	}
	if err := p.res.Push(ctx, pub, token); err != nil {
		return fmt.Errorf("push account %s: %w", pub, err)
	}
	return nil
}

// Deprovision applies on_deprovision. A tenant whose account is unknown to
// the resolver is treated as already deprovisioned; an account tagged for
// someone else is left alone.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	pub, err := p.accountPub(t)
	if err != nil {
		return err
	}
	cur, _, err := p.current(ctx, pub)
	if err != nil {
		return err
	}
	if cur == nil {
		return nil
	}
	if err := checkOwner(cur, t.ID); err != nil {
		p.log.Warn("not deprovisioning NATS account owned by someone else", "tenant", t.ID, "account", pub, "error", err)
		return nil
	}
	if p.cfg.OnDeprovision == DeprovisionDelete {
		err := p.deleteAccount(ctx, pub)
		if !errors.Is(err, errDeleteUnsupported) {
			return err
		}
		p.log.Warn("resolver does not allow deleting accounts, disabling instead (set allow_delete: true on the full resolver)", "tenant", t.ID, "account", pub, "error", err)
	}
	return p.disable(ctx, cur)
}

// deleteAccount sends a delete request signed by the operator signing key.
func (p *Plugin) deleteAccount(ctx context.Context, pub string) error {
	gc := jwt.NewGenericClaims(p.signerPub)
	gc.Data["accounts"] = []string{pub}
	token, err := gc.Encode(p.signer)
	if err != nil {
		return fmt.Errorf("sign delete request: %w", err)
	}
	if err := p.res.Delete(ctx, token); err != nil {
		return fmt.Errorf("delete account %s: %w", pub, err)
	}
	return nil
}

// disable re-pushes cur with every limit at 0 and all user JWTs revoked.
func (p *Plugin) disable(ctx context.Context, cur *jwt.AccountClaims) error {
	if cur.Tags.Contains(TagDisabled) {
		return nil
	}
	ac := jwt.NewAccountClaims(cur.Subject)
	ac.Name = cur.Name
	ac.Tags = slices.Clone(cur.Tags)
	ac.Tags.Add(TagDisabled)
	ac.Limits = disabledLimits()
	ac.RevokeAt(jwt.All, time.Now())
	token, err := p.encode(ac)
	if err != nil {
		return err
	}
	if err := p.res.Push(ctx, cur.Subject, token); err != nil {
		return fmt.Errorf("disable account %s: %w", cur.Subject, err)
	}
	return nil
}

func disabledLimits() jwt.OperatorLimits {
	var l jwt.OperatorLimits
	l.JetStreamTieredLimits = jwt.JetStreamTieredLimits{}
	return l // every limit 0: no connections, subscriptions, data or JetStream
}

// TenantInfo is the response of GET /tenants/{tenant}.
type TenantInfo struct {
	AccountPublicKey string `json:"account_public_key"`
	AccountName      string `json:"account_name"`
	// AccountJWT is the JWT the resolver holds (empty when not provisioned).
	AccountJWT  string `json:"account_jwt,omitempty"`
	Provisioned bool   `json:"provisioned"`
	Disabled    bool   `json:"disabled,omitempty"`
	// OperatorPublicKey is the operator identity, when configured.
	OperatorPublicKey string `json:"operator_public_key,omitempty"`
	// SigningKey is the public key that signs account JWTs.
	SigningKey   string `json:"signing_key"`
	ResolverMode string `json:"resolver_mode"`
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
	pub, err := p.accountPub(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name, err := p.accountName(t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info := TenantInfo{
		AccountPublicKey: pub, AccountName: name, OperatorPublicKey: p.operatorPub,
		SigningKey: p.signerPub, ResolverMode: p.cfg.Resolver.Mode,
	}
	cur, token, err := p.current(r.Context(), pub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if cur != nil && checkOwner(cur, t.ID) == nil {
		info.AccountJWT, info.Provisioned = token, true
		info.Disabled = cur.Tags.Contains(TagDisabled)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// Health checks that the resolver is reachable.
func (p *Plugin) Health(ctx context.Context) error { return p.res.Health(ctx) }

// Stop closes the NATS connection, if any.
func (p *Plugin) Stop(context.Context) error {
	if p.res == nil {
		return nil
	}
	return p.res.Close()
}
