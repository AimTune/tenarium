// Package ldap authenticates API callers with HTTP Basic credentials against
// an LDAP directory or Active Directory.
//
// A service account (or an anonymous bind) searches for the user entry, the
// caller's password is verified by binding as that entry, and group
// memberships are mapped to Tenarium roles. Successful authentications are
// cached briefly so that not every request costs a directory round trip.
package ldap

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("ldap", func() sdk.Plugin { return &Plugin{} })
}

// Config is the plugin's configuration block.
type Config struct {
	// URL of the directory, e.g. "ldaps://ldap.example.com:636".
	URL                string `json:"url"`
	StartTLS           bool   `json:"start_tls"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	// Timeout bounds dialing and each LDAP operation (default "5s").
	Timeout string `json:"timeout"`

	// BindDN and BindPassword identify the service account used to search.
	// When BindDN is empty the search is anonymous.
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`

	UserBaseDN string `json:"user_base_dn"`
	// UserFilter locates the user; %s is replaced by the escaped username.
	// Default "(uid=%s)"; use "(sAMAccountName=%s)" for Active Directory.
	UserFilter string `json:"user_filter"`
	// SubjectAttribute is the attribute used as Principal.Subject; "dn"
	// (default) uses the entry DN.
	SubjectAttribute string `json:"subject_attribute"`
	EmailAttribute   string `json:"email_attribute"`
	NameAttribute    string `json:"name_attribute"`

	// GroupAttribute lists group DNs on the user entry (default "memberOf").
	// It is ignored when GroupBaseDN is set.
	GroupAttribute string `json:"group_attribute"`
	// GroupBaseDN switches to searching groups; GroupFilter's %s is replaced
	// by the escaped user DN (default "(member=%s)").
	GroupBaseDN string `json:"group_base_dn"`
	GroupFilter string `json:"group_filter"`
	// RoleMapping maps group cn to Tenarium role. Unmapped groups are
	// ignored; when empty, group cns are used as roles verbatim.
	RoleMapping map[string]string `json:"role_mapping"`

	// TenantAttribute names a user attribute holding a tenant ID or slug
	// that scopes the principal to that tenant.
	TenantAttribute string `json:"tenant_attribute"`

	// CacheTTL caches successful authentications (default "60s", "0"
	// disables caching).
	CacheTTL string `json:"cache_ttl"`
}

// conn is the subset of *ldap.Conn the plugin uses.
type conn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	StartTLS(cfg *tls.Config) error
	Close() error
}

// Plugin is the LDAP authenticator.
type Plugin struct {
	cfg     Config
	timeout time.Duration
	tls     *tls.Config
	roles   map[string]string // lower-cased group cn -> role
	host    sdk.Host
	cache   *cache

	// dial opens a connection; replaced in tests.
	dial func(ctx context.Context, timeout time.Duration) (conn, error)
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "ldap",
		Name:         "LDAP",
		Version:      "0.1.0",
		Description:  "Authenticates API callers with HTTP Basic auth against LDAP or Active Directory.",
		ConfigSchema: configSchema,
	}
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["url", "user_base_dn"],
  "additionalProperties": false,
  "properties": {
    "url": {"type": "string", "pattern": "^ldaps?://"},
    "start_tls": {"type": "boolean"},
    "insecure_skip_verify": {"type": "boolean"},
    "timeout": {"type": "string"},
    "bind_dn": {"type": "string"},
    "bind_password": {"type": "string"},
    "user_base_dn": {"type": "string", "minLength": 1},
    "user_filter": {"type": "string"},
    "subject_attribute": {"type": "string"},
    "email_attribute": {"type": "string"},
    "name_attribute": {"type": "string"},
    "group_attribute": {"type": "string"},
    "group_base_dn": {"type": "string"},
    "group_filter": {"type": "string"},
    "role_mapping": {"type": "object", "additionalProperties": {"type": "string"}},
    "tenant_attribute": {"type": "string"},
    "cache_ttl": {"type": "string"}
  }
}`)

func (p *Plugin) Init(_ context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	if err := p.configure(); err != nil {
		return err
	}
	p.host = r.Host()
	r.Authenticator(p)
	return nil
}

// configure validates the configuration and applies defaults.
func (p *Plugin) configure() error {
	c := &p.cfg
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return fmt.Errorf("url must be an ldap:// or ldaps:// URL, got %q", c.URL)
	}
	if c.StartTLS && u.Scheme == "ldaps" {
		return errors.New("start_tls cannot be combined with an ldaps:// url")
	}
	if c.UserBaseDN == "" {
		return errors.New("user_base_dn is required")
	}
	if c.BindDN != "" && c.BindPassword == "" {
		return errors.New("bind_password is required when bind_dn is set")
	}
	c.UserFilter = cmpOr(c.UserFilter, "(uid=%s)")
	c.GroupFilter = cmpOr(c.GroupFilter, "(member=%s)")
	if strings.Count(c.UserFilter, "%s") != 1 {
		return errors.New("user_filter must contain exactly one %s")
	}
	if strings.Count(c.GroupFilter, "%s") != 1 {
		return errors.New("group_filter must contain exactly one %s")
	}
	c.SubjectAttribute = cmpOr(c.SubjectAttribute, "dn")
	c.EmailAttribute = cmpOr(c.EmailAttribute, "mail")
	c.NameAttribute = cmpOr(c.NameAttribute, "cn")
	c.GroupAttribute = cmpOr(c.GroupAttribute, "memberOf")

	if p.timeout, err = time.ParseDuration(cmpOr(c.Timeout, "5s")); err != nil || p.timeout <= 0 {
		return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
	}
	ttl, err := time.ParseDuration(cmpOr(c.CacheTTL, "60s"))
	if err != nil || ttl < 0 {
		return fmt.Errorf("cache_ttl: invalid duration %q", c.CacheTTL)
	}
	if ttl > 0 {
		p.cache = newCache(ttl, defaultCacheSize)
	}

	p.roles = make(map[string]string, len(c.RoleMapping))
	for g, role := range c.RoleMapping {
		p.roles[strings.ToLower(g)] = role
	}
	p.tls = &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // explicit opt-in
		MinVersion:         tls.VersionTLS12,
	}
	if p.dial == nil {
		p.dial = p.dialLDAP
	}
	return nil
}

func (p *Plugin) dialLDAP(_ context.Context, timeout time.Duration) (conn, error) {
	c, err := ldap.DialURL(p.cfg.URL,
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
		ldap.DialWithTLSConfig(p.tls))
	if err != nil {
		return nil, err
	}
	c.SetTimeout(timeout)
	return c, nil
}

// Name implements sdk.Authenticator.
func (p *Plugin) Name() string { return "basic" }

// Authenticate implements sdk.Authenticator.
func (p *Plugin) Authenticate(ctx context.Context, r *http.Request) (*sdk.Principal, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, sdk.ErrNoCredentials
	}
	if username == "" || password == "" {
		return nil, errors.New("ldap: username and password are required")
	}

	var key [32]byte
	if p.cache != nil {
		key = sha256.Sum256([]byte(username + "\x00" + password))
		if pr, ok := p.cache.get(key); ok {
			return pr, nil
		}
	}
	pr, err := p.authenticate(ctx, username, password)
	if err != nil {
		return nil, err
	}
	if p.cache != nil {
		p.cache.put(key, pr)
	}
	return pr, nil
}

// errInvalidCredentials hides whether the user or the password was wrong.
var errInvalidCredentials = errors.New("ldap: invalid credentials")

func (p *Plugin) authenticate(ctx context.Context, username, password string) (*sdk.Principal, error) {
	c, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	// Abort blocking LDAP calls when the request goes away.
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()

	user, err := p.findUser(c, username)
	if err != nil {
		return nil, err
	}
	if err := c.Bind(user.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, errInvalidCredentials
		}
		return nil, fmt.Errorf("ldap: user bind: %w", err)
	}

	groups, err := p.groups(c, user)
	if err != nil {
		return nil, err
	}
	subject, err := p.subject(user)
	if err != nil {
		return nil, err
	}
	pr := &sdk.Principal{
		Subject: subject,
		Kind:    "user",
		Roles:   p.mapRoles(groups),
		Claims: map[string]any{
			"username": username,
			"dn":       user.DN,
			"email":    user.GetEqualFoldAttributeValue(p.cfg.EmailAttribute),
			"name":     user.GetEqualFoldAttributeValue(p.cfg.NameAttribute),
		},
	}
	if attr := p.cfg.TenantAttribute; attr != "" {
		v := user.GetEqualFoldAttributeValue(attr)
		if v == "" {
			return nil, fmt.Errorf("ldap: user has no %s attribute", attr)
		}
		t, err := p.host.GetTenant(ctx, v)
		if err != nil {
			return nil, fmt.Errorf("ldap: tenant %q: %w", v, err)
		}
		pr.TenantID = t.ID
	}
	return pr, nil
}

// connect dials the directory, upgrades with StartTLS if configured and
// binds the service account.
func (p *Plugin) connect(ctx context.Context) (conn, error) {
	timeout := p.timeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(dl))
	}
	if timeout <= 0 {
		return nil, context.DeadlineExceeded
	}
	c, err := p.dial(ctx, timeout)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial: %w", err)
	}
	if p.cfg.StartTLS {
		if err := c.StartTLS(p.tls); err != nil {
			c.Close()
			return nil, fmt.Errorf("ldap: starttls: %w", err)
		}
	}
	if p.cfg.BindDN != "" {
		if err := c.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
			c.Close()
			return nil, fmt.Errorf("ldap: service bind: %w", err)
		}
	}
	return c, nil
}

func (p *Plugin) findUser(c conn, username string) (*ldap.Entry, error) {
	attrs := []string{p.cfg.EmailAttribute, p.cfg.NameAttribute}
	if p.cfg.SubjectAttribute != "dn" {
		attrs = append(attrs, p.cfg.SubjectAttribute)
	}
	if p.cfg.GroupBaseDN == "" {
		attrs = append(attrs, p.cfg.GroupAttribute)
	}
	if p.cfg.TenantAttribute != "" {
		attrs = append(attrs, p.cfg.TenantAttribute)
	}
	res, err := c.Search(&ldap.SearchRequest{
		BaseDN:     p.cfg.UserBaseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     fmt.Sprintf(p.cfg.UserFilter, ldap.EscapeFilter(username)),
		Attributes: attrs,
		SizeLimit:  2,
		TimeLimit:  int(p.timeout.Seconds()),
	})
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded):
		return nil, errors.New("ldap: username matches multiple entries")
	case err != nil:
		return nil, fmt.Errorf("ldap: user search: %w", err)
	case len(res.Entries) == 0:
		return nil, errInvalidCredentials
	case len(res.Entries) > 1:
		return nil, errors.New("ldap: username matches multiple entries")
	}
	return res.Entries[0], nil
}

// groups returns the cns of the user's groups. In search mode the service
// account is re-bound first (the connection is bound as the user).
func (p *Plugin) groups(c conn, user *ldap.Entry) ([]string, error) {
	if p.cfg.GroupBaseDN == "" {
		var cns []string
		for _, dn := range user.GetEqualFoldAttributeValues(p.cfg.GroupAttribute) {
			cns = append(cns, cnFromDN(dn))
		}
		return cns, nil
	}
	if p.cfg.BindDN != "" {
		if err := c.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("ldap: service re-bind: %w", err)
		}
	}
	res, err := c.Search(&ldap.SearchRequest{
		BaseDN:     p.cfg.GroupBaseDN,
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     fmt.Sprintf(p.cfg.GroupFilter, ldap.EscapeFilter(user.DN)),
		Attributes: []string{"cn"},
		TimeLimit:  int(p.timeout.Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("ldap: group search: %w", err)
	}
	cns := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		cns = append(cns, cmpOr(e.GetEqualFoldAttributeValue("cn"), cnFromDN(e.DN)))
	}
	return cns, nil
}

// cnFromDN returns the value of the leading cn RDN, or dn itself.
func cnFromDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 {
		return dn
	}
	for _, a := range parsed.RDNs[0].Attributes {
		if strings.EqualFold(a.Type, "cn") {
			return a.Value
		}
	}
	return dn
}

func (p *Plugin) mapRoles(groups []string) []string {
	var roles []string
	for _, g := range groups {
		if len(p.roles) == 0 {
			roles = append(roles, g)
		} else if role, ok := p.roles[strings.ToLower(g)]; ok {
			roles = append(roles, role)
		}
	}
	slices.Sort(roles)
	return slices.Compact(roles)
}

func (p *Plugin) subject(user *ldap.Entry) (string, error) {
	attr := p.cfg.SubjectAttribute
	if strings.EqualFold(attr, "dn") {
		return user.DN, nil
	}
	raw := user.GetEqualFoldRawAttributeValue(attr)
	switch {
	case len(raw) == 0:
		return "", fmt.Errorf("ldap: user has no %s attribute", attr)
	case strings.EqualFold(attr, "objectGUID") && len(raw) == 16:
		return formatGUID(raw), nil
	case !utf8.Valid(raw):
		return hex.EncodeToString(raw), nil
	}
	return string(raw), nil
}

// formatGUID renders an Active Directory objectGUID in its canonical form
// (the first three groups are little-endian).
func formatGUID(b []byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%x-%x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8:10], b[10:16])
}

// Health implements sdk.HealthChecker by dialing and binding the service
// account.
func (p *Plugin) Health(ctx context.Context) error {
	c, err := p.connect(ctx)
	if err != nil {
		return err
	}
	return c.Close()
}

func cmpOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func clonePrincipal(p *sdk.Principal) *sdk.Principal {
	c := *p
	c.Roles = slices.Clone(p.Roles)
	c.Claims = maps.Clone(p.Claims)
	return &c
}

const defaultCacheSize = 10_000

// cache holds successful authentications keyed by a hash of the
// credentials. It is bounded: when full, expired entries are dropped and,
// failing that, the entry closest to expiry is evicted.
type cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[[32]byte]cacheEntry
	now     func() time.Time
}

type cacheEntry struct {
	p   *sdk.Principal
	exp time.Time
}

func newCache(ttl time.Duration, max int) *cache {
	return &cache{ttl: ttl, max: max, entries: map[[32]byte]cacheEntry{}, now: time.Now}
}

func (c *cache) get(k [32]byte) (*sdk.Principal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok {
		return nil, false
	}
	if !c.now().Before(e.exp) {
		delete(c.entries, k)
		return nil, false
	}
	return clonePrincipal(e.p), true
}

func (c *cache) put(k [32]byte, p *sdk.Principal) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if _, exists := c.entries[k]; !exists && len(c.entries) >= c.max {
		var oldest [32]byte
		var oldestExp time.Time
		for key, e := range c.entries {
			if !now.Before(e.exp) {
				delete(c.entries, key)
			} else if oldestExp.IsZero() || e.exp.Before(oldestExp) {
				oldest, oldestExp = key, e.exp
			}
		}
		if len(c.entries) >= c.max {
			delete(c.entries, oldest)
		}
	}
	c.entries[k] = cacheEntry{p: clonePrincipal(p), exp: now.Add(c.ttl)}
}
