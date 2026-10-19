// Package ldapdir keeps Tenarium's platform users in a writable LDAP
// directory (OpenLDAP, 389 Directory Server, Active Directory, ...).
//
// A service account adds user entries under a base DN, modifies, renames
// and deletes them, and sets passwords (with the Password Modify extended
// operation, a userPassword write, or Active Directory's unicodePwd).
// Disabling a user sets a configurable attribute or, on Active Directory,
// the ACCOUNTDISABLE bit of userAccountControl. Passwords are verified by
// binding as the user's entry (sdk.PasswordVerifier).
//
// The plugin does not send invitations: Tenarium sends its own and sets the
// password the user chooses through SetPassword.
package ldapdir

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func init() {
	sdk.Register("ldap-directory", func() sdk.Plugin { return &Plugin{} })
}

// Password modes.
const (
	PasswordModify = "password_modify" // RFC 3062 extended operation
	PasswordAttr   = "user_password"   // replace userPassword (the server hashes it)
	PasswordAD     = "unicode_pwd"     //nolint:gosec // Active Directory unicodePwd; G101: a mode name, not a credential
)

// Disable modes.
const (
	DisableNone      = "none"
	DisableAttribute = "attribute"
	DisableAD        = "ad_user_account_control"
)

// RDN sources.
const (
	RDNFromEmail  = "email"
	RDNFromUserID = "user_id"
)

// Config is the plugin's configuration block.
type Config struct {
	// URL of the directory, e.g. "ldaps://ldap.example.com:636".
	URL                string `json:"url"`
	StartTLS           bool   `json:"start_tls"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	// Timeout bounds dialing and each LDAP operation (default "5s").
	Timeout string `json:"timeout"`
	// BindDN and BindPassword identify the service account; it needs write
	// access to UserBaseDN.
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`

	// UserBaseDN is where new entries are created.
	UserBaseDN string `json:"user_base_dn"`
	// SearchBaseDN is where users are looked up (default UserBaseDN).
	SearchBaseDN string `json:"search_base_dn"`
	// UserFilter finds a user by email; %s is replaced by the escaped email.
	// Default "(mail=%s)" with mail being EmailAttribute.
	UserFilter string `json:"user_filter"`
	// ActiveDirectory switches the defaults to Active Directory: object
	// classes top/person/organizationalPerson/user, RDN cn, ID objectGUID,
	// name in displayName, unicodePwd passwords, userAccountControl for
	// disabling and userPrincipalName set to the email.
	ActiveDirectory bool `json:"active_directory"`
	// ObjectClasses of new entries; default
	// top/person/organizationalPerson/inetOrgPerson.
	ObjectClasses []string `json:"object_classes"`
	// RDNAttribute names new entries (default "uid", AD "cn"); its value
	// comes from RDNSource: "email" (default; entries are renamed when the
	// email changes) or "user_id" (the Tenarium user ID, stable).
	RDNAttribute string `json:"rdn_attribute"`
	RDNSource    string `json:"rdn_source"`
	// IDAttribute is the stable identifier returned as the user's external
	// ID: "entryUUID" (default), "objectGUID" (AD default), "nsUniqueId",
	// "dn", ...
	IDAttribute string `json:"id_attribute"`

	// Attribute mapping. Empty values use the defaults; "-" leaves the
	// attribute out (not possible for email_attribute).
	EmailAttribute     string `json:"email_attribute"`      // "mail"
	NameAttribute      string `json:"name_attribute"`       // "cn" (AD "displayName")
	GivenNameAttribute string `json:"given_name_attribute"` // "givenName"
	SurnameAttribute   string `json:"surname_attribute"`    // "sn"
	// UserIDAttribute stores the owning Tenarium user ID, e.g.
	// "employeeNumber". Without it ownership is not recorded and an
	// existing entry with the same email is always adopted.
	UserIDAttribute string `json:"user_id_attribute"`
	// AttributeMap copies Tenarium user attributes to LDAP attributes, e.g.
	// {"dept": "departmentNumber"}. Others are ignored.
	AttributeMap map[string]string `json:"attribute_map"`
	// ExtraAttributes are set when an entry is created, as text/template
	// strings over .ID, .IDHex, .Email, .LocalPart, .Domain, .Name,
	// .GivenName and .Surname, e.g. {"sAMAccountName": "{{slice .IDHex 0 20}}"}.
	ExtraAttributes map[string]string `json:"extra_attributes"`

	// PasswordMode is "password_modify" (default), "user_password" or
	// "unicode_pwd" (AD default; needs ldaps:// or start_tls).
	PasswordMode string `json:"password_mode"`
	// Disable configures how disabled users are marked.
	Disable *DisableConfig `json:"disable"`
	// VerifyPasswords enables password verification by binding as the
	// user (default true).
	VerifyPasswords *bool `json:"verify_passwords"`
}

// DisableConfig configures disabled users.
type DisableConfig struct {
	// Mode is "none" (default without AD), "attribute" or
	// "ad_user_account_control" (default with AD).
	Mode string `json:"mode"`
	// Attribute, DisabledValue and EnabledValue configure mode "attribute":
	// disabled users get DisabledValue, others EnabledValue (empty removes
	// the attribute). E.g. OpenLDAP ppolicy: pwdAccountLockedTime with
	// disabled_value "000001010000Z".
	Attribute     string `json:"attribute"`
	DisabledValue string `json:"disabled_value"`
	EnabledValue  string `json:"enabled_value"`
}

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["url", "bind_dn", "bind_password", "user_base_dn"],
  "additionalProperties": false,
  "properties": {
    "url": {"type": "string", "pattern": "^ldaps?://"},
    "start_tls": {"type": "boolean"},
    "insecure_skip_verify": {"type": "boolean"},
    "timeout": {"type": "string"},
    "bind_dn": {"type": "string", "minLength": 1},
    "bind_password": {"type": "string", "minLength": 1},
    "user_base_dn": {"type": "string", "minLength": 1},
    "search_base_dn": {"type": "string"},
    "user_filter": {"type": "string"},
    "active_directory": {"type": "boolean"},
    "object_classes": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}},
    "rdn_attribute": {"type": "string"},
    "rdn_source": {"enum": ["email", "user_id"]},
    "id_attribute": {"type": "string"},
    "email_attribute": {"type": "string"},
    "name_attribute": {"type": "string"},
    "given_name_attribute": {"type": "string"},
    "surname_attribute": {"type": "string"},
    "user_id_attribute": {"type": "string"},
    "attribute_map": {"type": "object", "additionalProperties": {"type": "string", "minLength": 1}},
    "extra_attributes": {"type": "object", "additionalProperties": {"type": "string"}},
    "password_mode": {"enum": ["password_modify", "user_password", "unicode_pwd"]},
    "disable": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "mode": {"enum": ["none", "attribute", "ad_user_account_control"]},
        "attribute": {"type": "string"},
        "disabled_value": {"type": "string"},
        "enabled_value": {"type": "string"}
      }
    },
    "verify_passwords": {"type": "boolean"}
  }
}`)

// conn is the subset of *ldap.Conn the plugin uses.
type conn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Add(req *ldap.AddRequest) error
	Modify(req *ldap.ModifyRequest) error
	ModifyDN(req *ldap.ModifyDNRequest) error
	Del(req *ldap.DelRequest) error
	PasswordModify(req *ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error)
	StartTLS(cfg *tls.Config) error
	Close() error
}

// Plugin is the LDAP user directory plugin.
type Plugin struct {
	cfg     Config
	timeout time.Duration
	tls     *tls.Config
	extra   map[string]*template.Template

	// dial opens a connection; replaced in tests.
	dial func(ctx context.Context, timeout time.Duration) (conn, error)
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           "ldap-directory",
		Name:         "LDAP user directory",
		Version:      "0.1.0",
		Description:  "Keeps platform users in a writable LDAP directory or Active Directory.",
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
	d := &directory{p: p}
	if p.cfg.VerifyPasswords == nil || *p.cfg.VerifyPasswords {
		r.UserDirectory(verifyingDirectory{d})
	} else {
		r.UserDirectory(d)
	}
	return nil
}

var attrName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
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
	if c.BindDN == "" || c.BindPassword == "" {
		return errors.New("bind_dn and bind_password are required")
	}
	for name, dn := range map[string]string{"user_base_dn": c.UserBaseDN, "search_base_dn": c.SearchBaseDN, "bind_dn": c.BindDN} {
		if dn == "" && name == "search_base_dn" {
			continue
		}
		if _, err := ldap.ParseDN(dn); err != nil || dn == "" {
			return fmt.Errorf("%s: invalid DN %q", name, dn)
		}
	}
	c.SearchBaseDN = or(c.SearchBaseDN, c.UserBaseDN)

	ad := c.ActiveDirectory
	if len(c.ObjectClasses) == 0 {
		if ad {
			c.ObjectClasses = []string{"top", "person", "organizationalPerson", "user"}
		} else {
			c.ObjectClasses = []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
		}
	}
	c.RDNAttribute = or(c.RDNAttribute, map[bool]string{true: "cn", false: "uid"}[ad])
	c.RDNSource = or(c.RDNSource, RDNFromEmail)
	c.IDAttribute = or(c.IDAttribute, map[bool]string{true: "objectGUID", false: "entryUUID"}[ad])
	c.EmailAttribute = or(c.EmailAttribute, "mail")
	c.NameAttribute = or(c.NameAttribute, map[bool]string{true: "displayName", false: "cn"}[ad])
	c.GivenNameAttribute = or(c.GivenNameAttribute, "givenName")
	c.SurnameAttribute = or(c.SurnameAttribute, "sn")
	c.UserFilter = or(c.UserFilter, "("+c.EmailAttribute+"=%s)")
	c.PasswordMode = or(c.PasswordMode, map[bool]string{true: PasswordAD, false: PasswordModify}[ad])
	if c.Disable == nil {
		c.Disable = &DisableConfig{}
	}
	c.Disable.Mode = or(c.Disable.Mode, map[bool]string{true: DisableAD, false: DisableNone}[ad])
	if ad {
		if _, ok := c.ExtraAttributes["userPrincipalName"]; !ok {
			if c.ExtraAttributes == nil {
				c.ExtraAttributes = map[string]string{}
			}
			c.ExtraAttributes["userPrincipalName"] = "{{.Email}}"
		}
	}

	switch c.RDNSource {
	case RDNFromEmail, RDNFromUserID:
	default:
		return fmt.Errorf("rdn_source must be email or user_id, got %q", c.RDNSource)
	}
	switch c.PasswordMode {
	case PasswordModify, PasswordAttr:
	case PasswordAD:
		if u.Scheme != "ldaps" && !c.StartTLS {
			return errors.New("password_mode unicode_pwd needs an ldaps:// url or start_tls")
		}
	default:
		return fmt.Errorf("password_mode must be password_modify, user_password or unicode_pwd, got %q", c.PasswordMode)
	}
	switch dc := c.Disable; dc.Mode {
	case DisableNone, DisableAD:
		if dc.Attribute != "" || dc.DisabledValue != "" || dc.EnabledValue != "" {
			return fmt.Errorf("disable.attribute and values are only used with disable.mode attribute")
		}
	case DisableAttribute:
		if !attrName.MatchString(dc.Attribute) || dc.DisabledValue == "" || dc.DisabledValue == dc.EnabledValue {
			return errors.New("disable.mode attribute needs disable.attribute and a disable.disabled_value different from enabled_value")
		}
	default:
		return fmt.Errorf("disable.mode must be none, attribute or ad_user_account_control, got %q", dc.Mode)
	}
	if strings.Count(c.UserFilter, "%s") != 1 {
		return errors.New("user_filter must contain exactly one %s")
	}
	if _, err := ldap.CompileFilter(strings.Replace(c.UserFilter, "%s", "x", 1)); err != nil {
		return fmt.Errorf("user_filter: %w", err)
	}
	if err := p.checkAttributes(); err != nil {
		return err
	}
	p.extra = map[string]*template.Template{}
	for attr, text := range c.ExtraAttributes {
		if !attrName.MatchString(attr) {
			return fmt.Errorf("extra_attributes: invalid attribute name %q", attr)
		}
		t, err := template.New(attr).Option("missingkey=error").Parse(text)
		if err != nil {
			return fmt.Errorf("extra_attributes[%s]: %w", attr, err)
		}
		if _, err := execTemplate(t, templateData(sampleUser)); err != nil {
			return fmt.Errorf("extra_attributes[%s]: %w", attr, err)
		}
		p.extra[attr] = t
	}

	if p.timeout, err = time.ParseDuration(or(c.Timeout, "5s")); err != nil || p.timeout <= 0 {
		return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
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

// checkAttributes validates attribute names and that no attribute is
// managed twice. The RDN attribute may only coincide with the email
// attribute when the RDN is the email.
func (p *Plugin) checkAttributes() error {
	c := &p.cfg
	used := map[string]string{}
	claim := func(field, attr string) error {
		if attr == "" || attr == "-" {
			return nil
		}
		if !attrName.MatchString(attr) {
			return fmt.Errorf("%s: invalid attribute name %q", field, attr)
		}
		key := strings.ToLower(attr)
		if prev, ok := used[key]; ok {
			return fmt.Errorf("%s: attribute %q is already used by %s", field, attr, prev)
		}
		used[key] = field
		return nil
	}
	if c.EmailAttribute == "-" {
		return errors.New("email_attribute cannot be left out")
	}
	fields := []struct{ field, attr string }{
		{"email_attribute", c.EmailAttribute}, {"name_attribute", c.NameAttribute},
		{"given_name_attribute", c.GivenNameAttribute}, {"surname_attribute", c.SurnameAttribute},
		{"user_id_attribute", c.UserIDAttribute},
	}
	for attr, ldapAttr := range c.AttributeMap {
		fields = append(fields, struct{ field, attr string }{"attribute_map[" + attr + "]", ldapAttr})
	}
	if c.Disable.Mode == DisableAttribute {
		fields = append(fields, struct{ field, attr string }{"disable.attribute", c.Disable.Attribute})
	}
	for _, f := range fields {
		if err := claim(f.field, f.attr); err != nil {
			return err
		}
	}
	if !attrName.MatchString(c.RDNAttribute) {
		return fmt.Errorf("rdn_attribute: invalid attribute name %q", c.RDNAttribute)
	}
	if prev, ok := used[strings.ToLower(c.RDNAttribute)]; ok && !(prev == "email_attribute" && c.RDNSource == RDNFromEmail) {
		return fmt.Errorf("rdn_attribute %q is also %s", c.RDNAttribute, prev)
	}
	if c.IDAttribute != "dn" && !attrName.MatchString(c.IDAttribute) {
		return fmt.Errorf("id_attribute: invalid attribute name %q", c.IDAttribute)
	}
	for attr := range c.ExtraAttributes {
		if prev, ok := used[strings.ToLower(attr)]; ok || strings.EqualFold(attr, c.RDNAttribute) {
			return fmt.Errorf("extra_attributes: %q is already managed (%s)", attr, or(prev, "rdn_attribute"))
		}
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

// connect dials the directory, upgrades with StartTLS if configured and
// binds the service account.
func (p *Plugin) connect(ctx context.Context) (conn, func(), error) {
	timeout := p.timeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(dl))
	}
	if timeout <= 0 {
		return nil, nil, context.DeadlineExceeded
	}
	c, err := p.dial(ctx, timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("ldap: dial: %w", err)
	}
	// Abort blocking LDAP calls when the request goes away.
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	done := func() { stop(); _ = c.Close() }
	if p.cfg.StartTLS {
		if err := c.StartTLS(p.tls); err != nil {
			done()
			return nil, nil, fmt.Errorf("ldap: starttls: %w", err)
		}
	}
	if err := c.Bind(p.cfg.BindDN, p.cfg.BindPassword); err != nil {
		done()
		return nil, nil, fmt.Errorf("ldap: service bind: %w", err)
	}
	return c, done, nil
}

// Health dials the directory and binds the service account.
func (p *Plugin) Health(ctx context.Context) error {
	_, done, err := p.connect(ctx)
	if err != nil {
		return err
	}
	done()
	return nil
}

// --- entry building ---

// tmplData is what extra_attributes templates see.
type tmplData struct {
	ID, IDHex, Email, LocalPart, Domain, Name, GivenName, Surname string
}

var sampleUser = sdk.User{ID: "0190a5c4-7b1e-7cc0-8a6e-1f2b3c4d5e6f", Email: "ada@example.com", Name: "Ada Lovelace"}

func templateData(u sdk.User) tmplData {
	local, domain, _ := strings.Cut(u.Email, "@")
	given, sur := splitName(u)
	return tmplData{
		ID: u.ID, IDHex: strings.ReplaceAll(u.ID, "-", ""), Email: u.Email, LocalPart: local, Domain: domain,
		Name: displayName(u), GivenName: given, Surname: sur,
	}
}

func execTemplate(t *template.Template, d tmplData) (s string, err error) {
	defer func() {
		if r := recover(); r != nil { // e.g. slice out of range
			err = fmt.Errorf("%v", r)
		}
	}()
	var b strings.Builder
	if err := t.Execute(&b, d); err != nil {
		return "", err
	}
	return b.String(), nil
}

func displayName(u sdk.User) string {
	if n := strings.Join(strings.Fields(u.Name), " "); n != "" {
		return n
	}
	return u.Email
}

// splitName returns the given name and the surname. The surname (sn is
// mandatory for person entries) falls back to the full name or the email's
// local part.
func splitName(u sdk.User) (string, string) {
	given, sur, _ := strings.Cut(strings.Join(strings.Fields(u.Name), " "), " ")
	if sur == "" {
		sur = given
		given = ""
	}
	if sur == "" {
		sur, _, _ = strings.Cut(u.Email, "@")
	}
	return given, sur
}

// rdnValue is the value of u's RDN attribute.
func (p *Plugin) rdnValue(u sdk.User) string {
	if p.cfg.RDNSource == RDNFromUserID {
		return u.ID
	}
	return u.Email
}

// dnFor is the DN of a new entry for u.
func (p *Plugin) dnFor(u sdk.User) string {
	return p.cfg.RDNAttribute + "=" + ldap.EscapeDN(p.rdnValue(u)) + "," + p.cfg.UserBaseDN
}

// managed returns the attributes the directory keeps in step with u. An
// empty value list means the attribute is removed. The RDN attribute is
// left out (it changes only through a rename).
func (p *Plugin) managed(u sdk.User) map[string][]string {
	c := p.cfg
	given, sur := splitName(u)
	out := map[string][]string{}
	set := func(attr, v string) {
		if attr == "" || attr == "-" || strings.EqualFold(attr, c.RDNAttribute) {
			return
		}
		if v == "" {
			out[attr] = []string{}
		} else {
			out[attr] = []string{v}
		}
	}
	set(c.EmailAttribute, u.Email)
	set(c.NameAttribute, displayName(u))
	set(c.GivenNameAttribute, given)
	set(c.SurnameAttribute, sur)
	if c.UserIDAttribute != "" {
		set(c.UserIDAttribute, u.ID)
	}
	for attr, ldapAttr := range c.AttributeMap {
		set(ldapAttr, u.Attributes[attr])
	}
	if c.Disable.Mode == DisableAttribute {
		if u.Status == sdk.UserDisabled {
			set(c.Disable.Attribute, c.Disable.DisabledValue)
		} else {
			set(c.Disable.Attribute, c.Disable.EnabledValue)
		}
	}
	return out
}

// Active Directory userAccountControl flags.
const (
	uacAccountDisable = 0x0002
	uacNormalAccount  = 0x0200
)

// addRequest builds the request creating u's entry.
func (p *Plugin) addRequest(u sdk.User) (*ldap.AddRequest, error) {
	c := p.cfg
	req := ldap.NewAddRequest(p.dnFor(u), nil)
	req.Attribute("objectClass", c.ObjectClasses)
	req.Attribute(c.RDNAttribute, []string{p.rdnValue(u)})
	for attr, vals := range p.managed(u) {
		if len(vals) > 0 {
			req.Attribute(attr, vals)
		}
	}
	data := templateData(u)
	for attr, t := range p.extra {
		v, err := execTemplate(t, data)
		if err != nil {
			return nil, fmt.Errorf("ldap: extra_attributes[%s]: %w", attr, err)
		}
		if v != "" {
			req.Attribute(attr, []string{v})
		}
	}
	if c.Disable.Mode == DisableAD {
		// Created disabled: AD refuses enabled accounts without a password.
		// SetPassword enables the account.
		req.Attribute("userAccountControl", []string{fmt.Sprint(uacNormalAccount | uacAccountDisable)})
	}
	return req, nil
}

// unicodePwd encodes password for Active Directory's unicodePwd: quoted
// and UTF-16LE.
func unicodePwd(password string) string {
	quoted := []rune("\"" + password + "\"")
	b := make([]byte, 0, len(quoted)*2)
	for _, r := range quoted {
		if r > 0xFFFF {
			r1, r2 := surrogates(r)
			b = append(b, byte(r1), byte(r1>>8), byte(r2), byte(r2>>8))
			continue
		}
		b = append(b, byte(r), byte(r>>8))
	}
	return string(b)
}

func surrogates(r rune) (rune, rune) {
	r -= 0x10000
	return 0xD800 + (r>>10)&0x3FF, 0xDC00 + r&0x3FF
}

// guidFilterValue converts a canonical GUID string to the escaped binary
// form an objectGUID filter needs.
func guidFilterValue(s string) (string, error) {
	h := strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 16 {
		return "", fmt.Errorf("invalid GUID %q", s)
	}
	// The first three groups are little-endian.
	order := []int{3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15}
	var sb strings.Builder
	for _, i := range order {
		fmt.Fprintf(&sb, "\\%02x", b[i])
	}
	return sb.String(), nil
}

// formatGUID renders an Active Directory objectGUID in its canonical form.
func formatGUID(b []byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%x-%x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8:10], b[10:16])
}
