package ldapdir

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"

	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/AimTune/tenarium/pkg/sdk/sdktest"
)

var ada = sdk.User{ID: "0190a5c4-7b1e-7cc0-8a6e-1f2b3c4d5e6f", Email: "Ada@Example.com", Name: "Ada King Lovelace",
	Status: sdk.UserInvited, Attributes: map[string]string{"dept": "math"}}

func newPlugin(t *testing.T, cfg map[string]any) *Plugin {
	t.Helper()
	base := map[string]any{"url": "ldap://ldap.example.com", "bind_dn": "cn=admin,dc=example,dc=org",
		"bind_password": "admin", "user_base_dn": "ou=people,dc=example,dc=org"}
	for k, v := range cfg {
		base[k] = v
	}
	p := &Plugin{}
	reg := sdktest.NewRegistrar(base)
	if err := p.Init(context.Background(), reg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return p
}

func attrMap(req *ldap.AddRequest) map[string][]string {
	m := map[string][]string{}
	for _, a := range req.Attributes {
		m[a.Type] = a.Vals
	}
	return m
}

func TestDefaultsAndEntryBuilding(t *testing.T) {
	p := newPlugin(t, map[string]any{"user_id_attribute": "employeeNumber",
		"attribute_map": map[string]any{"dept": "departmentNumber", "team": "ou"}})
	c := p.cfg
	if c.RDNAttribute != "uid" || c.IDAttribute != "entryUUID" || c.NameAttribute != "cn" || c.UserFilter != "(mail=%s)" ||
		c.PasswordMode != PasswordModify || c.Disable.Mode != DisableNone || c.SearchBaseDN != c.UserBaseDN {
		t.Fatalf("defaults = %+v", c)
	}
	u := ada
	u.Email = "a+b,c@example.com"
	if dn := p.dnFor(u); dn != `uid=a\+b\,c@example.com,ou=people,dc=example,dc=org` {
		t.Fatalf("dn = %s", dn)
	}
	req, err := p.addRequest(ada)
	if err != nil {
		t.Fatal(err)
	}
	got := attrMap(req)
	want := map[string][]string{
		"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
		"uid":         {"Ada@Example.com"}, "mail": {"Ada@Example.com"}, "cn": {"Ada King Lovelace"},
		"givenName": {"Ada"}, "sn": {"King Lovelace"}, "employeeNumber": {ada.ID}, "departmentNumber": {"math"},
	}
	if len(got) != len(want) {
		t.Fatalf("attributes = %v", got)
	}
	for k, v := range want {
		if !slices.Equal(got[k], v) {
			t.Fatalf("%s = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
	// Updates clear what the user lacks; sn falls back to the email.
	m := p.managed(sdk.User{ID: "x", Email: "grace@example.com"})
	if len(m["givenName"]) != 0 || !slices.Equal(m["sn"], []string{"grace"}) || !slices.Equal(m["cn"], []string{"grace@example.com"}) ||
		m["departmentNumber"] == nil || len(m["departmentNumber"]) != 0 || m["uid"] != nil {
		t.Fatalf("managed = %v", m)
	}
	if g, s := splitName(sdk.User{Name: "  Grace  "}); g != "" || s != "Grace" {
		t.Fatalf("split = %q %q", g, s)
	}
}

func TestActiveDirectoryDefaults(t *testing.T) {
	p := newPlugin(t, map[string]any{"url": "ldaps://dc.example.com", "active_directory": true,
		"extra_attributes": map[string]any{"sAMAccountName": "{{slice .IDHex 0 20}}"}})
	c := p.cfg
	if c.RDNAttribute != "cn" || c.IDAttribute != "objectGUID" || c.NameAttribute != "displayName" ||
		c.PasswordMode != PasswordAD || c.Disable.Mode != DisableAD {
		t.Fatalf("defaults = %+v", c)
	}
	req, err := p.addRequest(ada)
	if err != nil {
		t.Fatal(err)
	}
	got := attrMap(req)
	if req.DN != "cn=Ada@Example.com,ou=people,dc=example,dc=org" || !slices.Equal(got["userAccountControl"], []string{"514"}) ||
		!slices.Equal(got["userPrincipalName"], []string{"Ada@Example.com"}) || !slices.Equal(got["sAMAccountName"], []string{"0190a5c47b1e7cc08a6e"}) ||
		!slices.Equal(got["objectClass"], []string{"top", "person", "organizationalPerson", "user"}) ||
		!slices.Equal(got["displayName"], []string{"Ada King Lovelace"}) || got["cn"] == nil {
		t.Fatalf("AD entry %s = %v", req.DN, got)
	}
}

func TestEncodings(t *testing.T) {
	pw := unicodePwd("pä𝄞")
	var units []uint16
	for i := 0; i < len(pw); i += 2 {
		units = append(units, uint16(pw[i])|uint16(pw[i+1])<<8)
	}
	if got := string(utf16.Decode(units)); got != `"pä𝄞"` {
		t.Fatalf("unicodePwd decodes to %q", got)
	}
	raw, _ := hex.DecodeString("33221100554477668899aabbccddeeff")
	s := formatGUID(raw)
	if s != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatal(s)
	}
	f, err := guidFilterValue(s)
	if err != nil || f != `\33\22\11\00\55\44\77\66\88\99\aa\bb\cc\dd\ee\ff` {
		t.Fatalf("filter = %q, %v", f, err)
	}
	if _, err := guidFilterValue("nope"); err == nil {
		t.Fatal("bad GUID accepted")
	}
}

func TestConfigValidation(t *testing.T) {
	bad := map[string]map[string]any{
		"bad url":                 {"url": "http://x"},
		"starttls with ldaps":     {"url": "ldaps://x", "start_tls": true},
		"no bind password":        {"bind_password": ""},
		"bad base dn":             {"user_base_dn": "not a dn"},
		"unicode_pwd without tls": {"password_mode": "unicode_pwd"},
		"bad password mode":       {"password_mode": "md5"},
		"bad rdn source":          {"rdn_source": "name"},
		"filter without %s":       {"user_filter": "(mail=x)"},
		"bad filter":              {"user_filter": "(mail=%s"},
		"rdn equals name":         {"rdn_attribute": "cn"},
		"rdn is email by id":      {"rdn_attribute": "mail", "rdn_source": "user_id"},
		"duplicate attribute":     {"attribute_map": map[string]any{"x": "mail"}},
		"email left out":          {"email_attribute": "-"},
		"bad attribute name":      {"user_id_attribute": "employee number"},
		"attribute mode no attr":  {"disable": map[string]any{"mode": "attribute"}},
		"attribute same values":   {"disable": map[string]any{"mode": "attribute", "attribute": "x", "disabled_value": "a", "enabled_value": "a"}},
		"values without mode":     {"disable": map[string]any{"attribute": "x"}},
		"bad template":            {"extra_attributes": map[string]any{"description": "{{.Nope}}"}},
		"template out of range":   {"extra_attributes": map[string]any{"description": "{{slice .LocalPart 0 99}}"}},
		"extra overrides managed": {"extra_attributes": map[string]any{"mail": "x"}},
		"bad timeout":             {"timeout": "0"},
		"unknown key":             {"nope": true},
	}
	base := map[string]any{"url": "ldap://x", "bind_dn": "cn=a,dc=x", "bind_password": "p", "user_base_dn": "ou=p,dc=x"}
	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			cfg := map[string]any{}
			for k, v := range base {
				cfg[k] = v
			}
			for k, v := range extra {
				cfg[k] = v
			}
			if err := (&Plugin{}).Init(context.Background(), sdktest.NewRegistrar(cfg)); err == nil {
				t.Fatal("want error")
			}
		})
	}
	// The RDN may be the email attribute when named by email.
	newPlugin(t, map[string]any{"rdn_attribute": "mail"})
	newPlugin(t, map[string]any{"name_attribute": "-", "rdn_attribute": "cn", "surname_attribute": "-"})

	reg := sdktest.NewRegistrar(base)
	if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Directory.(sdk.PasswordVerifier); !ok || reg.Directory.Name() != "ldap" {
		t.Fatal("PasswordVerifier not offered by default")
	}
	if _, ok := reg.Directory.(sdk.InvitationSender); ok {
		t.Fatal("ldap directory must not send invitations")
	}
	cfg := map[string]any{"verify_passwords": false}
	for k, v := range base {
		cfg[k] = v
	}
	reg = sdktest.NewRegistrar(cfg)
	if err := (&Plugin{}).Init(context.Background(), reg); err != nil {
		t.Fatal(err)
	}
	if _, ok := reg.Directory.(sdk.PasswordVerifier); ok {
		t.Fatal("PasswordVerifier offered with verify_passwords false")
	}

	sch, err := schema.Compile((&Plugin{}).Manifest().ConfigSchema)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{"disable": map[string]any{"mode": "attribute", "attribute": "employeeType", "disabled_value": "disabled"},
		"object_classes": []any{"inetOrgPerson"}, "rdn_source": "user_id"}
	for k, v := range base {
		good[k] = v
	}
	if err := sch.Validate(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, c := range []map[string]any{{"url": "ldap://x"}, {"url": "ldap://x", "bind_dn": "a", "bind_password": "b", "user_base_dn": "c", "x": 1}} {
		if err := sch.Validate(c); err == nil {
			t.Fatalf("config %v accepted", c)
		}
	}
}

// --- Active Directory flow against an in-memory fake ---

// fakeAD is a minimal in-memory directory that understands the requests
// the plugin sends to Active Directory: equality filters, base and subtree
// searches, adds, modifies (userAccountControl, unicodePwd) and binds.
type fakeAD struct {
	mu        sync.Mutex
	entries   map[string]map[string][]string // lower-cased DN -> attributes
	dns       map[string]string              // lower-cased DN -> DN
	passwords map[string]string
	seq       int
}

type fakeConn struct {
	ad    *fakeAD
	tls   bool
	bound string
}

func (f *fakeAD) dial(context.Context, time.Duration) (conn, error) { return &fakeConn{ad: f}, nil }

func (c *fakeConn) StartTLS(*tls.Config) error { c.tls = true; return nil }
func (c *fakeConn) Close() error               { return nil }

func (c *fakeConn) Bind(dn, pw string) error {
	c.ad.mu.Lock()
	defer c.ad.mu.Unlock()
	key := strings.ToLower(dn)
	if dn == "cn=admin,dc=example,dc=org" && pw == "admin" {
		c.bound = dn
		return nil
	}
	e := c.ad.entries[key]
	if e == nil || c.ad.passwords[key] != pw || uac(e)&uacAccountDisable != 0 {
		return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("80090308: AcceptSecurityContext error, data 52e")}
	}
	c.bound = dn
	return nil
}

func uac(e map[string][]string) int {
	var n int
	if v := e["userAccountControl"]; len(v) > 0 {
		_, _ = fmt.Sscan(v[0], &n)
	}
	return n
}

func (c *fakeConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	c.ad.mu.Lock()
	defer c.ad.mu.Unlock()
	attr, value, _ := strings.Cut(strings.Trim(req.Filter, "()"), "=")
	res := &ldap.SearchResult{}
	for key, e := range c.ad.entries {
		dn := c.ad.dns[key]
		if req.Scope == ldap.ScopeBaseObject && key != strings.ToLower(req.BaseDN) {
			continue
		}
		if req.Scope != ldap.ScopeBaseObject && !strings.HasSuffix(key, ","+strings.ToLower(req.BaseDN)) {
			continue
		}
		if value != "*" {
			want := unescapeFilter(value)
			if !slices.ContainsFunc(e[attr], func(v string) bool { return strings.EqualFold(v, want) }) {
				continue
			}
		}
		entry := &ldap.Entry{DN: dn}
		for _, a := range req.Attributes {
			if v, ok := e[a]; ok {
				entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: a, Values: v,
					ByteValues: func() [][]byte {
						var b [][]byte
						for _, s := range v {
							b = append(b, []byte(s))
						}
						return b
					}()})
			}
		}
		res.Entries = append(res.Entries, entry)
	}
	if req.Scope == ldap.ScopeBaseObject && len(res.Entries) == 0 {
		return nil, &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject}
	}
	return res, nil
}

func unescapeFilter(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+2 < len(s) {
			v, _ := hex.DecodeString(s[i+1 : i+3])
			b = append(b, v...)
			i += 2
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}

func (c *fakeConn) Add(req *ldap.AddRequest) error {
	c.ad.mu.Lock()
	defer c.ad.mu.Unlock()
	key := strings.ToLower(req.DN)
	if c.ad.entries[key] != nil {
		return &ldap.Error{ResultCode: ldap.LDAPResultEntryAlreadyExists}
	}
	e := map[string][]string{}
	for _, a := range req.Attributes {
		e[a.Type] = a.Vals
	}
	if uac(e)&uacAccountDisable == 0 {
		return &ldap.Error{ResultCode: ldap.LDAPResultUnwillingToPerform, Err: errors.New("0000052D: password required")}
	}
	c.ad.seq++
	guid := make([]byte, 16)
	guid[15] = byte(c.ad.seq)
	e["objectGUID"] = []string{string(guid)}
	c.ad.entries[key], c.ad.dns[key] = e, req.DN
	return nil
}

func (c *fakeConn) Modify(req *ldap.ModifyRequest) error {
	c.ad.mu.Lock()
	defer c.ad.mu.Unlock()
	key := strings.ToLower(req.DN)
	e := c.ad.entries[key]
	if e == nil {
		return &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject}
	}
	for _, ch := range req.Changes {
		a := ch.Modification
		if a.Type == "unicodePwd" {
			if !c.tls {
				return &ldap.Error{ResultCode: ldap.LDAPResultUnwillingToPerform}
			}
			raw := a.Vals[0]
			var units []uint16
			for i := 0; i+1 < len(raw); i += 2 {
				units = append(units, uint16(raw[i])|uint16(raw[i+1])<<8)
			}
			pw := strings.Trim(string(utf16.Decode(units)), `"`)
			if len(pw) < 8 {
				return &ldap.Error{ResultCode: ldap.LDAPResultConstraintViolation, Err: errors.New("0000052D: Constraint violation")}
			}
			c.ad.passwords[key] = pw
			continue
		}
		if a.Type == "userAccountControl" && c.ad.passwords[key] == "" {
			var n int
			_, _ = fmt.Sscan(a.Vals[0], &n)
			if n&uacAccountDisable == 0 {
				return &ldap.Error{ResultCode: ldap.LDAPResultUnwillingToPerform, Err: errors.New("0000052D: password required")}
			}
		}
		if len(a.Vals) == 0 {
			delete(e, a.Type)
		} else {
			e[a.Type] = a.Vals
		}
	}
	return nil
}

func (c *fakeConn) ModifyDN(req *ldap.ModifyDNRequest) error {
	c.ad.mu.Lock()
	defer c.ad.mu.Unlock()
	key := strings.ToLower(req.DN)
	e := c.ad.entries[key]
	if e == nil {
		return &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject}
	}
	_, parent, _ := strings.Cut(req.DN, ",")
	newDN := req.NewRDN + "," + parent
	attr, val, _ := strings.Cut(req.NewRDN, "=")
	e[attr] = []string{val}
	delete(c.ad.entries, key)
	c.ad.entries[strings.ToLower(newDN)], c.ad.dns[strings.ToLower(newDN)] = e, newDN
	c.ad.passwords[strings.ToLower(newDN)] = c.ad.passwords[key]
	return nil
}

func (c *fakeConn) Del(req *ldap.DelRequest) error {
	c.ad.mu.Lock()
	defer c.ad.mu.Unlock()
	key := strings.ToLower(req.DN)
	if c.ad.entries[key] == nil {
		return &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject}
	}
	delete(c.ad.entries, key)
	return nil
}

func (c *fakeConn) PasswordModify(*ldap.PasswordModifyRequest) (*ldap.PasswordModifyResult, error) {
	return nil, &ldap.Error{ResultCode: ldap.LDAPResultUnwillingToPerform}
}

func TestActiveDirectoryFlow(t *testing.T) {
	ad := &fakeAD{entries: map[string]map[string][]string{}, dns: map[string]string{}, passwords: map[string]string{}}
	p := &Plugin{dial: ad.dial}
	reg := sdktest.NewRegistrar(map[string]any{"url": "ldap://dc.example.com", "start_tls": true, "active_directory": true,
		"bind_dn": "cn=admin,dc=example,dc=org", "bind_password": "admin", "user_base_dn": "ou=people,dc=example,dc=org",
		"user_id_attribute": "employeeID"})
	ctx := context.Background()
	if err := p.Init(ctx, reg); err != nil {
		t.Fatal(err)
	}
	if err := p.Health(ctx); err != nil {
		t.Fatal(err)
	}
	dir := reg.Directory
	u := ada
	id, err := dir.CreateUser(ctx, u)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if id != "00000000-0000-0000-0000-000000000001" {
		t.Fatalf("external ID = %q", id)
	}
	if again, err := dir.CreateUser(ctx, u); err != nil || again != id {
		t.Fatalf("re-create = %q, %v", again, err)
	}
	other := u
	other.ID = "someone-else"
	if _, err := dir.CreateUser(ctx, other); err == nil {
		t.Fatal("entry of another Tenarium user handed out")
	}
	u.ExternalID = id
	key := "cn=ada@example.com,ou=people,dc=example,dc=org"

	// Invited users stay disabled until they have a password.
	if err := dir.UpdateUser(ctx, u); err != nil || uac(ad.entries[key]) != 514 {
		t.Fatalf("update invited: %v, %v", err, ad.entries[key])
	}
	if err := dir.SetPassword(ctx, u, "short"); err == nil || !strings.Contains(err.Error(), "password policy") {
		t.Fatalf("policy err = %v", err)
	}
	if err := dir.SetPassword(ctx, u, "correct horse"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if uac(ad.entries[key]) != 512 {
		t.Fatalf("not enabled: %v", ad.entries[key])
	}
	v := dir.(sdk.PasswordVerifier)
	if err := v.VerifyPassword(ctx, u, "correct horse"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if err := v.VerifyPassword(ctx, u, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password err = %v", err)
	}
	if err := v.VerifyPassword(ctx, u, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty password err = %v", err)
	}

	u.Status = sdk.UserDisabled
	u.Email = "ada@lovelace.org"
	if err := dir.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	key = "cn=ada@lovelace.org,ou=people,dc=example,dc=org"
	if e := ad.entries[key]; e == nil || uac(e) != 514 || e["mail"][0] != "ada@lovelace.org" {
		t.Fatalf("renamed entry = %v (all %v)", e, ad.dns)
	}
	if err := v.VerifyPassword(ctx, u, "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled err = %v", err)
	}
	u.Status = sdk.UserActive
	if err := dir.UpdateUser(ctx, u); err != nil || uac(ad.entries[key]) != 512 {
		t.Fatalf("enable: %v", err)
	}
	for range 2 {
		if err := dir.DeleteUser(ctx, u); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
	}
	if len(ad.entries) != 0 {
		t.Fatalf("entries = %v", ad.entries)
	}
}

// TestIntegration runs against a real OpenLDAP when TENARIUM_TEST_LDAP_URL
// is set (same server as the ldap plugin's integration test), e.g.:
//
//	docker run --rm -d -p 3389:389 -e LDAP_DOMAIN=example.org \
//	  -e LDAP_ADMIN_PASSWORD=admin osixia/openldap:1.5.0
//	TENARIUM_TEST_LDAP_URL=ldap://localhost:3389 go test ./plugins/ldapdir/ -run Integration
//
// It binds as TENARIUM_TEST_LDAP_BIND_DN (default cn=admin,dc=example,dc=org)
// with TENARIUM_TEST_LDAP_BIND_PASSWORD (default "admin") and works in a
// fresh OU under TENARIUM_TEST_LDAP_BASE_DN (default dc=example,dc=org),
// which it removes again.
func TestIntegration(t *testing.T) {
	ldapURL := os.Getenv("TENARIUM_TEST_LDAP_URL")
	if ldapURL == "" {
		t.Skip("TENARIUM_TEST_LDAP_URL not set")
	}
	bindDN := or(os.Getenv("TENARIUM_TEST_LDAP_BIND_DN"), "cn=admin,dc=example,dc=org")
	bindPW := or(os.Getenv("TENARIUM_TEST_LDAP_BIND_PASSWORD"), "admin")
	baseDN := or(os.Getenv("TENARIUM_TEST_LDAP_BASE_DN"), "dc=example,dc=org")
	ou := fmt.Sprintf("ou=it-dir-%d,%s", time.Now().UnixNano(), baseDN)

	lc, err := ldap.DialURL(ldapURL)
	if err != nil {
		t.Fatal(err)
	}
	defer lc.Close()
	if err := lc.Bind(bindDN, bindPW); err != nil {
		t.Fatal(err)
	}
	add := ldap.NewAddRequest(ou, nil)
	add.Attribute("objectClass", []string{"organizationalUnit"})
	add.Attribute("ou", []string{strings.TrimPrefix(strings.Split(ou, ",")[0], "ou=")})
	if err := lc.Add(add); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		res, err := lc.Search(ldap.NewSearchRequest(ou, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", []string{"dn"}, nil))
		if err == nil {
			for _, e := range res.Entries {
				_ = lc.Del(ldap.NewDelRequest(e.DN, nil))
			}
		}
		_ = lc.Del(ldap.NewDelRequest(ou, nil))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfgs := map[string]map[string]any{
		"password_modify,rdn email": {},
		"user_password,rdn user_id": {"password_mode": "user_password", "rdn_source": "user_id"},
	}
	for name, extra := range cfgs {
		t.Run(name, func(t *testing.T) {
			cfg := map[string]any{"url": ldapURL, "bind_dn": bindDN, "bind_password": bindPW, "user_base_dn": ou,
				"user_id_attribute": "employeeNumber", "attribute_map": map[string]any{"dept": "departmentNumber"},
				"disable": map[string]any{"mode": "attribute", "attribute": "employeeType", "disabled_value": "disabled"}}
			for k, v := range extra {
				cfg[k] = v
			}
			reg := sdktest.NewRegistrar(cfg)
			p := &Plugin{}
			if err := p.Init(ctx, reg); err != nil {
				t.Fatal(err)
			}
			if err := p.Health(ctx); err != nil {
				t.Fatalf("Health: %v", err)
			}
			dir := reg.Directory
			u := ada
			u.ID = fmt.Sprintf("it-%d", time.Now().UnixNano())
			u.Email = u.ID + "@Example.org"
			id, err := dir.CreateUser(ctx, u)
			if err != nil {
				t.Fatalf("CreateUser: %v", err)
			}
			if len(id) != 36 {
				t.Fatalf("entryUUID = %q", id)
			}
			if again, err := dir.CreateUser(ctx, u); err != nil || again != id {
				t.Fatalf("re-create = %q, %v", again, err)
			}
			other := u
			other.ID = "someone-else"
			if _, err := dir.CreateUser(ctx, other); err == nil || !strings.Contains(err.Error(), "another Tenarium user") {
				t.Fatalf("conflict err = %v", err)
			}
			u.ExternalID = id
			v := dir.(sdk.PasswordVerifier)
			if err := v.VerifyPassword(ctx, u, "anything"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("no password yet err = %v", err)
			}
			if err := dir.SetPassword(ctx, u, "correct horse"); err != nil {
				t.Fatalf("SetPassword: %v", err)
			}
			if err := v.VerifyPassword(ctx, u, "correct horse"); err != nil {
				t.Fatalf("VerifyPassword: %v", err)
			}
			if err := v.VerifyPassword(ctx, u, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("wrong password err = %v", err)
			}

			u.Name, u.Email, u.Status, u.Attributes = "Ada", "renamed-"+u.Email, sdk.UserDisabled, nil
			if err := dir.UpdateUser(ctx, u); err != nil {
				t.Fatalf("UpdateUser: %v", err)
			}
			res, err := lc.Search(ldap.NewSearchRequest(ou, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false,
				"(entryUUID="+id+")", []string{"uid", "mail", "cn", "sn", "givenName", "departmentNumber", "employeeType", "employeeNumber"}, nil))
			if err != nil || len(res.Entries) != 1 {
				t.Fatalf("search: %v, %v", err, res)
			}
			e := res.Entries[0]
			if !strings.EqualFold(e.GetAttributeValue("mail"), u.Email) || e.GetAttributeValue("cn") != "Ada" ||
				e.GetAttributeValue("sn") != "Ada" || e.GetAttributeValue("givenName") != "" ||
				e.GetAttributeValue("departmentNumber") != "" || e.GetAttributeValue("employeeType") != "disabled" ||
				e.GetAttributeValue("employeeNumber") != u.ID {
				t.Fatalf("entry %s = %v", e.DN, e.Attributes)
			}
			if p.cfg.RDNSource == RDNFromEmail && !strings.HasPrefix(strings.ToLower(e.DN), "uid=renamed-") {
				t.Fatalf("entry not renamed: %s", e.DN)
			}
			if p.cfg.RDNSource == RDNFromUserID && !strings.HasPrefix(e.DN, "uid="+u.ID+",") {
				t.Fatalf("DN = %s", e.DN)
			}
			if err := v.VerifyPassword(ctx, u, "correct horse"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("disabled err = %v", err)
			}
			u.Status = sdk.UserActive
			if err := dir.UpdateUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			if err := v.VerifyPassword(ctx, u, "correct horse"); err != nil {
				t.Fatalf("re-enabled VerifyPassword: %v", err)
			}
			for range 2 {
				if err := dir.DeleteUser(ctx, u); err != nil {
					t.Fatalf("DeleteUser: %v", err)
				}
			}
			u.ExternalID = ""
			if err := dir.DeleteUser(ctx, u); err != nil {
				t.Fatalf("DeleteUser by email: %v", err)
			}
		})
	}
}
