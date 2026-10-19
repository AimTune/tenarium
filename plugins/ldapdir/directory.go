package ldapdir

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// ErrInvalidCredentials is returned by VerifyPassword when the bind fails
// because of the password, or the entry is missing or disabled.
var ErrInvalidCredentials = errors.New("invalid credentials")

// directory is a sdk.UserDirectory over one LDAP subtree.
type directory struct{ p *Plugin }

// verifyingDirectory adds sdk.PasswordVerifier (the default).
type verifyingDirectory struct{ *directory }

var (
	_ sdk.UserDirectory    = (*directory)(nil)
	_ sdk.PasswordVerifier = verifyingDirectory{}
)

func (d *directory) Name() string { return "ldap" }

// errNoUser reports that the user has no entry.
var errNoUser = errors.New("ldap: user not found in directory")

func (d *directory) CreateUser(ctx context.Context, u sdk.User) (string, error) {
	if u.Email == "" {
		return "", errors.New("ldap: create user: email is required")
	}
	c, done, err := d.p.connect(ctx)
	if err != nil {
		return "", err
	}
	defer done()
	if e, err := d.findByEmail(c, u); err != nil {
		return "", err
	} else if e != nil {
		return d.p.externalID(e)
	}
	req, err := d.p.addRequest(u)
	if err != nil {
		return "", err
	}
	if err := c.Add(req); err != nil {
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return "", fmt.Errorf("ldap: create user: %w", err)
		}
		// Created concurrently, or the DN is taken by another entry.
		e, err := d.readDN(c, req.DN)
		if err != nil {
			return "", err
		}
		if err := d.checkOwner(e, u); err != nil {
			return "", err
		}
		if !strings.EqualFold(e.GetEqualFoldAttributeValue(d.p.cfg.EmailAttribute), u.Email) &&
			!strings.EqualFold(d.p.cfg.EmailAttribute, d.p.cfg.RDNAttribute) {
			return "", fmt.Errorf("ldap: create user: %s exists with another email", req.DN)
		}
		return d.p.externalID(e)
	}
	e, err := d.readDN(c, req.DN)
	if err != nil {
		return "", err
	}
	return d.p.externalID(e)
}

func (d *directory) UpdateUser(ctx context.Context, u sdk.User) error {
	c, done, err := d.p.connect(ctx)
	if err != nil {
		return err
	}
	defer done()
	e, err := d.resolve(c, u)
	if err != nil {
		return err
	}
	mod := ldap.NewModifyRequest(e.DN, nil)
	for attr, vals := range d.p.managed(u) {
		mod.Replace(attr, vals)
	}
	if d.p.cfg.Disable.Mode == DisableAD {
		uac, err := userAccountControl(e)
		if err != nil {
			return err
		}
		next := uac
		switch u.Status {
		case sdk.UserDisabled:
			next |= uacAccountDisable
		case sdk.UserActive:
			next &^= uacAccountDisable
		} // invited users stay as they are until they have a password
		if next != uac {
			mod.Replace("userAccountControl", []string{strconv.Itoa(next)})
		}
	}
	if err := c.Modify(mod); err != nil {
		return fmt.Errorf("ldap: update user: %w", err)
	}
	return d.rename(c, e, u)
}

// rename moves the entry to a new RDN when the RDN is the email and the
// email changed.
func (d *directory) rename(c conn, e *ldap.Entry, u sdk.User) error {
	if d.p.cfg.RDNSource != RDNFromEmail {
		return nil
	}
	dn, err := ldap.ParseDN(e.DN)
	if err != nil || len(dn.RDNs) == 0 {
		return fmt.Errorf("ldap: update user: bad DN %q", e.DN)
	}
	rdn := dn.RDNs[0]
	if len(rdn.Attributes) != 1 || !strings.EqualFold(rdn.Attributes[0].Type, d.p.cfg.RDNAttribute) ||
		strings.EqualFold(rdn.Attributes[0].Value, u.Email) {
		return nil // not an entry named by the directory, or unchanged
	}
	newRDN := d.p.cfg.RDNAttribute + "=" + ldap.EscapeDN(u.Email)
	if err := c.ModifyDN(ldap.NewModifyDNRequest(e.DN, newRDN, true, "")); err != nil {
		return fmt.Errorf("ldap: rename user: %w", err)
	}
	return nil
}

func (d *directory) DeleteUser(ctx context.Context, u sdk.User) error {
	c, done, err := d.p.connect(ctx)
	if err != nil {
		return err
	}
	defer done()
	e, err := d.resolve(c, u)
	if errors.Is(err, errNoUser) {
		return nil
	} else if err != nil {
		return err
	}
	if err := c.Del(ldap.NewDelRequest(e.DN, nil)); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return fmt.Errorf("ldap: delete user: %w", err)
	}
	return nil
}

func (d *directory) SetPassword(ctx context.Context, u sdk.User, password string) error {
	c, done, err := d.p.connect(ctx)
	if err != nil {
		return err
	}
	defer done()
	e, err := d.resolve(c, u)
	if err != nil {
		return err
	}
	switch d.p.cfg.PasswordMode {
	case PasswordModify:
		_, err = c.PasswordModify(ldap.NewPasswordModifyRequest(e.DN, "", password))
	case PasswordAttr:
		mod := ldap.NewModifyRequest(e.DN, nil)
		mod.Replace("userPassword", []string{password})
		err = c.Modify(mod)
	case PasswordAD:
		mod := ldap.NewModifyRequest(e.DN, nil)
		mod.Replace("unicodePwd", []string{unicodePwd(password)})
		err = c.Modify(mod)
	}
	if err != nil {
		// LDAP errors never echo the password; constraint violations are
		// policy rejections.
		return fmt.Errorf("ldap: set password: %s", passwordError(err))
	}
	if d.p.cfg.Disable.Mode == DisableAD && u.Status != sdk.UserDisabled {
		// The account was created disabled; a password activates it.
		uac, err := userAccountControl(e)
		if err != nil {
			return err
		}
		if uac&uacAccountDisable != 0 {
			mod := ldap.NewModifyRequest(e.DN, nil)
			mod.Replace("userAccountControl", []string{strconv.Itoa(uac &^ uacAccountDisable)})
			if err := c.Modify(mod); err != nil {
				return fmt.Errorf("ldap: enable user: %w", err)
			}
		}
	}
	return nil
}

func passwordError(err error) string {
	var le *ldap.Error
	if errors.As(err, &le) {
		msg := ldap.LDAPResultCodeMap[le.ResultCode]
		if le.Err != nil && le.Err.Error() != "" {
			msg += ": " + le.Err.Error()
		}
		if le.ResultCode == ldap.LDAPResultConstraintViolation || le.ResultCode == ldap.LDAPResultUnwillingToPerform {
			msg = "rejected by the directory's password policy (" + msg + ")"
		}
		return msg
	}
	return err.Error()
}

// VerifyPassword binds as the user's entry. Wrong passwords, missing
// entries and disabled entries yield ErrInvalidCredentials.
func (v verifyingDirectory) VerifyPassword(ctx context.Context, u sdk.User, password string) error {
	if password == "" {
		// An empty password would be an unauthenticated bind, which succeeds.
		return fmt.Errorf("ldap: %w", ErrInvalidCredentials)
	}
	c, done, err := v.p.connect(ctx)
	if err != nil {
		return err
	}
	defer done()
	e, err := v.resolve(c, u)
	if errors.Is(err, errNoUser) {
		return fmt.Errorf("ldap: %w", ErrInvalidCredentials)
	} else if err != nil {
		return err
	}
	if dc := v.p.cfg.Disable; dc.Mode == DisableAttribute &&
		strings.EqualFold(e.GetEqualFoldAttributeValue(dc.Attribute), dc.DisabledValue) {
		return fmt.Errorf("ldap: %w: user is disabled", ErrInvalidCredentials)
	}
	if err := c.Bind(e.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return fmt.Errorf("ldap: %w", ErrInvalidCredentials)
		}
		return fmt.Errorf("ldap: user bind: %w", err)
	}
	return nil
}

// --- lookups ---

func (d *directory) attributes() []string {
	c := d.p.cfg
	attrs := []string{c.EmailAttribute}
	if c.Disable.Mode == DisableAD {
		attrs = append(attrs, "userAccountControl")
	}
	if c.IDAttribute != "dn" {
		attrs = append(attrs, c.IDAttribute)
	}
	if c.UserIDAttribute != "" {
		attrs = append(attrs, c.UserIDAttribute)
	}
	if c.Disable.Mode == DisableAttribute {
		attrs = append(attrs, c.Disable.Attribute)
	}
	return attrs
}

func (d *directory) search(c conn, base string, scope int, filter string) ([]*ldap.Entry, error) {
	res, err := c.Search(&ldap.SearchRequest{
		BaseDN: base, Scope: scope, Filter: filter, Attributes: d.attributes(),
		SizeLimit: 2, TimeLimit: int(d.p.timeout.Seconds()),
	})
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		return nil, nil
	case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded):
		return nil, errors.New("ldap: search matches multiple entries")
	case err != nil:
		return nil, fmt.Errorf("ldap: search: %w", err)
	}
	return res.Entries, nil
}

// readDN reads the entry at dn.
func (d *directory) readDN(c conn, dn string) (*ldap.Entry, error) {
	entries, err := d.search(c, dn, ldap.ScopeBaseObject, "(objectClass=*)")
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errNoUser
	}
	return entries[0], nil
}

// resolve returns u's entry: by u.ExternalID if set, else by email.
func (d *directory) resolve(c conn, u sdk.User) (*ldap.Entry, error) {
	if u.ExternalID == "" {
		e, err := d.findByEmail(c, u)
		if err != nil {
			return nil, err
		}
		if e == nil {
			return nil, errNoUser
		}
		return e, nil
	}
	id := d.p.cfg.IDAttribute
	if id == "dn" {
		return d.readDN(c, u.ExternalID)
	}
	value := ldap.EscapeFilter(u.ExternalID)
	if strings.EqualFold(id, "objectGUID") {
		var err error
		if value, err = guidFilterValue(u.ExternalID); err != nil {
			return nil, fmt.Errorf("ldap: external ID: %w", err)
		}
	}
	entries, err := d.search(c, d.p.cfg.SearchBaseDN, ldap.ScopeWholeSubtree, "("+id+"="+value+")")
	if err != nil {
		return nil, err
	}
	switch len(entries) {
	case 0:
		return nil, errNoUser
	case 1:
		return entries[0], nil
	}
	return nil, fmt.Errorf("ldap: %s %s matches multiple entries", id, u.ExternalID)
}

// findByEmail returns the entry with u's email, or nil. It fails if the
// entry belongs to another Tenarium user.
func (d *directory) findByEmail(c conn, u sdk.User) (*ldap.Entry, error) {
	filter := fmt.Sprintf(d.p.cfg.UserFilter, ldap.EscapeFilter(u.Email))
	entries, err := d.search(c, d.p.cfg.SearchBaseDN, ldap.ScopeWholeSubtree, filter)
	if err != nil {
		return nil, err
	}
	switch len(entries) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, fmt.Errorf("ldap: %s matches multiple entries", u.Email)
	}
	if err := d.checkOwner(entries[0], u); err != nil {
		return nil, err
	}
	return entries[0], nil
}

func (d *directory) checkOwner(e *ldap.Entry, u sdk.User) error {
	if a := d.p.cfg.UserIDAttribute; a != "" {
		if owner := e.GetEqualFoldAttributeValue(a); owner != "" && owner != u.ID {
			return fmt.Errorf("ldap: %s already belongs to another Tenarium user", u.Email)
		}
	}
	return nil
}

// externalID returns the entry's stable identifier.
func (p *Plugin) externalID(e *ldap.Entry) (string, error) {
	attr := p.cfg.IDAttribute
	if attr == "dn" {
		return e.DN, nil
	}
	raw := e.GetEqualFoldRawAttributeValue(attr)
	switch {
	case len(raw) == 0:
		return "", fmt.Errorf("ldap: entry %s has no %s attribute", e.DN, attr)
	case strings.EqualFold(attr, "objectGUID") && len(raw) == 16:
		return formatGUID(raw), nil
	case !utf8.Valid(raw):
		return hex.EncodeToString(raw), nil
	}
	return string(raw), nil
}

func userAccountControl(e *ldap.Entry) (int, error) {
	v := e.GetEqualFoldAttributeValue("userAccountControl")
	if v == "" {
		return uacNormalAccount, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("ldap: bad userAccountControl %q on %s", v, e.DN)
	}
	return n, nil
}
