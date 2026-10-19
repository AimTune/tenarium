package oktadir

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Okta user statuses.
const (
	statusStaged        = "STAGED"
	statusProvisioned   = "PROVISIONED"
	statusActive        = "ACTIVE"
	statusSuspended     = "SUSPENDED"
	statusDeprovisioned = "DEPROVISIONED"
	statusLockedOut     = "LOCKED_OUT"
)

// directory is a sdk.UserDirectory and sdk.InvitationSender over one Okta
// org.
type directory struct{ p *Plugin }

// verifyingDirectory adds sdk.PasswordVerifier; it is registered only with
// verify_passwords.
type verifyingDirectory struct{ *directory }

var (
	_ sdk.UserDirectory    = (*directory)(nil)
	_ sdk.InvitationSender = (*directory)(nil)
	_ sdk.PasswordVerifier = verifyingDirectory{}
)

func (d *directory) Name() string { return "okta" }

// oktaUser is the part of an Okta user the directory reads.
type oktaUser struct {
	ID      string         `json:"id"`
	Status  string         `json:"status"`
	Profile map[string]any `json:"profile"`
}

func (o *oktaUser) prop(name string) string {
	s, _ := o.Profile[name].(string)
	return s
}

func userPath(id string) string { return "/api/v1/users/" + url.PathEscape(id) }

// names splits u.Name into the required firstName and lastName. Okta needs
// both; a missing first name falls back to the email's local part, a
// missing last name to "-".
func names(u sdk.User) (string, string) {
	first, last, _ := strings.Cut(strings.Join(strings.Fields(u.Name), " "), " ")
	if first == "" {
		first, _, _ = strings.Cut(u.Email, "@")
	}
	if last == "" {
		last = "-"
	}
	return first, last
}

// profile returns the profile properties every create and update sets.
// Mapped attributes that u lacks are cleared.
func (d *directory) profile(u sdk.User) map[string]any {
	c := d.p.cfg
	first, last := names(u)
	prof := map[string]any{"email": u.Email, "firstName": first, "lastName": last}
	if c.UserIDAttribute != "" {
		prof[c.UserIDAttribute] = u.ID
	}
	for attr, prop := range c.AttributeMap {
		if v, ok := u.Attributes[attr]; ok && v != "" {
			prof[prop] = v
		} else {
			prof[prop] = nil
		}
	}
	return prof
}

func (d *directory) CreateUser(ctx context.Context, u sdk.User) (string, error) {
	if u.Email == "" {
		return "", errors.New("okta: create user: email is required")
	}
	existing, err := d.findByLogin(ctx, u)
	if err != nil {
		return "", err
	}
	if existing != nil {
		return existing.ID, nil
	}
	prof := d.profile(u)
	for k, v := range prof {
		if v == nil {
			delete(prof, k)
		}
	}
	prof["login"] = u.Email
	q := url.Values{"activate": {"false"}}
	status, body, err := d.p.do(ctx, http.MethodPost, "/api/v1/users", q, map[string]any{"profile": prof})
	if err != nil {
		return "", err
	}
	switch {
	case status == http.StatusOK || status == http.StatusCreated:
		var created oktaUser
		if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
			return "", errors.New("okta: create user: response has no id")
		}
		if u.Status == sdk.UserDisabled {
			// A staged user cannot be suspended; deactivate it.
			if err := d.lifecycle(ctx, created.ID, "deactivate", false); err != nil {
				return "", err
			}
		}
		return created.ID, nil
	case status == http.StatusBadRequest && strings.Contains(errorMessage(body), "already exists"):
		// Created concurrently, e.g. by a retry after a timeout.
		existing, err := d.findByLogin(ctx, u)
		if err != nil {
			return "", err
		}
		if existing == nil {
			return "", apiError("create user", status, body)
		}
		return existing.ID, nil
	default:
		return "", apiError("create user", status, body)
	}
}

func (d *directory) UpdateUser(ctx context.Context, u sdk.User) error {
	cur, err := d.lookup(ctx, u)
	if err != nil {
		return err
	}
	prof := d.profile(u)
	// The login follows the email if it was the email.
	if login := cur.prop("login"); strings.EqualFold(login, cur.prop("email")) && !strings.EqualFold(login, u.Email) {
		prof["login"] = u.Email
	}
	status, body, err := d.p.do(ctx, http.MethodPost, userPath(cur.ID), nil, map[string]any{"profile": prof})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("update user", status, body)
	}
	return d.syncStatus(ctx, cur, u.Status)
}

// syncStatus moves the Okta user into a state matching status.
func (d *directory) syncStatus(ctx context.Context, cur *oktaUser, status sdk.UserStatus) error {
	if status == sdk.UserDisabled {
		switch cur.Status {
		case statusDeprovisioned:
			return nil
		case statusSuspended:
			if d.p.cfg.DisableAction == DisableDeactivate {
				return d.lifecycle(ctx, cur.ID, "deactivate", false)
			}
			return nil
		case statusActive:
			if d.p.cfg.DisableAction == DisableSuspend {
				return d.lifecycle(ctx, cur.ID, "suspend", false)
			}
		}
		// Only active users can be suspended; deactivate everything else.
		return d.lifecycle(ctx, cur.ID, "deactivate", false)
	}
	switch cur.Status {
	case statusSuspended:
		return d.lifecycle(ctx, cur.ID, "unsuspend", false)
	case statusDeprovisioned:
		// The user comes back PROVISIONED (or ACTIVE once a password is set).
		return d.lifecycle(ctx, cur.ID, "activate", false)
	}
	return nil
}

// lifecycle runs a lifecycle operation such as "suspend".
func (d *directory) lifecycle(ctx context.Context, id, op string, sendEmail bool) error {
	q := url.Values{"sendEmail": {fmt.Sprint(sendEmail)}}
	status, body, err := d.p.do(ctx, http.MethodPost, userPath(id)+"/lifecycle/"+op, q, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return apiError(op+" user", status, body)
	}
	return nil
}

// DeleteUser deactivates the user (if needed) and then deletes it.
func (d *directory) DeleteUser(ctx context.Context, u sdk.User) error {
	cur, err := d.lookup(ctx, u)
	if errors.Is(err, errNoUser) {
		return nil
	} else if err != nil {
		return err
	}
	q := url.Values{"sendEmail": {"false"}}
	steps := 2
	if cur.Status == statusDeprovisioned {
		steps = 1
	}
	for range steps {
		// The first DELETE of a user that is not deprovisioned deactivates it.
		status, body, err := d.p.do(ctx, http.MethodDelete, userPath(cur.ID), q, nil)
		if err != nil {
			return err
		}
		switch status {
		case http.StatusNoContent, http.StatusOK:
		case http.StatusNotFound:
			return nil
		default:
			return apiError("delete user", status, body)
		}
	}
	return nil
}

// SetPassword sets the password. A staged user is activated afterwards
// (without email), since a password ends the invitation.
func (d *directory) SetPassword(ctx context.Context, u sdk.User, password string) error {
	cur, err := d.lookup(ctx, u)
	if err != nil {
		return err
	}
	in := map[string]any{"credentials": map[string]any{"password": map[string]any{"value": password}}}
	status, body, err := d.p.do(ctx, http.MethodPost, userPath(cur.ID), nil, in)
	switch {
	case err != nil:
		return err
	case status == http.StatusBadRequest || status == http.StatusForbidden:
		// Password policy violations; Okta never echoes the password.
		return fmt.Errorf("okta: set password: %s", errorMessage(body))
	case status != http.StatusOK:
		return apiError("set password", status, body)
	}
	if cur.Status == statusStaged && u.Status != sdk.UserDisabled {
		return d.lifecycle(ctx, cur.ID, "activate", false)
	}
	return nil
}

// SendInvitation sends Okta's activation email (staged users) or a new one
// (provisioned users). It returns sdk.ErrUnsupported unless
// send_invitation is set.
func (d *directory) SendInvitation(ctx context.Context, u sdk.User) error {
	if !d.p.cfg.SendInvitation {
		return sdk.ErrUnsupported
	}
	cur, err := d.lookup(ctx, u)
	if err != nil {
		return err
	}
	switch cur.Status {
	case statusStaged, statusDeprovisioned:
		return d.lifecycle(ctx, cur.ID, "activate", true)
	case statusProvisioned:
		return d.lifecycle(ctx, cur.ID, "reactivate", true)
	default:
		return fmt.Errorf("okta: send invitation: user is %s", cur.Status)
	}
}

// VerifyPassword checks the password with the Authentication API.
func (v verifyingDirectory) VerifyPassword(ctx context.Context, u sdk.User, password string) error {
	if password == "" {
		return fmt.Errorf("okta: %w", ErrInvalidCredentials)
	}
	login := u.Email
	if u.ExternalID != "" {
		cur, err := v.lookup(ctx, u)
		if errors.Is(err, errNoUser) {
			return fmt.Errorf("okta: %w", ErrInvalidCredentials)
		} else if err != nil {
			return err
		}
		login = cmpOr(cur.prop("login"), login)
	}
	in := map[string]any{"username": login, "password": password,
		"options": map[string]any{"warnBeforePasswordExpired": false, "multiOptionalFactorEnroll": false}}
	status, body, err := send(ctx, v.p.client, http.MethodPost, v.p.base+"/api/v1/authn", in)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK:
		var res struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(body, &res)
		switch res.Status {
		case "SUCCESS":
			return nil
		case "MFA_REQUIRED", "MFA_ENROLL", "MFA_CHALLENGE":
			return fmt.Errorf("okta: %w", ErrMFARequired)
		case statusLockedOut:
			return fmt.Errorf("okta: %w: user is locked out", ErrInvalidCredentials)
		default:
			return fmt.Errorf("okta: verify password: unexpected status %q", res.Status)
		}
	case http.StatusUnauthorized:
		if parseError(body).ErrorCode == "E0000004" {
			return fmt.Errorf("okta: %w", ErrInvalidCredentials)
		}
	}
	return apiError("verify password", status, body)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// errNoUser reports that the user has no identity in the org.
var errNoUser = errors.New("okta: user not found in directory")

// lookup returns u's Okta user: by u.ExternalID if set, else by login.
func (d *directory) lookup(ctx context.Context, u sdk.User) (*oktaUser, error) {
	if u.ExternalID == "" {
		existing, err := d.findByLogin(ctx, u)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			return nil, errNoUser
		}
		return existing, nil
	}
	return d.get(ctx, u.ExternalID)
}

// get returns the user with the given ID or login.
func (d *directory) get(ctx context.Context, idOrLogin string) (*oktaUser, error) {
	status, body, err := d.p.do(ctx, http.MethodGet, userPath(idOrLogin), nil, nil)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errNoUser
	default:
		return nil, apiError("get user", status, body)
	}
	var ou oktaUser
	if err := json.Unmarshal(body, &ou); err != nil || ou.ID == "" {
		return nil, fmt.Errorf("okta: get user: bad response")
	}
	return &ou, nil
}

// findByLogin returns the user whose login is u's email, or nil. It fails
// if that user belongs to another Tenarium user.
func (d *directory) findByLogin(ctx context.Context, u sdk.User) (*oktaUser, error) {
	ou, err := d.get(ctx, u.Email)
	if errors.Is(err, errNoUser) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if a := d.p.cfg.UserIDAttribute; a != "" {
		if owner := ou.prop(a); owner != "" && owner != u.ID {
			return nil, fmt.Errorf("okta: %s already belongs to another Tenarium user", u.Email)
		}
	}
	return ou, nil
}
