package entradir

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// directory is a sdk.UserDirectory and sdk.InvitationSender over one Entra
// tenant.
type directory struct{ p *Plugin }

var (
	_ sdk.UserDirectory    = (*directory)(nil)
	_ sdk.InvitationSender = (*directory)(nil)
)

func (d *directory) Name() string { return "entra" }

func (d *directory) guest() bool { return d.p.cfg.Mode == ModeGuest }

// graphUser is a Graph user as a property map; IDs and names are read with
// str.
type graphUser map[string]any

func (g graphUser) str(prop string) string {
	s, _ := g[prop].(string)
	return s
}

func userPath(id string) string { return "/users/" + url.PathEscape(id) }

func displayName(u sdk.User) string {
	if n := strings.TrimSpace(u.Name); n != "" {
		return n
	}
	return u.Email
}

// properties returns the Graph properties every create and update sets:
// accountEnabled, displayName, the owner property and mapped attributes
// (absent attributes are cleared).
func (d *directory) properties(u sdk.User) map[string]any {
	c := d.p.cfg
	rep := map[string]any{
		"accountEnabled": u.Status != sdk.UserDisabled,
		"displayName":    displayName(u),
	}
	if c.UserIDAttribute != "" {
		rep[c.UserIDAttribute] = u.ID
	}
	for attr, prop := range c.AttributeMap {
		if v, ok := u.Attributes[attr]; ok && v != "" {
			rep[prop] = v
		} else {
			rep[prop] = nil
		}
	}
	return rep
}

func (d *directory) CreateUser(ctx context.Context, u sdk.User) (string, error) {
	if u.Email == "" {
		return "", errors.New("entra: create user: email is required")
	}
	existing, err := d.findByEmail(ctx, u)
	if err != nil {
		return "", err
	}
	if existing != nil {
		return existing.str("id"), nil
	}
	if d.guest() {
		return d.invite(ctx, u, false)
	}
	pw, err := randomPassword()
	if err != nil {
		return "", err
	}
	rep := d.properties(u)
	for prop, v := range rep {
		if v == nil {
			delete(rep, prop)
		}
	}
	rep["mail"] = u.Email
	rep["mailNickname"] = mailNickname(u.Email)
	rep["userPrincipalName"] = d.upn(u.Email)
	rep["passwordProfile"] = map[string]any{"password": pw, "forceChangePasswordNextSignIn": true}
	status, body, err := d.p.do(ctx, http.MethodPost, "/users", nil, rep)
	if err != nil {
		return "", err
	}
	switch {
	case status == http.StatusCreated:
		var created graphUser
		if err := json.Unmarshal(body, &created); err != nil || created.str("id") == "" {
			return "", errors.New("entra: create user: response has no id")
		}
		return created.str("id"), nil
	case status == http.StatusBadRequest && strings.Contains(strings.ToLower(errorMessage(body)), "already exists"):
		// Created concurrently, e.g. by a retry after a timeout.
		existing, err := d.findByEmail(ctx, u)
		if err != nil {
			return "", err
		}
		if existing == nil {
			return "", apiError("create user", status, body)
		}
		return existing.str("id"), nil
	default:
		return "", apiError("create user", status, body)
	}
}

// invite creates (or re-invites) u as a B2B guest and returns the guest's
// ID. With send, Microsoft emails the invitation.
func (d *directory) invite(ctx context.Context, u sdk.User, send bool) (string, error) {
	in := map[string]any{
		"invitedUserEmailAddress": u.Email,
		"invitedUserDisplayName":  displayName(u),
		"inviteRedirectUrl":       d.p.cfg.InviteRedirectURL,
		"sendInvitationMessage":   send,
	}
	status, body, err := d.p.do(ctx, http.MethodPost, "/invitations", nil, in)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return "", apiError("invite user", status, body)
	}
	var inv struct {
		InvitedUser struct {
			ID string `json:"id"`
		} `json:"invitedUser"`
	}
	if err := json.Unmarshal(body, &inv); err != nil || inv.InvitedUser.ID == "" {
		return "", errors.New("entra: invite user: response has no invitedUser.id")
	}
	id := inv.InvitedUser.ID
	if !send {
		// The invitation API cannot set the remaining properties.
		if err := d.patch(ctx, id, "update invited user", d.properties(u)); err != nil {
			return "", err
		}
	}
	return id, nil
}

func (d *directory) UpdateUser(ctx context.Context, u sdk.User) error {
	cur, err := d.lookup(ctx, u)
	if err != nil {
		return err
	}
	rep := d.properties(u)
	if curMail := cur.str("mail"); !strings.EqualFold(curMail, u.Email) {
		rep["mail"] = u.Email
		// Rename the UPN only if the directory generated it from the email.
		if !d.guest() && curMail != "" && strings.EqualFold(cur.str("userPrincipalName"), d.upn(curMail)) {
			rep["userPrincipalName"] = d.upn(u.Email)
			rep["mailNickname"] = mailNickname(u.Email)
		}
	}
	return d.patch(ctx, cur.str("id"), "update user", rep)
}

func (d *directory) DeleteUser(ctx context.Context, u sdk.User) error {
	cur, err := d.lookup(ctx, u)
	if errors.Is(err, errNoUser) {
		return nil
	} else if err != nil {
		return err
	}
	id := cur.str("id")
	status, body, err := d.p.do(ctx, http.MethodDelete, userPath(id), nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return apiError("delete user", status, body)
	}
	if !d.p.cfg.HardDelete {
		return nil
	}
	status, body, err = d.retry404(ctx, http.MethodDelete, "/directory/deletedItems/"+url.PathEscape(id), nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return apiError("purge deleted user", status, body)
	}
	return nil
}

// SetPassword sets the password of a member account. Guests have no
// password in the tenant: it returns sdk.ErrUnsupported in guest mode.
func (d *directory) SetPassword(ctx context.Context, u sdk.User, password string) error {
	if d.guest() {
		return sdk.ErrUnsupported
	}
	cur, err := d.lookup(ctx, u)
	if err != nil {
		return err
	}
	rep := map[string]any{"passwordProfile": map[string]any{
		"password": password, "forceChangePasswordNextSignIn": d.p.cfg.ForceChangePassword,
	}}
	status, body, err := d.retry404(ctx, http.MethodPatch, userPath(cur.str("id")), rep)
	switch {
	case err != nil:
		return err
	case status == http.StatusNoContent || status == http.StatusOK:
		return nil
	case status == http.StatusBadRequest:
		// Complexity or history violation; Graph never echoes the password.
		return fmt.Errorf("entra: set password: %s", errorMessage(body))
	case status == http.StatusForbidden:
		return fmt.Errorf("entra: set password: %s (the app needs User-PasswordProfile.ReadWrite.All or the User Administrator role)",
			errorMessage(body))
	default:
		return apiError("set password", status, body)
	}
}

// SendInvitation, in guest mode, has Microsoft email a B2B invitation. In
// member mode it returns sdk.ErrUnsupported and Tenarium sends its own.
func (d *directory) SendInvitation(ctx context.Context, u sdk.User) error {
	if !d.guest() {
		return sdk.ErrUnsupported
	}
	_, err := d.invite(ctx, u, true)
	return err
}

// patch PATCHes the user, retrying while a new user has not replicated.
func (d *directory) patch(ctx context.Context, id, op string, rep map[string]any) error {
	status, body, err := d.retry404(ctx, http.MethodPatch, userPath(id), rep)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return apiError(op, status, body)
	}
	return nil
}

// retry404 sends a request and retries it on 404, because Entra replicates
// new objects asynchronously: a user just created may not be visible yet.
func (d *directory) retry404(ctx context.Context, method, path string, in any) (int, []byte, error) {
	for attempt := 0; ; attempt++ {
		status, body, err := d.p.do(ctx, method, path, nil, in)
		if err != nil || status != http.StatusNotFound || attempt >= len(d.p.retryDelays) {
			return status, body, err
		}
		if err := sleep(ctx, d.p.retryDelays[attempt]); err != nil {
			return 0, nil, err
		}
	}
}

// errNoUser reports that the user has no account in the tenant.
var errNoUser = errors.New("entra: user not found in directory")

func (d *directory) selectFields() string {
	fields := []string{"id", "mail", "userPrincipalName", "accountEnabled", "userType"}
	if a := d.p.cfg.UserIDAttribute; a != "" {
		fields = append(fields, a)
	}
	return strings.Join(fields, ",")
}

// lookup returns u's Graph user: by u.ExternalID if set (waiting for
// replication), else by email.
func (d *directory) lookup(ctx context.Context, u sdk.User) (graphUser, error) {
	if u.ExternalID == "" {
		existing, err := d.findByEmail(ctx, u)
		if err != nil {
			return nil, err
		}
		if existing == nil {
			return nil, errNoUser
		}
		return existing, nil
	}
	path := userPath(u.ExternalID) + "?$select=" + url.QueryEscape(d.selectFields())
	status, body, err := d.retry404(ctx, http.MethodGet, path, nil)
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
	var g graphUser
	if err := json.Unmarshal(body, &g); err != nil {
		return nil, fmt.Errorf("entra: get user: %w", err)
	}
	if g.str("id") == "" {
		g["id"] = u.ExternalID
	}
	return g, nil
}

// findByEmail returns the user whose mail (or generated UPN) is u's email,
// or nil. It fails if that user belongs to another Tenarium user.
func (d *directory) findByEmail(ctx context.Context, u sdk.User) (graphUser, error) {
	filter := "mail eq " + odataString(u.Email)
	if !d.guest() {
		filter += " or userPrincipalName eq " + odataString(d.upn(u.Email))
	}
	q := url.Values{"$filter": {filter}, "$select": {d.selectFields()}, "$top": {"5"}}
	status, body, err := d.p.do(ctx, http.MethodGet, "/users", q, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError("search users", status, body)
	}
	var res struct {
		Value []graphUser `json:"value"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("entra: search users: %w", err)
	}
	for _, g := range res.Value {
		if !strings.EqualFold(g.str("mail"), u.Email) && !strings.EqualFold(g.str("userPrincipalName"), d.upn(u.Email)) {
			continue
		}
		if a := d.p.cfg.UserIDAttribute; a != "" {
			if owner := g.str(a); owner != "" && owner != u.ID {
				return nil, fmt.Errorf("entra: %s already belongs to another Tenarium user", u.Email)
			}
		}
		return g, nil
	}
	return nil, nil
}

// odataString quotes s as an OData string literal.
func odataString(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// upn returns the userPrincipalName generated for email.
func (d *directory) upn(email string) string {
	dom := d.p.cfg.UPNDomain
	if dom == "" {
		return email
	}
	local := sanitize(strings.Replace(email, "@", "_", 1))
	if len(local) > 64 {
		sum := sha256.Sum256([]byte(strings.ToLower(email)))
		local = local[:55] + "_" + hex.EncodeToString(sum[:4])
	}
	return local + "@" + dom
}

// mailNickname derives the required mailNickname from the email's local
// part.
func mailNickname(email string) string {
	local, _, _ := strings.Cut(email, "@")
	n := sanitize(local)
	if n == "" {
		n = "user"
	}
	return n[:min(len(n), 64)]
}

// sanitize keeps the characters valid in a UPN local part and a
// mailNickname.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), ".")
}
