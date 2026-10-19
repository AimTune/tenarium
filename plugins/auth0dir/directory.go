package auth0dir

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// directory is a sdk.UserDirectory and sdk.InvitationSender over one Auth0
// database connection.
type directory struct{ p *Plugin }

// verifyingDirectory adds sdk.PasswordVerifier; it is registered only when
// password_login is configured.
type verifyingDirectory struct{ *directory }

var (
	_ sdk.UserDirectory    = (*directory)(nil)
	_ sdk.InvitationSender = (*directory)(nil)
	_ sdk.PasswordVerifier = verifyingDirectory{}
)

func (d *directory) Name() string { return "auth0" }

// a0User is the part of an Auth0 user the directory reads.
type a0User struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	Blocked    bool   `json:"blocked"`
	Identities []struct {
		Connection string `json:"connection"`
	} `json:"identities"`
	AppMetadata struct {
		Tenarium struct {
			UserID string `json:"user_id"`
		} `json:"tenarium"`
	} `json:"app_metadata"`
}

func (a *a0User) inConnection(conn string) bool {
	for _, id := range a.Identities {
		if id.Connection == conn {
			return true
		}
	}
	return false
}

// metadata is the app_metadata.tenarium object of u.
func metadata(u sdk.User) map[string]any {
	attrs := maps.Clone(u.Attributes)
	if attrs == nil {
		attrs = map[string]string{}
	}
	return map[string]any{MetadataKey: map[string]any{"user_id": u.ID, "attributes": attrs}}
}

func displayName(u sdk.User) string {
	if n := strings.TrimSpace(u.Name); n != "" {
		return n
	}
	return u.Email
}

func userPath(id string) string { return "/api/v2/users/" + url.PathEscape(id) }

func (d *directory) CreateUser(ctx context.Context, u sdk.User) (string, error) {
	if u.Email == "" {
		return "", errors.New("auth0: create user: email is required")
	}
	existing, err := d.findByEmail(ctx, u)
	if err != nil {
		return "", err
	}
	if existing != nil {
		return existing.UserID, nil
	}
	pw, err := randomPassword()
	if err != nil {
		return "", err
	}
	c := d.p.cfg
	rep := map[string]any{
		"connection":     c.Connection,
		"email":          u.Email,
		"name":           displayName(u),
		"password":       pw,
		"email_verified": u.EmailVerified,
		"verify_email":   c.VerifyEmail && !u.EmailVerified,
		"blocked":        u.Status == sdk.UserDisabled,
		"app_metadata":   metadata(u),
	}
	status, body, err := d.p.do(ctx, http.MethodPost, "/api/v2/users", nil, rep)
	if err != nil {
		return "", err
	}
	switch status {
	case http.StatusCreated, http.StatusOK:
		var created a0User
		if err := json.Unmarshal(body, &created); err != nil || created.UserID == "" {
			return "", fmt.Errorf("auth0: create user: response has no user_id")
		}
		return created.UserID, nil
	case http.StatusConflict:
		// Created concurrently, e.g. by a retry after a timeout.
		existing, err := d.findByEmail(ctx, u)
		if err != nil {
			return "", err
		}
		if existing == nil {
			return "", apiError("create user", status, body)
		}
		return existing.UserID, nil
	default:
		return "", apiError("create user", status, body)
	}
}

func (d *directory) UpdateUser(ctx context.Context, u sdk.User) error {
	cur, err := d.lookup(ctx, u)
	if err != nil {
		return err
	}
	rep := map[string]any{
		"name":         displayName(u),
		"blocked":      u.Status == sdk.UserDisabled,
		"app_metadata": metadata(u),
	}
	if !strings.EqualFold(cur.Email, u.Email) {
		// Auth0 needs the connection with an email change and resets
		// email_verified unless it is sent too.
		rep["email"] = u.Email
		rep["connection"] = d.p.cfg.Connection
	}
	rep["email_verified"] = u.EmailVerified
	status, body, err := d.p.do(ctx, http.MethodPatch, userPath(cur.UserID), nil, rep)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return apiError("update user", status, body)
	}
	return nil
}

func (d *directory) DeleteUser(ctx context.Context, u sdk.User) error {
	cur, err := d.lookup(ctx, u)
	if errors.Is(err, errNoUser) {
		return nil
	} else if err != nil {
		return err
	}
	status, body, err := d.p.do(ctx, http.MethodDelete, userPath(cur.UserID), nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusOK && status != http.StatusNotFound {
		return apiError("delete user", status, body)
	}
	return nil
}

func (d *directory) SetPassword(ctx context.Context, u sdk.User, password string) error {
	cur, err := d.lookup(ctx, u)
	if err != nil {
		return err
	}
	rep := map[string]any{"password": password, "connection": d.p.cfg.Connection}
	status, body, err := d.p.do(ctx, http.MethodPatch, userPath(cur.UserID), nil, rep)
	switch {
	case err != nil:
		return err
	case status == http.StatusOK:
		return nil
	case status == http.StatusBadRequest:
		// Password policy violation; Auth0 never echoes the password.
		return fmt.Errorf("auth0: set password: %s", errorMessage(body))
	default:
		return apiError("set password", status, body)
	}
}

// SendInvitation asks Auth0 to email the user, according to the invitation
// setting. It returns sdk.ErrUnsupported with invitation "none".
func (d *directory) SendInvitation(ctx context.Context, u sdk.User) error {
	c := d.p.cfg
	switch c.Invitation {
	case InvitationChangePassword:
		// Authentication API: Auth0 emails a link to choose a password.
		in := map[string]any{"client_id": c.InvitationClientID, "email": u.Email, "connection": c.Connection}
		status, body, err := send(ctx, d.p.client, http.MethodPost, d.p.base+"/dbconnections/change_password", in)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return apiError("send invitation", status, body)
		}
		return nil
	case InvitationVerifyEmail:
		cur, err := d.lookup(ctx, u)
		if err != nil {
			return err
		}
		in := map[string]any{"user_id": cur.UserID, "client_id": c.InvitationClientID}
		status, body, err := d.p.do(ctx, http.MethodPost, "/api/v2/jobs/verification-email", nil, in)
		if err != nil {
			return err
		}
		if status != http.StatusCreated && status != http.StatusOK {
			return apiError("send invitation", status, body)
		}
		return nil
	default:
		return sdk.ErrUnsupported
	}
}

// VerifyPassword checks the password with the password-realm grant against
// the configured connection. Rejected credentials (including blocked users)
// yield ErrInvalidCredentials.
func (v verifyingDirectory) VerifyPassword(ctx context.Context, u sdk.User, password string) error {
	if password == "" {
		return fmt.Errorf("auth0: %w", ErrInvalidCredentials)
	}
	c := v.p.cfg
	pl := c.PasswordLogin
	form := url.Values{
		"grant_type":    {"http://auth0.com/oauth/grant-type/password-realm"},
		"realm":         {c.Connection},
		"client_id":     {pl.ClientID},
		"client_secret": {pl.ClientSecret},
		"username":      {u.Email},
		"password":      {password},
		"scope":         {"openid"},
	}
	if pl.Audience != "" {
		form.Set("audience", pl.Audience)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.p.base+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.p.client.Do(req)
	if err != nil {
		return fmt.Errorf("auth0: verify password: %w", err)
	}
	defer resp.Body.Close()
	var e struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	_ = json.NewDecoder(resp.Body).Decode(&e)
	switch {
	case e.Error == "invalid_grant":
		return fmt.Errorf("auth0: %w: %s", ErrInvalidCredentials, e.ErrorDescription)
	case e.Error == "unauthorized" && strings.Contains(strings.ToLower(e.ErrorDescription), "blocked"):
		return fmt.Errorf("auth0: %w: %s", ErrInvalidCredentials, e.ErrorDescription)
	case e.Error == "mfa_required":
		return fmt.Errorf("auth0: %w", ErrMFARequired)
	}
	return fmt.Errorf("auth0: verify password: %s: %s", http.StatusText(resp.StatusCode),
		strings.TrimSpace(e.Error+" "+e.ErrorDescription))
}

// errNoUser reports that the user has no identity in the connection.
var errNoUser = errors.New("auth0: user not found in directory")

// lookup returns u's Auth0 user: by u.ExternalID if set, else by email.
func (d *directory) lookup(ctx context.Context, u sdk.User) (*a0User, error) {
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
	q := url.Values{"fields": {"user_id,email,blocked,identities,app_metadata"}}
	status, body, err := d.p.do(ctx, http.MethodGet, userPath(u.ExternalID), q, nil)
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
	var au a0User
	if err := json.Unmarshal(body, &au); err != nil {
		return nil, fmt.Errorf("auth0: get user: %w", err)
	}
	if au.UserID == "" {
		au.UserID = u.ExternalID
	}
	return &au, nil
}

// findByEmail returns the user of the connection with u's email, or nil. It
// fails if that user belongs to another Tenarium user.
func (d *directory) findByEmail(ctx context.Context, u sdk.User) (*a0User, error) {
	q := url.Values{"email": {u.Email}}
	status, body, err := d.p.do(ctx, http.MethodGet, "/api/v2/users-by-email", q, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError("search users", status, body)
	}
	var users []a0User
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("auth0: search users: %w", err)
	}
	for _, au := range users {
		if !strings.EqualFold(au.Email, u.Email) || !au.inConnection(d.p.cfg.Connection) {
			continue
		}
		if owner := au.AppMetadata.Tenarium.UserID; owner != "" && owner != u.ID {
			return nil, fmt.Errorf("auth0: %s already belongs to another Tenarium user", u.Email)
		}
		return &au, nil
	}
	return nil, nil
}
