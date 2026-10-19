package keycloak

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// UserIDAttribute is the Keycloak user attribute holding the Tenarium user
// ID. It marks which Tenarium user owns a Keycloak identity.
const UserIDAttribute = "tenarium_user_id"

// ErrInvalidCredentials is returned by VerifyPassword when Keycloak rejects
// the email and password.
var ErrInvalidCredentials = errors.New("invalid credentials")

// UsersConfig configures the user directory.
type UsersConfig struct {
	// Realm holds the platform users.
	Realm string `json:"realm"`
	// CreateRealm creates Realm at Init if it does not exist.
	CreateRealm bool `json:"create_realm"`
	// ClientID and ClientSecret name a client of Realm with direct access
	// grants enabled. When ClientID is set the directory verifies passwords.
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	// SendInvitation sends invitations with Keycloak's execute-actions
	// email, which needs SMTP configured in Realm. Otherwise Tenarium sends
	// its own.
	SendInvitation bool `json:"send_invitation"`
	// InvitationActions are the required actions of the invitation email;
	// default UPDATE_PASSWORD and VERIFY_EMAIL.
	InvitationActions []string `json:"invitation_actions"`
	// InvitationLifespan is how long the email link is valid; default "72h".
	InvitationLifespan string `json:"invitation_lifespan"`
	// RedirectURI and ClientForRedirect are where the user lands after the
	// actions. ClientForRedirect defaults to ClientID.
	RedirectURI       string `json:"redirect_uri"`
	ClientForRedirect string `json:"client_for_redirect"`
}

// directory is a sdk.UserDirectory and sdk.InvitationSender over one realm.
type directory struct {
	p        *Plugin
	cfg      UsersConfig
	lifespan time.Duration
}

// verifyingDirectory adds sdk.PasswordVerifier; it is registered only when
// users.client_id is set.
type verifyingDirectory struct{ *directory }

var (
	_ sdk.UserDirectory    = (*directory)(nil)
	_ sdk.InvitationSender = (*directory)(nil)
	_ sdk.PasswordVerifier = verifyingDirectory{}
)

func newDirectory(p *Plugin, c *UsersConfig) (*directory, error) {
	if c.Realm == "" {
		return nil, errors.New("users.realm is required")
	}
	if c.ClientID != "" && c.ClientSecret == "" {
		return nil, errors.New("users.client_secret is required with users.client_id")
	}
	if len(c.InvitationActions) == 0 {
		c.InvitationActions = []string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}
	}
	d := &directory{p: p, cfg: *c, lifespan: 72 * time.Hour}
	if c.InvitationLifespan != "" {
		var err error
		if d.lifespan, err = time.ParseDuration(c.InvitationLifespan); err != nil {
			return nil, fmt.Errorf("users.invitation_lifespan: %w", err)
		}
		if d.lifespan < time.Second {
			return nil, errors.New("users.invitation_lifespan must be at least 1s")
		}
	}
	if c.RedirectURI != "" && d.redirectClient() == "" {
		return nil, errors.New("users.redirect_uri needs users.client_for_redirect or users.client_id")
	}
	return d, nil
}

func (d *directory) redirectClient() string {
	if d.cfg.ClientForRedirect != "" {
		return d.cfg.ClientForRedirect
	}
	if d.cfg.RedirectURI != "" {
		return d.cfg.ClientID
	}
	return ""
}

func (d *directory) Name() string { return "keycloak" }

func (d *directory) usersPath() string { return realmPath(d.cfg.Realm) + "/users" }

func (d *directory) userPath(id string) string { return d.usersPath() + "/" + url.PathEscape(id) }

// representation is the Keycloak UserRepresentation of u.
func representation(u sdk.User) map[string]any {
	first, last, _ := strings.Cut(strings.Join(strings.Fields(u.Name), " "), " ")
	attrs := map[string][]string{}
	for k, v := range u.Attributes {
		attrs[k] = []string{v}
	}
	attrs[UserIDAttribute] = []string{u.ID}
	return map[string]any{
		"username":      strings.ToLower(u.Email),
		"email":         u.Email,
		"firstName":     first,
		"lastName":      last,
		"enabled":       u.Status != sdk.UserDisabled,
		"emailVerified": u.EmailVerified,
		"attributes":    attrs,
	}
}

func (d *directory) CreateUser(ctx context.Context, u sdk.User) (string, error) {
	if u.Email == "" {
		return "", errors.New("keycloak: create user: email is required")
	}
	status, body, hdr, err := d.p.doHeader(ctx, http.MethodPost, d.usersPath(), nil, representation(u))
	if err != nil {
		return "", err
	}
	switch status {
	case http.StatusCreated:
		loc, err := url.Parse(hdr.Get("Location"))
		if err != nil || loc.Path == "" {
			return "", fmt.Errorf("keycloak: create user: bad Location %q", hdr.Get("Location"))
		}
		return path.Base(loc.Path), nil
	case http.StatusConflict:
		// Already there, e.g. a retry after a timeout.
		existing, err := d.findByEmail(ctx, u)
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
	id, err := d.externalID(ctx, u)
	if err != nil {
		return err
	}
	return d.p.expect(ctx, http.MethodPut, d.userPath(id), representation(u), http.StatusNoContent)
}

func (d *directory) DeleteUser(ctx context.Context, u sdk.User) error {
	id, err := d.externalID(ctx, u)
	if errors.Is(err, errNoUser) {
		return nil
	} else if err != nil {
		return err
	}
	return d.p.expect(ctx, http.MethodDelete, d.userPath(id), nil, http.StatusNoContent, http.StatusNotFound)
}

func (d *directory) SetPassword(ctx context.Context, u sdk.User, password string) error {
	id, err := d.externalID(ctx, u)
	if err != nil {
		return err
	}
	cred := map[string]any{"type": "password", "value": password, "temporary": false}
	status, body, err := d.p.do(ctx, http.MethodPut, d.userPath(id)+"/reset-password", nil, cred)
	switch {
	case err != nil:
		return err
	case status == http.StatusNoContent || status == http.StatusOK:
		return nil
	case status == http.StatusBadRequest:
		// Password policy violation; the body never echoes the password.
		return fmt.Errorf("keycloak: set password: %s", errorMessage(body))
	default:
		return apiError("set password", status, body)
	}
}

// SendInvitation emails the user a link to perform the invitation actions.
// It returns sdk.ErrUnsupported unless users.send_invitation is set.
func (d *directory) SendInvitation(ctx context.Context, u sdk.User) error {
	if !d.cfg.SendInvitation {
		return sdk.ErrUnsupported
	}
	id, err := d.externalID(ctx, u)
	if err != nil {
		return err
	}
	q := url.Values{"lifespan": {strconv.FormatInt(int64(d.lifespan/time.Second), 10)}}
	if c := d.redirectClient(); c != "" {
		q.Set("client_id", c)
	}
	if d.cfg.RedirectURI != "" {
		q.Set("redirect_uri", d.cfg.RedirectURI)
	}
	status, body, err := d.p.do(ctx, http.MethodPut, d.userPath(id)+"/execute-actions-email", q, d.cfg.InvitationActions)
	switch {
	case err != nil:
		return err
	case status == http.StatusNoContent || status == http.StatusOK:
		return nil
	default:
		return apiError("send invitation", status, body)
	}
}

// VerifyPassword checks the password with the direct grant of
// users.client_id. Rejected credentials yield ErrInvalidCredentials.
func (v verifyingDirectory) VerifyPassword(ctx context.Context, u sdk.User, password string) error {
	c := v.cfg
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
		"username":      {strings.ToLower(u.Email)},
		"password":      {password},
		"scope":         {"openid"},
	}
	endpoint := v.p.Issuer(c.Realm) + "/protocol/openid-connect/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.p.client.Do(req)
	if err != nil {
		return fmt.Errorf("keycloak: verify password: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusBadRequest:
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "invalid_grant" {
			return fmt.Errorf("keycloak: %w: %s", ErrInvalidCredentials, errorMessage(body))
		}
	}
	return apiError("verify password", resp.StatusCode, body)
}

// errNoUser reports that the user has no identity in the directory.
var errNoUser = errors.New("keycloak: user not found in directory")

// externalID returns u's Keycloak ID: u.ExternalID or, if unset, the ID of
// the identity owned by u with u's email.
func (d *directory) externalID(ctx context.Context, u sdk.User) (string, error) {
	if u.ExternalID != "" {
		return u.ExternalID, nil
	}
	existing, err := d.findByEmail(ctx, u)
	if err != nil {
		return "", err
	}
	if existing == nil {
		return "", errNoUser
	}
	return existing.ID, nil
}

type kcUser struct {
	ID         string              `json:"id"`
	Email      string              `json:"email"`
	Attributes map[string][]string `json:"attributes"`
}

// findByEmail returns the identity with u's email, or nil. It fails if the
// identity belongs to another Tenarium user.
func (d *directory) findByEmail(ctx context.Context, u sdk.User) (*kcUser, error) {
	q := url.Values{"email": {u.Email}, "exact": {"true"}}
	status, body, err := d.p.do(ctx, http.MethodGet, d.usersPath(), q, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError("search users", status, body)
	}
	var users []kcUser
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("keycloak: search users: %w", err)
	}
	for _, ku := range users {
		if !strings.EqualFold(ku.Email, u.Email) {
			continue
		}
		if owner := ku.Attributes[UserIDAttribute]; len(owner) > 0 && owner[0] != u.ID {
			return nil, fmt.Errorf("keycloak: %s already belongs to another Tenarium user", u.Email)
		}
		return &ku, nil
	}
	return nil, nil
}

// ensureRealm creates realm if it is missing. A new realm lets admins store
// unmanaged attributes (Keycloak 24+) so tenarium_user_id is kept.
func (p *Plugin) ensureRealm(ctx context.Context, realm string) error {
	status, body, err := p.do(ctx, http.MethodPost, "/admin/realms", nil, map[string]any{"realm": realm, "enabled": true})
	if err != nil {
		return err
	}
	switch status {
	case http.StatusConflict:
		return nil
	case http.StatusCreated, http.StatusOK, http.StatusNoContent:
	default:
		return apiError("create realm "+realm, status, body)
	}
	profilePath := realmPath(realm) + "/users/profile"
	status, body, err = p.do(ctx, http.MethodGet, profilePath, nil, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil // Keycloak before 24 stores any attribute
	} else if status != http.StatusOK {
		return apiError("get user profile of "+realm, status, body)
	}
	var profile map[string]any
	if err := json.Unmarshal(body, &profile); err != nil {
		return fmt.Errorf("keycloak: user profile of %s: %w", realm, err)
	}
	profile["unmanagedAttributePolicy"] = "ADMIN_EDIT"
	return p.expect(ctx, http.MethodPut, profilePath, profile, http.StatusOK, http.StatusNoContent)
}

// errorMessage extracts Keycloak's error text from a JSON error body.
func errorMessage(body []byte) string {
	var e struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorMessage     string `json:"errorMessage"`
	}
	if json.Unmarshal(body, &e) == nil {
		if msg := cmp.Or(e.ErrorDescription, e.ErrorMessage, e.Error); msg != "" {
			return msg
		}
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 512 {
		msg = msg[:512]
	}
	return msg
}
