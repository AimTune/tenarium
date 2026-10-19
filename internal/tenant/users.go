package tenant

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/mail"
	"slices"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// InternalDirectory is the name of the built-in user directory.
const InternalDirectory = "internal"

// Action token kinds.
const (
	tokenInvitation    = "invitation"
	tokenPasswordReset = "password_reset"
)

var (
	// ErrInvalidCredentials hides whether the user exists.
	ErrInvalidCredentials = errors.New("invalid email or password")
	// ErrAccountLocked is returned while a user is locked out after too many
	// failed logins.
	ErrAccountLocked = errors.New("account temporarily locked after too many failed logins")
	// ErrTenantRequired is returned when a user without platform roles signs
	// in without choosing a tenant.
	ErrTenantRequired = errors.New("choose a tenant to sign in to")
	// ErrPasswordLoginUnavailable means the user directory does not let
	// Tenarium check passwords; users sign in at the identity provider.
	ErrPasswordLoginUnavailable = errors.New("password login is not available for this directory; sign in with your identity provider")
	// ErrInvalidToken covers unknown, used or expired emailed/refresh tokens.
	ErrInvalidToken = errors.New("invalid or expired token")
)

// UserOptions configure user management.
type UserOptions struct {
	// WebAuthn enables passkeys (nil disables them).
	WebAuthn *webauthn.WebAuthn
	// Impersonation configures support access to user sessions.
	Impersonation ImpersonationOptions
	// Directory stores identities; nil means the internal directory.
	Directory     sdk.UserDirectory
	DirectoryName string
	Mailer        sdk.Mailer
	// PublicURL is used for links in emails.
	PublicURL     string
	ProductName   string
	Policy        identity.Policy
	InvitationTTL time.Duration
	ResetTTL      time.Duration
	MaxFailures   int
	LockFor       time.Duration
	Issuer        *identity.Issuer
	RefreshTTL    time.Duration
	// MagicLinkTTL enables passwordless sign-in by emailed link (0: off).
	MagicLinkTTL time.Duration
	// EmailChangeTTL bounds email-change confirmations (default 24h).
	EmailChangeTTL time.Duration
	// BreachCheck, if set, rejects new passwords found in data breaches.
	// Errors (e.g. the service is down) are logged and the password is
	// accepted.
	BreachCheck func(ctx context.Context, password string) (bool, error)
	// Templates override the default email templates by tag.
	Templates map[string]EmailTemplate
	Log       *slog.Logger
}

// EmailTemplate is a text/template triple; HTML is optional.
type EmailTemplate struct {
	Subject string `yaml:"subject" json:"subject"`
	Text    string `yaml:"text" json:"text"`
	HTML    string `yaml:"html" json:"html"`
}

var defaultTemplates = map[string]EmailTemplate{
	tokenInvitation: {
		Subject: "Set up your {{.Product}} account",
		Text: `Hello{{if .User.Name}} {{.User.Name}}{{end}},

You have been invited to {{.Product}}. Choose a password to activate your account:

{{.Link}}

This link expires on {{.Expires}}. If you did not expect this email, ignore it.
`,
	},
	tokenPasswordReset: {
		Subject: "Reset your {{.Product}} password",
		Text: `Hello{{if .User.Name}} {{.User.Name}}{{end}},

Someone asked to reset the password for {{.User.Email}}. To choose a new one, open:

{{.Link}}

This link expires on {{.Expires}}. If you did not ask for this, ignore this email; your password is unchanged.
`,
	},
	tokenMagicLink: {
		Subject: "Sign in to {{.Product}}",
		Text: `Hello{{if .User.Name}} {{.User.Name}}{{end}},

To sign in to {{.Product}} as {{.User.Email}}, open:

{{.Link}}

The link works once and expires on {{.Expires}}. If you did not ask for it, ignore this email.
`,
	},
	tokenEmailChange: {
		Subject: "Confirm your new {{.Product}} email address",
		Text: `Hello{{if .User.Name}} {{.User.Name}}{{end}},

To use {{.User.Email}} for your {{.Product}} account, confirm it here:

{{.Link}}

This link expires on {{.Expires}}. If you did not ask for this, ignore this email.
`,
	},
	noticeEmailChanged: {
		Subject: "Your {{.Product}} email address was changed",
		Text: `Hello{{if .User.Name}} {{.User.Name}}{{end}},

The email address of your {{.Product}} account was changed from {{.User.Email}} to {{.NewEmail}}.

If you did not do this, contact your administrator immediately.
`,
	},
}

func (s *Service) directoryName() string {
	if s.userOpts == nil || s.userOpts.Directory == nil {
		return InternalDirectory
	}
	return s.userOpts.DirectoryName
}

func (s *Service) internalDirectory() bool { return s.directoryName() == InternalDirectory }

// UserInput creates a user.
type UserInput struct {
	Email      string            `json:"email"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	// Password activates the user immediately (no invitation). Optional.
	Password string `json:"password,omitempty"`
	// SendInvitation emails a setup link to a user created without a
	// password. Defaults to true.
	SendInvitation *bool `json:"send_invitation,omitempty"`
}

// UserUpdate is a partial update.
type UserUpdate struct {
	Email         *string            `json:"email,omitempty"`
	Name          *string            `json:"name,omitempty"`
	Roles         *[]string          `json:"roles,omitempty"`
	Attributes    *map[string]string `json:"attributes,omitempty"`
	EmailVerified *bool              `json:"email_verified,omitempty"`
}

func normalizeEmail(e string) string { return strings.TrimSpace(e) }

func validateUser(u *sdk.User) error {
	addr, err := mail.ParseAddress(u.Email)
	if err != nil || addr.Address != u.Email || len(u.Email) > 254 {
		return invalid("email", "must be a plain email address")
	}
	if utf8.RuneCountInString(u.Name) > maxNameLen {
		return invalid("name", "must be at most %d characters", maxNameLen)
	}
	for _, r := range u.Roles {
		if !keyRe.MatchString(r) {
			return invalid("roles", "invalid role %q", r)
		}
	}
	if len(u.Attributes) > maxLabels {
		return invalid("attributes", "at most %d attributes", maxLabels)
	}
	for k, v := range u.Attributes {
		if !labelKeyRe.MatchString(k) || len(v) > maxLabelValueLen {
			return invalid("attributes", "invalid attribute %q", k)
		}
	}
	return nil
}

// CreateUser adds a user to the directory. Without a password the user is
// invited and (by default) receives a setup email.
func (s *Service) CreateUser(ctx context.Context, in UserInput) (sdk.User, error) {
	now := s.now()
	u := sdk.User{
		ID:         uuid.Must(uuid.NewV7()).String(),
		Email:      normalizeEmail(in.Email),
		Name:       strings.TrimSpace(in.Name),
		Status:     sdk.UserInvited,
		Roles:      slices.Clone(in.Roles),
		Directory:  s.directoryName(),
		Attributes: maps.Clone(in.Attributes),
		Version:    1,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if in.Password != "" {
		if err := s.checkNewPassword(ctx, in.Password, u.Email); err != nil {
			return sdk.User{}, err
		}
		u.Status = sdk.UserActive
	}
	if err := validateUser(&u); err != nil {
		return sdk.User{}, err
	}
	u, err := s.runUserHooks(ctx, sdk.HookBeforeUserCreate, u)
	if err != nil {
		return sdk.User{}, err
	}
	if _, err := s.store.GetUserByEmail(ctx, u.Email); err == nil {
		return sdk.User{}, fmt.Errorf("user %q: %w", u.Email, store.ErrAlreadyExists)
	} else if !errors.Is(err, store.ErrNotFound) {
		return sdk.User{}, err
	}

	dir := s.userOpts.Directory
	if dir != nil {
		ext, err := dir.CreateUser(ctx, u)
		if err != nil {
			return sdk.User{}, fmt.Errorf("user directory: %w", err)
		}
		u.ExternalID = ext
		if in.Password != "" {
			if err := dir.SetPassword(ctx, u, in.Password); err != nil {
				s.compensateDirectory(ctx, u)
				return sdk.User{}, fmt.Errorf("user directory: %w", err)
			}
		}
	}
	var hash string
	if dir == nil && in.Password != "" {
		if hash, err = identity.HashPassword(in.Password); err != nil {
			return sdk.User{}, err
		}
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.CreateUser(ctx, u); err != nil {
			return err
		}
		if hash != "" {
			if err := tx.SetPasswordHash(ctx, u.ID, hash); err != nil {
				return err
			}
		}
		return s.appendUserEvent(ctx, tx, sdk.EventUserCreated, u, nil)
	})
	if err != nil {
		if dir != nil {
			s.compensateDirectory(ctx, u)
		}
		if errors.Is(err, store.ErrAlreadyExists) {
			return sdk.User{}, fmt.Errorf("user %q: %w", u.Email, err)
		}
		return sdk.User{}, err
	}
	s.notify()
	if u.Status == sdk.UserInvited && (in.SendInvitation == nil || *in.SendInvitation) {
		if err := s.sendInvitation(ctx, u); err != nil {
			s.userOpts.Log.Warn("sending invitation failed; resend it later", "user_id", u.ID, "err", err)
		}
	}
	return u, nil
}

// compensateDirectory undoes a directory create after a failed local write.
func (s *Service) compensateDirectory(ctx context.Context, u sdk.User) {
	if err := s.userOpts.Directory.DeleteUser(context.WithoutCancel(ctx), u); err != nil {
		s.userOpts.Log.Error("could not roll back user in directory", "email", u.Email, "err", err)
	}
}

// GetUser resolves a user by ID or email.
func (s *Service) GetUser(ctx context.Context, idOrEmail string) (sdk.User, error) {
	if strings.Contains(idOrEmail, "@") {
		return s.store.GetUserByEmail(ctx, idOrEmail)
	}
	return s.store.GetUser(ctx, idOrEmail)
}

func (s *Service) ListUsers(ctx context.Context, q store.ListUsersQuery) ([]sdk.User, error) {
	return s.store.ListUsers(ctx, q)
}

// UserMemberships lists the tenants a user belongs to.
func (s *Service) UserMemberships(ctx context.Context, userID string) ([]sdk.Member, error) {
	return s.store.ListMembershipsOfUser(ctx, userID)
}

func (s *Service) UpdateUser(ctx context.Context, idOrEmail string, in UserUpdate, expectedVersion *int64) (sdk.User, error) {
	return s.mutateUser(ctx, idOrEmail, expectedVersion, sdk.EventUserUpdated, true, func(u *sdk.User) error {
		if in.Email != nil {
			u.Email = normalizeEmail(*in.Email)
		}
		if in.Name != nil {
			u.Name = strings.TrimSpace(*in.Name)
		}
		if in.Roles != nil {
			u.Roles = slices.Clone(*in.Roles)
		}
		if in.Attributes != nil {
			u.Attributes = maps.Clone(*in.Attributes)
		}
		if in.EmailVerified != nil {
			u.EmailVerified = *in.EmailVerified
		}
		return nil
	})
}

// DisableUser blocks sign-in and revokes refresh tokens. Access tokens
// stop working immediately too: every request re-checks the user.
func (s *Service) DisableUser(ctx context.Context, idOrEmail string) (sdk.User, error) {
	u, err := s.mutateUser(ctx, idOrEmail, nil, sdk.EventUserDisabled, false, func(u *sdk.User) error {
		if u.Status == sdk.UserDisabled {
			return stateErr("user is already disabled")
		}
		u.Status = sdk.UserDisabled
		return nil
	})
	if err == nil {
		err = s.store.RevokeUserRefreshTokens(ctx, u.ID)
	}
	return u, err
}

// EnableUser re-enables a disabled user. Users who never set credentials
// go back to invited.
func (s *Service) EnableUser(ctx context.Context, idOrEmail string) (sdk.User, error) {
	return s.mutateUser(ctx, idOrEmail, nil, sdk.EventUserEnabled, false, func(u *sdk.User) error {
		if u.Status != sdk.UserDisabled {
			return stateErr("user is not disabled")
		}
		u.Status = sdk.UserActive
		if s.internalDirectory() {
			if c, err := s.store.GetCredentials(ctx, u.ID); err == nil && c.PasswordHash == "" {
				u.Status = sdk.UserInvited
			}
		}
		return nil
	})
}

// DeleteUser removes the user, its memberships, credentials and tokens.
func (s *Service) DeleteUser(ctx context.Context, idOrEmail string) error {
	u, err := s.GetUser(ctx, idOrEmail)
	if err != nil {
		return err
	}
	if dir := s.userOpts.Directory; dir != nil {
		if err := dir.DeleteUser(ctx, u); err != nil {
			return fmt.Errorf("user directory: %w", err)
		}
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		ms, err := tx.ListMembersOfUser(ctx, u.ID)
		if err != nil {
			return err
		}
		for _, m := range ms {
			if err := tx.DeleteMember(ctx, m.TenantID, m.ID); err != nil {
				return err
			}
			if err := s.appendEvent(ctx, tx, sdk.EventMemberRemoved, m.TenantID, "tenants/"+m.TenantID+"/members/"+m.ID,
				sdk.MemberEventData{Member: m}); err != nil {
				return err
			}
		}
		if err := tx.DeleteUser(ctx, u.ID); err != nil {
			return err
		}
		return s.appendUserEvent(ctx, tx, sdk.EventUserDeleted, u, nil)
	})
	if err != nil {
		return err
	}
	s.notify()
	return nil
}

// mutateUser is the read-modify-write cycle for users. sync pushes the new
// state to an external directory before it is stored.
func (s *Service) mutateUser(ctx context.Context, idOrEmail string, expectedVersion *int64, eventType string,
	hooks bool, change func(u *sdk.User) error,
) (sdk.User, error) {
	prev, err := s.GetUser(ctx, idOrEmail)
	if err != nil {
		return sdk.User{}, err
	}
	if expectedVersion != nil && *expectedVersion != prev.Version {
		return sdk.User{}, store.ErrConflict
	}
	next := prev.Clone()
	if err := change(&next); err != nil {
		return sdk.User{}, err
	}
	if err := validateUser(&next); err != nil {
		return sdk.User{}, err
	}
	if hooks {
		if next, err = s.runUserHooks(ctx, sdk.HookBeforeUserUpdate, next); err != nil {
			return sdk.User{}, err
		}
	}
	next.Version, next.UpdatedAt = prev.Version+1, s.now()
	if dir := s.userOpts.Directory; dir != nil {
		if err := dir.UpdateUser(ctx, next); err != nil {
			return sdk.User{}, fmt.Errorf("user directory: %w", err)
		}
	}
	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if err := tx.UpdateUser(ctx, next, prev.Version); err != nil {
			return err
		}
		return s.appendUserEvent(ctx, tx, eventType, next, &prev)
	})
	if err != nil {
		return sdk.User{}, err
	}
	s.notify()
	return next, nil
}

// runUserHooks lets hooks adjust name, roles and attributes.
func (s *Service) runUserHooks(ctx context.Context, point sdk.HookPoint, u sdk.User) (sdk.User, error) {
	if s.hooks == nil {
		return u, nil
	}
	proposed := u.Clone()
	if err := s.hooks.RunHooks(ctx, &sdk.HookRequest{Point: point, User: &proposed}); err != nil {
		return sdk.User{}, err
	}
	out := u
	out.Name, out.Roles, out.Attributes = proposed.Name, proposed.Roles, proposed.Attributes
	if err := validateUser(&out); err != nil {
		return sdk.User{}, fmt.Errorf("hook produced invalid user: %w", err)
	}
	return out, nil
}

func (s *Service) appendUserEvent(ctx context.Context, tx store.Tx, typ string, u sdk.User, prev *sdk.User) error {
	return s.appendEvent(ctx, tx, typ, "", "users/"+u.ID, sdk.UserEventData{User: u, Previous: prev})
}

// --- passwords ------------------------------------------------------------------

// SetUserPassword sets a password on behalf of an administrator and
// activates an invited user.
func (s *Service) SetUserPassword(ctx context.Context, idOrEmail, password string) error {
	u, err := s.GetUser(ctx, idOrEmail)
	if err != nil {
		return err
	}
	return s.setPassword(ctx, u, password)
}

// ChangePassword is the self-service password change; it requires the
// current password.
func (s *Service) ChangePassword(ctx context.Context, userID, current, next string) error {
	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.checkPassword(ctx, u, current); err != nil {
		return ErrInvalidCredentials
	}
	return s.setPassword(ctx, u, next)
}

func (s *Service) setPassword(ctx context.Context, u sdk.User, password string) error {
	if u.Status == sdk.UserDisabled {
		return stateErr("user is disabled")
	}
	if err := s.checkNewPassword(ctx, password, u.Email); err != nil {
		return err
	}
	var hash string
	if dir := s.userOpts.Directory; dir != nil {
		if err := dir.SetPassword(ctx, u, password); err != nil {
			if errors.Is(err, sdk.ErrUnsupported) {
				return ErrPasswordLoginUnavailable
			}
			return fmt.Errorf("user directory: %w", err)
		}
	} else {
		var err error
		if hash, err = identity.HashPassword(password); err != nil {
			return err
		}
	}
	err := s.store.InTx(ctx, func(tx store.Tx) error {
		cur, err := tx.GetUser(ctx, u.ID)
		if err != nil {
			return err
		}
		if hash != "" {
			if err := tx.SetPasswordHash(ctx, u.ID, hash); err != nil {
				return err
			}
		}
		if err := s.appendUserEvent(ctx, tx, sdk.EventUserPasswordChanged, cur, nil); err != nil {
			return err
		}
		if cur.Status == sdk.UserInvited {
			return s.activateUser(ctx, tx, cur)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// A new password ends all sessions.
	if err := s.store.RevokeUserRefreshTokens(ctx, u.ID); err != nil {
		return err
	}
	s.notify()
	return nil
}

// activateUser marks an invited user active (their email is now proven)
// and activates their pending memberships, inside tx.
func (s *Service) activateUser(ctx context.Context, tx store.Tx, u sdk.User) error {
	prev := u.Clone()
	u.Status, u.EmailVerified = sdk.UserActive, true
	u.Version, u.UpdatedAt = prev.Version+1, s.now()
	if err := tx.UpdateUser(ctx, u, prev.Version); err != nil {
		return err
	}
	if err := s.appendUserEvent(ctx, tx, sdk.EventUserActivated, u, &prev); err != nil {
		return err
	}
	ms, err := tx.ListMembersOfUser(ctx, u.ID)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if m.Status != sdk.MemberInvited {
			continue
		}
		pm := m
		m.Status, m.Version, m.UpdatedAt = sdk.MemberActive, m.Version+1, s.now()
		if err := tx.UpdateMember(ctx, m, pm.Version); err != nil {
			return err
		}
		if err := s.appendEvent(ctx, tx, sdk.EventMemberUpdated, m.TenantID, "tenants/"+m.TenantID+"/members/"+m.ID,
			sdk.MemberEventData{Member: m, Previous: &pm}); err != nil {
			return err
		}
	}
	return nil
}

// ResendInvitation emails a new setup link to an invited user.
func (s *Service) ResendInvitation(ctx context.Context, idOrEmail string) error {
	u, err := s.GetUser(ctx, idOrEmail)
	if err != nil {
		return err
	}
	if u.Status != sdk.UserInvited {
		return stateErr("user is %s, not invited", u.Status)
	}
	return s.sendInvitation(ctx, u)
}

func (s *Service) sendInvitation(ctx context.Context, u sdk.User) error {
	if inv, ok := s.userOpts.Directory.(sdk.InvitationSender); ok {
		err := inv.SendInvitation(ctx, u)
		if !errors.Is(err, sdk.ErrUnsupported) {
			return err
		}
	}
	return s.emailToken(ctx, u, tokenInvitation, s.userOpts.InvitationTTL, "accept")
}

// RequestPasswordReset emails a reset link if the user exists and is
// active. It never reveals whether the email is known.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	u, err := s.store.GetUserByEmail(ctx, normalizeEmail(email))
	if errors.Is(err, store.ErrNotFound) || (err == nil && u.Status != sdk.UserActive) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.emailToken(ctx, u, tokenPasswordReset, s.userOpts.ResetTTL, "reset")
}

func (s *Service) emailToken(ctx context.Context, u sdk.User, kind string, ttl time.Duration, uiPath string) error {
	token, hash := identity.NewToken()
	now := s.now()
	expires := now.Add(ttl)
	if err := s.store.CreateActionToken(ctx, store.ActionToken{Hash: hash, Kind: kind, UserID: u.ID, ExpiresAt: expires, CreatedAt: now}); err != nil {
		return err
	}
	link := strings.TrimRight(s.userOpts.PublicURL, "/") + "/ui/#/" + uiPath + "/" + token
	msg, err := s.renderEmail(kind, u, link, expires)
	if err != nil {
		return err
	}
	return s.userOpts.Mailer.Send(ctx, msg)
}

// extra adds template data, e.g. NewEmail for email-change notices.
func (s *Service) renderEmail(kind string, u sdk.User, link string, expires time.Time, extra ...map[string]any) (sdk.Message, error) {
	tpl, ok := s.userOpts.Templates[kind]
	if !ok {
		tpl = defaultTemplates[kind]
	}
	data := map[string]any{
		"User": u, "Link": link, "Product": s.userOpts.ProductName,
		"Expires": expires.UTC().Format("2006-01-02 15:04 MST"),
	}
	for _, e := range extra {
		maps.Copy(data, e)
	}
	render := func(name, src string) (string, error) {
		if src == "" {
			return "", nil
		}
		t, err := template.New(name).Parse(src)
		if err != nil {
			return "", fmt.Errorf("email template %s/%s: %w", kind, name, err)
		}
		var b bytes.Buffer
		err = t.Execute(&b, data)
		return b.String(), err
	}
	subject, err := render("subject", tpl.Subject)
	if err != nil {
		return sdk.Message{}, err
	}
	text, err := render("text", tpl.Text)
	if err != nil {
		return sdk.Message{}, err
	}
	html, err := render("html", tpl.HTML)
	if err != nil {
		return sdk.Message{}, err
	}
	return sdk.Message{To: []string{u.Email}, Subject: strings.TrimSpace(subject), Text: text, HTML: html, Tag: kind}, nil
}

// AcceptInvitation sets the first password of an invited user.
func (s *Service) AcceptInvitation(ctx context.Context, token, password, name string) (sdk.User, error) {
	at, err := s.store.ConsumeActionToken(ctx, identity.HashToken(token), tokenInvitation, s.now())
	if err != nil {
		return sdk.User{}, ErrInvalidToken
	}
	u, err := s.store.GetUser(ctx, at.UserID)
	if err != nil {
		return sdk.User{}, ErrInvalidToken
	}
	if name = strings.TrimSpace(name); name != "" && name != u.Name {
		if u, err = s.UpdateUser(ctx, u.ID, UserUpdate{Name: &name}, nil); err != nil {
			return sdk.User{}, err
		}
	}
	if err := s.setPassword(ctx, u, password); err != nil {
		return sdk.User{}, err
	}
	return s.store.GetUser(ctx, u.ID)
}

// ResetPassword completes a password reset.
func (s *Service) ResetPassword(ctx context.Context, token, password string) error {
	at, err := s.store.ConsumeActionToken(ctx, identity.HashToken(token), tokenPasswordReset, s.now())
	if err != nil {
		return ErrInvalidToken
	}
	u, err := s.store.GetUser(ctx, at.UserID)
	if err != nil {
		return ErrInvalidToken
	}
	return s.setPassword(ctx, u, password)
}

// --- sessions ----------------------------------------------------------------------

// TokenPair is the result of a login or refresh.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
}

func (s *Service) checkPassword(ctx context.Context, u sdk.User, password string) error {
	if dir := s.userOpts.Directory; dir != nil {
		v, ok := dir.(sdk.PasswordVerifier)
		if !ok {
			return ErrPasswordLoginUnavailable
		}
		return v.VerifyPassword(ctx, u, password)
	}
	c, err := s.store.GetCredentials(ctx, u.ID)
	if err != nil {
		return err
	}
	if c.PasswordHash == "" {
		identity.BurnTime(password)
		return ErrInvalidCredentials
	}
	return identity.VerifyPassword(c.PasswordHash, password)
}

// Login verifies a password and issues tokens, optionally for one tenant.
// LoginInput is a password sign-in; OTP is required for users with
// two-factor authentication.
type LoginInput struct {
	Email, Password, Tenant, OTP string
}

// Login signs a user in with email and password.
func (s *Service) Login(ctx context.Context, email, password, tenantRef string) (TokenPair, error) {
	return s.SignIn(ctx, LoginInput{Email: email, Password: password, Tenant: tenantRef})
}

// SignIn checks the password (and second factor) and opens a session.
// SignIn checks the password (and second factor) and opens a session.
func (s *Service) SignIn(ctx context.Context, in LoginInput) (TokenPair, error) {
	u, err := s.VerifyLogin(ctx, in)
	if err != nil {
		return TokenPair{}, err
	}
	return s.OpenSession(ctx, u, in.Tenant, true)
}

// VerifyLogin checks a password sign-in (lockout, SSO enforcement, second
// factor) without opening a session.
func (s *Service) VerifyLogin(ctx context.Context, in LoginInput) (sdk.User, error) {
	email, password, tenantRef := in.Email, in.Password, in.Tenant
	if s.userOpts.Directory != nil {
		if _, ok := s.userOpts.Directory.(sdk.PasswordVerifier); !ok {
			return sdk.User{}, ErrPasswordLoginUnavailable
		}
	}
	// Domains enforcing SSO answer the same whether or not the account
	// exists; only platform users signing in without a tenant (break-glass
	// admins) may still use their password.
	enforced, err := s.ssoEnforced(ctx, email)
	if err != nil {
		return sdk.User{}, err
	}
	u, err := s.store.GetUserByEmail(ctx, normalizeEmail(email))
	if errors.Is(err, store.ErrNotFound) {
		if enforced {
			return sdk.User{}, ErrSSORequired
		}
		identity.BurnTime(password)
		return sdk.User{}, ErrInvalidCredentials
	}
	if err != nil {
		return sdk.User{}, err
	}
	if enforced && (tenantRef != "" || len(u.Roles) == 0) {
		return sdk.User{}, ErrSSORequired
	}
	if u.Status != sdk.UserActive {
		identity.BurnTime(password)
		return sdk.User{}, ErrInvalidCredentials
	}
	now := s.now()
	creds, err := s.store.GetCredentials(ctx, u.ID)
	if err != nil {
		return sdk.User{}, err
	}
	if creds.LockedUntil != nil && now.Before(*creds.LockedUntil) {
		return sdk.User{}, ErrAccountLocked
	}
	if err := s.checkPassword(ctx, u, password); err != nil {
		if errors.Is(err, ErrPasswordLoginUnavailable) {
			return sdk.User{}, err
		}
		locked, lerr := s.store.RecordLoginFailure(ctx, u.ID, s.userOpts.MaxFailures, s.userOpts.LockFor, now)
		if lerr == nil && locked {
			s.userOpts.Log.Warn("user locked after repeated failed logins", "user_id", u.ID)
			_ = s.store.InTx(ctx, func(tx store.Tx) error { return s.appendUserEvent(ctx, tx, sdk.EventUserLocked, u, nil) })
			s.notify()
		}
		return sdk.User{}, ErrInvalidCredentials
	}
	if on, err := s.mfaEnabled(ctx, u.ID); err != nil {
		return sdk.User{}, err
	} else if on {
		if err := s.checkOTP(ctx, u.ID, in.OTP); err != nil {
			if errors.Is(err, ErrInvalidOTP) {
				// Guessing codes counts toward the lockout.
				_, _ = s.store.RecordLoginFailure(ctx, u.ID, s.userOpts.MaxFailures, s.userOpts.LockFor, now)
			}
			return sdk.User{}, err
		}
	}
	return u, nil
}

// sessionScope works out the tenant and roles a session gets.
func (s *Service) sessionScope(ctx context.Context, u sdk.User, tenantRef string) (string, []string, error) {
	if tenantRef == "" {
		if len(u.Roles) == 0 {
			return "", nil, ErrTenantRequired
		}
		return "", u.Roles, nil
	}
	t, err := s.Get(ctx, tenantRef)
	if err != nil {
		return "", nil, ErrInvalidCredentials
	}
	m, err := s.activeMembership(ctx, u.ID, t)
	if err != nil {
		return "", nil, err
	}
	return t.ID, s.EffectiveRoles(ctx, m), nil
}

// activeMembership returns the user's active membership in an active
// tenant. Errors are deliberately uniform.
func (s *Service) activeMembership(ctx context.Context, userID string, t sdk.Tenant) (sdk.Member, error) {
	if t.Status != sdk.StatusActive {
		return sdk.Member{}, fmt.Errorf("%w: tenant is %s", sdk.ErrForbidden, t.Status)
	}
	ms, err := s.store.ListMembershipsOfUser(ctx, userID)
	if err != nil {
		return sdk.Member{}, err
	}
	for _, m := range ms {
		if m.TenantID == t.ID && m.Status == sdk.MemberActive {
			return m, nil
		}
	}
	return sdk.Member{}, fmt.Errorf("%w: not a member of this tenant", sdk.ErrForbidden)
}

// ErrTokensDisabled is returned by Login when token issuing is off.
var ErrTokensDisabled = errors.New("token issuing is disabled")

func (s *Service) issue(ctx context.Context, u sdk.User, tenantID string, roles []string, refresh string) (TokenPair, error) {
	if s.userOpts.Issuer == nil {
		return TokenPair{}, ErrTokensDisabled
	}
	c := identity.Claims{Email: u.Email, Name: u.Name, TenantID: tenantID, Roles: roles}
	if tenantID != "" {
		// The region lets edges route without looking the tenant up.
		if t, err := s.store.GetTenant(ctx, tenantID); err == nil {
			c.Region = t.Region
		}
	}
	access, exp, err := s.userOpts.Issuer.SignAccess(u.ID, c, 0)
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{
		AccessToken: access, TokenType: "Bearer", ExpiresIn: int(time.Until(exp).Seconds()),
		RefreshToken: refresh, TenantID: tenantID,
	}, nil
}

// Refresh rotates a refresh token and issues a new access token with the
// user's current roles. Reusing a rotated token revokes the session.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (TokenPair, error) {
	now := s.now()
	next, hash := identity.NewToken()
	old, err := s.store.RotateRefreshToken(ctx, identity.HashToken(refreshToken),
		store.RefreshToken{Hash: hash, ExpiresAt: now.Add(s.userOpts.RefreshTTL), CreatedAt: now,
			UserAgent: clientFrom(ctx).UserAgent, IP: clientFrom(ctx).IP}, now)
	if errors.Is(err, store.ErrTokenReused) {
		s.userOpts.Log.Warn("refresh token reuse detected; session revoked")
		return TokenPair{}, ErrInvalidToken
	}
	if err != nil {
		return TokenPair{}, ErrInvalidToken
	}
	if old.ClientID != oauthClientFrom(ctx) {
		// Presented by the wrong client: treat it as stolen.
		s.userOpts.Log.Warn("refresh token presented by another client; session revoked", "user_id", old.UserID)
		_ = s.store.RevokeRefreshToken(ctx, hash)
		return TokenPair{}, ErrInvalidToken
	}
	u, err := s.store.GetUser(ctx, old.UserID)
	if err != nil || u.Status != sdk.UserActive {
		_ = s.store.RevokeRefreshToken(ctx, hash)
		return TokenPair{}, ErrInvalidToken
	}
	roles := u.Roles
	if old.TenantID != "" {
		t, err := s.store.GetTenant(ctx, old.TenantID)
		if err != nil {
			return TokenPair{}, ErrInvalidToken
		}
		m, err := s.activeMembership(ctx, u.ID, t)
		if err != nil {
			_ = s.store.RevokeRefreshToken(ctx, hash)
			return TokenPair{}, ErrInvalidToken
		}
		roles = []string{m.Role}
	} else if len(roles) == 0 {
		return TokenPair{}, ErrInvalidToken
	}
	return s.issue(ctx, u, old.TenantID, roles, next)
}

// Logout revokes the session the refresh token belongs to.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	return s.store.RevokeRefreshToken(ctx, identity.HashToken(refreshToken))
}

// RevokeSessions signs a user out everywhere.
func (s *Service) RevokeSessions(ctx context.Context, idOrEmail string) error {
	u, err := s.GetUser(ctx, idOrEmail)
	if err != nil {
		return err
	}
	return s.store.RevokeUserRefreshTokens(ctx, u.ID)
}

// TokenPrincipal turns a verified Tenarium access token into a principal,
// re-checking that the user is active and, for tenant tokens, still an
// active member. Roles always come from the current state, so demoting or
// removing a member takes effect immediately.
func (s *Service) TokenPrincipal(ctx context.Context, c identity.Claims) (*sdk.Principal, error) {
	u, err := s.store.GetUser(ctx, c.Subject)
	if err != nil || u.Status != sdk.UserActive {
		return nil, ErrInvalidToken
	}
	p := &sdk.Principal{
		Subject: u.ID, Kind: "user",
		Claims: map[string]any{"email": u.Email, "name": u.Name, "tenarium_user_id": u.ID},
	}
	if c.Act != nil {
		p.Claims[ImpersonationClaim] = c.Act.Subject
	}
	if c.TenantID == "" {
		if len(u.Roles) == 0 {
			return nil, ErrInvalidToken
		}
		p.Roles = slices.Clone(u.Roles)
		return p, nil
	}
	t, err := s.store.GetTenant(ctx, c.TenantID)
	if err != nil {
		return nil, ErrInvalidToken
	}
	m, err := s.activeMembership(ctx, u.ID, t)
	if err != nil {
		return nil, ErrInvalidToken
	}
	p.TenantID, p.Roles = t.ID, s.EffectiveRoles(ctx, m)
	return p, nil
}

// LinkExternalPrincipal attaches the Tenarium user to a principal
// authenticated by an external identity provider (e.g. Keycloak through the
// oidc plugin) whose subject is the user's directory ID. Disabled users are
// refused.
func (s *Service) LinkExternalPrincipal(ctx context.Context, p *sdk.Principal) error {
	if s.internalDirectory() {
		return nil
	}
	u, err := s.store.GetUserByExternalID(ctx, s.directoryName(), p.Subject)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if u.Status == sdk.UserDisabled {
		return fmt.Errorf("%w: user is disabled", sdk.ErrForbidden)
	}
	if p.Claims == nil {
		p.Claims = map[string]any{}
	}
	p.Claims["tenarium_user_id"] = u.ID
	return nil
}

// ensureMemberUser finds the user for a new membership, creating and
// inviting them if needed.
func (s *Service) ensureMemberUser(ctx context.Context, in MemberInput) (sdk.User, error) {
	if in.UserID != "" {
		u, err := s.store.GetUser(ctx, in.UserID)
		if errors.Is(err, store.ErrNotFound) {
			return sdk.User{}, invalid("user_id", "unknown user")
		}
		return u, err
	}
	u, err := s.store.GetUserByEmail(ctx, normalizeEmail(in.Email))
	if err == nil || !errors.Is(err, store.ErrNotFound) {
		return u, err
	}
	u, err = s.CreateUser(ctx, UserInput{Email: in.Email, Name: in.Name})
	if errors.Is(err, store.ErrAlreadyExists) {
		// Created concurrently by another request.
		return s.store.GetUserByEmail(ctx, normalizeEmail(in.Email))
	}
	return u, err
}

// checkNewPassword applies the password policy and, if configured, the
// breached-password check, which fails open: an outage of the breach
// service must not stop users from setting passwords.
func (s *Service) checkNewPassword(ctx context.Context, password, email string) error {
	if err := s.userOpts.Policy.Check(password, email); err != nil {
		return invalid("password", "%v", err)
	}
	if check := s.userOpts.BreachCheck; check != nil {
		if breached, err := check(ctx, password); err != nil {
			s.userOpts.Log.Warn("breached-password check failed; accepting the password", "err", err)
		} else if breached {
			return invalid("password", "this password appears in a known data breach; choose another")
		}
	}
	return nil
}
