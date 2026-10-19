package sdk

import (
	"context"
	"errors"
	"maps"
	"slices"
	"time"
)

// UserStatus is the state of a user account.
type UserStatus string

const (
	// UserInvited users exist but have not set up their credentials yet.
	UserInvited  UserStatus = "invited"
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
)

// User is a person who can sign in. Users are platform-wide; tenant access
// comes from memberships (Member.UserID references User.ID).
type User struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Name          string     `json:"name,omitempty"`
	Status        UserStatus `json:"status"`
	EmailVerified bool       `json:"email_verified"`
	// Roles are platform-level roles (e.g. "admin"), granted when the user
	// signs in without choosing a tenant. Tenant roles come from memberships.
	Roles []string `json:"roles,omitempty"`
	// Directory names where the identity lives: "internal" or the instance
	// name of a plugin providing a UserDirectory.
	Directory string `json:"directory"`
	// ExternalID is the user's ID in an external directory (e.g. the
	// Keycloak user ID, which is the "sub" of its tokens).
	ExternalID  string            `json:"external_id,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	Version     int64             `json:"version"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	LastLoginAt *time.Time        `json:"last_login_at,omitempty"`
}

// Clone returns a deep copy of u.
func (u User) Clone() User {
	c := u
	c.Roles = slices.Clone(u.Roles)
	c.Attributes = maps.Clone(u.Attributes)
	if u.LastLoginAt != nil {
		t := *u.LastLoginAt
		c.LastLoginAt = &t
	}
	return c
}

// UserEventData is the payload of user.* events. It never contains
// credentials.
type UserEventData struct {
	User     User  `json:"user"`
	Previous *User `json:"previous,omitempty"`
}

// User event types.
const (
	EventUserCreated         = "user.created"
	EventUserUpdated         = "user.updated"
	EventUserActivated       = "user.activated"
	EventUserDisabled        = "user.disabled"
	EventUserEnabled         = "user.enabled"
	EventUserDeleted         = "user.deleted"
	EventUserPasswordChanged = "user.password_changed"
	EventUserLocked          = "user.locked"
)

// ErrUnsupported is returned by optional operations a backend cannot do.
var ErrUnsupported = errors.New("not supported")

// UserDirectory keeps user identities and credentials outside Tenarium,
// e.g. in Keycloak. Tenarium stores a reference row for every user (for
// memberships and auditing) and calls the directory for every change.
//
// All methods must be idempotent: a retry after a timeout must not fail
// because the first attempt succeeded.
type UserDirectory interface {
	Name() string
	// CreateUser creates the identity and returns its ID in the directory.
	// If a user with the same email already exists there, return its ID.
	CreateUser(ctx context.Context, u User) (externalID string, err error)
	// UpdateUser applies email, name, status and attribute changes.
	UpdateUser(ctx context.Context, u User) error
	DeleteUser(ctx context.Context, u User) error
	// SetPassword sets the user's password. Return ErrUnsupported if
	// passwords are managed only in the directory's own UI.
	SetPassword(ctx context.Context, u User, password string) error
}

// PasswordVerifier is optionally implemented by a UserDirectory that can
// check passwords (e.g. LDAP bind), enabling Tenarium's password login for
// its users.
type PasswordVerifier interface {
	VerifyPassword(ctx context.Context, u User, password string) error
}

// InvitationSender is optionally implemented by a UserDirectory that sends
// its own invitation or setup email (e.g. Keycloak's "execute actions"
// email). Otherwise Tenarium sends one through the Mailer.
type InvitationSender interface {
	SendInvitation(ctx context.Context, u User) error
}

// Message is an email to send.
type Message struct {
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
	HTML    string   `json:"html,omitempty"`
	// Tag identifies the kind of message (invitation, password_reset,
	// email_verification) for templates, metrics and providers.
	Tag string `json:"tag,omitempty"`
}

// Mailer sends email (invitations, password resets).
type Mailer interface {
	Name() string
	Send(ctx context.Context, m Message) error
}
