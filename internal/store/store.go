// Package store defines persistence for tenants, plans, members, usage, the
// event log (outbox), subscription cursors, leases and dead letters.
//
// The key guarantee is that every write and the events describing it are
// committed in one transaction (transactional outbox). Event delivery to
// plugins happens afterwards by reading the log, so a crash can never produce
// a change without its event, or an event without its change.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

var (
	ErrNotFound      = sdk.ErrNotFound
	ErrAlreadyExists = errors.New("already exists")
	// ErrConflict signals an optimistic-locking failure: the row changed
	// since it was read.
	ErrConflict = errors.New("version conflict")
	// ErrQuotaExceeded is returned by IncrementUsage when the limit would be
	// exceeded.
	ErrQuotaExceeded = errors.New("quota exceeded")
)

// ListTenantsQuery filters and paginates tenants. Results are ordered by ID,
// which (being UUIDv7) is creation order.
type ListTenantsQuery struct {
	Status sdk.TenantStatus
	// Labels must all match (AND).
	Labels         map[string]string
	Plan           string
	ParentID       string
	IncludeDeleted bool
	// IDs restricts results to these tenants (used for tenant-scoped callers).
	IDs []string
	// After is an exclusive ID cursor.
	After string
	Limit int
}

// DeadLetter is an event a subscription gave up on.
type DeadLetter struct {
	ID           string    `json:"id"`
	Subscription string    `json:"subscription"`
	Event        sdk.Event `json:"event"`
	Error        string    `json:"error"`
	Attempts     int       `json:"attempts"`
	FailedAt     time.Time `json:"failed_at"`
}

// IdempotencyRecord stores the response to a request carrying an
// Idempotency-Key, so retries get the same answer.
type IdempotencyRecord struct {
	Key         string
	RequestHash string
	StatusCode  int
	Body        []byte
	CreatedAt   time.Time
}

// Usage is a tenant's counter for one metric in one period.
type Usage struct {
	TenantID string `json:"tenant_id"`
	Metric   string `json:"metric"`
	// Period names the window the counter covers: "" for counters that
	// never reset, otherwise e.g. "2026", "2026-10" or "2026-10-09" (UTC).
	Period    string     `json:"period,omitempty"`
	Value     int64      `json:"value"`
	PeriodEnd *time.Time `json:"period_end,omitempty"`
	// ClosedAt is set once the ended period was reported (usage.period_closed).
	ClosedAt  *time.Time `json:"closed_at,omitempty"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// UsageKey identifies a counter; PeriodEnd is stored with a new counter.
type UsageKey struct {
	TenantID, Metric, Period string
	PeriodEnd                *time.Time
}

// UsageQuery filters usage counters. Zero fields match everything.
type UsageQuery struct {
	TenantID string
	Metric   string
	Periods  []string
	Limit    int
}

// Match reports whether u satisfies the query (ignoring Limit).
func (q UsageQuery) Match(u Usage) bool {
	return (q.TenantID == "" || u.TenantID == q.TenantID) && (q.Metric == "" || u.Metric == q.Metric) &&
		(len(q.Periods) == 0 || slices.Contains(q.Periods, u.Period))
}

// ListUsersQuery filters and paginates users (ordered by ID).
type ListUsersQuery struct {
	// Search matches email or name, case-insensitively.
	Search string
	Status sdk.UserStatus
	After  string
	Limit  int
}

// Credentials are a user's login secrets and lockout state. They are never
// part of sdk.User.
type Credentials struct {
	PasswordHash string
	FailedLogins int
	LockedUntil  *time.Time
}

// MFA is a user's second factor: a TOTP secret plus hashed single-use
// recovery codes. It is pending until Enabled.
type MFA struct {
	UserID     string
	TOTPSecret string
	Enabled    bool
	// LastStep is the last TOTP time step used, to refuse replays.
	LastStep       int64
	RecoveryHashes []string
	UpdatedAt      time.Time
}

// ActionToken is a single-use token sent by email (invitation, password
// reset, email verification). Only its hash is stored.
type ActionToken struct {
	Hash   string
	Kind   string
	UserID string
	// Data is kind-specific, e.g. the new address of an email change.
	Data      string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// RefreshToken is a long-lived token exchanged for access tokens. Tokens
// rotate on every use; all tokens descending from one login share a Family,
// and reusing a rotated token revokes the whole family.
type RefreshToken struct {
	Hash      string
	UserID    string
	TenantID  string
	Family    string
	ExpiresAt time.Time
	CreatedAt time.Time
	// UserAgent and IP describe the client; a rotation without them keeps
	// the previous values.
	UserAgent string
	IP        string
	// ClientID is the OAuth client of sessions opened through the OpenID
	// provider; only that client may refresh them.
	ClientID string
}

// Session is a signed-in client: a refresh token family.
type Session struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	TenantID   string    `json:"tenant_id,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	IP         string    `json:"ip,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ErrTokenReused is returned when a rotated refresh token is presented
// again, which means it was stolen; the family has been revoked.
var ErrTokenReused = errors.New("refresh token reused")

// SigningKey is a private key Tenarium signs its tokens with.
type SigningKey struct {
	ID         string
	Algorithm  string
	PrivatePEM []byte
	CreatedAt  time.Time
}

// APIKey is a long-lived credential for services. Only the hash of the
// secret is stored.
type APIKey struct {
	ID string `json:"id"`
	// TenantID scopes the key to a tenant; empty means platform-wide.
	TenantID   string     `json:"tenant_id,omitempty"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Hash       string     `json:"-"`
	Roles      []string   `json:"roles"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// Domain is a custom hostname of a tenant.
type Domain struct {
	Hostname   string     `json:"hostname"`
	TenantID   string     `json:"tenant_id"`
	Verified   bool       `json:"verified"`
	Token      string     `json:"verification_token"`
	CreatedAt  time.Time  `json:"created_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// EventQuery filters the event log (the audit trail). Zero fields match
// everything.
type EventQuery struct {
	// TenantIDs matches events of any of these tenants.
	TenantIDs []string
	Actor     string
	// Types are exact types or prefixes ending in "*" ("tenant.*").
	Types []string
	// Since and Until bound the event time (inclusive, exclusive).
	Since, Until time.Time
	// Before returns only events with Seq < Before, for paging backwards.
	Before int64
	Limit  int
}

// MatchType reports whether typ matches one of the patterns of Types.
func (q EventQuery) MatchType(typ string) bool {
	if len(q.Types) == 0 {
		return true
	}
	for _, p := range q.Types {
		if prefix, ok := strings.CutSuffix(p, "*"); ok && strings.HasPrefix(typ, prefix) || p == typ {
			return true
		}
	}
	return false
}

// Match reports whether e satisfies the query (ignoring Limit).
func (q EventQuery) Match(e sdk.Event) bool {
	return (len(q.TenantIDs) == 0 || slices.Contains(q.TenantIDs, e.TenantID)) &&
		(q.Actor == "" || e.Actor == q.Actor) && q.MatchType(e.Type) &&
		(q.Since.IsZero() || !e.Time.Before(q.Since)) && (q.Until.IsZero() || e.Time.Before(q.Until)) &&
		(q.Before <= 0 || e.Seq < q.Before)
}

// Webhook is an endpoint a tenant registered to receive its own events.
type Webhook struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
	Secret      string `json:"-"`
	// Types are glob patterns on the event type ("tenant.*"); empty means
	// all.
	Types   []string `json:"types,omitempty"`
	Enabled bool     `json:"enabled"`
	// Failures counts consecutive events that could not be delivered.
	Failures  int       `json:"failures"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WebhookDelivery records one event sent (or attempted) to a webhook.
type WebhookDelivery struct {
	ID         string          `json:"id"`
	WebhookID  string          `json:"webhook_id"`
	TenantID   string          `json:"tenant_id"`
	EventID    string          `json:"event_id"`
	EventType  string          `json:"event_type"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	Attempts   int             `json:"attempts"`
	StatusCode int             `json:"status_code,omitempty"`
	Error      string          `json:"error,omitempty"`
	Success    bool            `json:"success"`
	DurationMS int64           `json:"duration_ms"`
	CreatedAt  time.Time       `json:"created_at"`
}

// SSOConnection is a tenant's OpenID Connect identity provider. Users of
// its email domains (verified domains of the tenant) can sign in to the
// tenant through it.
type SSOConnection struct {
	TenantID string `json:"tenant_id"`
	// Protocol is "oidc" (default) or "saml".
	Protocol     string `json:"protocol"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"-"`
	// SAMLMetadata is the identity provider's metadata XML (SAML only);
	// SAMLMetadataURL is where it was fetched from, if anywhere.
	SAMLMetadata       string   `json:"-"`
	SAMLMetadataURL    string   `json:"saml_metadata_url,omitempty"`
	SAMLEmailAttribute string   `json:"saml_email_attribute,omitempty"`
	SAMLNameAttribute  string   `json:"saml_name_attribute,omitempty"`
	Domains            []string `json:"domains"`
	// Enforce refuses password logins for users of the domains.
	Enforce bool `json:"enforce"`
	// AutoProvision creates users and memberships on first sign-in.
	AutoProvision bool      `json:"auto_provision"`
	DefaultRole   string    `json:"default_role"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TenantRole is a role a tenant defined itself: a name for a set of action
// patterns, usable like the built-in member roles.
type TenantRole struct {
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Actions     []string  `json:"actions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Group is a team inside a tenant. Its members additionally hold its roles.
type Group struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Roles       []string  `json:"roles"`
	Members     []string  `json:"members"` // member IDs
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// WebAuthnCredential is a user's passkey or security key.
type WebAuthnCredential struct {
	// ID is the credential ID, base64url without padding.
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	Name   string `json:"name"`
	// Data is the library's serialized credential (public key, sign count,
	// flags); opaque to the store.
	Data       []byte     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// OAuthClient is an application that signs users in through Tenarium's
// OpenID Connect provider.
type OAuthClient struct {
	ID   string `json:"client_id"`
	Name string `json:"name"`
	// SecretHash is empty for public clients (SPAs, mobile apps), which
	// must use PKCE.
	SecretHash             string   `json:"-"`
	RedirectURIs           []string `json:"redirect_uris"`
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	// TenantID scopes sessions to one tenant (a tenant's own app).
	TenantID string `json:"tenant_id,omitempty"`
	// Scopes the client may request.
	Scopes []string `json:"scopes"`
	// FirstParty clients skip the consent screen.
	FirstParty bool      `json:"first_party"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// OAuthConsent records the scopes a user granted a client.
type OAuthConsent struct {
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	CreatedAt time.Time `json:"created_at"`
}

// PlanRevision is a snapshot of a plan's features and limits; its number
// is the plan version that introduced it. Tenants pinned to it keep these
// entitlements after the plan changes (grandfathering).
type PlanRevision struct {
	PlanID    string           `json:"plan_id"`
	Revision  int64            `json:"revision"`
	Features  map[string]bool  `json:"features,omitempty"`
	Limits    map[string]int64 `json:"limits,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
}

// Rollout gradually enables a feature for tenants that don't set it
// themselves: a deterministic percentage of the matching cohort, plus
// explicit includes, minus excludes.
type Rollout struct {
	Feature string `json:"feature"`
	// Percentage of matching tenants (0-100), chosen by a stable hash of
	// feature and tenant ID, so raising it only adds tenants.
	Percentage int `json:"percentage"`
	// Cohort filters; empty matches all.
	Plans   []string          `json:"plans,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	Regions []string          `json:"regions,omitempty"`
	// Include and Exclude list tenant IDs that always or never get it.
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	// Enabled false turns the rollout off (kill switch).
	Enabled   bool      `json:"enabled"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Scheduled action states.
const (
	SchedulePending  = "pending"
	ScheduleRunning  = "running"
	ScheduleDone     = "done"
	ScheduleFailed   = "failed"
	ScheduleCanceled = "canceled"
)

// ScheduledAction is a tenant lifecycle change (suspend, resume, set_plan,
// delete) to run at RunAt, e.g. the end of a trial or a deletion grace
// period.
type ScheduledAction struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Action    string     `json:"action"`
	Plan      string     `json:"plan,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	RunAt     time.Time  `json:"run_at"`
	Status    string     `json:"status"`
	Error     string     `json:"error,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ClaimedAt *time.Time `json:"-"`
	DoneAt    *time.Time `json:"done_at,omitempty"`
}

// Store is the persistence port. Implementations must be safe for
// concurrent use.
type Store interface {
	GetDomain(ctx context.Context, hostname string) (Domain, error)
	ListDomains(ctx context.Context, tenantID string) ([]Domain, error)

	GetScheduledAction(ctx context.Context, id string) (ScheduledAction, error)
	// ListScheduledActions lists a tenant's actions by run time.
	ListScheduledActions(ctx context.Context, tenantID string) ([]ScheduledAction, error)
	// DueScheduledActions returns up to limit actions that are pending with
	// RunAt <= now, or running but claimed before staleBefore (their runner
	// died), by run time.
	DueScheduledActions(ctx context.Context, now, staleBefore time.Time, limit int) ([]ScheduledAction, error)

	GetWebhook(ctx context.Context, id string) (Webhook, error)
	ListWebhooks(ctx context.Context, tenantID string) ([]Webhook, error)
	// RecordWebhookResult resets the failure counter on success, or
	// increments it and disables the webhook once it reaches maxFailures
	// (0: never); it reports whether this call disabled it.
	RecordWebhookResult(ctx context.Context, id string, success bool, maxFailures int) (disabled bool, err error)
	AddWebhookDelivery(ctx context.Context, d WebhookDelivery) error
	GetWebhookDelivery(ctx context.Context, id string) (WebhookDelivery, error)
	// ListWebhookDeliveries returns a webhook's deliveries newest first,
	// those with an ID before beforeID (IDs sort by time) if given.
	ListWebhookDeliveries(ctx context.Context, webhookID, beforeID string, limit int) ([]WebhookDelivery, error)
	PruneWebhookDeliveries(ctx context.Context, before time.Time) (int64, error)

	GetSSOConnection(ctx context.Context, tenantID string) (SSOConnection, error)
	// FindSSOConnection returns the connection claiming an email domain.
	FindSSOConnection(ctx context.Context, domain string) (SSOConnection, error)
	// PutSSOConnection creates or replaces a tenant's connection;
	// ErrAlreadyExists if one of its domains is claimed by another tenant.
	PutSSOConnection(ctx context.Context, c SSOConnection) error
	DeleteSSOConnection(ctx context.Context, tenantID string) error

	GetTenantRole(ctx context.Context, tenantID, name string) (TenantRole, error)
	ListTenantRoles(ctx context.Context, tenantID string) ([]TenantRole, error)
	GetGroup(ctx context.Context, tenantID, id string) (Group, error)
	// ListGroups lists a tenant's groups by name.
	ListGroups(ctx context.Context, tenantID string) ([]Group, error)

	GetAPIKeyByHash(ctx context.Context, hash string) (APIKey, error)
	// ListAPIKeys lists keys of a tenant, or platform keys when tenantID is
	// empty.
	ListAPIKeys(ctx context.Context, tenantID string) ([]APIKey, error)
	// TouchAPIKey records when a key was last used.
	TouchAPIKey(ctx context.Context, id string, at time.Time) error

	GetUser(ctx context.Context, id string) (sdk.User, error)
	// GetUserByEmail matches case-insensitively.
	GetUserByEmail(ctx context.Context, email string) (sdk.User, error)
	GetUserByExternalID(ctx context.Context, directory, externalID string) (sdk.User, error)
	ListUsers(ctx context.Context, q ListUsersQuery) ([]sdk.User, error)
	// ListMembershipsOfUser returns the user's memberships in all tenants.
	ListMembershipsOfUser(ctx context.Context, userID string) ([]sdk.Member, error)

	GetCredentials(ctx context.Context, userID string) (Credentials, error)
	// RecordLoginFailure increments the failure counter and, once it reaches
	// maxFailures, locks the account until now+lockFor and resets the
	// counter. It reports whether this call locked the account.
	RecordLoginFailure(ctx context.Context, userID string, maxFailures int, lockFor time.Duration, now time.Time) (locked bool, err error)
	// RecordLoginSuccess clears failures and sets the last login time.
	RecordLoginSuccess(ctx context.Context, userID string, now time.Time) error

	CreateActionToken(ctx context.Context, t ActionToken) error
	// ConsumeActionToken atomically marks a token used and returns it. It
	// returns ErrNotFound for unknown, used, expired or wrong-kind tokens.
	ConsumeActionToken(ctx context.Context, hash, kind string, now time.Time) (ActionToken, error)

	CreateRefreshToken(ctx context.Context, t RefreshToken) error
	// RotateRefreshToken atomically replaces oldHash with next (inheriting
	// its family). It returns ErrNotFound for unknown or expired tokens and
	// ErrTokenReused (after revoking the family) for already-rotated ones.
	RotateRefreshToken(ctx context.Context, oldHash string, next RefreshToken, now time.Time) (RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, hash string) error
	RevokeUserRefreshTokens(ctx context.Context, userID string) error
	// ListSessions returns the user's live sessions (refresh token
	// families), most recently used first.
	ListSessions(ctx context.Context, userID string, now time.Time) ([]Session, error)
	// RevokeSession revokes one of the user's sessions (ErrNotFound if it
	// is not theirs or not live).
	RevokeSession(ctx context.Context, userID, sessionID string, now time.Time) error

	ListSigningKeys(ctx context.Context) ([]SigningKey, error)
	// AddSigningKey inserts k; ErrAlreadyExists if its ID is taken.
	AddSigningKey(ctx context.Context, k SigningKey) error
	// DeleteSigningKey removes a key; tokens it signed stop verifying.
	DeleteSigningKey(ctx context.Context, id string) error
	// ReplaceSigningKeyPEM rewrites a key's stored private key (e.g. re-encrypted)
	// if it still equals old; ErrConflict otherwise.
	ReplaceSigningKeyPEM(ctx context.Context, id string, old, next []byte) error

	// GetMFA returns ErrNotFound if the user has no second factor.
	GetMFA(ctx context.Context, userID string) (MFA, error)
	// PutMFA creates or replaces the MFA record; ErrNotFound if the user
	// does not exist.
	PutMFA(ctx context.Context, m MFA) error
	DeleteMFA(ctx context.Context, userID string) error
	// UseTOTPStep records step as used if it is newer than the last one;
	// false means the code was already used.
	UseTOTPStep(ctx context.Context, userID string, step int64) (bool, error)
	// UseRecoveryCode removes a recovery code hash; false if it was not
	// there (wrong or already used).
	UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error)

	ListWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error)
	GetWebAuthnCredential(ctx context.Context, id string) (WebAuthnCredential, error)
	// PutWebAuthnCredential creates or updates a credential; ErrNotFound if
	// the user does not exist, ErrAlreadyExists if the ID belongs to
	// another user.
	PutWebAuthnCredential(ctx context.Context, c WebAuthnCredential) error
	DeleteWebAuthnCredential(ctx context.Context, userID, id string) error

	GetOAuthClient(ctx context.Context, id string) (OAuthClient, error)
	ListOAuthClients(ctx context.Context) ([]OAuthClient, error)
	// PutOAuthClient creates or replaces a client.
	PutOAuthClient(ctx context.Context, c OAuthClient) error
	// DeleteOAuthClient removes a client and the consents given to it.
	DeleteOAuthClient(ctx context.Context, id string) error
	GetOAuthConsent(ctx context.Context, userID, clientID string) (OAuthConsent, error)
	PutOAuthConsent(ctx context.Context, c OAuthConsent) error

	// A small shared key-value space (ACME certificates and locks).
	// KVGet returns ErrNotFound for a missing key; KVPutIfAbsent reports
	// whether it wrote.
	KVGet(ctx context.Context, key string) ([]byte, error)
	KVPut(ctx context.Context, key string, value []byte) error
	KVPutIfAbsent(ctx context.Context, key string, value []byte) (bool, error)
	KVDelete(ctx context.Context, key string) error
	// KVKeys lists the keys starting with prefix, sorted.
	KVKeys(ctx context.Context, prefix string) ([]string, error)
	// KVCompareAndSwap replaces the value of key only if it still equals old.
	KVCompareAndSwap(ctx context.Context, key string, old, next []byte) (bool, error)

	// ListPlanRevisions returns a plan's revisions, newest first.
	ListPlanRevisions(ctx context.Context, planID string) ([]PlanRevision, error)
	GetPlanRevision(ctx context.Context, planID string, revision int64) (PlanRevision, error)

	ListTenantTemplates(ctx context.Context) ([]TenantTemplate, error)
	GetTenantTemplate(ctx context.Context, id string) (TenantTemplate, error)
	PutTenantTemplate(ctx context.Context, t TenantTemplate) error
	DeleteTenantTemplate(ctx context.Context, id string) error
	ListRollouts(ctx context.Context) ([]Rollout, error)
	GetRollout(ctx context.Context, feature string) (Rollout, error)
	PutRollout(ctx context.Context, r Rollout) error
	DeleteRollout(ctx context.Context, feature string) error

	// InTx runs fn in a transaction. If fn returns an error nothing is
	// committed.
	InTx(ctx context.Context, fn func(tx Tx) error) error

	GetTenant(ctx context.Context, id string) (sdk.Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (sdk.Tenant, error)
	ListTenants(ctx context.Context, q ListTenantsQuery) ([]sdk.Tenant, error)

	GetPlan(ctx context.Context, id string) (sdk.Plan, error)
	ListPlans(ctx context.Context) ([]sdk.Plan, error)

	GetMember(ctx context.Context, tenantID, memberID string) (sdk.Member, error)
	ListMembers(ctx context.Context, tenantID string) ([]sdk.Member, error)

	// ListUsage returns matching counters ordered by metric, newest period
	// first.
	ListUsage(ctx context.Context, q UsageQuery) ([]Usage, error)
	// EndedUsage returns up to limit unclosed counters whose period ended
	// at or before now.
	EndedUsage(ctx context.Context, now time.Time, limit int) ([]Usage, error)
	// IncrementUsage atomically adds delta to the counter. If limit is
	// non-nil and the result would exceed it, nothing changes and
	// ErrQuotaExceeded is returned along with the current value.
	IncrementUsage(ctx context.Context, key UsageKey, delta int64, limit *int64) (int64, error)

	// ReadEvents returns up to limit events with Seq > after, in Seq order.
	ReadEvents(ctx context.Context, after int64, limit int) ([]sdk.Event, error)
	// LastEventSeq returns the highest committed Seq, or 0.
	LastEventSeq(ctx context.Context) (int64, error)
	// QueryEvents returns events matching q, newest first.
	QueryEvents(ctx context.Context, q EventQuery) ([]sdk.Event, error)
	// PruneEvents deletes events older than before with Seq <= maxSeq and
	// returns how many were deleted. Seq numbering is unaffected.
	PruneEvents(ctx context.Context, before time.Time, maxSeq int64) (int64, error)
	// RedactEvents replaces needle in the data of every event (erasure of
	// personal data from the audit trail) and returns how many changed.
	RedactEvents(ctx context.Context, needle, replacement string) (int64, error)

	// GetCursor returns the last Seq processed by a subscription.
	GetCursor(ctx context.Context, subscription string) (seq int64, found bool, err error)
	// SetCursor advances a subscription's cursor; it never moves it backwards,
	// so a stale writer (e.g. a replica that just lost its lease) cannot undo
	// progress made by another.
	SetCursor(ctx context.Context, subscription string, seq int64) error

	// AcquireLease grants owner exclusive use of name for ttl, or renews it
	// if owner already holds it. It returns false if someone else holds an
	// unexpired lease. Leases let several Tenarium instances share the
	// event log while each subscription is processed by exactly one.
	// A preferred owner (one in the subscription's region) also takes over
	// a lease held by a non-preferred one.
	AcquireLease(ctx context.Context, name, owner string, ttl time.Duration, preferred bool) (bool, error)
	ReleaseLease(ctx context.Context, name, owner string) error

	// IncrementRateCounter adds one to the counter of key in the fixed window
	// starting at window and returns the new count. Counters of windows
	// that ended before expireBefore may be deleted.
	IncrementRateCounter(ctx context.Context, key string, window, expireBefore time.Time) (int, error)

	AddDeadLetter(ctx context.Context, dl DeadLetter) error
	GetDeadLetter(ctx context.Context, id string) (DeadLetter, error)
	ListDeadLetters(ctx context.Context, subscription string, limit int) ([]DeadLetter, error)
	DeleteDeadLetter(ctx context.Context, id string) error

	GetIdempotency(ctx context.Context, key string) (IdempotencyRecord, error)
	// PutIdempotency fails with ErrAlreadyExists if key is taken.
	PutIdempotency(ctx context.Context, rec IdempotencyRecord) error

	Close() error
}

// Tx is the write side, only usable inside Store.InTx.
type Tx interface {
	// GetTenant reads a tenant, locking it for the rest of the transaction
	// where the backend supports it.
	GetTenant(ctx context.Context, id string) (sdk.Tenant, error)
	// CreateTenant fails with ErrAlreadyExists if the ID or slug is taken
	// by a tenant that is not deleted.
	CreateTenant(ctx context.Context, t sdk.Tenant) error
	// UpdateTenant writes t if the stored version equals expectedVersion,
	// otherwise it returns ErrConflict.
	UpdateTenant(ctx context.Context, t sdk.Tenant, expectedVersion int64) error
	// CountLiveChildren counts non-deleted tenants whose parent is id.
	CountLiveChildren(ctx context.Context, id string) (int, error)

	CreatePlan(ctx context.Context, p sdk.Plan) error
	UpdatePlan(ctx context.Context, p sdk.Plan, expectedVersion int64) error
	DeletePlan(ctx context.Context, id string) error
	// CountTenantsOnPlan counts live tenants using the plan.
	CountTenantsOnPlan(ctx context.Context, planID string) (int, error)

	// CreateMember fails with ErrAlreadyExists if the email is already a
	// member of the tenant.
	CreateMember(ctx context.Context, m sdk.Member) error
	UpdateMember(ctx context.Context, m sdk.Member, expectedVersion int64) error
	DeleteMember(ctx context.Context, tenantID, memberID string) error
	CountMembers(ctx context.Context, tenantID string) (int, error)
	// ListMembersOfUser returns all memberships of a user, for update.
	ListMembersOfUser(ctx context.Context, userID string) ([]sdk.Member, error)

	GetUser(ctx context.Context, id string) (sdk.User, error)
	// CreateUser fails with ErrAlreadyExists if the email is taken
	// (case-insensitively).
	CreateUser(ctx context.Context, u sdk.User) error
	UpdateUser(ctx context.Context, u sdk.User, expectedVersion int64) error
	// DeleteUser removes the user, its credentials and its tokens.
	DeleteUser(ctx context.Context, id string) error
	// SetPasswordHash replaces the password hash and clears lockout state.
	SetPasswordHash(ctx context.Context, userID, hash string) error

	// CreateDomain fails with ErrAlreadyExists if the hostname is taken.
	CreateDomain(ctx context.Context, d Domain) error
	MarkDomainVerified(ctx context.Context, hostname string, at time.Time) error
	DeleteDomain(ctx context.Context, hostname string) error

	CreateScheduledAction(ctx context.Context, a ScheduledAction) error
	// ClaimScheduledAction marks a due action running; ErrConflict if it is
	// no longer pending (or stale-running), so only one runner executes it.
	ClaimScheduledAction(ctx context.Context, id string, at, staleBefore time.Time) error
	// FinishScheduledAction moves a pending or running action to a final
	// state; ErrConflict if it already is final.
	FinishScheduledAction(ctx context.Context, id, status, errMsg string, at time.Time) error

	// CreateWebhook fails with ErrAlreadyExists on a duplicate ID.
	CreateWebhook(ctx context.Context, w Webhook) error
	// UpdateWebhook replaces a webhook; ErrNotFound if missing.
	UpdateWebhook(ctx context.Context, w Webhook) error
	// DeleteWebhook removes a webhook and its deliveries.
	DeleteWebhook(ctx context.Context, id string) error

	// CloseUsage marks an ended period reported; ErrConflict if it already
	// was, ErrNotFound if there is no such counter.
	CloseUsage(ctx context.Context, tenantID, metric, period string, at time.Time) error

	// PutTenantRole creates or replaces a custom role.
	PutTenantRole(ctx context.Context, r TenantRole) error
	DeleteTenantRole(ctx context.Context, tenantID, name string) error
	// CreateGroup fails with ErrAlreadyExists if the name is taken in the
	// tenant.
	CreateGroup(ctx context.Context, g Group) error
	UpdateGroup(ctx context.Context, g Group) error
	DeleteGroup(ctx context.Context, tenantID, id string) error

	// PurgeTenantData deletes everything a tenant owns except the tenant
	// record and its events: members, usage, API keys, domains, webhooks,
	// SSO, roles, groups and scheduled actions.
	PurgeTenantData(ctx context.Context, tenantID string) error

	// PutPlanRevision records a plan snapshot (idempotent per revision).
	PutPlanRevision(ctx context.Context, r PlanRevision) error

	CreateAPIKey(ctx context.Context, k APIKey) error
	// RevokeAPIKey revokes a key of the given tenant ("" for platform keys)
	// and returns it; ErrNotFound if there is no such unrevoked key.
	RevokeAPIKey(ctx context.Context, tenantID, id string, at time.Time) (APIKey, error)

	// AppendEvents adds events to the log and returns them with Seq set.
	AppendEvents(ctx context.Context, events ...sdk.Event) ([]sdk.Event, error)
}

// Notifier is optionally implemented by stores that can signal new events
// committed by any instance (e.g. Postgres LISTEN/NOTIFY).
type Notifier interface {
	// Listen calls fn whenever new events may be available, until ctx ends.
	Listen(ctx context.Context, fn func()) error
}

// TenantTemplate presets new tenants: its values are defaults that the
// create request can override, and its roles are created with the tenant.
type TenantTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Plan        string            `json:"plan,omitempty"`
	AddOns      []string          `json:"add_ons,omitempty"`
	Region      string            `json:"region,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Settings    map[string]any    `json:"settings,omitempty"`
	Features    map[string]bool   `json:"features,omitempty"`
	Limits      map[string]int64  `json:"limits,omitempty"`
	Branding    *sdk.Branding     `json:"branding,omitempty"`
	Roles       []TemplateRole    `json:"roles,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// TemplateRole is a custom role a template creates.
type TemplateRole struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Actions     []string `json:"actions"`
}
