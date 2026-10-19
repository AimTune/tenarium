// Package extplugin defines the out-of-process plugin protocol and lets any
// sdk.Plugin run as a separate process.
//
// # Protocol (version 1)
//
// An external plugin is an HTTP server. Tenarium calls it; every request
// carries "Authorization: Bearer <secret>". Bodies are JSON.
//
//	POST /init                          InitRequest  → InitResponse
//	POST /events/{subscription}         CloudEvent   → 2xx (non-2xx = retry)
//	POST /hooks/{point}                 HookRequest  → HookResponse
//	POST /provisioners/{name}/provision   Tenant     → 2xx
//	POST /provisioners/{name}/deprovision Tenant     → 2xx
//	POST /authorize/{name}              AuthorizeRequest    → AuthorizeResponse
//	POST /authenticate/{name}           AuthenticateRequest → AuthenticateResponse
//	POST /directory/create_user         DirectoryRequest → CreateUserResponse
//	POST /directory/update_user         DirectoryRequest → 2xx
//	POST /directory/delete_user         DirectoryRequest → 2xx
//	POST /directory/set_password        DirectoryRequest → 2xx
//	POST /directory/verify_password     DirectoryRequest → 2xx (if declared)
//	POST /directory/send_invitation     DirectoryRequest → 2xx (if declared)
//	POST /mailer/send                   sdk.Message      → 2xx
//	GET  /health                        → 2xx when healthy
//	ANY  /routes/...                    plugin HTTP routes, proxied from
//	                                    /v1/plugins/{instance}/... with the
//	                                    caller in X-Tenarium-Principal
//
// Errors are reported with a non-2xx status and an ErrorResponse body. Its
// optional code maps the error back to an sdk sentinel on the host (see
// ErrorCode and ErrorForCode); the status alone is never interpreted.
//
// In managed mode Tenarium starts the plugin process itself and passes
// TENARIUM_PLUGIN_ADDR (host:port to listen on) and TENARIUM_PLUGIN_SECRET in
// the environment; the plugin must start serving on that address.
package extplugin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// ProtocolVersion is the version implemented by this package.
const ProtocolVersion = 1

// Environment variables used in managed mode.
const (
	EnvAddr   = "TENARIUM_PLUGIN_ADDR"
	EnvSecret = "TENARIUM_PLUGIN_SECRET" //nolint:gosec // variable name, not a secret
	// EnvAPIURL and EnvAPIKey let a plugin call the Tenarium REST API (used
	// to implement sdk.Host on the plugin side).
	EnvProofKey = "TENARIUM_PLUGIN_PROOF_KEY"
	EnvAPIURL   = "TENARIUM_API_URL"
	EnvAPIKey   = "TENARIUM_API_KEY" //nolint:gosec // variable name, not a secret
)

// PrincipalHeader carries the base64url-encoded JSON principal on proxied
// route requests.
const PrincipalHeader = "X-Tenarium-Principal"

type InitRequest struct {
	Protocol int            `json:"protocol"`
	Instance string         `json:"instance"`
	Config   map[string]any `json:"config"`
	// Nonce is a random challenge; see InitResponse.Proof.
	Nonce string `json:"nonce,omitempty"`
}

type InitResponse struct {
	Protocol int `json:"protocol"`
	// Proof is Proof(TENARIUM_PLUGIN_PROOF_KEY, nonce). In managed mode
	// Tenarium requires it: the proof key is only ever passed to the process
	// it started, never sent over the network, so a process that grabbed the
	// plugin's port cannot impersonate it.
	Proof          string             `json:"proof,omitempty"`
	Manifest       sdk.Manifest       `json:"manifest"`
	Subscriptions  []SubscriptionSpec `json:"subscriptions,omitempty"`
	Hooks          []HookSpec         `json:"hooks,omitempty"`
	Provisioners   []string           `json:"provisioners,omitempty"`
	Routes         []string           `json:"routes,omitempty"`
	Authenticators []string           `json:"authenticators,omitempty"`
	Authorizers    []string           `json:"authorizers,omitempty"`
	// UserDirectory, when set, offers an sdk.UserDirectory served on
	// /directory/{op}.
	UserDirectory *DirectorySpec `json:"user_directory,omitempty"`
	// Mailer, when set, offers an sdk.Mailer served on /mailer/send.
	Mailer *MailerSpec `json:"mailer,omitempty"`
}

// DirectorySpec declares a user directory. Name defaults to the instance
// name. VerifyPassword and SendInvitation declare the optional
// sdk.PasswordVerifier and sdk.InvitationSender capabilities.
type DirectorySpec struct {
	Name           string `json:"name,omitempty"`
	VerifyPassword bool   `json:"verify_password,omitempty"`
	SendInvitation bool   `json:"send_invitation,omitempty"`
}

// MailerSpec declares a mailer. Name defaults to the instance name.
type MailerSpec struct {
	Name string `json:"name,omitempty"`
}

// Directory operations, served on POST /directory/{op}.
const (
	DirCreateUser     = "create_user"
	DirUpdateUser     = "update_user"
	DirDeleteUser     = "delete_user"
	DirSetPassword    = "set_password"
	DirVerifyPassword = "verify_password"
	DirSendInvitation = "send_invitation"
)

// DirectoryRequest is the body of every /directory/{op} call. Password is
// only set for set_password and verify_password.
type DirectoryRequest struct {
	User     sdk.User `json:"user"`
	Password string   `json:"password,omitempty"`
}

// CreateUserResponse answers /directory/create_user with the user's ID in
// the directory. It must not be empty.
type CreateUserResponse struct {
	ExternalID string `json:"external_id"`
}

type SubscriptionSpec struct {
	Name        string   `json:"name"`
	Types       []string `json:"types,omitempty"`
	MaxAttempts int      `json:"max_attempts,omitempty"`
	TimeoutMS   int64    `json:"timeout_ms,omitempty"`
	StartAtEnd  bool     `json:"start_at_end,omitempty"`
}

type HookSpec struct {
	Point    sdk.HookPoint `json:"point"`
	Priority int           `json:"priority,omitempty"`
}

// HookResponse either rejects the operation or returns the (possibly
// modified) tenant and member.
type HookResponse struct {
	Reject string      `json:"reject,omitempty"`
	Tenant *sdk.Tenant `json:"tenant,omitempty"`
	Member *sdk.Member `json:"member,omitempty"`
	User   *sdk.User   `json:"user,omitempty"`
}

type AuthorizeRequest struct {
	Principal sdk.Principal `json:"principal"`
	Action    sdk.Action    `json:"action"`
	Resource  sdk.Resource  `json:"resource"`
}

type AuthorizeResponse struct {
	// Decision is "allow", "deny" or "abstain".
	Decision string `json:"decision"`
}

// AuthenticateRequest describes the incoming API request. Only headers are
// forwarded; bodies are not.
type AuthenticateRequest struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
}

type AuthenticateResponse struct {
	// NoCredentials means the request has no credentials this
	// authenticator understands; the next one is tried.
	NoCredentials bool           `json:"no_credentials,omitempty"`
	Principal     *sdk.Principal `json:"principal,omitempty"`
	Error         string         `json:"error,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
	// Code optionally classifies the error; see the Code* constants.
	Code string `json:"code,omitempty"`
}

// Error codes carried in ErrorResponse.Code.
const (
	CodeNotFound           = "not_found"           // sdk.ErrNotFound
	CodeUnsupported        = "unsupported"         // sdk.ErrUnsupported
	CodeForbidden          = "forbidden"           // sdk.ErrForbidden
	CodeInvalidCredentials = "invalid_credentials" //nolint:gosec // ErrInvalidCredentials; G101: an error code, not a credential
)

// ErrInvalidCredentials is returned by a remote directory's VerifyPassword
// when it rejects the password. Go plugins served with this package report
// it by returning (or wrapping) it from VerifyPassword.
var ErrInvalidCredentials = errors.New("invalid credentials")

var codeErrors = []struct {
	code string
	err  error
}{
	{CodeNotFound, sdk.ErrNotFound},
	{CodeUnsupported, sdk.ErrUnsupported},
	{CodeForbidden, sdk.ErrForbidden},
	{CodeInvalidCredentials, ErrInvalidCredentials},
}

// ErrorCode returns the wire code for err, or "" if it has none.
func ErrorCode(err error) string {
	for _, c := range codeErrors {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return ""
}

// ErrorForCode returns the sentinel error for a wire code, or nil for an
// empty or unknown code.
func ErrorForCode(code string) error {
	for _, c := range codeErrors {
		if c.code == code {
			return c.err
		}
	}
	return nil
}

// ParseDecision converts a wire decision to sdk.Decision.
func ParseDecision(s string) sdk.Decision {
	switch s {
	case "allow":
		return sdk.Allow
	case "deny":
		return sdk.Deny
	default:
		return sdk.Abstain
	}
}

// EventFromCloudEvent converts the wire format back into an sdk.Event.
func EventFromCloudEvent(ce sdk.CloudEvent) sdk.Event {
	seq, _ := strconv.ParseInt(ce.Sequence, 10, 64)
	t, _ := time.Parse(time.RFC3339Nano, ce.Time)
	return sdk.Event{
		Seq: seq, ID: ce.ID, Type: ce.Type, Source: ce.Source, Subject: ce.Subject,
		TenantID: ce.TenantID, Actor: ce.Actor, Time: t, Data: ce.Data,
		TraceParent: ce.TraceParent, TraceState: ce.TraceState, DataSchema: ce.DataSchema,
	}
}

// Proof computes the init proof: hex(HMAC-SHA256(key, nonce)).
func Proof(key, nonce string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// EncodePrincipal encodes p for PrincipalHeader.
func EncodePrincipal(p *sdk.Principal) string {
	b, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodePrincipal decodes a PrincipalHeader value.
func DecodePrincipal(s string) (*sdk.Principal, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var p sdk.Principal
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}
