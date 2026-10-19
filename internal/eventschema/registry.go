package eventschema

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/internal/identity"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// Entry is the published schema of one version of one event type's data.
type Entry struct {
	// Type is the CloudEvents type, e.g. "tenant.created".
	Type string `json:"type"`
	// Version is a positive decimal integer ("1", "2", ...).
	Version     string `json:"version"`
	Description string `json:"description"`
	// Schema is a JSON Schema (draft 2020-12) of the CloudEvent's "data".
	Schema json.RawMessage `json:"schema"`
}

// Version1 is the version of every event type's first schema.
const Version1 = "1"

// def is one row of the registry table: an event type, the Go type its
// data is encoded from and a one-line description.
type def struct {
	typ, version, desc string
	payload            reflect.Type
}

func d[T any](typ, desc string) def {
	return def{typ: typ, version: Version1, desc: desc, payload: reflect.TypeFor[T]()}
}

// Payloads the code builds as anonymous maps are described by these
// structs, which mirror the maps' keys.
type (
	userErasedData struct {
		UserID         string `json:"user_id"`
		RedactedEvents int    `json:"redacted_events"`
	}
	tenantPurgedData struct {
		TenantID string `json:"tenant_id"`
	}
	signingKeyRetiredData struct {
		KID string `json:"kid"`
	}
	passkeyData struct {
		UserID    string `json:"user_id"`
		Email     string `json:"email"`
		PasskeyID string `json:"passkey_id"`
		Name      string `json:"name"`
	}
	webhookTestData struct {
		Message string `json:"message"`
	}
	impersonationConsentData struct {
		UserID    string    `json:"user_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	sessionRevokedData struct {
		UserID    string `json:"user_id"`
		SessionID string `json:"session_id"`
	}
	impersonatedData struct {
		UserID       string    `json:"user_id"`
		Impersonator string    `json:"impersonator"`
		Reason       string    `json:"reason"`
		TenantID     string    `json:"tenant_id"`
		ExpiresAt    time.Time `json:"expires_at"`
		Consent      bool      `json:"consent"`
	}
)

// table lists every event type the core emits. A test fails when the code
// emits a type missing here. To publish a breaking change of a type, keep
// its existing row and add one with the next version (see doc.go).
var table = []def{
	// Tenant lifecycle (pkg/sdk).
	d[sdk.TenantEventData](sdk.EventTenantCreated, "A tenant was created."),
	d[sdk.TenantEventData](sdk.EventTenantUpdated, "A tenant's name, plan, labels, settings, features or limits changed."),
	d[sdk.TenantEventData](sdk.EventTenantProvisioning, "Provisioning of a tenant's resources started (or was retried)."),
	d[sdk.TenantEventData](sdk.EventTenantProvisioned, "A tenant's resources were provisioned; the tenant is active."),
	d[sdk.TenantEventData](sdk.EventTenantProvisioningFailed, "Provisioning failed; the tenant is failed and can be retried."),
	d[sdk.TenantEventData](sdk.EventTenantSuspended, "A tenant was suspended."),
	d[sdk.TenantEventData](sdk.EventTenantResumed, "A suspended tenant was resumed."),
	d[sdk.TenantEventData](sdk.EventTenantDeleting, "Deletion of a tenant started; its resources are being removed."),
	d[sdk.TenantEventData](sdk.EventTenantDeleted, "A tenant was deleted."),
	d[sdk.TenantEventData](sdk.EventTenantDeprovisioningFailed, "A tenant's resources could not be removed; deleting it again retries."),
	d[sdk.TenantEventData](sdk.EventTenantPlanChanged, "A tenant's plan changed (emitted in addition to tenant.updated)."),
	d[sdk.TenantEventData](sdk.EventTenantRegionChanged, "A tenant was moved to another region (data residency); previous.region is the old one."),
	d[sdk.TenantEventData]("tenant.maintenance_started", "A maintenance window started; the tenant is read-only for its own users until it ends (tenant.maintenance.until, if set)."),
	d[sdk.TenantEventData]("tenant.maintenance_ended", "A maintenance window was ended."),
	d[store.Rollout]("rollout.updated", "A feature rollout was created or changed; entitlements of the tenants it covers may have changed."),
	d[store.Rollout]("rollout.deleted", "A feature rollout was deleted."),
	d[tenantPurgedData]("tenant.purged", "The data of a tenant deleted long enough ago was purged; a tombstone remains."),

	// Usage and quotas.
	d[sdk.UsageEventData](sdk.EventTenantQuotaExceeded, "A usage increment was refused because it would exceed the limit."),
	d[sdk.UsagePeriodData](sdk.EventTenantUsageThreshold, "A usage counter crossed a configured percentage of its limit."),
	d[sdk.UsagePeriodData](sdk.EventTenantUsagePeriodClosed, "A usage period ended; carries the counter's final value (emitted once)."),

	// Scheduled tenant actions.
	d[store.ScheduledAction]("tenant.action_scheduled", "A tenant lifecycle action was scheduled to run later."),
	d[store.ScheduledAction]("tenant.action_canceled", "A scheduled tenant action was canceled."),
	d[store.ScheduledAction]("tenant.action_failed", "A scheduled tenant action ran and failed."),

	// Memberships.
	d[sdk.MemberEventData](sdk.EventMemberAdded, "A user was added or invited to a tenant."),
	d[sdk.MemberEventData](sdk.EventMemberUpdated, "A membership's role or status changed."),
	d[sdk.MemberEventData](sdk.EventMemberRemoved, "A user was removed from a tenant."),

	// Plans.
	d[sdk.PlanEventData](sdk.EventPlanCreated, "A plan was created."),
	d[sdk.PlanEventData](sdk.EventPlanUpdated, "A plan's features or limits changed."),
	d[sdk.PlanEventData](sdk.EventPlanDeleted, "A plan was deleted."),

	// Users.
	d[sdk.UserEventData](sdk.EventUserCreated, "A user was created."),
	d[sdk.UserEventData](sdk.EventUserUpdated, "A user's profile, roles or attributes changed."),
	d[sdk.UserEventData](sdk.EventUserActivated, "An invited user set up their credentials and became active."),
	d[sdk.UserEventData](sdk.EventUserDisabled, "A user was disabled and can no longer sign in."),
	d[sdk.UserEventData](sdk.EventUserEnabled, "A disabled user was enabled again."),
	d[sdk.UserEventData](sdk.EventUserDeleted, "A user was deleted, together with their memberships."),
	d[sdk.UserEventData](sdk.EventUserPasswordChanged, "A user's password was set or changed."),
	d[sdk.UserEventData](sdk.EventUserLocked, "A user was locked out after too many failed sign-ins."),
	d[sdk.UserEventData]("user.mfa_enabled", "A user enrolled a TOTP second factor."),
	d[sdk.UserEventData]("user.mfa_disabled", "A user's TOTP second factor was removed."),
	d[passkeyData]("user.passkey_added", "A user registered a passkey or security key."),
	d[passkeyData]("user.passkey_removed", "A user's passkey or security key was removed."),
	d[userErasedData]("user.erased", "A user's personal data was erased from the event log (GDPR)."),
	d[impersonationConsentData]("user.impersonation_consented", "A user granted support a single-use code to impersonate them until expires_at."),
	d[impersonatedData]("user.impersonated", "Support started a short-lived, tenant-scoped session as a user."),
	d[sessionRevokedData]("user.session_revoked", "One of a user's sessions (signed-in clients) was revoked."),

	// Custom domains.
	d[store.Domain]("domain.added", "A custom hostname was added to a tenant and awaits verification."),
	d[store.Domain]("domain.verified", "A custom hostname's DNS ownership was verified."),
	d[store.Domain]("domain.removed", "A custom hostname was removed from a tenant."),

	// API keys (the secret and its hash are never included).
	d[store.APIKey]("apikey.created", "An API key was created."),
	d[store.APIKey]("apikey.revoked", "An API key was revoked."),

	// Single sign-on (client secret and SAML metadata are never included).
	d[store.SSOConnection]("sso.updated", "A tenant's SSO connection was created or changed."),
	d[store.SSOConnection]("sso.deleted", "A tenant's SSO connection was deleted."),

	// Tenant roles and groups.
	d[store.TenantRole]("role.updated", "A tenant-defined role was created or changed."),
	d[store.TenantRole]("role.deleted", "A tenant-defined role was deleted."),
	d[store.Group]("group.created", "A group was created in a tenant."),
	d[store.Group]("group.updated", "A group's name, roles or members changed."),
	d[store.Group]("group.deleted", "A group was deleted."),

	// Webhooks (the signing secret is never included).
	d[store.Webhook]("webhook.created", "A webhook was registered."),
	d[store.Webhook]("webhook.updated", "A webhook was changed or its secret rotated."),
	d[store.Webhook]("webhook.deleted", "A webhook was deleted."),
	d[store.Webhook]("webhook.disabled", "A webhook was disabled after too many consecutive delivery failures."),
	d[webhookTestData]("webhook.test", "A test delivery sent on request to one webhook; never stored in the event log."),

	// OAuth/OIDC clients (the secret hash is never included).
	d[store.OAuthClient]("oauth_client.updated", "An OAuth client was created or changed, or its secret rotated."),
	d[store.OAuthClient]("oauth_client.deleted", "An OAuth client was deleted."),

	// Token signing keys.
	d[identity.KeyInfo]("signing_key.rotated", "A new token signing key was created and made active."),
	d[signingKeyRetiredData]("signing_key.retired", "A token signing key was retired; tokens it signed no longer verify."),
}

var registry = sync.OnceValue(func() []Entry {
	out := make([]Entry, 0, len(table))
	seen := map[[2]string]bool{}
	for _, row := range table {
		k := [2]string{row.typ, row.version}
		if seen[k] {
			panic("eventschema: duplicate entry " + row.typ + " v" + row.version)
		}
		seen[k] = true
		s := Generate(row.payload)
		s["title"] = row.typ + " v" + row.version
		s["description"] = row.desc
		raw, err := json.Marshal(s)
		if err != nil {
			panic(fmt.Sprintf("eventschema: %s: %v", row.typ, err))
		}
		out = append(out, Entry{Type: row.typ, Version: row.version, Description: row.desc, Schema: raw})
	}
	slices.SortFunc(out, func(a, b Entry) int {
		return cmp.Or(strings.Compare(a.Type, b.Type), cmp.Compare(versionNum(a.Version), versionNum(b.Version)))
	})
	return out
})

func versionNum(v string) int {
	n, _ := strconv.Atoi(v)
	return n
}

func clone(e Entry) Entry {
	e.Schema = slices.Clone(e.Schema)
	return e
}

// All returns every published schema, sorted by type and then version.
func All() []Entry {
	all := registry()
	out := make([]Entry, len(all))
	for i, e := range all {
		out[i] = clone(e)
	}
	return out
}

// Types returns the distinct event types, sorted.
func Types() []string {
	var out []string
	for _, e := range registry() {
		if len(out) == 0 || out[len(out)-1] != e.Type {
			out = append(out, e.Type)
		}
	}
	return out
}

// Get returns the latest version of an event type's schema.
func Get(typ string) (Entry, bool) {
	var found *Entry
	for i, e := range registry() {
		if e.Type == typ {
			found = &registry()[i]
		}
	}
	if found == nil {
		return Entry{}, false
	}
	return clone(*found), true
}

// GetVersion returns one version of an event type's schema.
func GetVersion(typ, version string) (Entry, bool) {
	for _, e := range registry() {
		if e.Type == typ && e.Version == version {
			return clone(e), true
		}
	}
	return Entry{}, false
}

// Versions returns the published versions of an event type, oldest first.
func Versions(typ string) []string {
	var out []string
	for _, e := range registry() {
		if e.Type == typ {
			out = append(out, e.Version)
		}
	}
	return out
}

// DataSchemaURI returns where the schema of a type's version is published,
// for the CloudEvents "dataschema" attribute:
//
//	DataSchemaURI("https://tenarium.example.com", "tenant.created", "1")
//	  == "https://tenarium.example.com/v1/event-schemas/tenant.created/1"
//
// The "/v1/" segment is the API version, not the schema version.
func DataSchemaURI(base, typ, version string) string {
	return strings.TrimRight(base, "/") + "/v1/event-schemas/" + url.PathEscape(typ) + "/" + url.PathEscape(version)
}
