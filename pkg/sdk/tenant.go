package sdk

import (
	"maps"
	"slices"
	"time"
)

// TenantStatus is the lifecycle state of a tenant.
//
//	create ─▶ provisioning ─fail─▶ failed
//	              │    ▲              │
//	              │    └────retry─────┘
//	              ▼ ok
//	           active ◀─resume── suspended
//	              │ └──suspend──────▲
//	              ▼ delete (from any live status)
//	          deleting ─▶ deleted
//
// Without provisioners, create goes straight to active and delete straight
// to deleted.
type TenantStatus string

const (
	StatusProvisioning TenantStatus = "provisioning"
	StatusActive       TenantStatus = "active"
	StatusSuspended    TenantStatus = "suspended"
	StatusFailed       TenantStatus = "failed"
	StatusDeleting     TenantStatus = "deleting"
	StatusDeleted      TenantStatus = "deleted"
)

// Tenant is the canonical tenant representation shared with plugins.
type Tenant struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
	// ParentID makes tenants hierarchical (e.g. organization → workspace).
	// It is set at creation and cannot change.
	ParentID string       `json:"parent_id,omitempty"`
	Status   TenantStatus `json:"status"`
	// StatusReason explains the current status (e.g. why provisioning failed
	// or why the tenant was suspended).
	StatusReason string `json:"status_reason,omitempty"`
	Plan         string `json:"plan,omitempty"`
	// PlanRevision pins the tenant to a past revision of its plan
	// (grandfathering); 0 follows the plan's current definition.
	PlanRevision int64 `json:"plan_revision,omitempty"`
	// AddOns are add-on plans whose features and limits are added to the
	// plan's.
	AddOns []string `json:"add_ons,omitempty"`
	// Region places the tenant (data residency); set at creation.
	Region string `json:"region,omitempty"`
	// BillingAnchor starts the tenant's monthly billing cycles (usage
	// period "cycle"); nil means its creation time.
	BillingAnchor *time.Time        `json:"billing_anchor,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	Settings      map[string]any    `json:"settings,omitempty"`
	// Features and Limits override the plan's values for this tenant.
	Features map[string]bool  `json:"features,omitempty"`
	Limits   map[string]int64 `json:"limits,omitempty"`
	// Branding customises sign-in pages and emails for the tenant.
	Branding *Branding `json:"branding,omitempty"`
	// Maintenance, while active, makes the tenant read-only for its own
	// users (platform callers can still change it), e.g. during a
	// migration between regions or cells.
	Maintenance *Maintenance `json:"maintenance,omitempty"`
	// Version is incremented on every write and used for optimistic locking.
	Version   int64      `json:"version"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// Clone returns a deep copy of t.
func (t Tenant) Clone() Tenant {
	c := t
	c.Labels = maps.Clone(t.Labels)
	c.Settings = DeepCopyMap(t.Settings)
	c.Features = maps.Clone(t.Features)
	c.Limits = maps.Clone(t.Limits)
	c.AddOns = slices.Clone(t.AddOns)
	if t.DeletedAt != nil {
		d := *t.DeletedAt
		c.DeletedAt = &d
	}
	if t.BillingAnchor != nil {
		a := *t.BillingAnchor
		c.BillingAnchor = &a
	}
	if t.Branding != nil {
		b := *t.Branding
		c.Branding = &b
	}
	if t.Maintenance != nil {
		m := *t.Maintenance
		if m.Until != nil {
			u := *m.Until
			m.Until = &u
		}
		c.Maintenance = &m
	}
	return c
}

// IsLive reports whether the tenant is not being or has not been deleted.
func (t Tenant) IsLive() bool {
	return t.Status != StatusDeleting && t.Status != StatusDeleted
}

// DeepCopyMap copies JSON-like data (maps, slices, scalars) recursively.
func DeepCopyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return DeepCopyMap(x)
	case []any:
		s := make([]any, len(x))
		for i, e := range x {
			s[i] = deepCopyValue(e)
		}
		return s
	default:
		return v
	}
}

// TenantEventData is the payload of every tenant.* event.
type TenantEventData struct {
	Tenant   Tenant  `json:"tenant"`
	Previous *Tenant `json:"previous,omitempty"`
}

// Plan bundles features and limits that tenants subscribe to.
type Plan struct {
	// ID is a short, stable identifier such as "free" or "enterprise".
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Features    map[string]bool  `json:"features,omitempty"`
	Limits      map[string]int64 `json:"limits,omitempty"`
	Version     int64            `json:"version"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

func (p Plan) Clone() Plan {
	c := p
	c.Features = maps.Clone(p.Features)
	c.Limits = maps.Clone(p.Limits)
	return c
}

// PlanEventData is the payload of plan.* events.
type PlanEventData struct {
	Plan     Plan  `json:"plan"`
	Previous *Plan `json:"previous,omitempty"`
}

// Entitlements are a tenant's effective features and limits: the plan's
// values, plus add-ons and feature rollouts, with the tenant's overrides
// applied.
type Entitlements struct {
	TenantID string `json:"tenant_id"`
	Plan     string `json:"plan,omitempty"`
	// PlanRevision is set when the tenant is pinned to an older plan
	// revision.
	PlanRevision int64            `json:"plan_revision,omitempty"`
	AddOns       []string         `json:"add_ons,omitempty"`
	Features     map[string]bool  `json:"features"`
	Limits       map[string]int64 `json:"limits"`
}

// HasFeature reports whether feature is enabled.
func (e Entitlements) HasFeature(feature string) bool { return e.Features[feature] }

// Limit returns the limit for metric and whether one is set. Absent limits
// mean unlimited.
func (e Entitlements) Limit(metric string) (int64, bool) {
	v, ok := e.Limits[metric]
	return v, ok
}

// ComputeEntitlements merges plan values with tenant overrides. p may be nil.
func ComputeEntitlements(t Tenant, p *Plan) Entitlements {
	e := Entitlements{TenantID: t.ID, Plan: t.Plan, Features: map[string]bool{}, Limits: map[string]int64{}}
	if p != nil {
		maps.Copy(e.Features, p.Features)
		maps.Copy(e.Limits, p.Limits)
	}
	maps.Copy(e.Features, t.Features)
	maps.Copy(e.Limits, t.Limits)
	return e
}

// MemberStatus is the state of a tenant membership.
type MemberStatus string

const (
	MemberInvited MemberStatus = "invited"
	MemberActive  MemberStatus = "active"
	// MemberSuspended members keep their role but cannot sign in to the
	// tenant (e.g. deactivated by the customer's identity provider via SCIM).
	MemberSuspended MemberStatus = "suspended"
)

// Member links a user identity to a tenant with a role.
type Member struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	// UserID is the subject in the identity provider; empty while invited.
	UserID    string       `json:"user_id,omitempty"`
	Email     string       `json:"email"`
	Role      string       `json:"role"`
	Status    MemberStatus `json:"status"`
	InvitedBy string       `json:"invited_by,omitempty"`
	Version   int64        `json:"version"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// MemberEventData is the payload of tenant.member_* events.
type MemberEventData struct {
	Member   Member  `json:"member"`
	Previous *Member `json:"previous,omitempty"`
}

// UsageEventData is the payload of tenant.quota_exceeded events.
type UsageEventData struct {
	TenantID  string `json:"tenant_id"`
	Metric    string `json:"metric"`
	Current   int64  `json:"current"`
	Requested int64  `json:"requested"`
	Limit     int64  `json:"limit"`
}

// UsagePeriodData is the payload of tenant.usage_threshold_reached and
// tenant.usage_period_closed.
type UsagePeriodData struct {
	TenantID string `json:"tenant_id"`
	Metric   string `json:"metric"`
	// Period is "" for counters that never reset, else e.g. "2026-10".
	Period    string     `json:"period,omitempty"`
	PeriodEnd *time.Time `json:"period_end,omitempty"`
	Value     int64      `json:"value"`
	Limit     *int64     `json:"limit,omitempty"`
	// Percent is the threshold crossed (threshold events only).
	Percent int `json:"percent,omitempty"`
}

// Branding is a tenant's look on sign-in pages and in emails.
type Branding struct {
	DisplayName  string `json:"display_name,omitempty"`
	LogoURL      string `json:"logo_url,omitempty"`
	IconURL      string `json:"icon_url,omitempty"`
	PrimaryColor string `json:"primary_color,omitempty"`
	AccentColor  string `json:"accent_color,omitempty"`
	SupportEmail string `json:"support_email,omitempty"`
	SupportURL   string `json:"support_url,omitempty"`
}

// Maintenance describes a maintenance window of a tenant.
type Maintenance struct {
	Message   string     `json:"message,omitempty"`
	StartedAt time.Time  `json:"started_at"`
	Until     *time.Time `json:"until,omitempty"`
	// MoveTo is set for windows opened by a region move with reprovisioning;
	// the window ends when provisioning in that region succeeds.
	MoveTo string `json:"move_to,omitempty"`
}

// MaintenanceActive reports whether t is in an active maintenance window.
func (t Tenant) MaintenanceActive(now time.Time) bool {
	return t.Maintenance != nil && (t.Maintenance.Until == nil || now.Before(*t.Maintenance.Until))
}
