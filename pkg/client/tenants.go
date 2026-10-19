package client

import (
	"context"
	"iter"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// TenantsService manages tenants (/v1/tenants). Tenant arguments accept an
// ID or a slug.
type TenantsService struct{ c *Client }

// CreateTenantRequest creates a tenant. Plan, Features and Limits require
// the plans:write permission.
type CreateTenantRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	// ParentID (ID or slug) makes the tenant a child, e.g. a workspace of an
	// organization. It cannot change later.
	ParentID string            `json:"parent_id,omitempty"`
	Plan     string            `json:"plan,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Settings map[string]any    `json:"settings,omitempty"`
	Features map[string]bool   `json:"features,omitempty"`
	Limits   map[string]int64  `json:"limits,omitempty"`
	// AddOns are plan IDs stacked on the plan (needs plans:write).
	AddOns []string `json:"add_ons,omitempty"`
	// Region places the tenant (data residency).
	Region   string        `json:"region,omitempty"`
	Branding *sdk.Branding `json:"branding,omitempty"`
	// Template presets the tenant; the request's values win.
	Template string `json:"template,omitempty"`
}

// UpdateTenantRequest is a partial update: nil fields are left unchanged.
type UpdateTenantRequest struct {
	Name *string `json:"name,omitempty"`
	Plan *string `json:"plan,omitempty"`
	// Labels, Features and Limits replace the whole map when non-nil.
	Labels   *map[string]string `json:"labels,omitempty"`
	Features *map[string]bool   `json:"features,omitempty"`
	Limits   *map[string]int64  `json:"limits,omitempty"`
	// AddOns replaces the add-ons; BillingAnchor starts monthly billing
	// cycles (both need plans:write). Branding replaces the branding (an
	// empty value removes it).
	AddOns        *[]string  `json:"add_ons,omitempty"`
	BillingAnchor *time.Time `json:"billing_anchor,omitempty"`
	// ClearBillingAnchor removes the anchor (needs plans:write).
	ClearBillingAnchor bool          `json:"clear_billing_anchor,omitempty"`
	Branding           *sdk.Branding `json:"branding,omitempty"`
	// Settings is an RFC 7386 JSON merge patch (null values delete keys).
	Settings map[string]any `json:"settings,omitempty"`
}

// TenantListOptions filter and paginate tenant lists.
type TenantListOptions struct {
	Status sdk.TenantStatus
	Plan   string
	// ParentID (ID or slug) lists the parent's direct children.
	ParentID string
	// Labels match tenants carrying all of these labels.
	Labels         map[string]string
	IncludeDeleted bool
	After          string
	Limit          int
}

func (o TenantListOptions) query() url.Values {
	q := url.Values{}
	setStr(q, "status", string(o.Status))
	setStr(q, "plan", o.Plan)
	setStr(q, "parent_id", o.ParentID)
	setStr(q, "after", o.After)
	setLimit(q, o.Limit)
	if o.IncludeDeleted {
		q.Set("include_deleted", "true")
	}
	keys := make([]string, 0, len(o.Labels))
	for k := range o.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		q.Add("label", k+"="+o.Labels[k])
	}
	return q
}

// Create creates a tenant. With retries enabled it carries an automatic
// Idempotency-Key unless WithIdempotencyKey sets one.
func (s *TenantsService) Create(ctx context.Context, req CreateTenantRequest, opts ...CallOption) (sdk.Tenant, error) {
	var t sdk.Tenant
	err := s.c.do(ctx, http.MethodPost, "/v1/tenants", nil, req, &t, append([]CallOption{autoIdempotency()}, opts...)...)
	return t, err
}

// Get returns a tenant by ID or slug.
func (s *TenantsService) Get(ctx context.Context, id string, opts ...CallOption) (sdk.Tenant, error) {
	return s.tenant(ctx, http.MethodGet, id, "", nil, opts)
}

// List returns one page of tenants.
func (s *TenantsService) List(ctx context.Context, o TenantListOptions, opts ...CallOption) (Page[sdk.Tenant], error) {
	var p Page[sdk.Tenant]
	err := s.c.do(ctx, http.MethodGet, "/v1/tenants", o.query(), nil, &p, opts...)
	return p, err
}

// All iterates over every tenant matching o, fetching pages lazily.
func (s *TenantsService) All(ctx context.Context, o TenantListOptions, opts ...CallOption) iter.Seq2[sdk.Tenant, error] {
	return paginate(ctx, o.After, func(ctx context.Context, after string) (Page[sdk.Tenant], error) {
		o.After = after
		return s.List(ctx, o, opts...)
	})
}

// Update applies a partial update. Pass IfMatch(t.Version) for optimistic
// locking; the returned tenant carries the new Version.
func (s *TenantsService) Update(ctx context.Context, id string, req UpdateTenantRequest, opts ...CallOption) (sdk.Tenant, error) {
	return s.tenant(ctx, http.MethodPatch, id, "", req, opts)
}

// Delete starts deleting a tenant and returns it (status deleting or deleted).
func (s *TenantsService) Delete(ctx context.Context, id string, opts ...CallOption) (sdk.Tenant, error) {
	return s.tenant(ctx, http.MethodDelete, id, "", nil, opts)
}

// Suspend suspends an active tenant; reason is optional.
func (s *TenantsService) Suspend(ctx context.Context, id, reason string, opts ...CallOption) (sdk.Tenant, error) {
	body := struct {
		Reason string `json:"reason,omitempty"`
	}{reason}
	return s.tenant(ctx, http.MethodPost, id, "/suspend", body, opts)
}

// Resume reactivates a suspended tenant.
func (s *TenantsService) Resume(ctx context.Context, id string, opts ...CallOption) (sdk.Tenant, error) {
	return s.tenant(ctx, http.MethodPost, id, "/resume", nil, opts)
}

// RetryProvisioning re-runs provisioning for a failed tenant.
func (s *TenantsService) RetryProvisioning(ctx context.Context, id string, opts ...CallOption) (sdk.Tenant, error) {
	return s.tenant(ctx, http.MethodPost, id, "/retry-provisioning", nil, opts)
}

// Children returns one page of a tenant's direct children.
func (s *TenantsService) Children(ctx context.Context, id string, o ListOptions, opts ...CallOption) (Page[sdk.Tenant], error) {
	var p Page[sdk.Tenant]
	if err := checkIDs(id); err != nil {
		return p, err
	}
	q := url.Values{}
	setStr(q, "after", o.After)
	setLimit(q, o.Limit)
	err := s.c.do(ctx, http.MethodGet, "/v1/tenants/"+esc(id)+"/children", q, nil, &p, opts...)
	return p, err
}

// AllChildren iterates over all direct children of a tenant.
func (s *TenantsService) AllChildren(ctx context.Context, id string, o ListOptions, opts ...CallOption) iter.Seq2[sdk.Tenant, error] {
	return paginate(ctx, o.After, func(ctx context.Context, after string) (Page[sdk.Tenant], error) {
		o.After = after
		return s.Children(ctx, id, o, opts...)
	})
}

// Entitlements returns the tenant's effective features and limits.
func (s *TenantsService) Entitlements(ctx context.Context, id string, opts ...CallOption) (sdk.Entitlements, error) {
	var e sdk.Entitlements
	if err := checkIDs(id); err != nil {
		return e, err
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/tenants/"+esc(id)+"/entitlements", nil, nil, &e, opts...)
	return e, err
}

func (s *TenantsService) tenant(ctx context.Context, method, id, suffix string, body any, opts []CallOption) (sdk.Tenant, error) {
	var t sdk.Tenant
	if err := checkIDs(id); err != nil {
		return t, err
	}
	err := s.c.do(ctx, method, "/v1/tenants/"+esc(id)+suffix, nil, body, &t, opts...)
	return t, err
}

// MembersService manages tenant memberships (/v1/tenants/{id}/members).
type MembersService struct{ c *Client }

// MemberList is a tenant's members together with the allowed roles.
type MemberList struct {
	Items []sdk.Member `json:"items"`
	Roles []string     `json:"roles"`
}

// AddMemberRequest adds a member by Email or UserID. An unknown email
// creates an invited user who receives a setup email.
type AddMemberRequest struct {
	Email  string `json:"email,omitempty"`
	UserID string `json:"user_id,omitempty"`
	// Name is used when a new user is created.
	Name string `json:"name,omitempty"`
	Role string `json:"role"`
}

// UpdateMemberRequest is a partial member update.
type UpdateMemberRequest struct {
	Role *string `json:"role,omitempty"`
}

func memberPath(tenant string, member ...string) string {
	p := "/v1/tenants/" + esc(tenant) + "/members"
	for _, m := range member {
		p += "/" + esc(m)
	}
	return p
}

// List returns all members of a tenant.
func (s *MembersService) List(ctx context.Context, tenant string, opts ...CallOption) (MemberList, error) {
	var l MemberList
	if err := checkIDs(tenant); err != nil {
		return l, err
	}
	err := s.c.do(ctx, http.MethodGet, memberPath(tenant), nil, nil, &l, opts...)
	return l, err
}

// Add adds (or invites) a member.
func (s *MembersService) Add(ctx context.Context, tenant string, req AddMemberRequest, opts ...CallOption) (sdk.Member, error) {
	var m sdk.Member
	if err := checkIDs(tenant); err != nil {
		return m, err
	}
	err := s.c.do(ctx, http.MethodPost, memberPath(tenant), nil, req, &m, append([]CallOption{autoIdempotency()}, opts...)...)
	return m, err
}

// Get returns one membership by member ID.
func (s *MembersService) Get(ctx context.Context, tenant, member string, opts ...CallOption) (sdk.Member, error) {
	var m sdk.Member
	if err := checkIDs(tenant, member); err != nil {
		return m, err
	}
	err := s.c.do(ctx, http.MethodGet, memberPath(tenant, member), nil, nil, &m, opts...)
	return m, err
}

// Update changes a member's role.
func (s *MembersService) Update(ctx context.Context, tenant, member string, req UpdateMemberRequest, opts ...CallOption) (sdk.Member, error) {
	var m sdk.Member
	if err := checkIDs(tenant, member); err != nil {
		return m, err
	}
	err := s.c.do(ctx, http.MethodPatch, memberPath(tenant, member), nil, req, &m, opts...)
	return m, err
}

// Remove removes a membership.
func (s *MembersService) Remove(ctx context.Context, tenant, member string, opts ...CallOption) error {
	if err := checkIDs(tenant, member); err != nil {
		return err
	}
	err := s.c.do(ctx, http.MethodDelete, memberPath(tenant, member), nil, nil, nil, opts...)
	return err
}

// UsageService reads and records metered usage (/v1/tenants/{id}/usage).
type UsageService struct{ c *Client }

// UsageItem is a metric's current value next to its limit (nil = unlimited).
type UsageItem struct {
	Metric string `json:"metric"`
	Value  int64  `json:"value"`
	Limit  *int64 `json:"limit,omitempty"`
}

// Get lists a tenant's metered values and limits.
func (s *UsageService) Get(ctx context.Context, tenant string, opts ...CallOption) ([]UsageItem, error) {
	if err := checkIDs(tenant); err != nil {
		return nil, err
	}
	var out struct {
		Items []UsageItem `json:"items"`
	}
	err := s.c.do(ctx, http.MethodGet, "/v1/tenants/"+esc(tenant)+"/usage", nil, nil, &out, opts...)
	return out.Items, err
}

// Record adds delta (may be negative) to a metric. An increment beyond the
// tenant's limit fails with an error for which IsQuotaExceeded is true.
func (s *UsageService) Record(ctx context.Context, tenant, metric string, delta int64, opts ...CallOption) (UsageItem, error) {
	var it UsageItem
	if err := checkIDs(tenant, metric); err != nil {
		return it, err
	}
	body := struct {
		Delta int64 `json:"delta"`
	}{delta}
	err := s.c.do(ctx, http.MethodPost, "/v1/tenants/"+esc(tenant)+"/usage/"+esc(metric), nil, body, &it,
		append([]CallOption{autoIdempotency()}, opts...)...)
	return it, err
}
