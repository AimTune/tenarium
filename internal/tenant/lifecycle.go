package tenant

import (
	"context"
	"errors"
	"maps"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
)

const (
	EventTenantMaintenanceStarted = "tenant.maintenance_started"
	EventTenantMaintenanceEnded   = "tenant.maintenance_ended"

	// LabelClonedFrom marks tenants created by CloneTenant.
	LabelClonedFrom = "tenarium.io/cloned-from"
)

// ErrMaintenance means the tenant is in a maintenance window and read-only
// for its own users.
var ErrMaintenance = errors.New("the tenant is in maintenance and read-only")

var colorRe = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)

func validateBranding(b *sdk.Branding) error {
	if b == nil {
		return nil
	}
	if utf8.RuneCountInString(b.DisplayName) > maxNameLen {
		return invalid("branding.display_name", "must be at most %d characters", maxNameLen)
	}
	for field, u := range map[string]string{"logo_url": b.LogoURL, "icon_url": b.IconURL, "support_url": b.SupportURL} {
		if u == "" {
			continue
		}
		p, err := url.Parse(u)
		if err != nil || p.Scheme != "https" || p.Host == "" || len(u) > 2048 {
			return invalid("branding."+field, "must be an https URL")
		}
	}
	for field, c := range map[string]string{"primary_color": b.PrimaryColor, "accent_color": b.AccentColor} {
		if c != "" && !colorRe.MatchString(c) {
			return invalid("branding."+field, "must be a hex color like #1a2b3c")
		}
	}
	if b.SupportEmail != "" {
		if a, err := mail.ParseAddress(b.SupportEmail); err != nil || a.Address != b.SupportEmail {
			return invalid("branding.support_email", "invalid email address")
		}
	}
	return nil
}

// PublicBranding is what sign-in pages may show before anyone signs in.
type PublicBranding struct {
	TenantID string `json:"tenant_id"`
	Slug     string `json:"slug"`
	sdk.Branding
}

// BrandingFor returns the branding of a tenant found by ID, slug or
// verified custom domain. Tenants without branding answer ErrNotFound, so
// the endpoint reveals no more than the sign-in page would.
func (s *Service) BrandingFor(ctx context.Context, tenantRef, host string) (PublicBranding, error) {
	var (
		t   sdk.Tenant
		err error
	)
	if host != "" {
		t, err = s.ResolveDomain(ctx, host)
	} else {
		t, err = s.Get(ctx, tenantRef)
	}
	if err != nil || !t.IsLive() || t.Branding == nil {
		return PublicBranding{}, store.ErrNotFound
	}
	return PublicBranding{TenantID: t.ID, Slug: t.Slug, Branding: *t.Branding}, nil
}

// StartMaintenance opens a maintenance window, until a time or until
// EndMaintenance. During it the tenant is read-only for tenant-scoped
// callers; subscribers of tenant.maintenance_started can e.g. show a
// banner or start a migration.
func (s *Service) StartMaintenance(ctx context.Context, idOrSlug, message string, until *time.Time) (sdk.Tenant, error) {
	now := s.now()
	if until != nil && !until.After(now) {
		return sdk.Tenant{}, invalid("until", "must be in the future")
	}
	if utf8.RuneCountInString(message) > 500 {
		return sdk.Tenant{}, invalid("message", "must be at most 500 characters")
	}
	return s.mutate(ctx, idOrSlug, nil, "", EventTenantMaintenanceStarted, func(t *sdk.Tenant) error {
		if !t.IsLive() {
			return transitionErr("start maintenance of", t.Status)
		}
		m := &sdk.Maintenance{Message: message, StartedAt: now}
		if until != nil {
			u := until.UTC()
			m.Until = &u
		}
		t.Maintenance = m
		return nil
	})
}

// EndMaintenance closes the tenant's maintenance window.
func (s *Service) EndMaintenance(ctx context.Context, idOrSlug string) (sdk.Tenant, error) {
	return s.mutate(ctx, idOrSlug, nil, "", EventTenantMaintenanceEnded, func(t *sdk.Tenant) error {
		if t.Maintenance == nil {
			return stateErr("the tenant is not in maintenance")
		}
		t.Maintenance = nil
		return nil
	})
}

// CheckWritable returns ErrMaintenance if a tenant-scoped caller may not
// change the tenant right now.
func (s *Service) CheckWritable(ctx context.Context, tenantID string) error {
	t, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil // the operation reports missing tenants itself
	}
	if t.MaintenanceActive(s.now()) {
		return ErrMaintenance
	}
	return nil
}

// --- templates ------------------------------------------------------------------

func (s *Service) ListTemplates(ctx context.Context) ([]store.TenantTemplate, error) {
	return s.store.ListTenantTemplates(ctx)
}

func (s *Service) GetTemplate(ctx context.Context, id string) (store.TenantTemplate, error) {
	return s.store.GetTenantTemplate(ctx, id)
}

// PutTemplate creates or replaces a tenant template.
func (s *Service) PutTemplate(ctx context.Context, tpl store.TenantTemplate) (store.TenantTemplate, error) {
	if !slugRe.MatchString(tpl.ID) {
		return store.TenantTemplate{}, invalid("id", "must be 1-63 lowercase letters, digits or '-'")
	}
	if tpl.Name == "" || utf8.RuneCountInString(tpl.Name) > maxNameLen {
		return store.TenantTemplate{}, invalid("name", "must be 1-%d characters", maxNameLen)
	}
	if utf8.RuneCountInString(tpl.Description) > 1000 {
		return store.TenantTemplate{}, invalid("description", "too long")
	}
	// Check the values as a tenant would be checked.
	probe := sdk.Tenant{Slug: "template", Name: tpl.Name, Plan: tpl.Plan, AddOns: tpl.AddOns, Region: tpl.Region,
		Labels: tpl.Labels, Settings: tpl.Settings, Features: tpl.Features, Limits: tpl.Limits, Branding: tpl.Branding}
	if err := s.validateTenant(&probe); err != nil {
		return store.TenantTemplate{}, err
	}
	if err := s.checkPlan(ctx, tpl.Plan); err != nil {
		return store.TenantTemplate{}, err
	}
	if err := s.checkAddOns(ctx, tpl.AddOns); err != nil {
		return store.TenantTemplate{}, err
	}
	seen := map[string]bool{}
	for _, r := range tpl.Roles {
		switch {
		case !keyRe.MatchString(r.Name) || s.roleAllowed(r.Name) || seen[r.Name]:
			return store.TenantTemplate{}, invalid("roles", "invalid or duplicate custom role %q", r.Name)
		case len(r.Actions) == 0 || len(r.Actions) > 100:
			return store.TenantTemplate{}, invalid("roles", "role %q needs 1-100 action patterns", r.Name)
		}
		if _, err := ExpandActions(r.Actions); err != nil {
			return store.TenantTemplate{}, err
		}
		seen[r.Name] = true
	}
	tpl.UpdatedAt = s.now()
	return tpl, s.store.PutTenantTemplate(ctx, tpl)
}

func (s *Service) DeleteTemplate(ctx context.Context, id string) error {
	return s.store.DeleteTenantTemplate(ctx, id)
}

// applyTemplate fills in what the request leaves out; maps are merged
// with the request's entries winning.
func applyTemplate(in CreateInput, tpl store.TenantTemplate) CreateInput {
	in.Plan = cmpOr(in.Plan, tpl.Plan)
	in.Region = cmpOr(in.Region, tpl.Region)
	if in.AddOns == nil {
		in.AddOns = slices.Clone(tpl.AddOns)
	}
	if in.Branding == nil && tpl.Branding != nil {
		b := *tpl.Branding
		in.Branding = &b
	}
	in.Labels = mergeMaps(tpl.Labels, in.Labels)
	in.Features = mergeMaps(tpl.Features, in.Features)
	in.Limits = mergeMaps(tpl.Limits, in.Limits)
	if len(tpl.Settings) > 0 {
		in.Settings = mergePatch(sdk.DeepCopyMap(tpl.Settings), in.Settings)
	}
	return in
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func mergeMaps[K comparable, V any](base, over map[K]V) map[K]V {
	if len(base) == 0 {
		return over
	}
	out := maps.Clone(base)
	maps.Copy(out, over)
	return out
}

// TemplateRoles returns the custom roles a create request will add, so
// the API can check the caller may grant them.
func (s *Service) TemplateRoles(ctx context.Context, templateID string) ([]store.TemplateRole, error) {
	if templateID == "" {
		return nil, nil
	}
	tpl, err := s.store.GetTenantTemplate(ctx, templateID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, invalid("template", "unknown template %q", templateID)
	}
	return tpl.Roles, err
}

// createRoles adds custom roles to a new tenant. They are created after
// the tenant, so a failure leaves the tenant without some of them; the
// error says which.
func (s *Service) createRoles(ctx context.Context, tenantID string, roles []store.TemplateRole) error {
	for _, r := range roles {
		if _, err := s.PutRole(ctx, tenantID, r.Name, RoleInput{Description: r.Description, Actions: r.Actions}); err != nil {
			return errors.Join(stateErr("tenant created, but role %q could not be added", r.Name), err)
		}
	}
	return nil
}

// --- cloning --------------------------------------------------------------------

// CloneInput names the copy of a tenant.
type CloneInput struct {
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	ParentID string `json:"parent_id,omitempty"`
	// Members also copies the source's active memberships.
	Members bool `json:"members,omitempty"`
}

// CloneTenant creates a tenant with the source's plan, add-ons, region,
// labels, settings, features, limits, branding and custom roles (and
// optionally its members). Domains, SSO, API keys, webhooks and usage are
// not copied. The copy is labelled tenarium.io/cloned-from.
func (s *Service) CloneTenant(ctx context.Context, sourceRef string, in CloneInput) (sdk.Tenant, error) {
	src, err := s.Get(ctx, sourceRef)
	if err != nil {
		return sdk.Tenant{}, err
	}
	if !src.IsLive() {
		return sdk.Tenant{}, transitionErr("clone", src.Status)
	}
	roles, err := s.CloneRoles(ctx, src.ID)
	if err != nil {
		return sdk.Tenant{}, err
	}
	c := src.Clone()
	labels := c.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	labels[LabelClonedFrom] = src.ID
	t, err := s.Create(ctx, CreateInput{
		Slug: in.Slug, Name: in.Name, ParentID: in.ParentID, Plan: c.Plan, AddOns: c.AddOns, Region: c.Region,
		Labels: labels, Settings: c.Settings, Features: c.Features, Limits: c.Limits, Branding: c.Branding,
	})
	if err != nil {
		return sdk.Tenant{}, err
	}
	if err := s.createRoles(ctx, t.ID, roles); err != nil {
		return t, err
	}
	if !in.Members {
		return t, nil
	}
	ms, err := s.store.ListMembers(ctx, src.ID)
	if err != nil {
		return t, err
	}
	for _, m := range ms {
		if m.Status != sdk.MemberActive || m.UserID == "" {
			continue
		}
		if _, err := s.AddMember(ctx, t.ID, MemberInput{UserID: m.UserID, Role: m.Role}); err != nil {
			return t, errors.Join(stateErr("tenant cloned, but member %s could not be added", m.Email), err)
		}
	}
	return t, nil
}

// CloneRoles returns a tenant's custom roles in template form.
func (s *Service) CloneRoles(ctx context.Context, tenantID string) ([]store.TemplateRole, error) {
	rs, err := s.store.ListTenantRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]store.TemplateRole, 0, len(rs))
	for _, r := range rs {
		out = append(out, store.TemplateRole{Name: r.Name, Description: r.Description, Actions: r.Actions})
	}
	return out, nil
}
