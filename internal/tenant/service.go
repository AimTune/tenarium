// Package tenant implements the domain: tenant lifecycle and hierarchy,
// plans and entitlements, members and usage quotas. Every write runs plugin
// hooks first and commits its event in the same transaction.
package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/AimTune/tenarium/internal/eventschema"
	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/internal/store"
	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// EventSource is the CloudEvents "source" of events emitted by the core.
const EventSource = "tenarium"

// DefaultMemberRoles is used when Options.MemberRoles is empty.
var DefaultMemberRoles = []string{"owner", "admin", "member", "viewer"}

// HookRunner runs the plugin hooks registered for a point.
type HookRunner interface {
	RunHooks(ctx context.Context, req *sdk.HookRequest) error
}

type Service struct {
	store store.Store
	hooks HookRunner
	// provisioned reports whether any provisioners exist. Without them
	// tenants skip the asynchronous provisioning/deleting states.
	provisioned       bool
	requireKnownPlans bool
	settingsSchema    *schema.Schema
	memberRoles       []string
	userOpts          *UserOptions
	reservedDomains   []string
	deletionGrace     time.Duration
	ssoAllowPrivate   bool
	purgeAfter        time.Duration
	// live holds settings that configuration reloads can change.
	live      atomic.Pointer[liveSettings]
	lastPurge time.Time
	lookupTXT func(ctx context.Context, name string) ([]string, error)
	notify    func()
	now       func() time.Time
}

type Options struct {
	Hooks HookRunner
	// HasProvisioners enables the provisioning and deleting states.
	HasProvisioners bool
	// RequireKnownPlans rejects tenants whose plan is not a defined Plan.
	RequireKnownPlans bool
	// SettingsSchema, if set, validates every tenant's settings.
	SettingsSchema *schema.Schema
	// MemberRoles are the allowed member roles.
	MemberRoles []string
	// Notify is called after events are committed (wakes the dispatcher).
	Notify func()
	// Metrics are the usage policies (period, overage, thresholds) per
	// metric.
	Metrics map[string]MetricPolicy
	// PurgeDeletedAfter removes the data of tenants deleted that long ago
	// (0: keep it).
	PurgeDeletedAfter time.Duration
	// Regions are the allowed tenant regions (data residency); empty allows
	// any, including none.
	Regions []string
	// DefaultRegion is used when a tenant and its parent have none.
	DefaultRegion string
	// DeletionGracePeriod, if positive, turns deletion into suspension plus
	// a scheduled deletion that can be undone with Restore until it runs.
	DeletionGracePeriod time.Duration
	// ReservedDomains cannot be claimed by tenants (with their subdomains),
	// typically the platform's own domains.
	ReservedDomains []string
	// LookupTXT resolves TXT records for domain verification; default DNS.
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	// Users configures user management; nil uses the internal directory,
	// logs emails and disables token issuing.
	Users *UserOptions
}

func NewService(s store.Store, opts Options) *Service {
	svc := &Service{
		store:             s,
		hooks:             opts.Hooks,
		provisioned:       opts.HasProvisioners,
		requireKnownPlans: opts.RequireKnownPlans,
		settingsSchema:    opts.SettingsSchema,
		memberRoles:       opts.MemberRoles,
		notify:            opts.Notify,
		deletionGrace:     opts.DeletionGracePeriod,
		purgeAfter:        opts.PurgeDeletedAfter,
		now:               func() time.Time { return time.Now().UTC() },
	}
	svc.live.Store(&liveSettings{regions: slices.Clone(opts.Regions), defaultRegion: opts.DefaultRegion, metrics: maps.Clone(opts.Metrics)})
	if len(svc.memberRoles) == 0 {
		svc.memberRoles = DefaultMemberRoles
	}
	if svc.notify == nil {
		svc.notify = func() {}
	}
	svc.userOpts = withUserDefaults(opts.Users)
	svc.lookupTXT = opts.LookupTXT
	if svc.lookupTXT == nil {
		svc.lookupTXT = net.DefaultResolver.LookupTXT
	}
	for _, d := range opts.ReservedDomains {
		svc.reservedDomains = append(svc.reservedDomains, NormalizeHostname(d))
	}
	return svc
}

func withUserDefaults(o *UserOptions) *UserOptions {
	var c UserOptions
	if o != nil {
		c = *o
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.Mailer == nil {
		c.Mailer = LogMailer{Log: c.Log}
	}
	if c.DirectoryName == "" {
		c.DirectoryName = InternalDirectory
	}
	if c.ProductName == "" {
		c.ProductName = "Tenarium"
	}
	if c.PublicURL == "" {
		c.PublicURL = "http://localhost:8080"
	}
	if c.Policy.MinLength == 0 {
		c.Policy.MinLength = 12
	}
	if c.InvitationTTL == 0 {
		c.InvitationTTL = 7 * 24 * time.Hour
	}
	if c.ResetTTL == 0 {
		c.ResetTTL = time.Hour
	}
	if c.MaxFailures == 0 {
		c.MaxFailures = 10
	}
	if c.LockFor == 0 {
		c.LockFor = 15 * time.Minute
	}
	if c.RefreshTTL == 0 {
		c.RefreshTTL = 30 * 24 * time.Hour
	}
	if c.EmailChangeTTL == 0 {
		c.EmailChangeTTL = 24 * time.Hour
	}
	return &c
}

// LogMailer writes emails to the log instead of sending them. It is the
// default so that invitations work in development; configure a mailer
// plugin (e.g. smtp) in production.
type LogMailer struct{ Log *slog.Logger }

func (LogMailer) Name() string { return "log" }

func (m LogMailer) Send(_ context.Context, msg sdk.Message) error {
	m.Log.Info("email (not sent: no mailer configured)", "to", msg.To, "subject", msg.Subject, "tag", msg.Tag, "text", msg.Text)
	return nil
}

func (s *Service) roleAllowed(r string) bool { return slices.Contains(s.memberRoles, r) }

// MemberRoles returns the allowed member roles.
func (s *Service) MemberRoles() []string { return slices.Clone(s.memberRoles) }

type CreateInput struct {
	Slug     string            `json:"slug"`
	Name     string            `json:"name"`
	ParentID string            `json:"parent_id,omitempty"`
	Plan     string            `json:"plan,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
	Settings map[string]any    `json:"settings,omitempty"`
	Features map[string]bool   `json:"features,omitempty"`
	Limits   map[string]int64  `json:"limits,omitempty"`
	// AddOns are plan IDs whose features and limits stack on the plan.
	AddOns []string `json:"add_ons,omitempty"`
	// Region places the tenant; defaults to the parent's, then to the
	// default region.
	Region   string        `json:"region,omitempty"`
	Branding *sdk.Branding `json:"branding,omitempty"`
	// Template presets the tenant (see TenantTemplate); the request's own
	// values win.
	Template string `json:"template,omitempty"`
	// Schedule adds actions to run later, e.g. ending a trial.
	Schedule []ScheduleInput `json:"schedule,omitempty"`
}

// UpdateInput is a partial update; nil fields are left unchanged.
type UpdateInput struct {
	Name *string `json:"name,omitempty"`
	Plan *string `json:"plan,omitempty"`
	// Labels, Features and Limits replace the whole map when non-nil.
	Labels   *map[string]string `json:"labels,omitempty"`
	Features *map[string]bool   `json:"features,omitempty"`
	Limits   *map[string]int64  `json:"limits,omitempty"`
	AddOns   *[]string          `json:"add_ons,omitempty"`
	// Branding replaces the branding; an empty object removes it.
	Branding *sdk.Branding `json:"branding,omitempty"`
	// BillingAnchor starts the monthly billing cycles ("cycle" usage
	// periods), e.g. synced from the billing provider's subscription.
	BillingAnchor *time.Time `json:"billing_anchor,omitempty"`
	// ClearBillingAnchor removes the anchor (cycles start at creation again).
	ClearBillingAnchor bool `json:"clear_billing_anchor,omitempty"`
	// Settings is an RFC 7386 merge patch.
	Settings map[string]any `json:"settings,omitempty"`
}

func (s *Service) Create(ctx context.Context, in CreateInput) (sdk.Tenant, error) {
	var roles []store.TemplateRole
	if in.Template != "" {
		tpl, err := s.store.GetTenantTemplate(ctx, in.Template)
		if errors.Is(err, store.ErrNotFound) {
			return sdk.Tenant{}, invalid("template", "unknown template %q", in.Template)
		} else if err != nil {
			return sdk.Tenant{}, err
		}
		in, roles = applyTemplate(in, tpl), tpl.Roles
	}
	now := s.now()
	t := sdk.Tenant{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Slug:      in.Slug,
		Name:      in.Name,
		Status:    sdk.StatusActive,
		Plan:      in.Plan,
		Labels:    maps.Clone(in.Labels),
		Settings:  sdk.DeepCopyMap(in.Settings),
		Features:  maps.Clone(in.Features),
		Limits:    maps.Clone(in.Limits),
		AddOns:    slices.Clone(in.AddOns),
		Branding:  in.Branding,
		Region:    in.Region,
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if in.ParentID != "" {
		parent, err := s.Get(ctx, in.ParentID)
		if errors.Is(err, store.ErrNotFound) {
			return sdk.Tenant{}, invalid("parent_id", "parent tenant not found")
		} else if err != nil {
			return sdk.Tenant{}, err
		}
		if !parent.IsLive() {
			return sdk.Tenant{}, invalid("parent_id", "parent tenant is %s", parent.Status)
		}
		t.ParentID = parent.ID
		// Children inherit the parent's plan unless one is given, so a
		// workspace never silently ends up without limits.
		if t.Plan == "" {
			t.Plan = parent.Plan
		}
		if t.Region == "" {
			t.Region = parent.Region
		}
	}
	if t.Region == "" {
		t.Region = s.live.Load().defaultRegion
	}
	if regions := s.live.Load().regions; t.Region == "" && len(regions) > 0 {
		return sdk.Tenant{}, invalid("region", "required: one of %v", regions)
	}
	if s.provisioned {
		t.Status = sdk.StatusProvisioning
	}
	if err := s.validateTenant(&t); err != nil {
		return sdk.Tenant{}, err
	}
	t, err := s.runTenantHooks(ctx, sdk.HookBeforeTenantCreate, t, nil)
	if err != nil {
		return sdk.Tenant{}, err
	}
	if err := s.checkPlan(ctx, t.Plan); err != nil {
		return sdk.Tenant{}, err
	}
	if err := s.checkAddOns(ctx, t.AddOns); err != nil {
		return sdk.Tenant{}, err
	}
	var scheduled []store.ScheduledAction
	for i, in := range in.Schedule {
		a, err := s.newScheduled(ctx, t.ID, in)
		if err != nil {
			var ve *ValidationError
			if errors.As(err, &ve) {
				ve.Field = fmt.Sprintf("schedule[%d].%s", i, ve.Field)
			}
			return sdk.Tenant{}, err
		}
		scheduled = append(scheduled, a)
	}

	err = s.store.InTx(ctx, func(tx store.Tx) error {
		if t.ParentID != "" {
			// Re-check under lock: the parent may be deleted concurrently.
			parent, err := tx.GetTenant(ctx, t.ParentID)
			if err != nil {
				return err
			}
			if !parent.IsLive() {
				return invalid("parent_id", "parent tenant is %s", parent.Status)
			}
		}
		if err := tx.CreateTenant(ctx, t); err != nil {
			if errors.Is(err, store.ErrAlreadyExists) {
				return fmt.Errorf("tenant with slug %q: %w", t.Slug, err)
			}
			return err
		}
		if err := s.appendTenantEvent(ctx, tx, sdk.EventTenantCreated, t, nil); err != nil {
			return err
		}
		for _, a := range scheduled {
			if err := s.createScheduled(ctx, tx, a); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return sdk.Tenant{}, err
	}
	s.notify()
	return t, s.createRoles(ctx, t.ID, roles)
}

func (s *Service) checkPlan(ctx context.Context, plan string) error {
	if plan == "" || !s.requireKnownPlans {
		return nil
	}
	if _, err := s.store.GetPlan(ctx, plan); errors.Is(err, store.ErrNotFound) {
		return invalid("plan", "unknown plan %q", plan)
	} else if err != nil {
		return err
	}
	return nil
}

// Get resolves a tenant by ID or slug.
func (s *Service) Get(ctx context.Context, idOrSlug string) (sdk.Tenant, error) {
	if _, err := uuid.Parse(idOrSlug); err == nil {
		return s.store.GetTenant(ctx, idOrSlug)
	}
	return s.store.GetTenantBySlug(ctx, idOrSlug)
}

func (s *Service) List(ctx context.Context, q store.ListTenantsQuery) ([]sdk.Tenant, error) {
	return s.store.ListTenants(ctx, q)
}

// Update applies a partial update. If expectedVersion is non-nil the update
// fails with store.ErrConflict unless it matches (optimistic concurrency for
// API clients, e.g. via If-Match).
func (s *Service) Update(ctx context.Context, idOrSlug string, in UpdateInput, expectedVersion *int64) (sdk.Tenant, error) {
	if in.ClearBillingAnchor && in.BillingAnchor != nil {
		return sdk.Tenant{}, invalid("billing_anchor", "set it or clear it, not both")
	}
	if in.Plan != nil {
		if err := s.checkPlan(ctx, *in.Plan); err != nil {
			return sdk.Tenant{}, err
		}
	}
	if in.AddOns != nil {
		if err := s.checkAddOns(ctx, *in.AddOns); err != nil {
			return sdk.Tenant{}, err
		}
	}
	return s.mutate(ctx, idOrSlug, expectedVersion, sdk.HookBeforeTenantUpdate, sdk.EventTenantUpdated,
		func(t *sdk.Tenant) error {
			if !t.IsLive() {
				return transitionErr("update", t.Status)
			}
			if in.Name != nil {
				t.Name = *in.Name
			}
			if in.Plan != nil {
				if *in.Plan != t.Plan {
					t.PlanRevision = 0 // a new plan starts on its current revision
				}
				t.Plan = *in.Plan
			}
			if in.Labels != nil {
				t.Labels = maps.Clone(*in.Labels)
			}
			if in.Features != nil {
				t.Features = maps.Clone(*in.Features)
			}
			if in.Limits != nil {
				t.Limits = maps.Clone(*in.Limits)
			}
			if in.AddOns != nil {
				t.AddOns = slices.Clone(*in.AddOns)
			}
			if in.Branding != nil {
				if *in.Branding == (sdk.Branding{}) {
					t.Branding = nil
				} else {
					b := *in.Branding
					t.Branding = &b
				}
			}
			if in.BillingAnchor != nil {
				a := in.BillingAnchor.UTC()
				t.BillingAnchor = &a
			}
			if in.ClearBillingAnchor {
				t.BillingAnchor = nil
			}
			if in.Settings != nil {
				t.Settings = mergePatch(t.Settings, in.Settings)
			}
			return nil
		})
}

func (s *Service) Suspend(ctx context.Context, idOrSlug, reason string) (sdk.Tenant, error) {
	if reason == PendingDeletionReason {
		return sdk.Tenant{}, invalid("reason", "%q is reserved for deletion requests", reason)
	}
	return s.suspend(ctx, idOrSlug, reason)
}

func (s *Service) suspend(ctx context.Context, idOrSlug, reason string) (sdk.Tenant, error) {
	return s.mutate(ctx, idOrSlug, nil, sdk.HookBeforeTenantSuspend, sdk.EventTenantSuspended,
		func(t *sdk.Tenant) error {
			if t.Status != sdk.StatusActive {
				return transitionErr("suspend", t.Status)
			}
			t.Status, t.StatusReason = sdk.StatusSuspended, reason
			return nil
		})
}

// Resume reactivates a suspended tenant. Tenants suspended for a pending
// deletion are resumed by Restore instead, which also cancels the deletion.
func (s *Service) Resume(ctx context.Context, idOrSlug string) (sdk.Tenant, error) {
	return s.resume(ctx, idOrSlug, false)
}

func (s *Service) resume(ctx context.Context, idOrSlug string, restoring bool) (sdk.Tenant, error) {
	return s.mutate(ctx, idOrSlug, nil, sdk.HookBeforeTenantResume, sdk.EventTenantResumed,
		func(t *sdk.Tenant) error {
			if t.Status != sdk.StatusSuspended {
				return transitionErr("resume", t.Status)
			}
			if t.StatusReason == PendingDeletionReason && !restoring {
				return stateErr("tenant is pending deletion; restore it instead")
			}
			t.Status, t.StatusReason = sdk.StatusActive, ""
			return nil
		})
}

// Delete starts deletion. With provisioners the tenant enters "deleting"
// until its resources are deprovisioned; otherwise it is deleted at once.
// Tenants with live children cannot be deleted.
func (s *Service) Delete(ctx context.Context, idOrSlug string) (sdk.Tenant, error) {
	evt := sdk.EventTenantDeleted
	if s.provisioned {
		evt = sdk.EventTenantDeleting
	}
	return s.mutate(ctx, idOrSlug, nil, sdk.HookBeforeTenantDelete, evt,
		func(t *sdk.Tenant) error {
			if !t.IsLive() {
				return transitionErr("delete", t.Status)
			}
			if s.provisioned {
				t.Status, t.StatusReason = sdk.StatusDeleting, ""
				return nil
			}
			s.markDeleted(t)
			return nil
		})
}

// RetryProvisioning moves a failed tenant back to provisioning.
func (s *Service) RetryProvisioning(ctx context.Context, idOrSlug string) (sdk.Tenant, error) {
	return s.mutate(ctx, idOrSlug, nil, "", sdk.EventTenantProvisioning,
		func(t *sdk.Tenant) error {
			if t.Status != sdk.StatusFailed {
				return transitionErr("retry provisioning of", t.Status)
			}
			t.Status, t.StatusReason = sdk.StatusProvisioning, ""
			return nil
		})
}

// Entitlements returns the effective features and limits of a tenant.
func (s *Service) Entitlements(ctx context.Context, idOrSlug string) (sdk.Entitlements, error) {
	t, err := s.Get(ctx, idOrSlug)
	if err != nil {
		return sdk.Entitlements{}, err
	}
	return s.entitlementsOf(ctx, t)
}

func (s *Service) entitlementsOf(ctx context.Context, t sdk.Tenant) (sdk.Entitlements, error) {
	return store.ResolveEntitlements(ctx, s.store, t)
}

// The following transitions are driven by the provisioning runner.

func (s *Service) markProvisioned(ctx context.Context, id string) error {
	t, err := s.mutate(ctx, id, nil, "", sdk.EventTenantProvisioned, func(t *sdk.Tenant) error {
		if t.Status != sdk.StatusProvisioning {
			return transitionErr("activate", t.Status)
		}
		t.Status, t.StatusReason = sdk.StatusActive, ""
		return nil
	})
	if err != nil {
		return err
	}
	// A region move with reprovisioning is complete.
	if m := t.Maintenance; m != nil && m.MoveTo != "" && m.MoveTo == t.Region {
		_, err = s.EndMaintenance(ctx, t.ID)
	}
	return err
}

func (s *Service) markProvisioningFailed(ctx context.Context, id, reason string) error {
	_, err := s.mutate(ctx, id, nil, "", sdk.EventTenantProvisioningFailed, func(t *sdk.Tenant) error {
		if t.Status != sdk.StatusProvisioning {
			return transitionErr("fail", t.Status)
		}
		t.Status, t.StatusReason = sdk.StatusFailed, reason
		return nil
	})
	return err
}

func (s *Service) markDeprovisioned(ctx context.Context, id string) error {
	_, err := s.mutate(ctx, id, nil, "", sdk.EventTenantDeleted, func(t *sdk.Tenant) error {
		if t.Status != sdk.StatusDeleting {
			return transitionErr("finish deleting", t.Status)
		}
		s.markDeleted(t)
		return nil
	})
	return err
}

func (s *Service) markDeprovisioningFailed(ctx context.Context, id, reason string) error {
	_, err := s.mutate(ctx, id, nil, "", sdk.EventTenantDeprovisioningFailed, func(t *sdk.Tenant) error {
		if t.Status != sdk.StatusDeleting {
			return transitionErr("fail deleting", t.Status)
		}
		t.Status, t.StatusReason = sdk.StatusFailed, reason
		return nil
	})
	return err
}

func (s *Service) markDeleted(t *sdk.Tenant) {
	now := s.now()
	t.Status, t.StatusReason, t.DeletedAt = sdk.StatusDeleted, "", &now
}

// mutate is the read-modify-write cycle shared by all tenant updates: apply
// change, run hooks (outside the transaction, since they may be slow), then
// commit the new state and its events atomically, guarded by the version
// read.
func (s *Service) mutate(
	ctx context.Context,
	idOrSlug string,
	expectedVersion *int64,
	point sdk.HookPoint,
	eventType string,
	change func(t *sdk.Tenant) error,
) (sdk.Tenant, error) {
	prev, err := s.Get(ctx, idOrSlug)
	if err != nil {
		return sdk.Tenant{}, err
	}
	if expectedVersion != nil && *expectedVersion != prev.Version {
		return sdk.Tenant{}, store.ErrConflict
	}
	next := prev.Clone()
	if err := change(&next); err != nil {
		return sdk.Tenant{}, err
	}
	if err := s.validateTenant(&next); err != nil {
		return sdk.Tenant{}, err
	}
	if point != "" {
		if next, err = s.runTenantHooks(ctx, point, next, &prev); err != nil {
			return sdk.Tenant{}, err
		}
	}
	next.Version = prev.Version + 1
	next.UpdatedAt = s.now()

	err = s.store.InTx(ctx, func(tx store.Tx) error {
		// Lock the row first: concurrent writers touching this tenant (e.g.
		// creating a child under it) are serialised behind this point.
		if _, err := tx.GetTenant(ctx, prev.ID); err != nil {
			return err
		}
		// Deletion requested by a caller (not the final deprovisioned step).
		if eventType == sdk.EventTenantDeleting || (eventType == sdk.EventTenantDeleted && prev.IsLive()) {
			n, err := tx.CountLiveChildren(ctx, prev.ID)
			if err != nil {
				return err
			}
			if n > 0 {
				return stateErr("tenant has %d live child tenant(s); delete them first", n)
			}
		}
		if err := tx.UpdateTenant(ctx, next, prev.Version); err != nil {
			return err
		}
		if err := s.appendTenantEvent(ctx, tx, eventType, next, &prev); err != nil {
			return err
		}
		if next.Plan != prev.Plan && eventType == sdk.EventTenantUpdated {
			return s.appendTenantEvent(ctx, tx, sdk.EventTenantPlanChanged, next, &prev)
		}
		return nil
	})
	if err != nil {
		return sdk.Tenant{}, err
	}
	s.notify()
	return next, nil
}

// runTenantHooks runs the hooks for point on a copy of t. Only create/update
// hooks may change data, and never identity or lifecycle fields.
func (s *Service) runTenantHooks(ctx context.Context, point sdk.HookPoint, t sdk.Tenant, prev *sdk.Tenant) (sdk.Tenant, error) {
	if s.hooks == nil {
		return t, nil
	}
	proposed := t.Clone()
	req := &sdk.HookRequest{Point: point, Tenant: &proposed}
	if prev != nil {
		p := prev.Clone()
		req.Previous = &p
	}
	if err := s.hooks.RunHooks(ctx, req); err != nil {
		return sdk.Tenant{}, err
	}
	if point != sdk.HookBeforeTenantCreate && point != sdk.HookBeforeTenantUpdate {
		return t, nil
	}
	out := *req.Tenant
	out.ID, out.Slug, out.ParentID, out.Status, out.StatusReason = t.ID, t.Slug, t.ParentID, t.Status, t.StatusReason
	out.Version, out.CreatedAt, out.UpdatedAt, out.DeletedAt = t.Version, t.CreatedAt, t.UpdatedAt, t.DeletedAt
	out.PlanRevision = t.PlanRevision
	out.Maintenance = t.Maintenance
	if point != sdk.HookBeforeTenantCreate {
		out.Region = t.Region // moved only with MoveRegion
	}
	if err := s.validateTenant(&out); err != nil {
		return sdk.Tenant{}, fmt.Errorf("hook produced invalid tenant: %w", err)
	}
	return out, nil
}

// actor names the caller in events; impersonated sessions also name the
// impersonator, so the audit trail shows who really acted.
func actor(ctx context.Context) string {
	p, ok := sdk.PrincipalFrom(ctx)
	if !ok {
		return "system"
	}
	a := p.Authenticator + ":" + p.Subject
	if imp, ok := p.Claims[ImpersonationClaim].(string); ok {
		a += ";impersonated-by=" + imp
	}
	return a
}

func (s *Service) appendTenantEvent(ctx context.Context, tx store.Tx, typ string, t sdk.Tenant, prev *sdk.Tenant) error {
	return s.appendEvent(ctx, tx, typ, t.ID, "tenants/"+t.ID, sdk.TenantEventData{Tenant: t, Previous: prev})
}

func (s *Service) appendEvent(ctx context.Context, tx store.Tx, typ, tenantID, subject string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	parent, state := traceContext(ctx)
	_, err = tx.AppendEvents(ctx, sdk.Event{
		ID:          uuid.Must(uuid.NewV7()).String(),
		Type:        typ,
		Source:      EventSource,
		Subject:     subject,
		TenantID:    tenantID,
		Actor:       actor(ctx),
		Time:        s.now(),
		Data:        data,
		TraceParent: parent,
		TraceState:  state,
		DataSchema:  s.dataSchema(typ),
	})
	return err
}

// traceContext returns the W3C trace context of the current span, so
// consumers of the event can link their work to the request behind it.
func traceContext(ctx context.Context) (parent, state string) {
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return "", ""
	}
	c := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, c)
	return c["traceparent"], c["tracestate"]
}

// SetPlan changes a tenant's plan (used by plugins through sdk.Host).
func (s *Service) SetPlan(ctx context.Context, idOrSlug, plan string) (sdk.Tenant, error) {
	return s.Update(ctx, idOrSlug, UpdateInput{Plan: &plan}, nil)
}

// RecordUsageValue is RecordUsage returning only the new value.
func (s *Service) RecordUsageValue(ctx context.Context, idOrSlug, metric string, delta int64) (int64, error) {
	it, err := s.RecordUsage(ctx, idOrSlug, metric, delta)
	return it.Value, err
}

// RecordEvent appends an event for a change made outside the tenant
// service (e.g. a signing key rotation), so it reaches the audit trail and
// subscribers.
func (s *Service) RecordEvent(ctx context.Context, typ, tenantID, subject string, payload any) error {
	err := s.store.InTx(ctx, func(tx store.Tx) error {
		return s.appendEvent(ctx, tx, typ, tenantID, subject, payload)
	})
	if err == nil {
		s.notify()
	}
	return err
}

// dataSchema names the published schema of an event type's current
// version, so consumers know which shape the payload has.
func (s *Service) dataSchema(typ string) string {
	e, ok := eventschema.Get(typ)
	if !ok {
		return ""
	}
	return eventschema.DataSchemaURI(s.userOpts.PublicURL, typ, e.Version)
}
