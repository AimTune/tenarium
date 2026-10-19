// Package sdktest helps plugin authors unit-test plugins without a server:
// Registrar records everything a plugin registers, and Host serves tenants
// and plans from memory.
//
//	reg := sdktest.NewRegistrar(map[string]any{"url": srv.URL})
//	if err := plugin.Init(ctx, reg); err != nil { ... }
//	err := reg.Deliver(ctx, "publish", sdktest.TenantEvent(sdk.EventTenantCreated, tenant))
package sdktest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"github.com/google/uuid"
)

// Subscription is a recorded Subscribe call.
type Subscription struct {
	Name    string
	Filter  sdk.EventFilter
	Handler sdk.EventHandler
	Options sdk.SubscribeOptions
}

// Hook is a recorded Hook call.
type Hook struct {
	Point    sdk.HookPoint
	Handler  sdk.HookHandler
	Priority int
}

// Registrar is an sdk.Registrar that records registrations.
type Registrar struct {
	ConfigData     map[string]any
	Instance       string
	Log            *slog.Logger
	HostImpl       *Host
	Subscriptions  []Subscription
	Hooks          []Hook
	Provisioners   []sdk.Provisioner
	Mux            *http.ServeMux
	Routes         []string
	Authenticators []sdk.Authenticator
	Authorizers    []sdk.Authorizer
	Directory      sdk.UserDirectory
	MailerImpl     sdk.Mailer
}

func (r *Registrar) UserDirectory(d sdk.UserDirectory) { r.Directory = d }
func (r *Registrar) Mailer(m sdk.Mailer)               { r.MailerImpl = m }

var _ sdk.Registrar = (*Registrar)(nil)

// NewRegistrar returns a Registrar serving cfg as the plugin configuration.
func NewRegistrar(cfg map[string]any) *Registrar {
	return &Registrar{
		ConfigData: cfg,
		Instance:   "test",
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		HostImpl:   NewHost(),
		Mux:        http.NewServeMux(),
	}
}

// Config decodes the configuration strictly, like the real server.
func (r *Registrar) Config(v any) error {
	raw, err := json.Marshal(r.ConfigData)
	if err != nil {
		return err
	}
	if string(raw) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (r *Registrar) Logger() *slog.Logger { return r.Log }
func (r *Registrar) Host() sdk.Host       { return r.HostImpl }
func (r *Registrar) InstanceName() string { return r.Instance }

func (r *Registrar) Subscribe(name string, f sdk.EventFilter, h sdk.EventHandler, opts ...sdk.SubscribeOption) {
	o := sdk.DefaultSubscribeOptions()
	for _, opt := range opts {
		opt(&o)
	}
	r.Subscriptions = append(r.Subscriptions, Subscription{Name: name, Filter: f, Handler: h, Options: o})
}

func (r *Registrar) Hook(point sdk.HookPoint, h sdk.HookHandler, opts ...sdk.HookOption) {
	var o sdk.HookOptions
	for _, opt := range opts {
		opt(&o)
	}
	r.Hooks = append(r.Hooks, Hook{Point: point, Handler: h, Priority: o.Priority})
}

func (r *Registrar) Provisioner(p sdk.Provisioner) { r.Provisioners = append(r.Provisioners, p) }

func (r *Registrar) Route(pattern string, h http.Handler) {
	r.Routes = append(r.Routes, pattern)
	r.Mux.Handle(pattern, h)
}

func (r *Registrar) Authenticator(a sdk.Authenticator) {
	r.Authenticators = append(r.Authenticators, a)
}
func (r *Registrar) Authorizer(a sdk.Authorizer) { r.Authorizers = append(r.Authorizers, a) }

// Deliver sends e to the named subscription if its filter matches.
func (r *Registrar) Deliver(ctx context.Context, subscription string, e sdk.Event) error {
	for _, s := range r.Subscriptions {
		if s.Name == subscription {
			if !s.Filter.Match(e) {
				return nil
			}
			return s.Handler(ctx, e)
		}
	}
	return fmt.Errorf("sdktest: no subscription %q", subscription)
}

// RunHooks runs the registered hooks for req.Point in priority order, like
// the server does.
func (r *Registrar) RunHooks(ctx context.Context, req *sdk.HookRequest) error {
	hooks := slices.Clone(r.Hooks)
	slices.SortStableFunc(hooks, func(a, b Hook) int { return a.Priority - b.Priority })
	for _, h := range hooks {
		if h.Point == req.Point {
			if err := h.Handler(ctx, req); err != nil {
				return err
			}
		}
	}
	return nil
}

// TenantEvent builds a tenant.* event carrying t, as the core would.
func TenantEvent(typ string, t sdk.Tenant) sdk.Event {
	data, _ := json.Marshal(sdk.TenantEventData{Tenant: t})
	return sdk.Event{
		ID: uuid.NewString(), Type: typ, Source: "tenarium", Subject: "tenants/" + t.ID,
		TenantID: t.ID, Time: time.Now().UTC(), Data: data,
	}
}

// MemberEvent builds a tenant.member_* event.
func MemberEvent(typ string, m sdk.Member) sdk.Event {
	data, _ := json.Marshal(sdk.MemberEventData{Member: m})
	return sdk.Event{
		ID: uuid.NewString(), Type: typ, Source: "tenarium", Subject: "tenants/" + m.TenantID + "/members/" + m.ID,
		TenantID: m.TenantID, Time: time.Now().UTC(), Data: data,
	}
}

// Host is an in-memory sdk.Host.
type Host struct {
	mu      sync.Mutex
	tenants map[string]sdk.Tenant
	plans   map[string]sdk.Plan
	users   map[string]sdk.User
	actions []Action
	// AuthorizeFunc overrides Authorize. By default a caller is allowed if
	// it is platform-wide or the resource belongs to its own tenant.
	AuthorizeFunc func(ctx context.Context, p *sdk.Principal, action sdk.Action, res sdk.Resource) error
}

func (h *Host) Authorize(ctx context.Context, action sdk.Action, res sdk.Resource) error {
	p, ok := sdk.PrincipalFrom(ctx)
	if !ok {
		return fmt.Errorf("%w: no caller", sdk.ErrForbidden)
	}
	if h.AuthorizeFunc != nil {
		return h.AuthorizeFunc(ctx, p, action, res)
	}
	if p.TenantID == "" || p.TenantID == res.TenantID {
		return nil
	}
	return fmt.Errorf("%w: outside the caller's tenant", sdk.ErrForbidden)
}

var _ sdk.Host = (*Host)(nil)

func NewHost() *Host {
	return &Host{tenants: map[string]sdk.Tenant{}, plans: map[string]sdk.Plan{}, users: map[string]sdk.User{}}
}

// AddUser stores u, assigning an ID if empty, and returns it.
func (h *Host) AddUser(u sdk.User) sdk.User {
	h.mu.Lock()
	defer h.mu.Unlock()
	if u.ID == "" {
		u.ID = uuid.Must(uuid.NewV7()).String()
	}
	if u.Status == "" {
		u.Status = sdk.UserActive
	}
	h.users[u.ID] = u
	return u
}

func (h *Host) GetUser(_ context.Context, idOrEmail string) (sdk.User, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if u, ok := h.users[idOrEmail]; ok {
		return u, nil
	}
	for _, u := range h.users {
		if strings.EqualFold(u.Email, idOrEmail) {
			return u, nil
		}
	}
	return sdk.User{}, sdk.ErrNotFound
}

// AddTenant stores t, assigning an ID if empty, and returns it.
func (h *Host) AddTenant(t sdk.Tenant) sdk.Tenant {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t.ID == "" {
		t.ID = uuid.Must(uuid.NewV7()).String()
	}
	if t.Status == "" {
		t.Status = sdk.StatusActive
	}
	h.tenants[t.ID] = t
	return t
}

func (h *Host) AddPlan(p sdk.Plan) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.plans[p.ID] = p
}

func (h *Host) GetTenant(_ context.Context, idOrSlug string) (sdk.Tenant, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t, ok := h.tenants[idOrSlug]; ok {
		return t, nil
	}
	for _, t := range h.tenants {
		if t.Slug == idOrSlug && t.Status != sdk.StatusDeleted {
			return t, nil
		}
	}
	return sdk.Tenant{}, sdk.ErrNotFound
}

func (h *Host) ListTenants(_ context.Context, after string, limit int) ([]sdk.Tenant, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []sdk.Tenant
	for _, id := range slices.Sorted(maps.Keys(h.tenants)) {
		if id > after && h.tenants[id].Status != sdk.StatusDeleted {
			out = append(out, h.tenants[id])
			if limit > 0 && len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

func (h *Host) GetPlan(_ context.Context, id string) (sdk.Plan, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.plans[id]
	if !ok {
		return sdk.Plan{}, sdk.ErrNotFound
	}
	return p, nil
}

func (h *Host) Entitlements(ctx context.Context, tenantID string) (sdk.Entitlements, error) {
	t, err := h.GetTenant(ctx, tenantID)
	if err != nil {
		return sdk.Entitlements{}, err
	}
	var plan *sdk.Plan
	if p, err := h.GetPlan(ctx, t.Plan); err == nil {
		plan = &p
	}
	return sdk.ComputeEntitlements(t, plan), nil
}

// PublicRoute mounts the handler on Mux under "/public" so tests can call
// it like the server would (/v1/plugins/{instance}/public/...).
func (r *Registrar) PublicRoute(pattern string, h http.Handler) {
	r.Routes = append(r.Routes, "public: "+pattern)
	method, path, ok := strings.Cut(pattern, " ")
	if !ok {
		method, path = "", pattern
	}
	r.Mux.Handle(strings.TrimSpace(method+" /public"+path), h)
}

// Action is a state change a plugin requested through the Host.
type Action struct {
	Kind     string // "suspend", "resume", "set_plan", "record_usage"
	TenantID string
	Value    string
	Delta    int64
}

// Actions returns the recorded host actions.
func (h *Host) Actions() []Action {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.actions)
}

func (h *Host) mutate(idOrSlug string, a Action, fn func(t *sdk.Tenant) error) (sdk.Tenant, error) {
	t, err := h.GetTenant(context.Background(), idOrSlug)
	if err != nil {
		return sdk.Tenant{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := fn(&t); err != nil {
		return sdk.Tenant{}, err
	}
	t.Version++
	h.tenants[t.ID] = t
	a.TenantID = t.ID
	h.actions = append(h.actions, a)
	return t, nil
}

func (h *Host) SuspendTenant(_ context.Context, idOrSlug, reason string) (sdk.Tenant, error) {
	return h.mutate(idOrSlug, Action{Kind: "suspend", Value: reason}, func(t *sdk.Tenant) error {
		if t.Status != sdk.StatusActive {
			return fmt.Errorf("cannot suspend a %s tenant", t.Status)
		}
		t.Status, t.StatusReason = sdk.StatusSuspended, reason
		return nil
	})
}

func (h *Host) ResumeTenant(_ context.Context, idOrSlug string) (sdk.Tenant, error) {
	return h.mutate(idOrSlug, Action{Kind: "resume"}, func(t *sdk.Tenant) error {
		if t.Status != sdk.StatusSuspended {
			return fmt.Errorf("cannot resume a %s tenant", t.Status)
		}
		t.Status, t.StatusReason = sdk.StatusActive, ""
		return nil
	})
}

func (h *Host) SetTenantPlan(_ context.Context, idOrSlug, plan string) (sdk.Tenant, error) {
	return h.mutate(idOrSlug, Action{Kind: "set_plan", Value: plan}, func(t *sdk.Tenant) error {
		t.Plan = plan
		return nil
	})
}

func (h *Host) RecordUsage(_ context.Context, idOrSlug, metric string, delta int64) (int64, error) {
	_, err := h.mutate(idOrSlug, Action{Kind: "record_usage", Value: metric, Delta: delta}, func(*sdk.Tenant) error { return nil })
	return delta, err
}
