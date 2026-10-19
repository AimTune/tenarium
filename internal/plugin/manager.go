// Package plugin loads plugins, collects what they register and runs hooks.
package plugin

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/AimTune/tenarium/internal/events"
	"github.com/AimTune/tenarium/internal/metrics"
	"github.com/AimTune/tenarium/internal/schema"
	"github.com/AimTune/tenarium/internal/tenant"
	"github.com/AimTune/tenarium/pkg/sdk"
)

// Spec configures one plugin instance. The same plugin may be instantiated
// several times under different names (e.g. two webhook targets).
type Spec struct {
	// Plugin is the registered plugin ID.
	Plugin string `yaml:"plugin" json:"plugin"`
	// Name identifies the instance; defaults to Plugin. It prefixes
	// subscription names and the HTTP route mount point.
	Name    string `yaml:"name" json:"name"`
	Enabled *bool  `yaml:"enabled" json:"enabled"`
	// Scope limits the instance to some tenants. Nil means all tenants.
	Scope  *Scope         `yaml:"scope" json:"scope,omitempty"`
	Config map[string]any `yaml:"config" json:"config"`
}

func (s Spec) instanceName() string { return cmp.Or(s.Name, s.Plugin) }

// Scope selects tenants a plugin instance applies to. All set criteria must
// match. Scoping applies to event subscriptions (tenant events only),
// hooks and provisioning; deprovisioning always runs, so resources are
// cleaned up even if a tenant left the scope after being provisioned.
type Scope struct {
	Plans   []string          `yaml:"plans" json:"plans,omitempty"`
	Labels  map[string]string `yaml:"labels" json:"labels,omitempty"`
	Tenants []string          `yaml:"tenants" json:"tenants,omitempty"` // IDs or slugs
	Regions []string          `yaml:"regions" json:"regions,omitempty"`
}

// Matches reports whether t is in scope. A nil scope matches everything.
func (s *Scope) Matches(t sdk.Tenant) bool {
	if s == nil {
		return true
	}
	if len(s.Plans) > 0 && !slices.Contains(s.Plans, t.Plan) {
		return false
	}
	for k, v := range s.Labels {
		if hv, ok := t.Labels[k]; !ok || hv != v {
			return false
		}
	}
	if len(s.Regions) > 0 && !slices.Contains(s.Regions, t.Region) {
		return false
	}
	if len(s.Tenants) > 0 && !slices.Contains(s.Tenants, t.ID) && !slices.Contains(s.Tenants, t.Slug) {
		return false
	}
	return true
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Info describes a loaded plugin instance.
type Info struct {
	Name           string       `json:"name"`
	Manifest       sdk.Manifest `json:"manifest"`
	Scope          *Scope       `json:"scope,omitempty"`
	Subscriptions  []string     `json:"subscriptions,omitempty"`
	Hooks          []string     `json:"hooks,omitempty"`
	Provisioners   []string     `json:"provisioners,omitempty"`
	Routes         []string     `json:"routes,omitempty"`
	Authenticators []string     `json:"authenticators,omitempty"`
	Authorizers    []string     `json:"authorizers,omitempty"`
	UserDirectory  string       `json:"user_directory,omitempty"`
	Mailer         string       `json:"mailer,omitempty"`
}

// Route is an HTTP handler contributed by a plugin instance.
type Route struct {
	Instance string
	Pattern  string
	Handler  http.Handler
	// Public routes skip authentication; see sdk.Registrar.PublicRoute.
	Public bool
}

// AuthenticatorRef is an authenticator with its qualified name
// "{instance}/{name}".
type AuthenticatorRef struct {
	Name          string
	Authenticator sdk.Authenticator
}

// AuthorizerRef is an authorizer with its qualified name.
type AuthorizerRef struct {
	Name       string
	Authorizer sdk.Authorizer
}

type instance struct {
	info   Info
	plugin sdk.Plugin
	spec   Spec
}

type hookEntry struct {
	instance string
	priority int
	seq      int
	scope    *Scope
	handler  sdk.HookHandler
}

// Manager owns all plugin instances. It is configured once via Load and is
// read-only afterwards, so it needs no locking.
type Manager struct {
	log     *slog.Logger
	host    sdk.Host
	metrics *metrics.Metrics

	instances    []*instance
	hooks        map[sdk.HookPoint][]hookEntry
	hookSeq      int
	provisioners []tenant.ProvisionerRef
	subs         []events.Subscription
	routes       []Route
	authns       []AuthenticatorRef
	authzs       []AuthorizerRef
	directories  map[string]sdk.UserDirectory // by instance name
	mailers      map[string]sdk.Mailer        // by instance name
}

func NewManager(log *slog.Logger, host sdk.Host, m *metrics.Metrics) *Manager {
	if m == nil {
		m = metrics.New()
	}
	return &Manager{log: log, host: host, metrics: m, hooks: map[sdk.HookPoint][]hookEntry{}}
}

// Load instantiates and initialises the enabled plugins in the given order.
// Order matters: it is the order provisioners run in.
func (m *Manager) Load(ctx context.Context, specs []Spec) error {
	seen := map[string]bool{}
	for _, spec := range specs {
		if spec.Enabled != nil && !*spec.Enabled {
			continue
		}
		name := spec.instanceName()
		if !nameRe.MatchString(name) {
			return fmt.Errorf("plugin instance name %q is invalid", name)
		}
		if seen[name] {
			return fmt.Errorf("plugin instance %q configured twice; set a distinct name", name)
		}
		seen[name] = true

		factory, ok := sdk.Lookup(spec.Plugin)
		if !ok {
			return fmt.Errorf("plugin %q is not compiled into this binary (available: %s)",
				spec.Plugin, strings.Join(sdk.Registered(), ", "))
		}
		if err := m.initInstance(ctx, name, factory(), spec); err != nil {
			return fmt.Errorf("plugin %q: %w", name, err)
		}
	}
	return nil
}

func (m *Manager) initInstance(ctx context.Context, name string, p sdk.Plugin, spec Spec) (err error) {
	manifest := p.Manifest()
	if len(manifest.ConfigSchema) > 0 {
		sch, err := schema.Compile(manifest.ConfigSchema)
		if err != nil {
			return fmt.Errorf("plugin ships an invalid config schema: %w", err)
		}
		cfg := spec.Config
		if cfg == nil {
			cfg = map[string]any{}
		}
		if err := sch.Validate(cfg); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}
	}
	inst := &instance{plugin: p, spec: spec, info: Info{Name: name, Manifest: manifest, Scope: spec.Scope}}
	r := &registrar{m: m, inst: inst, cfg: spec.Config, scope: spec.Scope, log: m.log.With("plugin", name)}
	defer func() {
		r.closed = true
		if rec := recover(); rec != nil {
			err = fmt.Errorf("init panic: %v\n%s", rec, debug.Stack())
		}
	}()
	err = p.Init(ctx, r)
	if err == nil && r.routeErr != nil {
		err = r.routeErr
	}
	if err != nil {
		if s, ok := p.(sdk.Stopper); ok {
			_ = s.Stop(ctx)
		}
		return err
	}
	// Some plugins (e.g. external) only know their real manifest after Init.
	inst.info.Manifest = p.Manifest()
	inst.info.Manifest.ConfigSchema = nil
	m.instances = append(m.instances, inst)
	r.commit()
	m.log.Info("plugin loaded", "plugin", name, "id", inst.info.Manifest.ID, "version", inst.info.Manifest.Version)
	return nil
}

func (m *Manager) Infos() []Info {
	out := make([]Info, len(m.instances))
	for i, inst := range m.instances {
		out[i] = inst.info
	}
	return out
}

func (m *Manager) Subscriptions() []events.Subscription  { return m.subs }
func (m *Manager) Provisioners() []tenant.ProvisionerRef { return m.provisioners }
func (m *Manager) Routes() []Route                       { return m.routes }
func (m *Manager) Authenticators() []AuthenticatorRef    { return m.authns }
func (m *Manager) Authorizers() []AuthorizerRef          { return m.authzs }

// UserDirectories returns user directories by plugin instance name.
func (m *Manager) UserDirectories() map[string]sdk.UserDirectory { return m.directories }

// Mailers returns mailers by plugin instance name.
func (m *Manager) Mailers() map[string]sdk.Mailer { return m.mailers }

// RunHooks implements tenant.HookRunner.
func (m *Manager) RunHooks(ctx context.Context, req *sdk.HookRequest) error {
	for _, h := range m.hooks[req.Point] {
		if req.Tenant != nil && !h.scope.Matches(*req.Tenant) {
			continue
		}
		if err := callHook(ctx, h, req); err != nil {
			if _, ok := sdk.IsReject(err); ok {
				m.metrics.HookRejections.WithLabelValues(string(req.Point), h.instance).Inc()
				return err
			}
			return fmt.Errorf("hook %s (plugin %s): %w", req.Point, h.instance, err)
		}
	}
	return nil
}

func callHook(ctx context.Context, h hookEntry, req *sdk.HookRequest) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	return h.handler(ctx, req)
}

// Health returns the health error of every plugin implementing
// sdk.HealthChecker, keyed by instance name.
func (m *Manager) Health(ctx context.Context) map[string]error {
	out := map[string]error{}
	for _, inst := range m.instances {
		if hc, ok := inst.plugin.(sdk.HealthChecker); ok {
			out[inst.info.Name] = hc.Health(ctx)
		}
	}
	return out
}

// Stop stops plugins in reverse load order.
func (m *Manager) Stop(ctx context.Context) error {
	var errs []error
	for _, inst := range slices.Backward(m.instances) {
		if s, ok := inst.plugin.(sdk.Stopper); ok {
			if err := s.Stop(ctx); err != nil {
				errs = append(errs, fmt.Errorf("plugin %s: %w", inst.info.Name, err))
			}
		}
	}
	return errors.Join(errs...)
}

// scopedHandler skips tenant events for tenants outside the scope. Events
// carrying the previous state also reach scopes the tenant just left (a
// move out of a region, a plan change), so those instances can clean up.
func (m *Manager) scopedHandler(scope *Scope, h sdk.EventHandler) sdk.EventHandler {
	if scope == nil {
		return h
	}
	return func(ctx context.Context, e sdk.Event) error {
		if e.TenantID == "" {
			return h(ctx, e)
		}
		t, prev, err := m.eventTenant(ctx, e)
		if err != nil {
			return err
		}
		if !scope.Matches(t) && (prev == nil || !scope.Matches(*prev)) {
			return nil
		}
		return h(ctx, e)
	}
}

// eventTenant prefers the snapshot carried by tenant.* events, so scoping
// reflects the tenant as it was when the event happened.
func (m *Manager) eventTenant(ctx context.Context, e sdk.Event) (sdk.Tenant, *sdk.Tenant, error) {
	var data sdk.TenantEventData
	if json.Unmarshal(e.Data, &data) == nil && data.Tenant.ID == e.TenantID {
		return data.Tenant, data.Previous, nil
	}
	t, err := m.host.GetTenant(ctx, e.TenantID)
	return t, nil, err
}

// scopedProvisioner provisions only tenants in scope. Deprovision always
// runs; provisioners must treat unknown tenants as a no-op.
type scopedProvisioner struct {
	sdk.Provisioner
	scope *Scope
}

func (p scopedProvisioner) Provision(ctx context.Context, t sdk.Tenant) error {
	if !p.scope.Matches(t) {
		return nil
	}
	return p.Provisioner.Provision(ctx, t)
}

// registrar buffers registrations and only commits them if Init succeeds,
// so a failing plugin leaves no half-registered state behind.
type registrar struct {
	m      *Manager
	inst   *instance
	cfg    map[string]any
	scope  *Scope
	log    *slog.Logger
	closed bool

	hooks []struct {
		point sdk.HookPoint
		entry hookEntry
	}
	provisioners []tenant.ProvisionerRef
	subs         []events.Subscription
	routes       []Route
	authns       []AuthenticatorRef
	authzs       []AuthorizerRef
	directory    sdk.UserDirectory
	mailer       sdk.Mailer
	// routeErr records an invalid route pattern (Route cannot return errors).
	routeErr error
}

var _ sdk.Registrar = (*registrar)(nil)

// UserDirectory registers the instance's directory (at most one).
func (r *registrar) UserDirectory(d sdk.UserDirectory) {
	r.check()
	r.directory = d
	r.inst.info.UserDirectory = d.Name()
}

// Mailer registers the instance's mailer (at most one).
func (r *registrar) Mailer(m sdk.Mailer) {
	r.check()
	r.mailer = m
	r.inst.info.Mailer = m.Name()
}

func (r *registrar) check() {
	if r.closed {
		panic("sdk.Registrar used after Init returned")
	}
}

func (r *registrar) Config(v any) error { return decodeConfig(r.cfg, v) }

func decodeConfig(cfg map[string]any, v any) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if string(raw) == "null" {
		raw = []byte("{}")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	return nil
}

func (r *registrar) Logger() *slog.Logger { return r.log }
func (r *registrar) Host() sdk.Host       { return pluginHost{Host: r.m.host, instance: r.inst.info.Name} }
func (r *registrar) InstanceName() string { return r.inst.info.Name }

func (r *registrar) Subscribe(name string, filter sdk.EventFilter, h sdk.EventHandler, opts ...sdk.SubscribeOption) {
	r.check()
	o := sdk.DefaultSubscribeOptions()
	for _, opt := range opts {
		opt(&o)
	}
	full := r.inst.info.Name + "/" + name
	var regions []string
	if r.scope != nil {
		regions = r.scope.Regions
	}
	r.subs = append(r.subs, events.Subscription{Name: full, Filter: filter, Handler: r.m.scopedHandler(r.scope, h), Options: o, Regions: regions})
	r.inst.info.Subscriptions = append(r.inst.info.Subscriptions, full)
}

func (r *registrar) Hook(point sdk.HookPoint, h sdk.HookHandler, opts ...sdk.HookOption) {
	r.check()
	if !slices.Contains(sdk.HookPoints, point) {
		panic(fmt.Sprintf("sdk: unknown hook point %q", point))
	}
	var o sdk.HookOptions
	for _, opt := range opts {
		opt(&o)
	}
	r.hooks = append(r.hooks, struct {
		point sdk.HookPoint
		entry hookEntry
	}{point, hookEntry{instance: r.inst.info.Name, priority: o.Priority, scope: r.scope, handler: h}})
	r.inst.info.Hooks = append(r.inst.info.Hooks, string(point))
}

func (r *registrar) Provisioner(p sdk.Provisioner) {
	r.check()
	if r.scope != nil {
		p = scopedProvisioner{Provisioner: p, scope: r.scope}
	}
	ref := tenant.ProvisionerRef{Plugin: r.inst.info.Name, Provisioner: p}
	r.provisioners = append(r.provisioners, ref)
	r.inst.info.Provisioners = append(r.inst.info.Provisioners, ref.String())
}

func (r *registrar) Route(pattern string, h http.Handler) {
	r.check()
	r.addRoute(Route{Instance: r.inst.info.Name, Pattern: pattern, Handler: h}, pattern)
}

func (r *registrar) PublicRoute(pattern string, h http.Handler) {
	r.check()
	r.addRoute(Route{Instance: r.inst.info.Name, Pattern: pattern, Handler: h, Public: true}, "public: "+pattern)
}

// addRoute validates the pattern before accepting it: http.ServeMux panics
// on invalid or conflicting patterns, which must fail the plugin's Init,
// not crash the server when routes are mounted.
func (r *registrar) addRoute(rt Route, label string) {
	mux := http.NewServeMux()
	for _, prev := range r.routes {
		if prev.Public == rt.Public {
			mux.Handle(prev.Pattern, http.NotFoundHandler())
		}
	}
	if err := tryHandle(mux, rt.Pattern); err != nil {
		if r.routeErr == nil {
			r.routeErr = fmt.Errorf("route %q: %w", rt.Pattern, err)
		}
		return
	}
	r.routes = append(r.routes, rt)
	r.inst.info.Routes = append(r.inst.info.Routes, label)
}

func tryHandle(mux *http.ServeMux, pattern string) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("%v", rec)
		}
	}()
	if strings.TrimSpace(pattern) == "" {
		return errors.New("empty pattern")
	}
	mux.Handle(pattern, http.NotFoundHandler())
	return nil
}

func (r *registrar) Authenticator(a sdk.Authenticator) {
	r.check()
	ref := AuthenticatorRef{Name: r.inst.info.Name + "/" + a.Name(), Authenticator: a}
	r.authns = append(r.authns, ref)
	r.inst.info.Authenticators = append(r.inst.info.Authenticators, ref.Name)
}

func (r *registrar) Authorizer(a sdk.Authorizer) {
	r.check()
	ref := AuthorizerRef{Name: r.inst.info.Name + "/" + a.Name(), Authorizer: a}
	r.authzs = append(r.authzs, ref)
	r.inst.info.Authorizers = append(r.inst.info.Authorizers, ref.Name)
}

func (r *registrar) commit() {
	m := r.m
	for _, h := range r.hooks {
		h.entry.seq = m.hookSeq
		m.hookSeq++
		m.hooks[h.point] = append(m.hooks[h.point], h.entry)
		slices.SortStableFunc(m.hooks[h.point], func(a, b hookEntry) int {
			return cmp.Or(cmp.Compare(a.priority, b.priority), cmp.Compare(a.seq, b.seq))
		})
	}
	m.provisioners = append(m.provisioners, r.provisioners...)
	m.subs = append(m.subs, r.subs...)
	m.routes = append(m.routes, r.routes...)
	m.authns = append(m.authns, r.authns...)
	m.authzs = append(m.authzs, r.authzs...)
	if r.directory != nil {
		if m.directories == nil {
			m.directories = map[string]sdk.UserDirectory{}
		}
		m.directories[r.inst.info.Name] = r.directory
	}
	if r.mailer != nil {
		if m.mailers == nil {
			m.mailers = map[string]sdk.Mailer{}
		}
		m.mailers[r.inst.info.Name] = r.mailer
	}
}

// ErrRestartRequired means a plugin change cannot be applied while
// running.
var ErrRestartRequired = errors.New("restart required")

// Reconfigure applies spec to the running instance of the same name when
// only its config changed and the plugin implements sdk.Reconfigurer. It
// returns ErrRestartRequired for anything else.
func (m *Manager) Reconfigure(ctx context.Context, spec Spec) error {
	name := spec.instanceName()
	var inst *instance
	for _, in := range m.instances {
		if in.info.Name == name {
			inst = in
		}
	}
	if inst == nil || inst.spec.Plugin != spec.Plugin || !reflect.DeepEqual(inst.spec.Scope, spec.Scope) ||
		!reflect.DeepEqual(inst.spec.Enabled, spec.Enabled) {
		return ErrRestartRequired
	}
	if reflect.DeepEqual(inst.spec.Config, spec.Config) {
		return nil
	}
	rc, ok := inst.plugin.(sdk.Reconfigurer)
	if !ok {
		return ErrRestartRequired
	}
	cfg := spec.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	if s := inst.info.Manifest.ConfigSchema; len(s) > 0 {
		sch, err := schema.Compile(s)
		if err != nil {
			return err
		}
		if err := sch.Validate(cfg); err != nil {
			return fmt.Errorf("invalid config: %w", err)
		}
	}
	if err := rc.Reconfigure(ctx, func(v any) error { return decodeConfig(spec.Config, v) }); err != nil {
		return err
	}
	inst.spec.Config = spec.Config
	return nil
}
