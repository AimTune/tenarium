// Package iac provisions per-tenant infrastructure with an
// infrastructure-as-code engine:
//
//   - terraform / opentofu: runs the CLI on a module (a local directory or a
//     remote module source) in a working directory per tenant, with local
//     state or a remote backend whose configuration is rendered per tenant.
//   - pulumi: runs the CLI on a project with one stack per tenant.
//   - crossplane: creates a Claim (namespaced) or a Composite resource
//     (cluster-scoped) per tenant from a YAML template and waits for it to
//     become Ready.
//
// Every engine receives the tenant as input (ID, slug, name, plan, labels,
// settings and entitlements) plus static variables, and exposes its
// outputs through GET /v1/plugins/{instance}/tenants/{tenant}/outputs, with
// sensitive values redacted.
//
// Runs for the same tenant are serialized, bounded by a timeout, and
// optionally repeated on tenant.updated and tenant.plan_changed so the
// infrastructure follows the tenant's plan.
//
// The plugin runs the configured module or program with the permissions of
// the Tenarium process: its configuration must be trusted.
package iac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
	"k8s.io/client-go/dynamic"
)

// PluginID is the ID the plugin registers under.
const PluginID = "iac-tenant"

func init() {
	sdk.Register(PluginID, func() sdk.Plugin { return &Plugin{} })
}

// Engines.
const (
	EngineTerraform  = "terraform"
	EngineOpenTofu   = "opentofu"
	EnginePulumi     = "pulumi"
	EngineCrossplane = "crossplane"
)

// Deprovision actions.
const (
	DeprovisionDestroy = "destroy"
	DeprovisionKeep    = "keep"
)

// Defaults.
const (
	DefaultTimeout     = 30 * time.Minute
	DefaultLogLimit    = 8 << 10
	DefaultMaxParallel = 4
)

// DefaultReapplyOn are the events that re-apply a tenant's infrastructure
// when reapply_on is not set.
var DefaultReapplyOn = []string{sdk.EventTenantUpdated, sdk.EventTenantPlanChanged}

// reapplyEvents are the events reapply_on may list.
var reapplyEvents = []string{
	sdk.EventTenantUpdated, sdk.EventTenantPlanChanged,
	sdk.EventTenantSuspended, sdk.EventTenantResumed,
}

// Config is the plugin configuration.
type Config struct {
	// Engine is terraform, opentofu, pulumi or crossplane.
	Engine string `json:"engine"`
	// Timeout bounds one provisioning or deprovisioning run, e.g. "30m".
	Timeout string `json:"timeout"`
	// OnDeprovision is "destroy" (default) or "keep".
	OnDeprovision string `json:"on_deprovision"`
	// ReapplyOn lists the tenant events that re-apply the infrastructure.
	// Unset means tenant.updated and tenant.plan_changed; [] disables it.
	ReapplyOn []string `json:"reapply_on"`
	// MaxParallel bounds concurrent runs across tenants.
	MaxParallel int `json:"max_parallel"`
	// LogLimit is the number of trailing bytes of command output kept in
	// error messages.
	LogLimit int `json:"log_limit"`
	// StateDir holds a working directory per tenant (terraform, pulumi).
	StateDir string `json:"state_dir"`
	// EnvPassthrough names environment variables of the Tenarium process
	// passed to the CLI, e.g. AWS_ACCESS_KEY_ID; a trailing "*" matches a
	// prefix ("ARM_*").
	EnvPassthrough []string `json:"env_passthrough"`
	// Env sets environment variables for the CLI.
	Env map[string]string `json:"env"`
	// Vars are static input variables. String values are templates over
	// the tenant.
	Vars map[string]any `json:"vars"`

	Terraform  *TerraformConfig  `json:"terraform"`
	Pulumi     *PulumiConfig     `json:"pulumi"`
	Crossplane *CrossplaneConfig `json:"crossplane"`
}

// TerraformConfig configures the terraform and opentofu engines.
type TerraformConfig struct {
	// Binary is the CLI path; default "terraform" or "tofu".
	Binary string `json:"binary"`
	// ModuleDir is a local module directory, copied into each tenant's
	// working directory before every run.
	ModuleDir string `json:"module_dir"`
	// ModuleSource is a module source address (git::https://..., a
	// registry module, an archive URL) fetched with init -from-module.
	ModuleSource string `json:"module_source"`
	// BackendConfig is passed to init as -backend-config=key=value; values
	// are templates over the tenant. Empty means the module's backend, by
	// default local state in the tenant's working directory.
	BackendConfig map[string]string `json:"backend_config"`
	// PluginCacheDir shares downloaded providers between tenants.
	PluginCacheDir string `json:"plugin_cache_dir"`
}

// PulumiConfig configures the pulumi engine.
type PulumiConfig struct {
	// Binary is the CLI path; default "pulumi".
	Binary string `json:"binary"`
	// ProjectDir is the directory holding Pulumi.yaml.
	ProjectDir string `json:"project_dir"`
	// BackendURL is set as PULUMI_BACKEND_URL, e.g. file:///var/lib/pulumi
	// or s3://bucket.
	BackendURL string `json:"backend_url"`
	// StackTemplate names the tenant's stack; default "tenant-{{.ID}}".
	StackTemplate string `json:"stack_template"`
	// SecretsProvider is used when a stack is created (passphrase,
	// awskms://..., ...).
	SecretsProvider string `json:"secrets_provider"`
	// KeepStack keeps the (empty) stack after destroy.
	KeepStack bool `json:"keep_stack"`
}

// CrossplaneConfig configures the crossplane engine.
type CrossplaneConfig struct {
	Kubeconfig string  `json:"kubeconfig"`
	Context    string  `json:"context"`
	QPS        float32 `json:"qps"`
	Burst      int     `json:"burst"`
	// Manifest is a YAML template of the Claim or Composite resource;
	// ManifestFile reads it from a file. Exactly one is required.
	Manifest     string `json:"manifest"`
	ManifestFile string `json:"manifest_file"`
	// Resource is the plural resource name (e.g. "postgresinstances").
	// Empty discovers it from the API server.
	Resource string `json:"resource"`
	// Wait for the Ready condition after apply and for removal after
	// delete (default true).
	Wait *bool `json:"wait"`
	// PollInterval between readiness checks, default "5s".
	PollInterval string `json:"poll_interval"`
}

const envNamePattern = `^[A-Za-z_][A-Za-z0-9_]*$`

var configSchema = json.RawMessage(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "engine": {"enum": ["terraform", "opentofu", "pulumi", "crossplane"]},
    "timeout": {"type": "string", "minLength": 1},
    "on_deprovision": {"enum": ["destroy", "keep"]},
    "reapply_on": {
      "type": "array",
      "items": {"enum": ["tenant.updated", "tenant.plan_changed", "tenant.suspended", "tenant.resumed"]},
      "uniqueItems": true
    },
    "max_parallel": {"type": "integer", "minimum": 1},
    "log_limit": {"type": "integer", "minimum": 256},
    "state_dir": {"type": "string", "minLength": 1},
    "env_passthrough": {
      "type": "array",
      "items": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*\\*?$"}
    },
    "env": {
      "type": "object",
      "propertyNames": {"pattern": "` + envNamePattern + `"},
      "additionalProperties": {"type": "string"}
    },
    "vars": {
      "type": "object",
      "propertyNames": {"pattern": "^[A-Za-z_][A-Za-z0-9_-]*$"}
    },
    "terraform": {
      "type": "object",
      "properties": {
        "binary": {"type": "string", "minLength": 1},
        "module_dir": {"type": "string", "minLength": 1},
        "module_source": {"type": "string", "minLength": 1},
        "backend_config": {"type": "object", "additionalProperties": {"type": "string"}},
        "plugin_cache_dir": {"type": "string"}
      },
      "oneOf": [{"required": ["module_dir"]}, {"required": ["module_source"]}],
      "additionalProperties": false
    },
    "pulumi": {
      "type": "object",
      "properties": {
        "binary": {"type": "string", "minLength": 1},
        "project_dir": {"type": "string", "minLength": 1},
        "backend_url": {"type": "string"},
        "stack_template": {"type": "string", "minLength": 1},
        "secrets_provider": {"type": "string"},
        "keep_stack": {"type": "boolean"}
      },
      "required": ["project_dir"],
      "additionalProperties": false
    },
    "crossplane": {
      "type": "object",
      "properties": {
        "kubeconfig": {"type": "string"},
        "context": {"type": "string"},
        "qps": {"type": "number", "minimum": 0},
        "burst": {"type": "integer", "minimum": 0},
        "manifest": {"type": "string", "minLength": 1},
        "manifest_file": {"type": "string", "minLength": 1},
        "resource": {"type": "string"},
        "wait": {"type": "boolean"},
        "poll_interval": {"type": "string", "minLength": 1}
      },
      "oneOf": [{"required": ["manifest"]}, {"required": ["manifest_file"]}],
      "additionalProperties": false
    }
  },
  "required": ["engine"],
  "allOf": [
    {"if": {"properties": {"engine": {"enum": ["terraform", "opentofu"]}}, "required": ["engine"]},
     "then": {"required": ["terraform", "state_dir"]}},
    {"if": {"properties": {"engine": {"const": "pulumi"}}, "required": ["engine"]},
     "then": {"required": ["pulumi", "state_dir"]}},
    {"if": {"properties": {"engine": {"const": "crossplane"}}, "required": ["engine"]},
     "then": {"required": ["crossplane"]}}
  ],
  "additionalProperties": false
}`)

// Engine applies and destroys one tenant's infrastructure.
type Engine interface {
	// Name identifies the engine ("terraform", "pulumi", ...).
	Name() string
	// Apply creates or updates the tenant's infrastructure and returns
	// its outputs. It must be idempotent.
	Apply(ctx context.Context, in Input) (*Result, error)
	// Destroy removes the tenant's infrastructure. It must tolerate a
	// tenant that was never provisioned.
	Destroy(ctx context.Context, in Input) error
	// Outputs returns the outputs of the last successful apply, or
	// ErrNoOutputs.
	Outputs(ctx context.Context, in Input) (*Result, error)
	// Health reports whether the engine can run (binary, cluster).
	Health(ctx context.Context) error
}

// ErrNoOutputs means the tenant has not been provisioned by the engine.
var ErrNoOutputs = errors.New("no outputs")

// Input is what an engine receives for a tenant.
type Input struct {
	Tenant       sdk.Tenant
	Entitlements sdk.Entitlements
}

// Result holds an engine's outputs.
type Result struct {
	// Outputs by name. Sensitive values are never stored or returned.
	Outputs map[string]Output `json:"outputs"`
	// ConnectionSecret lists the keys of a Crossplane connection secret.
	ConnectionSecret *ConnectionSecret `json:"connection_secret,omitempty"`
	// Ready is the Crossplane Ready condition.
	Ready     *bool     `json:"ready,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// Output is one output value.
type Output struct {
	Value     any  `json:"value,omitempty"`
	Sensitive bool `json:"sensitive,omitempty"`
	// Redacted is set when the value was withheld because it is sensitive.
	Redacted bool `json:"redacted,omitempty"`
}

// ConnectionSecret names a connection secret and its keys (never values).
type ConnectionSecret struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace,omitempty"`
	Keys      []string `json:"keys,omitempty"`
}

// Plugin is the iac-tenant plugin.
type Plugin struct {
	cfg    Config
	engine Engine
	host   sdk.Host
	log    *slog.Logger

	// runner executes CLI commands; dyn is the Kubernetes client. Both are
	// built from the configuration unless set (tests, embedding).
	runner Runner
	dyn    dynamic.Interface
	// environ returns the process environment (os.Environ).
	environ func() []string
	// lookPath resolves binaries (exec.LookPath).
	lookPath func(string) (string, error)
	now      func() time.Time

	timeout time.Duration
	sem     chan struct{}

	mu      sync.Mutex
	locks   map[string]chan struct{}
	applied map[string]int64 // tenant ID → last applied tenant version
}

// New returns a plugin that runs commands with runner and talks to
// Kubernetes with client instead of building them from the configuration.
// Either may be nil. It is meant for tests and embedding.
func New(runner Runner, client dynamic.Interface) *Plugin {
	return &Plugin{runner: runner, dyn: client}
}

func (p *Plugin) Manifest() sdk.Manifest {
	return sdk.Manifest{
		ID:           PluginID,
		Name:         "Infrastructure as Code",
		Version:      "0.1.0",
		Description:  "Provisions per-tenant infrastructure with Terraform/OpenTofu, Pulumi or Crossplane.",
		ConfigSchema: configSchema,
	}
}

func (p *Plugin) Init(ctx context.Context, r sdk.Registrar) error {
	if err := r.Config(&p.cfg); err != nil {
		return err
	}
	p.host = r.Host()
	p.log = r.Logger()
	if p.now == nil {
		p.now = time.Now
	}
	if p.environ == nil {
		p.environ = osEnviron
	}
	if p.lookPath == nil {
		p.lookPath = execLookPath
	}
	if p.runner == nil {
		p.runner = ExecRunner{}
	}
	if err := p.validate(); err != nil {
		return err
	}
	eng, err := p.buildEngine(ctx)
	if err != nil {
		return err
	}
	p.engine = eng
	p.sem = make(chan struct{}, p.cfg.MaxParallel)
	p.locks = map[string]chan struct{}{}
	p.applied = map[string]int64{}

	r.Provisioner(p)
	if len(p.cfg.ReapplyOn) > 0 {
		timeout := p.timeout + time.Minute
		r.Subscribe("reapply", sdk.EventFilter{Types: slices.Clone(p.cfg.ReapplyOn)}, p.reapply,
			sdk.WithStartAtEnd(), func(o *sdk.SubscribeOptions) { o.Timeout = timeout })
	}
	r.Route("GET /tenants/{tenant}/outputs", http.HandlerFunc(p.serveOutputs))
	return nil
}

// validate checks and defaults the engine-independent settings.
func (p *Plugin) validate() error {
	c := &p.cfg
	switch c.Engine {
	case EngineTerraform, EngineOpenTofu, EnginePulumi, EngineCrossplane:
	case "":
		return errors.New("engine is required (terraform, opentofu, pulumi or crossplane)")
	default:
		return fmt.Errorf("engine must be terraform, opentofu, pulumi or crossplane, got %q", c.Engine)
	}
	// Only the selected engine's block may be set, so a typo in engine
	// does not silently ignore the intended configuration.
	blocks := map[string]bool{
		"terraform":  c.Terraform != nil,
		"pulumi":     c.Pulumi != nil,
		"crossplane": c.Crossplane != nil,
	}
	want := c.Engine
	if want == EngineOpenTofu {
		want = "terraform"
	}
	for name, set := range blocks {
		if set && name != want {
			return fmt.Errorf("%s: not used by engine %s", name, c.Engine)
		}
		if !set && name == want {
			return fmt.Errorf("%s: required for engine %s", name, c.Engine)
		}
	}

	switch c.OnDeprovision {
	case "":
		c.OnDeprovision = DeprovisionDestroy
	case DeprovisionDestroy, DeprovisionKeep:
	default:
		return fmt.Errorf("on_deprovision must be destroy or keep, got %q", c.OnDeprovision)
	}
	p.timeout = DefaultTimeout
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("timeout: invalid duration %q", c.Timeout)
		}
		p.timeout = d
	}
	if c.ReapplyOn == nil {
		c.ReapplyOn = slices.Clone(DefaultReapplyOn)
	}
	for _, e := range c.ReapplyOn {
		if !slices.Contains(reapplyEvents, e) {
			return fmt.Errorf("reapply_on: unsupported event %q", e)
		}
	}
	if c.MaxParallel == 0 {
		c.MaxParallel = DefaultMaxParallel
	} else if c.MaxParallel < 0 {
		return errors.New("max_parallel must be positive")
	}
	if c.LogLimit == 0 {
		c.LogLimit = DefaultLogLimit
	} else if c.LogLimit < 256 {
		return errors.New("log_limit must be at least 256")
	}
	for _, name := range c.EnvPassthrough {
		if !validEnvName(strings.TrimSuffix(name, "*")) {
			return fmt.Errorf("env_passthrough: invalid name %q", name)
		}
	}
	for name := range c.Env {
		if !validEnvName(name) {
			return fmt.Errorf("env: invalid name %q", name)
		}
	}
	for name := range c.Vars {
		if !validVarName(name) {
			return fmt.Errorf("vars: invalid name %q", name)
		}
		if strings.HasPrefix(name, tenantVarPrefix) {
			return fmt.Errorf("vars: %q is reserved (names starting with %q are set from the tenant)", name, tenantVarPrefix)
		}
	}
	return nil
}

func (p *Plugin) buildEngine(ctx context.Context) (Engine, error) {
	vars, err := newVarRenderer(p.cfg.Vars)
	if err != nil {
		return nil, err
	}
	switch p.cfg.Engine {
	case EngineTerraform, EngineOpenTofu:
		return newTerraform(p, vars)
	case EnginePulumi:
		return newPulumi(p, vars)
	default:
		return newCrossplane(ctx, p)
	}
}

// Name implements sdk.Provisioner.
func (p *Plugin) Name() string { return p.cfg.Engine }

// Provision applies the tenant's infrastructure.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	unlock, err := p.lock(ctx, t.ID)
	if err != nil {
		return err
	}
	defer unlock()
	in, err := p.input(ctx, t)
	if err != nil {
		return err
	}
	start := p.now()
	res, err := p.engine.Apply(ctx, in)
	if err != nil {
		return fmt.Errorf("%s apply for tenant %s: %w", p.engine.Name(), t.ID, timeoutErr(ctx, err, p.timeout))
	}
	p.mu.Lock()
	if t.Version > p.applied[t.ID] {
		p.applied[t.ID] = t.Version
	}
	p.mu.Unlock()
	n := 0
	if res != nil {
		n = len(res.Outputs)
	}
	p.log.Info("applied tenant infrastructure", "tenant_id", t.ID, "engine", p.engine.Name(),
		"outputs", n, "duration", p.now().Sub(start).Round(time.Millisecond))
	return nil
}

// Deprovision destroys the tenant's infrastructure, or keeps it with
// on_deprovision: keep.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		p.log.Info("keeping tenant infrastructure", "tenant_id", t.ID, "engine", p.engine.Name())
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	unlock, err := p.lock(ctx, t.ID)
	if err != nil {
		return err
	}
	defer unlock()
	in, err := p.input(ctx, t)
	if err != nil {
		return err
	}
	if err := p.engine.Destroy(ctx, in); err != nil {
		return fmt.Errorf("%s destroy for tenant %s: %w", p.engine.Name(), t.ID, timeoutErr(ctx, err, p.timeout))
	}
	p.mu.Lock()
	delete(p.applied, t.ID)
	p.mu.Unlock()
	p.log.Info("destroyed tenant infrastructure", "tenant_id", t.ID, "engine", p.engine.Name())
	return nil
}

func timeoutErr(ctx context.Context, err error, d time.Duration) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("timed out after %s: %w", d, err)
	}
	return err
}

// input gathers what the engine needs for t.
func (p *Plugin) input(ctx context.Context, t sdk.Tenant) (Input, error) {
	ent, err := p.host.Entitlements(ctx, t.ID)
	if errors.Is(err, sdk.ErrNotFound) {
		// Deprovisioning a tenant that is already gone: use its own values.
		ent = sdk.ComputeEntitlements(t, nil)
	} else if err != nil {
		return Input{}, fmt.Errorf("entitlements of tenant %s: %w", t.ID, err)
	}
	return Input{Tenant: t, Entitlements: ent}, nil
}

// lock serializes runs for one tenant and bounds concurrent runs overall.
func (p *Plugin) lock(ctx context.Context, tenantID string) (func(), error) {
	p.mu.Lock()
	l, ok := p.locks[tenantID]
	if !ok {
		l = make(chan struct{}, 1)
		p.locks[tenantID] = l
	}
	p.mu.Unlock()
	select {
	case l <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for another run of tenant %s: %w", tenantID, ctx.Err())
	}
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		<-l
		return nil, fmt.Errorf("waiting for a free run slot (max_parallel %d): %w", cap(p.sem), ctx.Err())
	}
	return func() { <-p.sem; <-l }, nil
}

// reapply re-applies a tenant's infrastructure after a tenant event.
//
// Events are delivered at least once and may be replayed, so the handler
// acts on the tenant's current state and skips versions already applied.
func (p *Plugin) reapply(ctx context.Context, e sdk.Event) error {
	var data sdk.TenantEventData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return fmt.Errorf("decode %s event: %w", e.Type, err)
	}
	id := data.Tenant.ID
	if id == "" {
		id = e.TenantID
	}
	if id == "" {
		return nil
	}
	t, err := p.host.GetTenant(ctx, id)
	if errors.Is(err, sdk.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	// Only provisioned tenants: provisioning, failed and deleting tenants
	// belong to the provisioner.
	if t.Status != sdk.StatusActive && t.Status != sdk.StatusSuspended {
		return nil
	}
	p.mu.Lock()
	done := p.applied[t.ID] >= t.Version && t.Version > 0
	p.mu.Unlock()
	if done {
		return nil
	}
	return p.Provision(ctx, t)
}

// OutputsResponse is the body of GET /tenants/{tenant}/outputs.
type OutputsResponse struct {
	TenantID string `json:"tenant_id"`
	Engine   string `json:"engine"`
	Result
}

func (p *Plugin) serveOutputs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := p.host.GetTenant(ctx, r.PathValue("tenant"))
	if errors.Is(err, sdk.ErrNotFound) {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Answer "not found" rather than "forbidden" so callers cannot probe
	// other tenants' slugs.
	res := sdk.Resource{Type: "tenant", ID: t.ID, TenantID: t.ID}
	if err := p.host.Authorize(ctx, sdk.ActionTenantsRead, res); err != nil {
		http.Error(w, "tenant not found", http.StatusNotFound)
		return
	}
	in, err := p.input(ctx, t)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out, err := p.engine.Outputs(ctx, in)
	if errors.Is(err, ErrNoOutputs) {
		http.Error(w, "no outputs: the tenant has not been provisioned by this plugin", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	body := OutputsResponse{TenantID: t.ID, Engine: p.engine.Name(), Result: *out}
	if body.Outputs == nil {
		body.Outputs = map[string]Output{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// Health reports whether the engine can run.
func (p *Plugin) Health(ctx context.Context) error {
	if p.engine == nil {
		return errors.New("not initialized")
	}
	return p.engine.Health(ctx)
}

var (
	_ sdk.Plugin        = (*Plugin)(nil)
	_ sdk.Provisioner   = (*Plugin)(nil)
	_ sdk.HealthChecker = (*Plugin)(nil)
)
