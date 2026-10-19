package iac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
)

// terraform runs the terraform or tofu CLI. Each tenant has a working
// directory <state_dir>/<tenant-id> holding a fresh copy of the module,
// the .terraform directory and, without a remote backend, the state.
type terraform struct {
	cli
	name     string
	stateDir string
	// moduleDir is copied into the working directory before each run;
	// moduleSource is fetched with init -from-module before each run.
	moduleDir    string
	moduleSource string
	backend      map[string]*template.Template
	cacheDir     string
	vars         *varRenderer
}

// keepFiles survive the cleanup of a working directory between runs.
var keepFiles = []string{
	".terraform", ".terraform.lock.hcl",
	"terraform.tfstate", "terraform.tfstate.backup", "terraform.tfstate.d",
	metaDir,
}

const tfVarsFile = "vars.tfvars.json"

func newTerraform(p *Plugin, vars *varRenderer) (*terraform, error) {
	c := p.cfg.Terraform
	e := &terraform{name: p.cfg.Engine, vars: vars, backend: map[string]*template.Template{}}
	e.p = p
	e.binary = c.Binary
	if e.binary == "" {
		e.binary = "terraform"
		if e.name == EngineOpenTofu {
			e.binary = "tofu"
		}
	}
	switch {
	case c.ModuleDir != "" && c.ModuleSource != "":
		return nil, errors.New("terraform: set only one of module_dir and module_source")
	case c.ModuleDir != "":
		dir, err := checkDir("terraform.module_dir", c.ModuleDir)
		if err != nil {
			return nil, err
		}
		e.moduleDir = dir
	case c.ModuleSource != "":
		e.moduleSource = c.ModuleSource
	default:
		return nil, errors.New("terraform: module_dir or module_source is required")
	}
	var err error
	if e.stateDir, err = prepareStateDir(p.cfg.StateDir); err != nil {
		return nil, err
	}
	if e.moduleDir != "" && isWithin(e.moduleDir, e.stateDir) {
		return nil, errors.New("terraform: state_dir must not be inside module_dir")
	}
	if c.PluginCacheDir != "" {
		if e.cacheDir, err = filepath.Abs(c.PluginCacheDir); err != nil {
			return nil, fmt.Errorf("terraform.plugin_cache_dir: %w", err)
		}
		if err := os.MkdirAll(e.cacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("terraform.plugin_cache_dir: %w", err)
		}
	}
	for k, v := range c.BackendConfig {
		if k == "" || strings.ContainsAny(k, "= \t\n") {
			return nil, fmt.Errorf("terraform.backend_config: invalid key %q", k)
		}
		t, err := parseTemplate("terraform.backend_config."+k, v)
		if err != nil {
			return nil, err
		}
		e.backend[k] = t
	}
	if len(e.backend) > 0 {
		// With a remote backend, tenants would share state unless the
		// backend configuration depends on the tenant.
		a, err := e.backendArgs(sampleInputs[0])
		if err != nil {
			return nil, err
		}
		b, err := e.backendArgs(sampleInputs[1])
		if err != nil {
			return nil, err
		}
		if slices.Equal(a, b) {
			return nil, errors.New(`terraform.backend_config must depend on the tenant (e.g. key: "tenants/{{.ID}}.tfstate"), or tenants would share state`)
		}
	}
	return e, nil
}

func isWithin(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func (e *terraform) Name() string { return e.name }

func (e *terraform) Health(ctx context.Context) error { return e.health(ctx) }

func (e *terraform) env() []string {
	env := map[string]string{
		"TF_IN_AUTOMATION":   "1",
		"TF_INPUT":           "0",
		"CHECKPOINT_DISABLE": "1",
	}
	if e.cacheDir != "" {
		env["TF_PLUGIN_CACHE_DIR"] = e.cacheDir
	}
	return e.p.buildEnv(env)
}

// backendArgs renders -backend-config arguments, sorted by key.
func (e *terraform) backendArgs(in Input) ([]string, error) {
	d := templateData(in)
	var args []string
	for _, k := range slices.Sorted(maps.Keys(e.backend)) {
		v, err := render(e.backend[k], d)
		if err != nil {
			return nil, err
		}
		args = append(args, "-backend-config="+k+"="+v)
	}
	return args, nil
}

// prepare refreshes the module in the tenant's working directory, writes
// the variables and runs init. It returns the variables file path.
func (e *terraform) prepare(ctx context.Context, dir string, in Input, env []string) (string, error) {
	if err := os.MkdirAll(filepath.Join(dir, metaDir), 0o700); err != nil {
		return "", err
	}
	// Remove the previous copy of the module so files deleted from it do
	// not linger; state and provider caches are kept.
	if err := cleanDir(dir, keepFiles); err != nil {
		return "", fmt.Errorf("clean working directory: %w", err)
	}
	if e.moduleDir != "" {
		if err := copyTree(e.moduleDir, dir, skipModuleFile); err != nil {
			return "", fmt.Errorf("copy module: %w", err)
		}
	}
	if e.moduleSource != "" {
		if err := e.fetch(ctx, dir, in, env); err != nil {
			return "", err
		}
	}
	vars, err := e.vars.render(in)
	if err != nil {
		return "", err
	}
	varsPath := filepath.Join(dir, metaDir, tfVarsFile)
	if err := writeJSON(varsPath, vars); err != nil {
		return "", fmt.Errorf("write variables: %w", err)
	}
	backend, err := e.backendArgs(in)
	if err != nil {
		return "", err
	}
	args := append([]string{"init", "-input=false", "-no-color"}, backend...)
	if _, err := e.run(ctx, dir, env, args...); err != nil {
		return "", err
	}
	return varsPath, nil
}

// fetch downloads module_source. init -from-module only populates an
// empty directory, so the module is fetched into a temporary directory
// under state_dir (without a backend) and copied into the working
// directory, which keeps its state and .terraform.
func (e *terraform) fetch(ctx context.Context, dir string, in Input, env []string) error {
	tmp, err := os.MkdirTemp(e.stateDir, ".fetch-"+in.Tenant.ID+"-")
	if err != nil {
		return fmt.Errorf("fetch module: %w", err)
	}
	defer os.RemoveAll(tmp)
	if _, err := e.run(ctx, tmp, env, "init", "-input=false", "-no-color", "-backend=false",
		"-from-module="+e.moduleSource); err != nil {
		return err
	}
	if err := copyTree(tmp, dir, skipModuleFile); err != nil {
		return fmt.Errorf("copy module: %w", err)
	}
	return nil
}

// skipModuleFile leaves state, provider caches and VCS data out of module
// copies.
func skipModuleFile(rel string, isDir bool) bool {
	base := filepath.Base(rel)
	if isDir {
		return base == ".terraform" || base == ".git" || base == metaDir || base == "terraform.tfstate.d"
	}
	return strings.HasPrefix(base, "terraform.tfstate") || strings.HasSuffix(base, ".tfstate") ||
		strings.HasSuffix(base, ".tfstate.backup")
}

func (e *terraform) Apply(ctx context.Context, in Input) (*Result, error) {
	dir, err := tenantDir(e.stateDir, in.Tenant.ID)
	if err != nil {
		return nil, err
	}
	env := e.env()
	varsPath, err := e.prepare(ctx, dir, in, env)
	if err != nil {
		return nil, err
	}
	if _, err := e.run(ctx, dir, env, "apply", "-auto-approve", "-input=false", "-no-color", "-var-file="+varsPath); err != nil {
		return nil, err
	}
	res, err := e.run(ctx, dir, env, "output", "-json", "-no-color")
	if err != nil {
		return nil, err
	}
	out, err := parseTerraformOutputs(res.Stdout)
	if err != nil {
		return nil, err
	}
	result := &Result{Outputs: out, UpdatedAt: e.p.now().UTC()}
	if err := saveOutputs(dir, result); err != nil {
		return nil, fmt.Errorf("save outputs: %w", err)
	}
	return result, nil
}

func (e *terraform) Destroy(ctx context.Context, in Input) error {
	dir, err := tenantDir(e.stateDir, in.Tenant.ID)
	if err != nil {
		return err
	}
	ok, err := exists(dir)
	if err != nil {
		return err
	}
	if len(e.backend) == 0 {
		// Local state: without a state file there is nothing to destroy.
		state, err := exists(filepath.Join(dir, "terraform.tfstate"))
		if err != nil {
			return err
		}
		if !state {
			if ok {
				return os.RemoveAll(dir)
			}
			return nil
		}
	}
	// With a remote backend the state may exist even if the working
	// directory does not (another replica, a lost disk): init and destroy.
	env := e.env()
	varsPath, err := e.prepare(ctx, dir, in, env)
	if err != nil {
		return err
	}
	if _, err := e.run(ctx, dir, env, "destroy", "-auto-approve", "-input=false", "-no-color", "-var-file="+varsPath); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func (e *terraform) Outputs(_ context.Context, in Input) (*Result, error) {
	dir, err := tenantDir(e.stateDir, in.Tenant.ID)
	if err != nil {
		return nil, err
	}
	return loadOutputs(dir)
}

// parseTerraformOutputs decodes `output -json`, dropping sensitive values.
func parseTerraformOutputs(b []byte) (map[string]Output, error) {
	var raw map[string]struct {
		Sensitive bool            `json:"sensitive"`
		Value     json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("decode outputs: %w", err)
	}
	out := make(map[string]Output, len(raw))
	for name, o := range raw {
		if o.Sensitive {
			out[name] = Output{Sensitive: true, Redacted: true}
			continue
		}
		var v any
		if len(o.Value) > 0 {
			if err := json.Unmarshal(o.Value, &v); err != nil {
				return nil, fmt.Errorf("decode output %s: %w", name, err)
			}
		}
		out[name] = Output{Value: v}
	}
	return out, nil
}
