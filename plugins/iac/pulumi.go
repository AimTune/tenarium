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

// pulumi runs the pulumi CLI in the project directory with one stack per
// tenant. Every command names the stack explicitly (--stack), so runs for
// different tenants do not depend on the workspace's current stack, and
// the stack configuration lives in the tenant's directory
// (<state_dir>/<tenant-id>/Pulumi.<stack>.yaml, via --config-file) so the
// project directory is not modified per tenant.
type pulumi struct {
	cli
	projectDir      string
	stateDir        string
	backendURL      string
	secretsProvider string
	keepStack       bool
	stack           *template.Template
	vars            *varRenderer
}

// DefaultStackTemplate names a tenant's stack when stack_template is unset.
const DefaultStackTemplate = "tenant-{{.ID}}"

// pulumiSecret is how `pulumi stack output --json` shows secret outputs
// without --show-secrets.
const pulumiSecret = "[secret]"

const pulumiKeysFile = "pulumi-config-keys.json"

func newPulumi(p *Plugin, vars *varRenderer) (*pulumi, error) {
	c := p.cfg.Pulumi
	e := &pulumi{vars: vars, backendURL: c.BackendURL, secretsProvider: c.SecretsProvider, keepStack: c.KeepStack}
	e.p = p
	e.binary = c.Binary
	if e.binary == "" {
		e.binary = "pulumi"
	}
	if c.ProjectDir == "" {
		return nil, errors.New("pulumi.project_dir is required")
	}
	dir, err := checkDir("pulumi.project_dir", c.ProjectDir)
	if err != nil {
		return nil, err
	}
	found := false
	for _, name := range []string{"Pulumi.yaml", "Pulumi.yml"} {
		if ok, _ := exists(filepath.Join(dir, name)); ok {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("pulumi.project_dir: no Pulumi.yaml in %s", dir)
	}
	e.projectDir = dir
	if e.stateDir, err = prepareStateDir(p.cfg.StateDir); err != nil {
		return nil, err
	}
	st := c.StackTemplate
	if st == "" {
		st = DefaultStackTemplate
	}
	if e.stack, err = parseTemplate("pulumi.stack_template", st); err != nil {
		return nil, err
	}
	a, err := e.stackName(sampleInputs[0])
	if err != nil {
		return nil, err
	}
	b, err := e.stackName(sampleInputs[1])
	if err != nil {
		return nil, err
	}
	if a == b {
		return nil, errors.New("pulumi.stack_template must depend on the tenant (e.g. tenant-{{.ID}})")
	}
	return e, nil
}

func (e *pulumi) Name() string { return EnginePulumi }

func (e *pulumi) Health(ctx context.Context) error { return e.health(ctx) }

// stackName renders the tenant's stack name, keeping the characters Pulumi
// allows ([A-Za-z0-9_.-]).
func (e *pulumi) stackName(in Input) (string, error) {
	s, err := render(e.stack, templateData(in))
	if err != nil {
		return "", err
	}
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return '-'
	}, s)
	name = strings.Trim(name, "-.")
	if name == "" {
		return "", fmt.Errorf("pulumi.stack_template renders an empty stack name for tenant %q", in.Tenant.ID)
	}
	if len(name) > 100 {
		return "", fmt.Errorf("pulumi.stack_template renders a stack name longer than 100 characters for tenant %q", in.Tenant.ID)
	}
	return name, nil
}

func (e *pulumi) env() []string {
	env := map[string]string{
		"PULUMI_SKIP_UPDATE_CHECK":  "true",
		"PULUMI_SKIP_CONFIRMATIONS": "true",
	}
	if e.backendURL != "" {
		env["PULUMI_BACKEND_URL"] = e.backendURL
	}
	return e.p.buildEnv(env)
}

// target is a tenant's stack and directories.
type pulumiTarget struct {
	stack, dir, configFile string
	env                    []string
}

func (e *pulumi) target(in Input) (pulumiTarget, error) {
	stack, err := e.stackName(in)
	if err != nil {
		return pulumiTarget{}, err
	}
	dir, err := tenantDir(e.stateDir, in.Tenant.ID)
	if err != nil {
		return pulumiTarget{}, err
	}
	return pulumiTarget{
		stack: stack, dir: dir,
		configFile: filepath.Join(dir, "Pulumi."+stack+".yaml"),
		env:        e.env(),
	}, nil
}

// configure selects (creating) the stack and sets its configuration from
// the tenant, removing keys set by a previous run that are gone.
func (e *pulumi) configure(ctx context.Context, t pulumiTarget, in Input, create bool) error {
	if err := os.MkdirAll(filepath.Join(t.dir, metaDir), 0o700); err != nil {
		return err
	}
	if create {
		args := []string{"stack", "select", "--create", "--stack", t.stack, "--non-interactive"}
		if e.secretsProvider != "" {
			args = append(args, "--secrets-provider", e.secretsProvider)
		}
		if _, err := e.run(ctx, e.projectDir, t.env, args...); err != nil {
			return err
		}
	}
	vars, err := e.vars.render(in)
	if err != nil {
		return err
	}
	keys := slices.Sorted(maps.Keys(vars))
	for _, k := range keys {
		v, err := pulumiValue(vars[k])
		if err != nil {
			return fmt.Errorf("variable %s: %w", k, err)
		}
		if _, err := e.run(ctx, e.projectDir, t.env, "config", "set",
			"--stack", t.stack, "--config-file", t.configFile, "--non-interactive", "--", k, v); err != nil {
			return err
		}
	}
	keysPath := filepath.Join(t.dir, metaDir, pulumiKeysFile)
	var previous []string
	if b, err := os.ReadFile(keysPath); err == nil {
		_ = json.Unmarshal(b, &previous)
	}
	for _, k := range previous {
		if slices.Contains(keys, k) {
			continue
		}
		if _, err := e.run(ctx, e.projectDir, t.env, "config", "rm",
			"--stack", t.stack, "--config-file", t.configFile, "--non-interactive", "--", k); err != nil {
			return err
		}
	}
	return writeJSON(keysPath, keys)
}

// pulumiValue renders a variable as a config string: strings as they are,
// other values as JSON.
func pulumiValue(v any) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func (e *pulumi) Apply(ctx context.Context, in Input) (*Result, error) {
	t, err := e.target(in)
	if err != nil {
		return nil, err
	}
	if err := e.configure(ctx, t, in, true); err != nil {
		return nil, err
	}
	if _, err := e.run(ctx, e.projectDir, t.env, "up", "--yes", "--skip-preview", "--non-interactive",
		"--stack", t.stack, "--config-file", t.configFile); err != nil {
		return nil, err
	}
	res, err := e.run(ctx, e.projectDir, t.env, "stack", "output", "--json", "--non-interactive", "--stack", t.stack)
	if err != nil {
		return nil, err
	}
	out, err := parsePulumiOutputs(res.Stdout)
	if err != nil {
		return nil, err
	}
	result := &Result{Outputs: out, UpdatedAt: e.p.now().UTC()}
	if err := saveOutputs(t.dir, result); err != nil {
		return nil, fmt.Errorf("save outputs: %w", err)
	}
	return result, nil
}

func (e *pulumi) Destroy(ctx context.Context, in Input) error {
	t, err := e.target(in)
	if err != nil {
		return err
	}
	ok, err := e.stackExists(ctx, t)
	if err != nil {
		return err
	}
	if !ok {
		return os.RemoveAll(t.dir)
	}
	if err := e.configure(ctx, t, in, false); err != nil {
		return err
	}
	if _, err := e.run(ctx, e.projectDir, t.env, "destroy", "--yes", "--skip-preview", "--non-interactive",
		"--stack", t.stack, "--config-file", t.configFile); err != nil {
		return err
	}
	if !e.keepStack {
		if _, err := e.run(ctx, e.projectDir, t.env, "stack", "rm", "--yes", "--non-interactive", "--stack", t.stack); err != nil {
			return err
		}
	}
	return os.RemoveAll(t.dir)
}

// stackExists lists the project's stacks.
func (e *pulumi) stackExists(ctx context.Context, t pulumiTarget) (bool, error) {
	res, err := e.run(ctx, e.projectDir, t.env, "stack", "ls", "--json", "--non-interactive")
	if err != nil {
		return false, err
	}
	var stacks []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(res.Stdout, &stacks); err != nil {
		return false, fmt.Errorf("decode stack list: %w", err)
	}
	for _, s := range stacks {
		// Names may be fully qualified ("org/project/stack").
		if s.Name == t.stack || strings.HasSuffix(s.Name, "/"+t.stack) {
			return true, nil
		}
	}
	return false, nil
}

func (e *pulumi) Outputs(_ context.Context, in Input) (*Result, error) {
	dir, err := tenantDir(e.stateDir, in.Tenant.ID)
	if err != nil {
		return nil, err
	}
	return loadOutputs(dir)
}

// parsePulumiOutputs decodes `stack output --json`; secret outputs show as
// "[secret]" and are marked redacted.
func parsePulumiOutputs(b []byte) (map[string]Output, error) {
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("decode outputs: %w", err)
	}
	out := make(map[string]Output, len(raw))
	for k, v := range raw {
		if v == pulumiSecret {
			out[k] = Output{Sensitive: true, Redacted: true}
			continue
		}
		out[k] = Output{Value: v}
	}
	return out, nil
}
