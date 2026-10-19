package iac

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func pulumiProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, "Pulumi.yaml"), "name: tenant\nruntime: yaml\n")
	return dir
}

func pulumiConfig(t *testing.T) map[string]any {
	return map[string]any{
		"engine":          "pulumi",
		"state_dir":       t.TempDir(),
		"env_passthrough": []any{"AWS_ACCESS_KEY_ID"},
		"env":             map[string]any{"PULUMI_CONFIG_PASSPHRASE": "dev"},
		"vars":            map[string]any{"size": "small", "replicas": 2},
		"pulumi": map[string]any{
			"project_dir":      pulumiProject(t),
			"backend_url":      "file:///var/lib/pulumi",
			"secrets_provider": "passphrase",
		},
	}
}

// pulumiHandler simulates the CLI with a set of existing stacks.
func pulumiHandler(stacks *[]string) func(ctx context.Context, c Command) (RunResult, error) {
	return func(_ context.Context, c Command) (RunResult, error) {
		switch strings.Join(firstWords(c.Args), " ") {
		case "stack select":
			*stacks = append(*stacks, c.Args[slices.Index(c.Args, "--stack")+1])
		case "stack output":
			return RunResult{Stdout: []byte(`{"url":"https://acme.example","token":"[secret]","n":3}`)}, nil
		case "stack ls":
			var out []map[string]any
			for _, s := range *stacks {
				out = append(out, map[string]any{"name": "organization/tenant/" + s, "current": false})
			}
			b, _ := json.Marshal(out)
			return RunResult{Stdout: b}, nil
		case "stack rm":
			name := c.Args[slices.Index(c.Args, "--stack")+1]
			*stacks = slices.DeleteFunc(*stacks, func(s string) bool { return s == name })
		}
		return RunResult{}, nil
	}
}

func TestPulumi(t *testing.T) {
	ctx := context.Background()
	cfg := pulumiConfig(t)
	e := setup(t, cfg)
	var stacks []string
	e.runner.handle = pulumiHandler(&stacks)
	tn := e.addTenant("acme")
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}

	project := cfg["pulumi"].(map[string]any)["project_dir"].(string)
	project, _ = filepath.Abs(project)
	dir := filepath.Join(cfg["state_dir"].(string), tn.ID)
	stack := "tenant-" + tn.ID
	configFile := filepath.Join(dir, "Pulumi."+stack+".yaml")
	calls := e.runner.Calls()

	if !slices.Equal(calls[0].Args, []string{"stack", "select", "--create", "--stack", stack, "--non-interactive", "--secrets-provider", "passphrase"}) {
		t.Errorf("select = %v", calls[0].Args)
	}
	set := map[string]string{}
	var rest []Command
	for _, c := range calls[1:] {
		if c.Args[0] == "config" {
			wantPrefix := []string{"config", "set", "--stack", stack, "--config-file", configFile, "--non-interactive", "--"}
			if !slices.Equal(c.Args[:len(wantPrefix)], wantPrefix) || len(c.Args) != len(wantPrefix)+2 {
				t.Errorf("config call = %v", c.Args)
				continue
			}
			set[c.Args[len(c.Args)-2]] = c.Args[len(c.Args)-1]
		} else {
			rest = append(rest, c)
		}
	}
	for k, v := range map[string]string{
		VarTenantID: tn.ID, VarTenantSlug: "acme", VarTenantPlan: "pro",
		VarTenantLabels: `{"region":"eu"}`, "size": "small", "replicas": "2",
	} {
		if set[k] != v {
			t.Errorf("config %s = %q, want %q", k, set[k], v)
		}
	}
	if len(rest) != 2 {
		t.Fatalf("calls = %v", subcommands(calls))
	}
	if !slices.Equal(rest[0].Args, []string{"up", "--yes", "--skip-preview", "--non-interactive", "--stack", stack, "--config-file", configFile}) {
		t.Errorf("up = %v", rest[0].Args)
	}
	if !slices.Equal(rest[1].Args, []string{"stack", "output", "--json", "--non-interactive", "--stack", stack}) {
		t.Errorf("output = %v", rest[1].Args)
	}
	for _, c := range calls {
		env := envMap(c.Env)
		if c.Path != "pulumi" || c.Dir != project || env["PULUMI_BACKEND_URL"] != "file:///var/lib/pulumi" ||
			env["PULUMI_CONFIG_PASSPHRASE"] != "dev" || env["AWS_ACCESS_KEY_ID"] != "AKIA" {
			t.Errorf("call %v: path %s dir %s env %v", c.Args, c.Path, c.Dir, env)
		}
		if _, ok := env["AWS_SECRET_ACCESS_KEY"]; ok {
			t.Error("AWS_SECRET_ACCESS_KEY passed without being allowed")
		}
	}

	rec := e.get(t, &sdk.Principal{Subject: "admin"}, "/tenants/"+tn.ID+"/outputs")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET outputs = %d %s", rec.Code, rec.Body)
	}
	var resp OutputsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Engine != "pulumi" || resp.Outputs["url"].Value != "https://acme.example" || resp.Outputs["n"].Value != float64(3) {
		t.Errorf("outputs = %+v", resp)
	}
	if tok := resp.Outputs["token"]; !tok.Redacted || tok.Value != nil {
		t.Errorf("token = %+v", tok)
	}

	// A variable removed from the configuration is removed from the stack.
	delete(e.p.cfg.Vars, "size")
	vars, err := newVarRenderer(map[string]any{"replicas": 2})
	if err != nil {
		t.Fatal(err)
	}
	e.p.engine.(*pulumi).vars = vars
	e.runner.reset()
	if err := e.p.Provision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	var removed []string
	for _, c := range e.runner.Calls() {
		if c.Args[0] == "config" && c.Args[1] == "rm" {
			removed = append(removed, c.Args[len(c.Args)-1])
		}
	}
	if !slices.Equal(removed, []string{"size"}) {
		t.Errorf("removed config keys = %v", removed)
	}

	// Destroy: the stack exists, so destroy and remove it.
	e.runner.reset()
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	var steps []string
	for _, c := range e.runner.Calls() {
		if c.Args[0] != "config" {
			steps = append(steps, strings.Join(firstWords(c.Args), " "))
		}
	}
	if !slices.Equal(steps, []string{"stack ls", "destroy", "stack rm"}) {
		t.Fatalf("destroy steps = %v", steps)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("tenant directory kept")
	}
	// Again: the stack is gone, nothing but the listing runs.
	e.runner.reset()
	if err := e.p.Deprovision(ctx, tn); err != nil {
		t.Fatal(err)
	}
	if got := subcommands(e.runner.Calls()); !slices.Equal(got, []string{"stack ls"}) {
		t.Fatalf("second destroy = %v", got)
	}
}

func TestPulumiStackTemplate(t *testing.T) {
	cfg := pulumiConfig(t)
	cfg["pulumi"].(map[string]any)["stack_template"] = "t/{{.Slug}} x"
	cfg["pulumi"].(map[string]any)["keep_stack"] = true
	e := setup(t, cfg)
	var stacks []string
	e.runner.handle = pulumiHandler(&stacks)
	tn := e.addTenant("acme")
	if err := e.p.Provision(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(stacks, []string{"t-acme-x"}) {
		t.Fatalf("stacks = %v", stacks)
	}
	e.runner.reset()
	if err := e.p.Deprovision(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	for _, c := range e.runner.Calls() {
		if strings.Join(firstWords(c.Args), " ") == "stack rm" {
			t.Error("stack removed with keep_stack")
		}
	}
}
