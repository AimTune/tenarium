package iac

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// TemplateData is what templates (vars, backend_config, stack_template,
// the Crossplane manifest) are executed against. Tenant fields are
// promoted, so {{.ID}}, {{.Slug}}, {{.Plan}} and {{index .Labels "x"}}
// work, and {{.Entitlements.Limits}} holds the effective limits.
type TemplateData struct {
	sdk.Tenant
	Entitlements sdk.Entitlements
}

func templateData(in Input) TemplateData {
	ent := in.Entitlements
	if ent.Features == nil {
		ent.Features = map[string]bool{}
	}
	if ent.Limits == nil {
		ent.Limits = map[string]int64{}
	}
	return TemplateData{Tenant: in.Tenant, Entitlements: ent}
}

var funcs = template.FuncMap{
	// json renders a value as JSON, e.g. {{json .Labels}}.
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	// dns1123 turns a string into a DNS-1123 label (lowercase, [a-z0-9-]).
	"dns1123": sanitizeDNS,
	"lower":   strings.ToLower,
	"upper":   strings.ToUpper,
}

func parseTemplate(field, s string) (*template.Template, error) {
	t, err := template.New(field).Option("missingkey=error").Funcs(funcs).Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return t, nil
}

func render(t *template.Template, d TemplateData) (string, error) {
	var b strings.Builder
	if err := t.Execute(&b, d); err != nil {
		return "", fmt.Errorf("%s: %w", t.Name(), err)
	}
	return b.String(), nil
}

// sampleInputs are two distinct tenants used to check templates at Init:
// every template must render, and names must depend on the tenant.
var sampleInputs = []Input{
	{
		Tenant: sdk.Tenant{ID: "00000000-0000-0000-0000-000000000001", Slug: "example-one", Name: "Example One",
			Plan: "free", Labels: map[string]string{}, Settings: map[string]any{}},
		Entitlements: sdk.Entitlements{Plan: "free", Features: map[string]bool{}, Limits: map[string]int64{}},
	},
	{
		Tenant: sdk.Tenant{ID: "00000000-0000-0000-0000-000000000002", Slug: "example-two", Name: "Example Two",
			Plan: "free", Labels: map[string]string{}, Settings: map[string]any{}},
		Entitlements: sdk.Entitlements{Plan: "free", Features: map[string]bool{}, Limits: map[string]int64{}},
	},
}

// tenantVarPrefix prefixes the variables set from the tenant.
const tenantVarPrefix = "tenant_"

// Variables set from the tenant for every engine.
const (
	VarTenantID           = "tenant_id"
	VarTenantSlug         = "tenant_slug"
	VarTenantName         = "tenant_name"
	VarTenantPlan         = "tenant_plan"
	VarTenantParentID     = "tenant_parent_id"
	VarTenantLabels       = "tenant_labels"
	VarTenantSettings     = "tenant_settings_json"
	VarTenantEntitlements = "tenant_entitlements_json"
)

var (
	envNameRE = regexp.MustCompile(envNamePattern)
	varNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
)

func validEnvName(s string) bool { return envNameRE.MatchString(s) }
func validVarName(s string) bool { return varNameRE.MatchString(s) }

// varRenderer renders the input variables for a tenant: the tenant_*
// variables plus the configured static vars, whose string values (also
// nested in lists and objects) are templates.
type varRenderer struct {
	static map[string]any
	tmpls  map[string]*template.Template // keyed by a path within static
}

func newVarRenderer(static map[string]any) (*varRenderer, error) {
	v := &varRenderer{static: sdk.DeepCopyMap(static), tmpls: map[string]*template.Template{}}
	for _, k := range slices.Sorted(maps.Keys(static)) {
		if err := v.compile("vars."+k, static[k]); err != nil {
			return nil, err
		}
	}
	for _, in := range sampleInputs {
		if _, err := v.render(in); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func (v *varRenderer) compile(path string, val any) error {
	switch x := val.(type) {
	case string:
		t, err := parseTemplate(path, x)
		if err != nil {
			return err
		}
		v.tmpls[path] = t
	case map[string]any:
		for k, e := range x {
			if err := v.compile(path+"."+k, e); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range x {
			if err := v.compile(fmt.Sprintf("%s[%d]", path, i), e); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *varRenderer) expand(path string, val any, d TemplateData) (any, error) {
	switch x := val.(type) {
	case string:
		return render(v.tmpls[path], d)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			r, err := v.expand(path+"."+k, e, d)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			r, err := v.expand(fmt.Sprintf("%s[%d]", path, i), e, d)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	default:
		return val, nil
	}
}

// render returns every variable for the tenant.
func (v *varRenderer) render(in Input) (map[string]any, error) {
	d := templateData(in)
	settings, err := json.Marshal(nonNilMap(in.Tenant.Settings))
	if err != nil {
		return nil, fmt.Errorf("tenant settings: %w", err)
	}
	ent, err := json.Marshal(d.Entitlements)
	if err != nil {
		return nil, fmt.Errorf("tenant entitlements: %w", err)
	}
	labels := maps.Clone(in.Tenant.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	out := map[string]any{
		VarTenantID:           in.Tenant.ID,
		VarTenantSlug:         in.Tenant.Slug,
		VarTenantName:         in.Tenant.Name,
		VarTenantPlan:         in.Tenant.Plan,
		VarTenantParentID:     in.Tenant.ParentID,
		VarTenantLabels:       labels,
		VarTenantSettings:     string(settings),
		VarTenantEntitlements: string(ent),
	}
	for k, val := range v.static {
		r, err := v.expand("vars."+k, val, d)
		if err != nil {
			return nil, err
		}
		out[k] = r
	}
	return out, nil
}

func nonNilMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// sanitizeDNS turns s into a DNS-1123 label: lowercase, characters other
// than [a-z0-9-] become "-", leading and trailing "-" are trimmed.
func sanitizeDNS(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
