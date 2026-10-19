package provider

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/sdk"
)

func jsonMap(t *testing.T, s string) map[string]any {
	t.Helper()
	if s == "" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMergePatch(t *testing.T) {
	cases := []struct{ name, from, to, want string }{
		{"no change", `{"a":1,"b":{"c":true}}`, `{"b":{"c":true},"a":1}`, ""},
		{"add and remove", `{"a":1,"b":2}`, `{"a":1,"c":3}`, `{"b":null,"c":3}`},
		{"nested", `{"o":{"x":1,"y":2}}`, `{"o":{"x":1,"z":3}}`, `{"o":{"y":null,"z":3}}`},
		{"object to scalar", `{"o":{"x":1}}`, `{"o":"s"}`, `{"o":"s"}`},
		{"arrays replaced", `{"l":[1,2]}`, `{"l":[2]}`, `{"l":[2]}`},
		{"from empty", ``, `{"a":{"b":1}}`, `{"a":{"b":1}}`},
		{"to empty", `{"a":1}`, ``, `{"a":null}`},
		{"null value drops key", `{"a":1}`, `{"a":null}`, `{"a":null}`},
		{"null value new key", `{}`, `{"a":null}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mergePatch(jsonMap(t, c.from), jsonMap(t, c.to))
			want := jsonMap(t, c.want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("mergePatch = %v, want %v", got, want)
			}
		})
	}
}

func TestSettingsConversion(t *testing.T) {
	v, err := settingsValue(nil, jsontypes.NewNormalizedNull())
	if err != nil || !v.IsNull() {
		t.Fatalf("empty settings with null prior: %v %v", v, err)
	}
	v, err = settingsValue(nil, jsontypes.NewNormalizedValue("{}"))
	if err != nil || v.ValueString() != "{}" {
		t.Fatalf("empty settings with {} prior: %v %v", v, err)
	}
	v, err = settingsValue(map[string]any{"b": 1.0, "a": "x"}, jsontypes.NewNormalizedNull())
	if err != nil {
		t.Fatal(err)
	}
	eq, diags := v.StringSemanticEquals(context.Background(), jsontypes.NewNormalizedValue("{\n  \"a\": \"x\",\n  \"b\": 1\n}"))
	if diags.HasError() || !eq {
		t.Fatalf("semantic equality failed for %s", v.ValueString())
	}
	if m, err := settingsMap(jsontypes.NewNormalizedValue(`{"k":[1,"two"]}`)); err != nil || len(m["k"].([]any)) != 2 {
		t.Fatalf("settingsMap: %v %v", m, err)
	}
	if _, err := settingsMap(jsontypes.NewNormalizedValue(`[1,2]`)); err == nil {
		t.Fatal("a JSON array was accepted as settings")
	}
	if m, err := settingsMap(jsontypes.NewNormalizedNull()); err != nil || m != nil {
		t.Fatalf("null settings: %v %v", m, err)
	}
}

func TestMapConversions(t *testing.T) {
	ctx := context.Background()
	if v := stringMapValue(nil, types.MapNull(types.StringType)); !v.IsNull() {
		t.Fatal("empty map with null prior should be null")
	}
	if v := stringMapValue(nil, types.MapValueMust(types.StringType, nil)); v.IsNull() || len(v.Elements()) != 0 {
		t.Fatal("empty map with empty prior should stay empty")
	}
	v := int64MapValue(map[string]int64{"members": 5}, types.MapNull(types.Int64Type))
	var diags diag.Diagnostics
	if got := mapFrom[int64](ctx, v, &diags); got["members"] != 5 || diags.HasError() {
		t.Fatalf("round trip: %v %v", got, diags)
	}
	if p := mapPtr[bool](ctx, types.MapNull(types.BoolType), &diags); p == nil || len(*p) != 0 {
		t.Fatal("mapPtr of null must be a pointer to an empty map")
	}
	s := stringSetValue([]string{"b", "a"}, types.SetNull(types.StringType))
	if got := stringsFrom(ctx, s, &diags); len(got) != 2 {
		t.Fatalf("set round trip: %v", got)
	}
	if v := stringSetValue(nil, types.SetNull(types.StringType)); !v.IsNull() {
		t.Fatal("empty set with null prior should be null")
	}
	if v := stringListValue(nil, types.ListValueMust(types.StringType, nil)); v.IsNull() {
		t.Fatal("empty list with empty prior should stay empty")
	}
	if v := optionalString("", types.StringNull()); !v.IsNull() {
		t.Fatal(`"" with null prior should be null`)
	}
	if v := optionalString("", types.StringValue("")); v.IsNull() {
		t.Fatal(`"" with "" prior should stay ""`)
	}
}

func TestSplitImportID(t *testing.T) {
	if p, err := splitImportID("acme/123", "<tenant>/<id>"); err != nil || p[0] != "acme" || p[1] != "123" {
		t.Fatalf("%v %v", p, err)
	}
	for _, bad := range []string{"acme", "acme/", "/1", "a/b/c"} {
		if _, err := splitImportID(bad, "<tenant>/<id>"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got := normalizeHostname(" App.Example.COM. "); got != "app.example.com" {
		t.Fatalf("normalizeHostname = %q", got)
	}
}

// TestSchemas validates every resource and data source schema.
func TestSchemas(t *testing.T) {
	ctx := context.Background()
	p := New("test")()
	var presp fwprovider.SchemaResponse
	p.Schema(ctx, fwprovider.SchemaRequest{}, &presp)
	if presp.Diagnostics.HasError() {
		t.Fatalf("provider schema: %v", presp.Diagnostics)
	}
	names := map[string]bool{}
	for _, f := range p.Resources(ctx) {
		r := f()
		var meta resource.MetadataResponse
		r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "tenarium"}, &meta)
		var resp resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("%s: %v", meta.TypeName, resp.Diagnostics)
		}
		if d := resp.Schema.ValidateImplementation(ctx); d.HasError() {
			t.Fatalf("%s: %v", meta.TypeName, d)
		}
		if _, ok := resp.Schema.Attributes["id"]; !ok {
			t.Errorf("%s has no id attribute", meta.TypeName)
		}
		names[meta.TypeName] = true
	}
	for _, f := range p.DataSources(ctx) {
		d := f()
		var meta datasource.MetadataResponse
		d.Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: "tenarium"}, &meta)
		var resp datasource.SchemaResponse
		d.Schema(ctx, datasource.SchemaRequest{}, &resp)
		if diags := resp.Schema.ValidateImplementation(ctx); diags.HasError() {
			t.Fatalf("%s: %v", meta.TypeName, diags)
		}
		names["data."+meta.TypeName] = true
	}
	for _, want := range []string{
		"tenarium_plan", "tenarium_tenant", "tenarium_member", "tenarium_tenant_domain", "tenarium_tenant_webhook",
		"tenarium_tenant_role", "tenarium_tenant_group", "tenarium_tenant_sso", "tenarium_api_key",
		"tenarium_rollout", "tenarium_tenant_template",
		"data.tenarium_tenant", "data.tenarium_plan", "data.tenarium_entitlements", "data.tenarium_plan_revisions", "data.tenarium_tenant_health",
	} {
		if !names[want] {
			t.Errorf("%s is not registered", want)
		}
	}
}

func TestTimestamps(t *testing.T) {
	a, b := types.StringValue("2026-01-15T00:00:00+03:00"), types.StringValue("2026-01-14T21:00:00Z")
	if !sameInstant(a, b) || sameInstant(a, types.StringValue("2026-01-15T00:00:00Z")) {
		t.Fatal("sameInstant compares instants")
	}
	if !sameInstant(types.StringNull(), types.StringNull()) || sameInstant(a, types.StringNull()) {
		t.Fatal("sameInstant with null")
	}
	at := *parseTime(b)
	if v := timeValue(&at, a); v != a {
		t.Fatalf("timeValue must keep the prior spelling, got %v", v)
	}
	if v := timeValue(&at, types.StringNull()); v.ValueString() != "2026-01-14T21:00:00Z" {
		t.Fatalf("timeValue = %v", v)
	}
	if v := timeValue(nil, a); !v.IsNull() {
		t.Fatal("no time must be null")
	}
	if parseTime(types.StringValue("yesterday")) != nil {
		t.Fatal("invalid timestamps must not parse")
	}
}

func TestBrandingConversion(t *testing.T) {
	ctx := context.Background()
	var diags diag.Diagnostics
	null := types.ObjectNull(brandingAttrTypes)
	if v := brandingValue(ctx, nil, null, &diags); !v.IsNull() {
		t.Fatal("no branding with null prior must be null")
	}
	v := brandingValue(ctx, &sdk.Branding{DisplayName: "Acme", PrimaryColor: "#000000"}, null, &diags)
	got := brandingFrom(ctx, v, &diags)
	if got == nil || got.DisplayName != "Acme" || got.PrimaryColor != "#000000" || got.LogoURL != "" {
		t.Fatalf("round trip: %+v", got)
	}
	if !v.Attributes()["logo_url"].IsNull() {
		t.Fatal("unset fields must be null")
	}
	// The API drops an empty branding; a configured empty object stays.
	empty := brandingValue(ctx, &sdk.Branding{}, null, &diags)
	if v := brandingValue(ctx, nil, empty, &diags); v.IsNull() {
		t.Fatal("empty prior branding must be kept")
	}
	if v := brandingValue(ctx, nil, v, &diags); !v.IsNull() {
		t.Fatal("removed branding must be null")
	}
	if brandingFrom(ctx, null, &diags) != nil || diags.HasError() {
		t.Fatalf("null branding: %v", diags)
	}
}

type fakePrivate map[string][]byte

func (p fakePrivate) GetKey(_ context.Context, k string) ([]byte, diag.Diagnostics) { return p[k], nil }

func (p fakePrivate) SetKey(_ context.Context, k string, v []byte) diag.Diagnostics {
	if len(v) == 0 {
		delete(p, k)
	} else {
		p[k] = v
	}
	return nil
}

func TestTemplateOwned(t *testing.T) {
	ctx := context.Background()
	p := fakePrivate{}
	if templateOwned(ctx, p) != nil {
		t.Fatal("nothing is owned initially")
	}
	setTemplateOwned(ctx, p, map[string]bool{"labels": true, "branding": true})
	if got := templateOwned(ctx, p); !got["labels"] || !got["branding"] || len(got) != 2 {
		t.Fatalf("owned = %v", got)
	}
	setTemplateOwned(ctx, p, nil)
	if _, ok := p[templateOwnedKey]; ok {
		t.Fatal("an empty set must remove the key")
	}
}
