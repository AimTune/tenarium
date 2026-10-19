package provider

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// jsonSemanticPlan suppresses plan diffs between a JSON string in the
// configuration and a semantically equal one in state (different
// whitespace or key order). Semantic equality alone is applied only to
// apply and read results, so without it Terraform would still plan a
// "whitespace changes" update.
type jsonSemanticPlan struct{}

func (jsonSemanticPlan) Description(context.Context) string {
	return "Keeps the prior JSON value when the configured value is semantically equal."
}

func (m jsonSemanticPlan) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (jsonSemanticPlan) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.StateValue.IsNull() || req.StateValue.IsUnknown() || req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	prior := jsontypes.NewNormalizedValue(req.StateValue.ValueString())
	planned := jsontypes.NewNormalizedValue(req.PlanValue.ValueString())
	eq, diags := prior.StringSemanticEquals(ctx, planned)
	if diags.HasError() || !eq {
		return
	}
	resp.PlanValue = req.StateValue
}

// templateComputed plans attributes that a tenant template can fill in.
// They are Optional and Computed. When the configuration leaves one unset:
//   - at creation from a template it is "known after apply" (the template
//     may set it), and the provider remembers in private state that the
//     template owns it, so later plans keep the template's value;
//   - otherwise it is null, so removing it from the configuration clears
//     it on the server as for a plain Optional attribute. Configuring an
//     attribute ends the template's ownership.
type templateComputed struct{}

var (
	_ planmodifier.Map    = templateComputed{}
	_ planmodifier.Set    = templateComputed{}
	_ planmodifier.String = templateComputed{}
	_ planmodifier.Object = templateComputed{}
)

func (templateComputed) Description(context.Context) string {
	return "When unset, the value comes from the tenant template at creation and is null otherwise."
}

func (m templateComputed) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

type planChoice int

const (
	planAsIs    planChoice = iota // configured: keep the planned value
	planUnknown                   // creation from a template
	planState                     // owned by the template: keep the state value
	planNull                      // unset: clear
)

// choose decides the planned value of an attribute at p.
func (templateComputed) choose(ctx context.Context, p path.Path, configNull bool, config tfsdk.Config, state tfsdk.State, private privateGetter) planChoice {
	if !configNull {
		return planAsIs
	}
	if state.Raw.IsNull() {
		var tpl types.String
		if d := config.GetAttribute(ctx, path.Root("template"), &tpl); !d.HasError() && !tpl.IsNull() {
			return planUnknown
		}
		return planNull
	}
	if templateOwned(ctx, private)[p.String()] {
		return planState
	}
	return planNull
}

func (m templateComputed) PlanModifyMap(ctx context.Context, req planmodifier.MapRequest, resp *planmodifier.MapResponse) {
	switch m.choose(ctx, req.Path, req.ConfigValue.IsNull(), req.Config, req.State, req.Private) {
	case planUnknown:
		resp.PlanValue = types.MapUnknown(req.PlanValue.ElementType(ctx))
	case planState:
		resp.PlanValue = req.StateValue
	case planNull:
		resp.PlanValue = types.MapNull(req.PlanValue.ElementType(ctx))
	}
}

func (m templateComputed) PlanModifySet(ctx context.Context, req planmodifier.SetRequest, resp *planmodifier.SetResponse) {
	switch m.choose(ctx, req.Path, req.ConfigValue.IsNull(), req.Config, req.State, req.Private) {
	case planUnknown:
		resp.PlanValue = types.SetUnknown(req.PlanValue.ElementType(ctx))
	case planState:
		resp.PlanValue = req.StateValue
	case planNull:
		resp.PlanValue = types.SetNull(req.PlanValue.ElementType(ctx))
	}
}

// PlanModifyString handles settings; the framework converts the result to
// the attribute's custom type (jsontypes.Normalized).
func (m templateComputed) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	switch m.choose(ctx, req.Path, req.ConfigValue.IsNull(), req.Config, req.State, req.Private) {
	case planUnknown:
		resp.PlanValue = types.StringUnknown()
	case planState:
		resp.PlanValue = req.StateValue
	case planNull:
		resp.PlanValue = types.StringNull()
	}
}

func (m templateComputed) PlanModifyObject(ctx context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	switch m.choose(ctx, req.Path, req.ConfigValue.IsNull(), req.Config, req.State, req.Private) {
	case planUnknown:
		resp.PlanValue = types.ObjectUnknown(req.PlanValue.AttributeTypes(ctx))
	case planState:
		resp.PlanValue = req.StateValue
	case planNull:
		resp.PlanValue = types.ObjectNull(req.PlanValue.AttributeTypes(ctx))
	}
}

// templateOwnedKey is the private state key listing the attributes whose
// value came from the tenant template.
const templateOwnedKey = "template_owned"

type privateGetter interface {
	GetKey(ctx context.Context, key string) ([]byte, diag.Diagnostics)
}

type privateSetter interface {
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

// templateOwned returns the attributes owned by the template.
func templateOwned(ctx context.Context, p privateGetter) map[string]bool {
	if p == nil || reflect.ValueOf(p).IsNil() {
		return nil
	}
	raw, d := p.GetKey(ctx, templateOwnedKey)
	if d.HasError() || len(raw) == 0 {
		return nil
	}
	var names []string
	if json.Unmarshal(raw, &names) != nil {
		return nil
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out
}

// setTemplateOwned stores the attributes owned by the template.
func setTemplateOwned(ctx context.Context, p privateSetter, owned map[string]bool) diag.Diagnostics {
	names := slices.Sorted(maps.Keys(owned))
	raw, _ := json.Marshal(names)
	if len(names) == 0 {
		raw = nil // removes the key
	}
	return p.SetKey(ctx, templateOwnedKey, raw)
}

// rfc3339 validates RFC 3339 timestamps such as 2026-01-01T00:00:00Z.
type rfc3339 struct{}

var _ validator.String = rfc3339{}

func (rfc3339) Description(context.Context) string { return "must be an RFC 3339 timestamp" }

func (v rfc3339) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (rfc3339) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() || req.ConfigValue.ValueString() == "" {
		return // "" means "no timestamp"
	}
	if _, err := time.Parse(time.RFC3339, req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid timestamp",
			"Expected an RFC 3339 timestamp such as 2026-01-01T00:00:00Z: "+err.Error())
	}
}

// sameInstantPlan suppresses plan diffs between RFC 3339 timestamps that
// denote the same instant (for example `Z` and `+00:00`).
type sameInstantPlan struct{}

func (sameInstantPlan) Description(context.Context) string {
	return "Keeps the prior timestamp when the configured one denotes the same instant."
}

func (m sameInstantPlan) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (sameInstantPlan) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.StateValue.IsNull() || req.StateValue.IsUnknown() || req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	if sameInstant(req.StateValue, req.PlanValue) {
		resp.PlanValue = req.StateValue
	}
}
