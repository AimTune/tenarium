package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
)

// clientHolder gives resources and data sources the configured API client.
type clientHolder struct{ client *client.Client }

func (h *clientHolder) configure(data any, diags *diag.Diagnostics) {
	if data == nil { // provider not configured yet (validation, early plan)
		return
	}
	c, ok := data.(*client.Client)
	if !ok {
		diags.AddError("Unexpected provider data", fmt.Sprintf("expected *client.Client, got %T", data))
		return
	}
	h.client = c
}

// resourceBase implements resource.ResourceWithConfigure.
type resourceBase struct{ clientHolder }

func (r *resourceBase) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(req.ProviderData, &resp.Diagnostics)
}

// dataSourceBase implements datasource.DataSourceWithConfigure.
type dataSourceBase struct{ clientHolder }

func (d *dataSourceBase) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.configure(req.ProviderData, &resp.Diagnostics)
}

// apiError adds an error diagnostic describing a failed API call.
func apiError(diags *diag.Diagnostics, what string, err error) {
	detail := err.Error()
	if client.IsVersionConflict(err) {
		detail += "\n\nThe object was modified outside of Terraform since it was last read. " +
			"Run `terraform apply -refresh-only` (or plan again) to pick up the change, then retry."
	}
	diags.AddError("Tenarium API error: "+what, detail)
}

// splitImportID parses "a/b" import IDs.
func splitImportID(id, format string) ([]string, error) {
	s := strings.Split(id, "/")
	if len(s) != 2 || slices.Contains(s, "") {
		return nil, fmt.Errorf("unexpected import ID %q, expected %s", id, format)
	}
	return s, nil
}

// --- map conversions -------------------------------------------------------
//
// The API omits empty maps. To avoid perpetual diffs between "null" in the
// configuration and "{}" from the API, an empty API map becomes null unless
// the prior value was a known, empty map.

func keepEmpty(prior attr.Value) bool {
	if prior == nil || prior.IsNull() || prior.IsUnknown() {
		return false
	}
	if m, ok := prior.(types.Map); ok {
		return len(m.Elements()) == 0
	}
	return false
}

func stringMapValue(m map[string]string, prior attr.Value) types.Map {
	if len(m) == 0 && !keepEmpty(prior) {
		return types.MapNull(types.StringType)
	}
	el := make(map[string]attr.Value, len(m))
	for k, v := range m {
		el[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, el)
}

func boolMapValue(m map[string]bool, prior attr.Value) types.Map {
	if len(m) == 0 && !keepEmpty(prior) {
		return types.MapNull(types.BoolType)
	}
	el := make(map[string]attr.Value, len(m))
	for k, v := range m {
		el[k] = types.BoolValue(v)
	}
	return types.MapValueMust(types.BoolType, el)
}

func int64MapValue(m map[string]int64, prior attr.Value) types.Map {
	if len(m) == 0 && !keepEmpty(prior) {
		return types.MapNull(types.Int64Type)
	}
	el := make(map[string]attr.Value, len(m))
	for k, v := range m {
		el[k] = types.Int64Value(v)
	}
	return types.MapValueMust(types.Int64Type, el)
}

// mapFrom converts a Terraform map into a Go map; null and unknown give nil.
func mapFrom[T any](ctx context.Context, m types.Map, diags *diag.Diagnostics) map[string]T {
	if m.IsNull() || m.IsUnknown() {
		return nil
	}
	out := map[string]T{}
	diags.Append(m.ElementsAs(ctx, &out, false)...)
	return out
}

// mapPtr is mapFrom for "replace the whole map" update fields: a null map
// becomes a pointer to an empty map so the API clears it.
func mapPtr[T any](ctx context.Context, m types.Map, diags *diag.Diagnostics) *map[string]T {
	v := mapFrom[T](ctx, m, diags)
	if v == nil {
		v = map[string]T{}
	}
	return &v
}

// --- list / set conversions -------------------------------------------------

func stringsFrom(ctx context.Context, v attr.Value, diags *diag.Diagnostics) []string {
	if v == nil || v.IsNull() || v.IsUnknown() {
		return nil
	}
	var out []string
	switch x := v.(type) {
	case types.Set:
		diags.Append(x.ElementsAs(ctx, &out, false)...)
	case types.List:
		diags.Append(x.ElementsAs(ctx, &out, false)...)
	}
	return out
}

func stringSetValue(s []string, prior attr.Value) types.Set {
	if len(s) == 0 && (prior == nil || prior.IsNull() || prior.IsUnknown() || len(prior.(types.Set).Elements()) > 0) {
		return types.SetNull(types.StringType)
	}
	el := make([]attr.Value, len(s))
	for i, v := range s {
		el[i] = types.StringValue(v)
	}
	return types.SetValueMust(types.StringType, el)
}

func stringListValue(s []string, prior attr.Value) types.List {
	if len(s) == 0 && (prior == nil || prior.IsNull() || prior.IsUnknown() || len(prior.(types.List).Elements()) > 0) {
		return types.ListNull(types.StringType)
	}
	el := make([]attr.Value, len(s))
	for i, v := range s {
		el[i] = types.StringValue(v)
	}
	return types.ListValueMust(types.StringType, el)
}

// optionalString maps "" to null unless the prior value was a known "".
func optionalString(s string, prior types.String) types.String {
	if s == "" && (prior.IsNull() || prior.IsUnknown()) {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// --- settings (JSON) ----------------------------------------------------------

// settingsValue renders tenant settings as normalized JSON; empty settings
// are null unless the prior value was a JSON object.
func settingsValue(m map[string]any, prior jsontypes.Normalized) (jsontypes.Normalized, error) {
	if len(m) == 0 && (prior.IsNull() || prior.IsUnknown()) {
		return jsontypes.NewNormalizedNull(), nil
	}
	if m == nil {
		m = map[string]any{}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return jsontypes.NewNormalizedNull(), err
	}
	return jsontypes.NewNormalizedValue(string(raw)), nil
}

// settingsMap parses the settings attribute, which must be a JSON object.
func settingsMap(v jsontypes.Normalized) (map[string]any, error) {
	if v.IsNull() || v.IsUnknown() || strings.TrimSpace(v.ValueString()) == "" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(v.ValueString()), &m); err != nil {
		return nil, fmt.Errorf("settings must be a JSON object: %w", err)
	}
	return m, nil
}

// mergePatch returns the RFC 7386 JSON merge patch that turns from into to:
// removed keys map to nil, nested objects are diffed recursively and every
// other changed value is replaced. It returns nil when nothing changed.
func mergePatch(from, to map[string]any) map[string]any {
	patch := map[string]any{}
	for k := range from {
		if _, ok := to[k]; !ok {
			patch[k] = nil
		}
	}
	keys := slices.Sorted(maps.Keys(to))
	for _, k := range keys {
		nv := to[k]
		ov, existed := from[k]
		if existed && reflect.DeepEqual(ov, nv) {
			continue
		}
		om, oIsMap := ov.(map[string]any)
		nm, nIsMap := nv.(map[string]any)
		if existed && oIsMap && nIsMap {
			if sub := mergePatch(om, nm); sub != nil {
				patch[k] = sub
			}
			continue
		}
		if nv == nil {
			// A merge patch cannot store null; drop the key instead.
			if existed {
				patch[k] = nil
			}
			continue
		}
		patch[k] = nv
	}
	if len(patch) == 0 {
		return nil
	}
	return patch
}

// normalizeHostname mirrors the server's hostname normalization.
func normalizeHostname(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// diagnostics is a short alias used in helper signatures.
type diagnostics = diag.Diagnostics
