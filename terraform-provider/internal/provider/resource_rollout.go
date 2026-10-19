package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
)

var (
	_ resource.ResourceWithConfigure   = (*rolloutResource)(nil)
	_ resource.ResourceWithImportState = (*rolloutResource)(nil)
)

type rolloutResource struct{ resourceBase }

// NewRolloutResource returns the tenarium_rollout resource.
func NewRolloutResource() resource.Resource { return &rolloutResource{} }

type rolloutModel struct {
	ID         types.String `tfsdk:"id"`
	Feature    types.String `tfsdk:"feature"`
	Percentage types.Int64  `tfsdk:"percentage"`
	Plans      types.Set    `tfsdk:"plans"`
	Labels     types.Map    `tfsdk:"labels"`
	Regions    types.Set    `tfsdk:"regions"`
	Include    types.Set    `tfsdk:"include"`
	Exclude    types.Set    `tfsdk:"exclude"`
	Enabled    types.Bool   `tfsdk:"enabled"`
}

func (r *rolloutResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rollout"
}

func (r *rolloutResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	set := func(d string) schema.SetAttribute {
		return schema.SetAttribute{Optional: true, ElementType: types.StringType, Description: d}
	}
	resp.Schema = schema.Schema{
		Description: "A feature rollout: turns a feature on for a stable percentage of the tenants matching its cohort filters, independently of plans. " +
			"A tenant gets the feature when the rollout is enabled, the tenant is not excluded, and it is either included or matches every filter that is set and falls within the percentage. " +
			"A tenant's own feature override always wins. Rollouts are platform-only (`plans:write`).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "The feature name.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"feature": schema.StringAttribute{
				Required:      true,
				Description:   "Feature the rollout turns on. A feature has at most one rollout. Changing it replaces the rollout.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"percentage": schema.Int64Attribute{
				Required:    true,
				Description: "Share of the matching tenants (0-100) that get the feature. A stable hash of feature and tenant ID decides, so raising it keeps the tenants that already have the feature.",
				Validators:  []validator.Int64{int64validator.Between(0, 100)},
			},
			"plans":   set("Only tenants on one of these plans match."),
			"labels":  schema.MapAttribute{Optional: true, ElementType: types.StringType, Description: "Only tenants carrying all of these labels match."},
			"regions": set("Only tenants in one of these regions match."),
			"include": set("Tenant IDs that always get the feature (while enabled). Together with `exclude` at most 1000 IDs."),
			"exclude": set("Tenant IDs that never get the feature."),
			"enabled": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				Description: "Kill switch: `false` turns the feature off for every tenant of the rollout. Defaults to `true`.",
			},
		},
	}
}

func (m *rolloutModel) fromAPI(ro client.Rollout) {
	if ro.Feature != "" {
		m.Feature = types.StringValue(ro.Feature)
	}
	m.ID = m.Feature
	m.Percentage = types.Int64Value(int64(ro.Percentage))
	m.Plans = stringSetValue(ro.Plans, m.Plans)
	m.Labels = stringMapValue(ro.Labels, m.Labels)
	m.Regions = stringSetValue(ro.Regions, m.Regions)
	m.Include = stringSetValue(ro.Include, m.Include)
	m.Exclude = stringSetValue(ro.Exclude, m.Exclude)
	m.Enabled = types.BoolValue(ro.Enabled)
}

func (r *rolloutResource) put(ctx context.Context, m *rolloutModel, diags *diagnostics) {
	in := client.Rollout{
		Percentage: int(m.Percentage.ValueInt64()),
		Plans:      stringsFrom(ctx, m.Plans, diags),
		Labels:     mapFrom[string](ctx, m.Labels, diags),
		Regions:    stringsFrom(ctx, m.Regions, diags),
		Include:    stringsFrom(ctx, m.Include, diags),
		Exclude:    stringsFrom(ctx, m.Exclude, diags),
		Enabled:    m.Enabled.ValueBool(),
	}
	if diags.HasError() {
		return
	}
	out, err := r.client.Rollouts.Put(ctx, m.Feature.ValueString(), in)
	if err != nil {
		apiError(diags, "put rollout", err)
		return
	}
	m.fromAPI(out)
}

func (r *rolloutResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m rolloutModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// PUT would silently take over an existing rollout; refuse instead.
	if _, err := r.client.Rollouts.Get(ctx, m.Feature.ValueString()); err == nil {
		resp.Diagnostics.AddError("Rollout already exists",
			"Feature "+m.Feature.ValueString()+" already has a rollout. Import it with `terraform import` instead.")
		return
	} else if !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "read rollout", err)
		return
	}
	r.put(ctx, &m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *rolloutResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m rolloutModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.Rollouts.Get(ctx, m.Feature.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read rollout", err)
		return
	}
	m.fromAPI(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *rolloutResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m rolloutModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.put(ctx, &m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *rolloutResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m rolloutModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Rollouts.Delete(ctx, m.Feature.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete rollout", err)
	}
}

func (r *rolloutResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("feature"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
