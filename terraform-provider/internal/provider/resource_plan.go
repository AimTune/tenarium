package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

var (
	_ resource.ResourceWithConfigure   = (*planResource)(nil)
	_ resource.ResourceWithImportState = (*planResource)(nil)
)

type planResource struct{ resourceBase }

// NewPlanResource returns the tenarium_plan resource.
func NewPlanResource() resource.Resource { return &planResource{} }

type planModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Features    types.Map    `tfsdk:"features"`
	Limits      types.Map    `tfsdk:"limits"`
	Version     types.Int64  `tfsdk:"version"`
	Grandfather types.Bool   `tfsdk:"grandfather_on_update"`
}

func (r *planResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plan"
}

func (r *planResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A plan bundles features and limits that tenants subscribe to.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:      true,
				Description:   "Short, stable plan identifier such as `free` or `enterprise`. Changing it replaces the plan.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name":        schema.StringAttribute{Required: true, Description: "Display name."},
			"description": schema.StringAttribute{Optional: true, Description: "Free-form description."},
			"features": schema.MapAttribute{
				Optional: true, ElementType: types.BoolType,
				Description: "Feature flags granted by the plan.",
			},
			"limits": schema.MapAttribute{
				Optional: true, ElementType: types.Int64Type,
				Description: "Numeric limits (e.g. `members`, `api_calls`) granted by the plan.",
			},
			"version": schema.Int64Attribute{
				Computed:    true,
				Description: "Version of the plan, incremented on every change and used for optimistic locking.",
			},
			"grandfather_on_update": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "When true, every update of the plan first pins the tenants currently on it to its current revision (`grandfather`), so the change only applies to new subscribers. " +
					"Pinned tenants show the revision in `plan_revision` and can be moved on with it. Changing only this attribute calls no API. Defaults to `false`.",
			},
		},
	}
}

func (m *planModel) fromAPI(p sdk.Plan) {
	m.ID = types.StringValue(p.ID)
	m.Name = types.StringValue(p.Name)
	m.Description = optionalString(p.Description, m.Description)
	m.Features = boolMapValue(p.Features, m.Features)
	m.Limits = int64MapValue(p.Limits, m.Limits)
	m.Version = types.Int64Value(p.Version)
	if m.Grandfather.IsNull() || m.Grandfather.IsUnknown() {
		m.Grandfather = types.BoolValue(false)
	}
}

func (r *planResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m planModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	in := client.CreatePlanRequest{
		ID:          m.ID.ValueString(),
		Name:        m.Name.ValueString(),
		Description: m.Description.ValueString(),
		Features:    mapFrom[bool](ctx, m.Features, &resp.Diagnostics),
		Limits:      mapFrom[int64](ctx, m.Limits, &resp.Diagnostics),
	}
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.Plans.Create(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "create plan", err)
		return
	}
	m.fromAPI(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *planResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m planModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.Plans.Get(ctx, m.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read plan", err)
		return
	}
	m.fromAPI(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *planResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m, state planModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if m.Name.Equal(state.Name) && m.Description.Equal(state.Description) && m.Features.Equal(state.Features) && m.Limits.Equal(state.Limits) {
		// Only grandfather_on_update changed: an update would grandfather
		// the tenants for nothing, so just refresh.
		p, err := r.client.Plans.Get(ctx, m.ID.ValueString())
		if err != nil {
			apiError(&resp.Diagnostics, "read plan", err)
			return
		}
		m.fromAPI(p)
		resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
		return
	}
	in := client.UpdatePlanRequest{
		Name:        m.Name.ValueStringPointer(),
		Description: client.Ptr(m.Description.ValueString()),
		Features:    mapPtr[bool](ctx, m.Features, &resp.Diagnostics),
		Limits:      mapPtr[int64](ctx, m.Limits, &resp.Diagnostics),
		Grandfather: m.Grandfather.ValueBool(),
	}
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.client.Plans.Update(ctx, m.ID.ValueString(), in, client.IfMatch(state.Version.ValueInt64()))
	if err != nil {
		apiError(&resp.Diagnostics, "update plan", err)
		return
	}
	m.fromAPI(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *planResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m planModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Plans.Delete(ctx, m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete plan", err)
	}
}

func (r *planResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
