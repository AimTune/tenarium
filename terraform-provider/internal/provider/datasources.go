package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// --- tenarium_tenant ----------------------------------------------------------

type tenantDataSource struct{ dataSourceBase }

// NewTenantDataSource returns the tenarium_tenant data source.
func NewTenantDataSource() datasource.DataSource { return &tenantDataSource{} }

type tenantDataModel struct {
	ID            types.String         `tfsdk:"id"`
	Slug          types.String         `tfsdk:"slug"`
	Name          types.String         `tfsdk:"name"`
	Plan          types.String         `tfsdk:"plan"`
	PlanRevision  types.Int64          `tfsdk:"plan_revision"`
	AddOns        types.Set            `tfsdk:"add_ons"`
	Region        types.String         `tfsdk:"region"`
	BillingAnchor types.String         `tfsdk:"billing_anchor"`
	ParentID      types.String         `tfsdk:"parent_id"`
	Labels        types.Map            `tfsdk:"labels"`
	Settings      jsontypes.Normalized `tfsdk:"settings"`
	Features      types.Map            `tfsdk:"features"`
	Limits        types.Map            `tfsdk:"limits"`
	Status        types.String         `tfsdk:"status"`
	StatusReason  types.String         `tfsdk:"status_reason"`
	Version       types.Int64          `tfsdk:"version"`
}

func (d *tenantDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant"
}

func (d *tenantDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	lookup := []validator.String{stringvalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("slug"))}
	resp.Schema = schema.Schema{
		Description: "Looks up a tenant by ID or slug.",
		Attributes: map[string]schema.Attribute{
			"id":             schema.StringAttribute{Optional: true, Computed: true, Description: "Tenant ID. Exactly one of `id` and `slug` is required.", Validators: lookup},
			"slug":           schema.StringAttribute{Optional: true, Computed: true, Description: "Tenant slug. Exactly one of `id` and `slug` is required.", Validators: lookup},
			"name":           schema.StringAttribute{Computed: true, Description: "Display name."},
			"plan":           schema.StringAttribute{Computed: true, Description: "Plan ID."},
			"plan_revision":  schema.Int64Attribute{Computed: true, Description: "Plan revision the tenant is pinned to; `0` follows the current plan."},
			"add_ons":        schema.SetAttribute{Computed: true, ElementType: types.StringType, Description: "Add-on plan IDs."},
			"region":         schema.StringAttribute{Computed: true, Description: "Region; empty when the tenant has none."},
			"billing_anchor": schema.StringAttribute{Computed: true, Description: "Billing cycle anchor (RFC 3339); null when unset."},
			"parent_id":      schema.StringAttribute{Computed: true, Description: "Parent tenant ID."},
			"labels":         schema.MapAttribute{Computed: true, ElementType: types.StringType, Description: "Labels."},
			"settings":       schema.StringAttribute{Computed: true, CustomType: jsontypes.NormalizedType{}, Description: "Settings as a JSON object string; use `jsondecode()`."},
			"features":       schema.MapAttribute{Computed: true, ElementType: types.BoolType, Description: "Tenant feature overrides."},
			"limits":         schema.MapAttribute{Computed: true, ElementType: types.Int64Type, Description: "Tenant limit overrides."},
			"status":         schema.StringAttribute{Computed: true, Description: "Lifecycle status."},
			"status_reason":  schema.StringAttribute{Computed: true, Description: "Explanation of the status, if any."},
			"version":        schema.Int64Attribute{Computed: true, Description: "Version."},
		},
	}
}

func (d *tenantDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m tenantDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	ref := m.ID.ValueString()
	if ref == "" {
		ref = m.Slug.ValueString()
	}
	t, err := d.client.Tenants.Get(ctx, ref)
	if err != nil {
		apiError(&resp.Diagnostics, "read tenant", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, tenantData(t, &resp.Diagnostics))...)
}

func tenantData(t sdk.Tenant, diags *diagnostics) *tenantDataModel {
	settings, err := settingsValue(t.Settings, jsontypes.NewNormalizedValue("{}"))
	if err != nil {
		diags.AddError("Cannot encode tenant settings", err.Error())
	}
	parent := types.StringNull()
	if t.ParentID != "" {
		parent = types.StringValue(t.ParentID)
	}
	// Data sources always return maps (possibly empty), never null; a known
	// empty prior value tells the helpers so.
	return &tenantDataModel{
		ID:            types.StringValue(t.ID),
		Slug:          types.StringValue(t.Slug),
		Name:          types.StringValue(t.Name),
		Plan:          types.StringValue(t.Plan),
		PlanRevision:  types.Int64Value(t.PlanRevision),
		AddOns:        stringSetValue(t.AddOns, types.SetValueMust(types.StringType, nil)),
		Region:        types.StringValue(t.Region),
		BillingAnchor: timeValue(t.BillingAnchor, types.StringNull()),
		ParentID:      parent,
		Labels:        stringMapValue(t.Labels, types.MapValueMust(types.StringType, nil)),
		Settings:      settings,
		Features:      boolMapValue(t.Features, types.MapValueMust(types.BoolType, nil)),
		Limits:        int64MapValue(t.Limits, types.MapValueMust(types.Int64Type, nil)),
		Status:        types.StringValue(string(t.Status)),
		StatusReason:  types.StringValue(t.StatusReason),
		Version:       types.Int64Value(t.Version),
	}
}

// --- tenarium_plan ------------------------------------------------------------

type planDataSource struct{ dataSourceBase }

// NewPlanDataSource returns the tenarium_plan data source.
func NewPlanDataSource() datasource.DataSource { return &planDataSource{} }

func (d *planDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plan"
}

func (d *planDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up a plan by ID.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Required: true, Description: "Plan ID."},
			"name":        schema.StringAttribute{Computed: true, Description: "Display name."},
			"description": schema.StringAttribute{Computed: true, Description: "Description."},
			"features":    schema.MapAttribute{Computed: true, ElementType: types.BoolType, Description: "Feature flags."},
			"limits":      schema.MapAttribute{Computed: true, ElementType: types.Int64Type, Description: "Limits."},
			"version":     schema.Int64Attribute{Computed: true, Description: "Version."},
		},
	}
}

// planDataModel is planModel without the resource-only options.
type planDataModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Features    types.Map    `tfsdk:"features"`
	Limits      types.Map    `tfsdk:"limits"`
	Version     types.Int64  `tfsdk:"version"`
}

func (d *planDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg planDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := d.client.Plans.Get(ctx, cfg.ID.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "read plan", err)
		return
	}
	m := planModel{
		Description: types.StringValue(""),
		Features:    types.MapValueMust(types.BoolType, nil),
		Limits:      types.MapValueMust(types.Int64Type, nil),
	}
	m.fromAPI(p)
	out := planDataModel{ID: m.ID, Name: m.Name, Description: m.Description, Features: m.Features, Limits: m.Limits, Version: m.Version}
	resp.Diagnostics.Append(resp.State.Set(ctx, &out)...)
}

// --- tenarium_entitlements ----------------------------------------------------

type entitlementsDataSource struct{ dataSourceBase }

// NewEntitlementsDataSource returns the tenarium_entitlements data source.
func NewEntitlementsDataSource() datasource.DataSource { return &entitlementsDataSource{} }

type entitlementsModel struct {
	TenantID types.String `tfsdk:"tenant_id"`
	Plan     types.String `tfsdk:"plan"`
	Features types.Map    `tfsdk:"features"`
	Limits   types.Map    `tfsdk:"limits"`
}

func (d *entitlementsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_entitlements"
}

func (d *entitlementsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A tenant's effective entitlements: the plan's features and limits with the tenant's overrides applied.",
		Attributes: map[string]schema.Attribute{
			"tenant_id": schema.StringAttribute{Required: true, Description: "Tenant ID or slug."},
			"plan":      schema.StringAttribute{Computed: true, Description: "Plan ID."},
			"features":  schema.MapAttribute{Computed: true, ElementType: types.BoolType, Description: "Effective feature flags."},
			"limits":    schema.MapAttribute{Computed: true, ElementType: types.Int64Type, Description: "Effective limits; absent metrics are unlimited."},
		},
	}
}

func (d *entitlementsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m entitlementsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	e, err := d.client.Tenants.Entitlements(ctx, m.TenantID.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "read entitlements", err)
		return
	}
	m.Plan = types.StringValue(e.Plan)
	m.Features = boolMapValue(e.Features, types.MapValueMust(types.BoolType, nil))
	m.Limits = int64MapValue(e.Limits, types.MapValueMust(types.Int64Type, nil))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
