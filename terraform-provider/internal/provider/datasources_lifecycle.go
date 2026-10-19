package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// --- tenarium_plan_revisions --------------------------------------------------

type planRevisionsDataSource struct{ dataSourceBase }

// NewPlanRevisionsDataSource returns the tenarium_plan_revisions data source.
func NewPlanRevisionsDataSource() datasource.DataSource { return &planRevisionsDataSource{} }

type planRevisionsModel struct {
	PlanID    types.String        `tfsdk:"plan_id"`
	Latest    types.Int64         `tfsdk:"latest"`
	Revisions []planRevisionModel `tfsdk:"revisions"`
}

type planRevisionModel struct {
	Revision  types.Int64  `tfsdk:"revision"`
	Features  types.Map    `tfsdk:"features"`
	Limits    types.Map    `tfsdk:"limits"`
	CreatedAt types.String `tfsdk:"created_at"`
}

func (d *planRevisionsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_plan_revisions"
}

func (d *planRevisionsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists the recorded revisions of a plan (snapshots of its features and limits), to pin tenants to with `tenarium_tenant.plan_revision`.",
		Attributes: map[string]schema.Attribute{
			"plan_id": schema.StringAttribute{Required: true, Description: "Plan ID."},
			"latest":  schema.Int64Attribute{Computed: true, Description: "Newest revision number (`0` when none is recorded)."},
			"revisions": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Revisions, newest first.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"revision":   schema.Int64Attribute{Computed: true, Description: "Revision number (the plan's version at the time)."},
					"features":   schema.MapAttribute{Computed: true, ElementType: types.BoolType, Description: "Feature flags of the revision."},
					"limits":     schema.MapAttribute{Computed: true, ElementType: types.Int64Type, Description: "Limits of the revision."},
					"created_at": schema.StringAttribute{Computed: true, Description: "When the revision was recorded (RFC 3339)."},
				}},
			},
		},
	}
}

func (d *planRevisionsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m planRevisionsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	revs, err := d.client.Plans.Revisions(ctx, m.PlanID.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "list plan revisions", err)
		return
	}
	m.Latest = types.Int64Value(0)
	m.Revisions = make([]planRevisionModel, 0, len(revs))
	for _, r := range revs {
		if r.Revision > m.Latest.ValueInt64() {
			m.Latest = types.Int64Value(r.Revision)
		}
		m.Revisions = append(m.Revisions, planRevisionModel{
			Revision:  types.Int64Value(r.Revision),
			Features:  boolMapValue(r.Features, types.MapValueMust(types.BoolType, nil)),
			Limits:    int64MapValue(r.Limits, types.MapValueMust(types.Int64Type, nil)),
			CreatedAt: types.StringValue(r.CreatedAt.UTC().Format(time.RFC3339Nano)),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// --- tenarium_tenant_health ---------------------------------------------------

type tenantHealthDataSource struct{ dataSourceBase }

// NewTenantHealthDataSource returns the tenarium_tenant_health data source.
func NewTenantHealthDataSource() datasource.DataSource { return &tenantHealthDataSource{} }

type tenantHealthModel struct {
	TenantID types.String        `tfsdk:"tenant_id"`
	Score    types.Int64         `tfsdk:"score"`
	Grade    types.String        `tfsdk:"grade"`
	Factors  []healthFactorModel `tfsdk:"factors"`
}

type healthFactorModel struct {
	Name   types.String `tfsdk:"name"`
	Impact types.Int64  `tfsdk:"impact"`
	Detail types.String `tfsdk:"detail"`
}

func (d *tenantHealthDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_health"
}

func (d *tenantHealthDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A tenant's health score and the factors behind it, read when Terraform refreshes.",
		Attributes: map[string]schema.Attribute{
			"tenant_id": schema.StringAttribute{Required: true, Description: "Tenant ID or slug."},
			"score":     schema.Int64Attribute{Computed: true, Description: "100 minus the impact of each factor found."},
			"grade":     schema.StringAttribute{Computed: true, Description: "`healthy` (80 and above), `at_risk` (50 to 79) or `critical` (below 50)."},
			"factors": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Factors that lowered the score.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name":   schema.StringAttribute{Computed: true, Description: "Factor name."},
					"impact": schema.Int64Attribute{Computed: true, Description: "Points the factor takes off the score."},
					"detail": schema.StringAttribute{Computed: true, Description: "Explanation."},
				}},
			},
		},
	}
}

func (d *tenantHealthDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var m tenantHealthModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h, err := d.client.Tenants.Health(ctx, m.TenantID.ValueString())
	if err != nil {
		apiError(&resp.Diagnostics, "read tenant health", err)
		return
	}
	m.Score = types.Int64Value(int64(h.Score))
	m.Grade = types.StringValue(h.Grade)
	m.Factors = make([]healthFactorModel, 0, len(h.Factors))
	for _, f := range h.Factors {
		m.Factors = append(m.Factors, healthFactorModel{
			Name:   types.StringValue(f.Name),
			Impact: types.Int64Value(int64(f.Impact)),
			Detail: types.StringValue(f.Detail),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
