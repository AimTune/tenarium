package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
)

var (
	_ resource.ResourceWithConfigure   = (*templateResource)(nil)
	_ resource.ResourceWithImportState = (*templateResource)(nil)
)

type templateResource struct{ resourceBase }

// NewTemplateResource returns the tenarium_tenant_template resource.
func NewTemplateResource() resource.Resource { return &templateResource{} }

type templateModel struct {
	ID          types.String         `tfsdk:"id"`
	Name        types.String         `tfsdk:"name"`
	Description types.String         `tfsdk:"description"`
	Plan        types.String         `tfsdk:"plan"`
	AddOns      types.Set            `tfsdk:"add_ons"`
	Region      types.String         `tfsdk:"region"`
	Labels      types.Map            `tfsdk:"labels"`
	Settings    jsontypes.Normalized `tfsdk:"settings"`
	Features    types.Map            `tfsdk:"features"`
	Limits      types.Map            `tfsdk:"limits"`
	Branding    types.Object         `tfsdk:"branding"`
	Roles       []templateRoleModel  `tfsdk:"roles"`
}

type templateRoleModel struct {
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Actions     types.Set    `tfsdk:"actions"`
}

func (r *templateResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_template"
}

func (r *templateResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A tenant template presets new tenants (`tenarium_tenant.template`): plan, add-ons, region, labels, settings, features, limits, branding and custom roles. " +
			"Values set on the tenant win; maps are merged and template settings are the base the tenant's settings are merged into. " +
			"Tenants keep no link to the template, so changing or deleting it does not affect existing tenants. Managing templates needs `plans:write`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required:      true,
				Description:   "Template identifier (1-63 lowercase letters, digits or `-`). Changing it replaces the template.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name":        schema.StringAttribute{Required: true, Description: "Display name of the template."},
			"description": schema.StringAttribute{Optional: true, Description: "Free-form description."},
			"plan":        schema.StringAttribute{Optional: true, Description: "Plan of new tenants."},
			"add_ons": schema.SetAttribute{
				Optional: true, ElementType: types.StringType,
				Description: "Add-on plan IDs of new tenants.",
				Validators:  []validator.Set{setvalidator.SizeAtMost(20)},
			},
			"region": schema.StringAttribute{Optional: true, Description: "Region of new tenants."},
			"labels": schema.MapAttribute{Optional: true, ElementType: types.StringType, Description: "Labels of new tenants."},
			"settings": schema.StringAttribute{
				Optional:      true,
				CustomType:    jsontypes.NormalizedType{},
				PlanModifiers: []planmodifier.String{jsonSemanticPlan{}},
				Description:   "Settings of new tenants as a JSON object string, typically built with `jsonencode()`.",
			},
			"features": schema.MapAttribute{Optional: true, ElementType: types.BoolType, Description: "Feature overrides of new tenants."},
			"limits":   schema.MapAttribute{Optional: true, ElementType: types.Int64Type, Description: "Limit overrides of new tenants."},
			"branding": brandingAttribute("Branding of new tenants."),
			"roles": schema.ListNestedAttribute{
				Optional:    true,
				Description: "Custom roles created in new tenants. The caller creating a tenant from the template must be allowed every action of these roles.",
				Validators:  []validator.List{listvalidator.SizeAtLeast(1)},
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name":        schema.StringAttribute{Required: true, Description: "Lowercase role identifier; must not be a built-in role."},
					"description": schema.StringAttribute{Optional: true, Description: "Free-form description."},
					"actions": schema.SetAttribute{
						Required: true, ElementType: types.StringType,
						Description: "Action patterns the role grants, e.g. `members:read` or `webhooks:*`.",
						Validators:  []validator.Set{setvalidator.SizeBetween(1, 100)},
					},
				}},
			},
		},
	}
}

func (m *templateModel) fromAPI(ctx context.Context, t client.TenantTemplate, diags *diagnostics) {
	m.ID = types.StringValue(t.ID)
	m.Name = types.StringValue(t.Name)
	m.Description = optionalString(t.Description, m.Description)
	m.Plan = optionalString(t.Plan, m.Plan)
	m.AddOns = stringSetValue(t.AddOns, m.AddOns)
	m.Region = optionalString(t.Region, m.Region)
	m.Labels = stringMapValue(t.Labels, m.Labels)
	m.Features = boolMapValue(t.Features, m.Features)
	m.Limits = int64MapValue(t.Limits, m.Limits)
	s, err := settingsValue(t.Settings, m.Settings)
	if err != nil {
		diags.AddError("Cannot encode template settings", err.Error())
	}
	m.Settings = s
	m.Branding = brandingValue(ctx, t.Branding, m.Branding, diags)
	var roles []templateRoleModel
	for i, r := range t.Roles {
		var prior templateRoleModel
		if i < len(m.Roles) {
			prior = m.Roles[i]
		}
		roles = append(roles, templateRoleModel{
			Name:        types.StringValue(r.Name),
			Description: optionalString(r.Description, prior.Description),
			Actions:     stringSetValue(r.Actions, prior.Actions),
		})
	}
	m.Roles = roles
}

func (m *templateModel) toAPI(ctx context.Context, diags *diagnostics) client.TenantTemplate {
	settings, err := settingsMap(m.Settings)
	if err != nil {
		diags.AddAttributeError(path.Root("settings"), "Invalid settings", err.Error())
	}
	t := client.TenantTemplate{
		Name:        m.Name.ValueString(),
		Description: m.Description.ValueString(),
		Plan:        m.Plan.ValueString(),
		AddOns:      stringsFrom(ctx, m.AddOns, diags),
		Region:      m.Region.ValueString(),
		Labels:      mapFrom[string](ctx, m.Labels, diags),
		Settings:    settings,
		Features:    mapFrom[bool](ctx, m.Features, diags),
		Limits:      mapFrom[int64](ctx, m.Limits, diags),
		Branding:    brandingFrom(ctx, m.Branding, diags),
	}
	for _, r := range m.Roles {
		t.Roles = append(t.Roles, client.TemplateRole{
			Name:        r.Name.ValueString(),
			Description: r.Description.ValueString(),
			Actions:     stringsFrom(ctx, r.Actions, diags),
		})
	}
	return t
}

func (r *templateResource) put(ctx context.Context, m *templateModel, diags *diagnostics) {
	in := m.toAPI(ctx, diags)
	if diags.HasError() {
		return
	}
	out, err := r.client.Templates.Put(ctx, m.ID.ValueString(), in)
	if err != nil {
		apiError(diags, "put tenant template", err)
		return
	}
	m.fromAPI(ctx, out, diags)
}

func (r *templateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m templateModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// PUT would silently take over an existing template; refuse instead.
	if _, err := r.client.Templates.Get(ctx, m.ID.ValueString()); err == nil {
		resp.Diagnostics.AddError("Tenant template already exists",
			"Template "+m.ID.ValueString()+" already exists. Import it with `terraform import` instead.")
		return
	} else if !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "read tenant template", err)
		return
	}
	r.put(ctx, &m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *templateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m templateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.Templates.Get(ctx, m.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read tenant template", err)
		return
	}
	m.fromAPI(ctx, out, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *templateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m templateModel
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

func (r *templateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m templateModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Templates.Delete(ctx, m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete tenant template", err)
	}
}

func (r *templateResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
