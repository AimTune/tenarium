package provider

import (
	"context"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
)

var (
	_ resource.ResourceWithConfigure   = (*roleResource)(nil)
	_ resource.ResourceWithImportState = (*roleResource)(nil)
)

type roleResource struct{ resourceBase }

// NewRoleResource returns the tenarium_tenant_role resource.
func NewRoleResource() resource.Resource { return &roleResource{} }

type roleModel struct {
	ID          types.String `tfsdk:"id"`
	TenantID    types.String `tfsdk:"tenant_id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Actions     types.Set    `tfsdk:"actions"`
}

type apiRole struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Actions     []string `json:"actions"`
	BuiltIn     bool     `json:"built_in"`
}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_role"
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A custom role of a tenant: a name for a set of action patterns, usable like the built-in member roles.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "`<tenant_id>/<name>`.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id": tenantIDAttribute(),
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "Lowercase role identifier; must not be a built-in role. Changing it replaces the role.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"description": schema.StringAttribute{Optional: true, Description: "Free-form description."},
			"actions": schema.SetAttribute{
				Required: true, ElementType: types.StringType,
				Description: "Action patterns the role grants, e.g. `members:read` or `webhooks:*`.",
				Validators:  []validator.Set{setvalidator.SizeBetween(1, 100)},
			},
		},
	}
}

func rolePath(tenant, name string) string {
	return "/v1/tenants/" + url.PathEscape(tenant) + "/roles/" + url.PathEscape(name)
}

func (m *roleModel) fromAPI(r apiRole) {
	m.Name = types.StringValue(r.Name)
	m.ID = types.StringValue(m.TenantID.ValueString() + "/" + r.Name)
	m.Description = optionalString(r.Description, m.Description)
	m.Actions = stringSetValue(r.Actions, m.Actions)
}

func (r *roleResource) put(ctx context.Context, m *roleModel, diags *diagnostics) {
	body := map[string]any{
		"description": m.Description.ValueString(),
		"actions":     stringsFrom(ctx, m.Actions, diags),
	}
	if diags.HasError() {
		return
	}
	var out apiRole
	if err := r.client.Do(ctx, http.MethodPut, rolePath(m.TenantID.ValueString(), m.Name.ValueString()), nil, body, &out); err != nil {
		apiError(diags, "put role", err)
		return
	}
	m.fromAPI(out)
}

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// PUT would silently take over an existing role; refuse instead.
	var existing apiRole
	err := r.client.Do(ctx, http.MethodGet, rolePath(m.TenantID.ValueString(), m.Name.ValueString()), nil, nil, &existing)
	if err == nil {
		resp.Diagnostics.AddError("Role already exists",
			"Role "+m.Name.ValueString()+" already exists in the tenant. Import it with `terraform import` instead.")
		return
	} else if !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "read role", err)
		return
	}
	r.put(ctx, &m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out apiRole
	err := r.client.Do(ctx, http.MethodGet, rolePath(m.TenantID.ValueString(), m.Name.ValueString()), nil, nil, &out)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read role", err)
		return
	}
	if out.BuiltIn {
		resp.Diagnostics.AddError("Built-in role", "Role "+out.Name+" is built in and cannot be managed by Terraform.")
		return
	}
	m.fromAPI(out)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m roleModel
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

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.Do(ctx, http.MethodDelete, rolePath(m.TenantID.ValueString(), m.Name.ValueString()), nil, nil, nil)
	if err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete role", err)
	}
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importTenantChild(ctx, req, resp, "name", "<tenant>/<role_name>")
}
