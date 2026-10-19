package provider

import (
	"context"
	"net/http"
	"net/url"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
)

var (
	_ resource.ResourceWithConfigure   = (*groupResource)(nil)
	_ resource.ResourceWithImportState = (*groupResource)(nil)
)

type groupResource struct{ resourceBase }

// NewGroupResource returns the tenarium_tenant_group resource.
func NewGroupResource() resource.Resource { return &groupResource{} }

type groupModel struct {
	ID          types.String `tfsdk:"id"`
	TenantID    types.String `tfsdk:"tenant_id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Roles       types.Set    `tfsdk:"roles"`
	Members     types.Set    `tfsdk:"members"`
}

type apiGroup struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Roles       []string `json:"roles"`
	Members     []string `json:"members"`
}

func (r *groupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_group"
}

func (r *groupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A group (team) inside a tenant. Its members additionally hold the group's roles.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "Group ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id":   tenantIDAttribute(),
			"name":        schema.StringAttribute{Required: true, Description: "Group name, unique in the tenant."},
			"description": schema.StringAttribute{Optional: true, Description: "Free-form description."},
			"roles": schema.SetAttribute{
				Optional: true, ElementType: types.StringType,
				Description: "Built-in or custom roles granted to the group's members.",
			},
			"members": schema.SetAttribute{
				Optional: true, ElementType: types.StringType,
				Description: "Member IDs (`tenarium_member.x.id`) in the group. When unset, Terraform does not manage membership " +
					"(for example when SCIM provisions it).",
			},
		},
	}
}

func groupPath(tenant string, rest ...string) string {
	p := "/v1/tenants/" + url.PathEscape(tenant) + "/groups"
	for _, s := range rest {
		p += "/" + url.PathEscape(s)
	}
	return p
}

func (m *groupModel) fromAPI(g apiGroup) {
	m.ID = types.StringValue(g.ID)
	m.Name = types.StringValue(g.Name)
	m.Description = optionalString(g.Description, m.Description)
	m.Roles = stringSetValue(g.Roles, m.Roles)
	if !m.Members.IsNull() {
		m.Members = stringSetValue(g.Members, m.Members)
	}
}

func (r *groupResource) body(ctx context.Context, m groupModel, diags *diagnostics) map[string]any {
	roles := stringsFrom(ctx, m.Roles, diags)
	if roles == nil {
		roles = []string{}
	}
	return map[string]any{
		"name":        m.Name.ValueString(),
		"description": m.Description.ValueString(),
		"roles":       roles,
	}
}

// syncMembers makes the group's members equal to want.
func (r *groupResource) syncMembers(ctx context.Context, tenant string, g *apiGroup, want []string, diags *diagnostics) {
	for _, id := range g.Members {
		if !slices.Contains(want, id) {
			if err := r.client.Do(ctx, http.MethodDelete, groupPath(tenant, g.ID, "members", id), nil, nil, g); err != nil && !client.IsNotFound(err) {
				apiError(diags, "remove group member "+id, err)
				return
			}
		}
	}
	for _, id := range want {
		if !slices.Contains(g.Members, id) {
			if err := r.client.Do(ctx, http.MethodPut, groupPath(tenant, g.ID, "members", id), nil, nil, g); err != nil {
				apiError(diags, "add group member "+id, err)
				return
			}
		}
	}
}

func (r *groupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m groupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	body := r.body(ctx, m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var g apiGroup
	if err := r.client.Do(ctx, http.MethodPost, groupPath(m.TenantID.ValueString()), nil, body, &g); err != nil {
		apiError(&resp.Diagnostics, "create group", err)
		return
	}
	m.ID = types.StringValue(g.ID)
	if !m.Members.IsNull() {
		r.syncMembers(ctx, m.TenantID.ValueString(), &g, stringsFrom(ctx, m.Members, &resp.Diagnostics), &resp.Diagnostics)
	}
	m.fromAPI(g)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *groupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m groupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var g apiGroup
	err := r.client.Do(ctx, http.MethodGet, groupPath(m.TenantID.ValueString(), m.ID.ValueString()), nil, nil, &g)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read group", err)
		return
	}
	m.fromAPI(g)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *groupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m, state groupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	body := r.body(ctx, m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var g apiGroup
	if err := r.client.Do(ctx, http.MethodPatch, groupPath(m.TenantID.ValueString(), state.ID.ValueString()), nil, body, &g); err != nil {
		apiError(&resp.Diagnostics, "update group", err)
		return
	}
	if !m.Members.IsNull() {
		r.syncMembers(ctx, m.TenantID.ValueString(), &g, stringsFrom(ctx, m.Members, &resp.Diagnostics), &resp.Diagnostics)
	}
	m.fromAPI(g)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *groupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m groupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.Do(ctx, http.MethodDelete, groupPath(m.TenantID.ValueString(), m.ID.ValueString()), nil, nil, nil)
	if err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete group", err)
	}
}

func (r *groupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importTenantChild(ctx, req, resp, "id", "<tenant>/<group_id>")
}
