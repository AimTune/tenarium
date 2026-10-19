package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

var (
	_ resource.ResourceWithConfigure   = (*memberResource)(nil)
	_ resource.ResourceWithImportState = (*memberResource)(nil)
)

type memberResource struct{ resourceBase }

// NewMemberResource returns the tenarium_member resource.
func NewMemberResource() resource.Resource { return &memberResource{} }

type memberModel struct {
	ID       types.String `tfsdk:"id"`
	TenantID types.String `tfsdk:"tenant_id"`
	Email    types.String `tfsdk:"email"`
	UserID   types.String `tfsdk:"user_id"`
	Name     types.String `tfsdk:"name"`
	Role     types.String `tfsdk:"role"`
	Status   types.String `tfsdk:"status"`
}

func (r *memberResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_member"
}

// tenantIDAttribute is the parent tenant reference shared by tenant-scoped
// resources.
func tenantIDAttribute() schema.StringAttribute {
	return schema.StringAttribute{
		Required:      true,
		Description:   "ID (or slug) of the tenant. Changing it replaces the resource.",
		PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
	}
}

func (r *memberResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	identity := []validator.String{stringvalidator.ExactlyOneOf(path.MatchRoot("email"), path.MatchRoot("user_id"))}
	resp.Schema = schema.Schema{
		Description: "A membership linking a user to a tenant with a role. Adding an unknown email invites a new user.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "Member ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id": tenantIDAttribute(),
			"email": schema.StringAttribute{
				Optional: true, Computed: true,
				Description: "Email of the user to add or invite. Exactly one of `email` and `user_id` must be set. Changing it replaces the membership.",
				Validators:  identity,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"user_id": schema.StringAttribute{
				Optional: true, Computed: true,
				Description: "ID of an existing user. Exactly one of `email` and `user_id` must be set. Changing it replaces the membership.",
				Validators:  identity,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Name used when the membership creates (invites) a new user. Not read back.",
			},
			"role": schema.StringAttribute{Required: true, Description: "Built-in or custom tenant role, e.g. `owner`, `admin` or `member`."},
			"status": schema.StringAttribute{
				Computed: true, Description: "`invited`, `active` or `suspended`.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (m *memberModel) fromAPI(mem sdk.Member) {
	m.ID = types.StringValue(mem.ID)
	if m.Email.IsNull() || m.Email.IsUnknown() || !strings.EqualFold(m.Email.ValueString(), mem.Email) {
		m.Email = types.StringValue(mem.Email)
	}
	if mem.UserID != "" {
		m.UserID = types.StringValue(mem.UserID)
	} else if m.UserID.IsUnknown() {
		m.UserID = types.StringNull()
	}
	m.Role = types.StringValue(mem.Role)
	m.Status = types.StringValue(string(mem.Status))
}

func (r *memberResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m memberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	mem, err := r.client.Members.Add(ctx, m.TenantID.ValueString(), client.AddMemberRequest{
		Email:  m.Email.ValueString(),
		UserID: m.UserID.ValueString(),
		Name:   m.Name.ValueString(),
		Role:   m.Role.ValueString(),
	})
	if err != nil {
		apiError(&resp.Diagnostics, "add member", err)
		return
	}
	m.fromAPI(mem)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *memberResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m memberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	mem, err := r.client.Members.Get(ctx, m.TenantID.ValueString(), m.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read member", err)
		return
	}
	m.fromAPI(mem)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *memberResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m memberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	mem, err := r.client.Members.Update(ctx, m.TenantID.ValueString(), m.ID.ValueString(),
		client.UpdateMemberRequest{Role: client.Ptr(m.Role.ValueString())})
	if err != nil {
		apiError(&resp.Diagnostics, "update member", err)
		return
	}
	m.fromAPI(mem)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *memberResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m memberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Members.Remove(ctx, m.TenantID.ValueString(), m.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "remove member", err)
	}
}

func (r *memberResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importTenantChild(ctx, req, resp, "id", "<tenant>/<member_id>")
}

// importTenantChild handles "<tenant>/<child>" import IDs, setting
// tenant_id and the given child attribute.
func importTenantChild(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse, attr, format string) {
	parts, err := splitImportID(req.ID, format)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("tenant_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(attr), parts[1])...)
}
