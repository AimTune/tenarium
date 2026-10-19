package provider

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
)

var (
	_ resource.ResourceWithConfigure   = (*apiKeyResource)(nil)
	_ resource.ResourceWithImportState = (*apiKeyResource)(nil)
)

type apiKeyResource struct{ resourceBase }

// NewAPIKeyResource returns the tenarium_api_key resource.
func NewAPIKeyResource() resource.Resource { return &apiKeyResource{} }

type apiKeyModel struct {
	ID        types.String `tfsdk:"id"`
	TenantID  types.String `tfsdk:"tenant_id"`
	Name      types.String `tfsdk:"name"`
	Roles     types.Set    `tfsdk:"roles"`
	ExpiresIn types.String `tfsdk:"expires_in"`
	ExpiresAt types.String `tfsdk:"expires_at"`
	CreatedAt types.String `tfsdk:"created_at"`
	Prefix    types.String `tfsdk:"prefix"`
	Key       types.String `tfsdk:"key"`
}

type apiAPIKey struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"`
	Roles     []string   `json:"roles"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	Key       string     `json:"key"`
}

func (r *apiKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_api_key"
}

func (r *apiKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		Description: "An API key, scoped to a tenant or (without `tenant_id`) platform-wide. API keys are immutable: " +
			"every change creates a new key and revokes the old one. Destroying the resource revokes the key.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "API key ID.", PlanModifiers: keep},
			"tenant_id": schema.StringAttribute{
				Optional:      true,
				Description:   "ID (or slug) of the tenant the key belongs to. Omit for a platform key.",
				PlanModifiers: replace,
			},
			"name": schema.StringAttribute{Required: true, Description: "Display name.", PlanModifiers: replace},
			"roles": schema.SetAttribute{
				Required: true, ElementType: types.StringType,
				Description:   "Roles granted to the key (tenant roles for tenant keys, platform roles for platform keys).",
				PlanModifiers: []planmodifier.Set{setplanmodifier.RequiresReplace()},
			},
			"expires_in": schema.StringAttribute{
				Optional:      true,
				Description:   "Lifetime as a Go duration such as `720h`. Omit for a key that does not expire.",
				PlanModifiers: replace,
			},
			"expires_at": schema.StringAttribute{Computed: true, Description: "Expiry time (RFC 3339), if any.", PlanModifiers: keep},
			"created_at": schema.StringAttribute{Computed: true, Description: "Creation time (RFC 3339).", PlanModifiers: keep},
			"prefix":     schema.StringAttribute{Computed: true, Description: "Non-secret key prefix shown in listings.", PlanModifiers: keep},
			"key": schema.StringAttribute{
				Computed: true, Sensitive: true,
				Description:   "The secret key. The API returns it only once, at creation; it is empty after import.",
				PlanModifiers: keep,
			},
		},
	}
}

func apiKeysPath(tenant string, rest ...string) string {
	p := "/v1/api-keys"
	if tenant != "" {
		p = "/v1/tenants/" + url.PathEscape(tenant) + "/api-keys"
	}
	for _, s := range rest {
		p += "/" + url.PathEscape(s)
	}
	return p
}

func (m *apiKeyModel) fromAPI(k apiAPIKey) {
	m.ID = types.StringValue(k.ID)
	m.Name = types.StringValue(k.Name)
	m.Prefix = types.StringValue(k.Prefix)
	m.Roles = stringSetValue(k.Roles, m.Roles)
	m.CreatedAt = types.StringValue(k.CreatedAt.UTC().Format(time.RFC3339))
	if k.ExpiresAt != nil {
		m.ExpiresAt = types.StringValue(k.ExpiresAt.UTC().Format(time.RFC3339))
	} else {
		m.ExpiresAt = types.StringNull()
	}
	if k.Key != "" {
		m.Key = types.StringValue(k.Key)
	} else if m.Key.IsUnknown() {
		m.Key = types.StringNull()
	}
}

func (r *apiKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m apiKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	body := map[string]any{
		"name":  m.Name.ValueString(),
		"roles": stringsFrom(ctx, m.Roles, &resp.Diagnostics),
	}
	if !m.ExpiresIn.IsNull() {
		body["expires_in"] = m.ExpiresIn.ValueString()
	}
	if resp.Diagnostics.HasError() {
		return
	}
	var k apiAPIKey
	if err := r.client.Do(ctx, http.MethodPost, apiKeysPath(m.TenantID.ValueString()), nil, body, &k); err != nil {
		apiError(&resp.Diagnostics, "create API key", err)
		return
	}
	m.fromAPI(k)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *apiKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m apiKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out struct {
		Items []apiAPIKey `json:"items"`
	}
	err := r.client.Do(ctx, http.MethodGet, apiKeysPath(m.TenantID.ValueString()), nil, nil, &out)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "list API keys", err)
		return
	}
	for _, k := range out.Items {
		if k.ID == m.ID.ValueString() {
			if k.RevokedAt != nil {
				break
			}
			k.Key = "" // never returned by listings; keep the stored secret
			m.fromAPI(k)
			resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}

// Update is never called with a real change: every argument forces
// replacement. It only copies the plan for completeness.
func (r *apiKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m apiKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *apiKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m apiKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.Do(ctx, http.MethodDelete, apiKeysPath(m.TenantID.ValueString(), m.ID.ValueString()), nil, nil, nil)
	if err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "revoke API key", err)
	}
}

// ImportState accepts "<tenant>/<key_id>" for tenant keys and "<key_id>"
// for platform keys.
func (r *apiKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if parts, err := splitImportID(req.ID, ""); err == nil {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("tenant_id"), parts[0])...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), parts[1])...)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
