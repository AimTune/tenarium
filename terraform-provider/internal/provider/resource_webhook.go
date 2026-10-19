package provider

import (
	"context"
	"net/http"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
)

var (
	_ resource.ResourceWithConfigure   = (*webhookResource)(nil)
	_ resource.ResourceWithImportState = (*webhookResource)(nil)
)

type webhookResource struct{ resourceBase }

// NewWebhookResource returns the tenarium_tenant_webhook resource.
func NewWebhookResource() resource.Resource { return &webhookResource{} }

type webhookModel struct {
	ID          types.String `tfsdk:"id"`
	TenantID    types.String `tfsdk:"tenant_id"`
	URL         types.String `tfsdk:"url"`
	Description types.String `tfsdk:"description"`
	Types       types.List   `tfsdk:"types"`
	Enabled     types.Bool   `tfsdk:"enabled"`
	Secret      types.String `tfsdk:"secret"`
}

type apiWebhook struct {
	ID          string   `json:"id"`
	TenantID    string   `json:"tenant_id"`
	URL         string   `json:"url"`
	Description string   `json:"description"`
	Types       []string `json:"types"`
	Enabled     bool     `json:"enabled"`
}

type webhookInput struct {
	URL         *string   `json:"url,omitempty"`
	Description *string   `json:"description,omitempty"`
	Types       *[]string `json:"types,omitempty"`
	Enabled     *bool     `json:"enabled,omitempty"`
}

func (r *webhookResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_webhook"
}

func (r *webhookResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An outgoing webhook of a tenant. Tenarium signs deliveries with the webhook secret.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "Webhook ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id":   tenantIDAttribute(),
			"url":         schema.StringAttribute{Required: true, Description: "HTTPS endpoint receiving the events."},
			"description": schema.StringAttribute{Optional: true, Description: "Free-form description."},
			"types": schema.ListAttribute{
				Optional: true, ElementType: types.StringType,
				Description: "Event type patterns such as `tenant.*`. Empty means all events.",
			},
			"enabled": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				Description: "Whether events are delivered. Defaults to `true`.",
			},
			"secret": schema.StringAttribute{
				Computed: true, Sensitive: true,
				Description:   "Signing secret. The API returns it only when the webhook is created, so it is empty after import.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func webhooksPath(tenant string, rest ...string) string {
	p := "/v1/tenants/" + url.PathEscape(tenant) + "/webhooks"
	for _, s := range rest {
		p += "/" + url.PathEscape(s)
	}
	return p
}

func (m *webhookModel) fromAPI(w apiWebhook) {
	m.ID = types.StringValue(w.ID)
	m.URL = types.StringValue(w.URL)
	m.Description = optionalString(w.Description, m.Description)
	m.Types = stringListValue(w.Types, m.Types)
	m.Enabled = types.BoolValue(w.Enabled)
	if m.Secret.IsUnknown() {
		m.Secret = types.StringNull()
	}
}

func (r *webhookResource) input(ctx context.Context, m webhookModel, diags *diagnostics) webhookInput {
	typesList := stringsFrom(ctx, m.Types, diags)
	if typesList == nil {
		typesList = []string{}
	}
	return webhookInput{
		URL:         client.Ptr(m.URL.ValueString()),
		Description: client.Ptr(m.Description.ValueString()),
		Types:       &typesList,
		Enabled:     client.Ptr(m.Enabled.ValueBool()),
	}
}

func (r *webhookResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m webhookModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	in := r.input(ctx, m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var out struct {
		Webhook apiWebhook `json:"webhook"`
		Secret  string     `json:"secret"`
	}
	if err := r.client.Do(ctx, http.MethodPost, webhooksPath(m.TenantID.ValueString()), nil, in, &out); err != nil {
		apiError(&resp.Diagnostics, "create webhook", err)
		return
	}
	m.Secret = types.StringValue(out.Secret)
	m.fromAPI(out.Webhook)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *webhookResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m webhookModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var w apiWebhook
	err := r.client.Do(ctx, http.MethodGet, webhooksPath(m.TenantID.ValueString(), m.ID.ValueString()), nil, nil, &w)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read webhook", err)
		return
	}
	m.fromAPI(w)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *webhookResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m webhookModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	in := r.input(ctx, m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var w apiWebhook
	if err := r.client.Do(ctx, http.MethodPatch, webhooksPath(m.TenantID.ValueString(), m.ID.ValueString()), nil, in, &w); err != nil {
		apiError(&resp.Diagnostics, "update webhook", err)
		return
	}
	m.fromAPI(w)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *webhookResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m webhookModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.Do(ctx, http.MethodDelete, webhooksPath(m.TenantID.ValueString(), m.ID.ValueString()), nil, nil, nil)
	if err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete webhook", err)
	}
}

func (r *webhookResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importTenantChild(ctx, req, resp, "id", "<tenant>/<webhook_id>")
}
