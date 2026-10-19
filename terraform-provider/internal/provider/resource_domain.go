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
	_ resource.ResourceWithConfigure   = (*domainResource)(nil)
	_ resource.ResourceWithImportState = (*domainResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*domainResource)(nil)
)

// ChallengePrefix is the DNS label the verification TXT record lives under.
const challengePrefix = "_tenarium-challenge."

type domainResource struct{ resourceBase }

// NewDomainResource returns the tenarium_tenant_domain resource.
func NewDomainResource() resource.Resource { return &domainResource{} }

type domainModel struct {
	ID             types.String `tfsdk:"id"`
	TenantID       types.String `tfsdk:"tenant_id"`
	Hostname       types.String `tfsdk:"hostname"`
	Verify         types.Bool   `tfsdk:"verify"`
	Verified       types.Bool   `tfsdk:"verified"`
	Token          types.String `tfsdk:"verification_token"`
	TXTRecordName  types.String `tfsdk:"txt_record_name"`
	TXTRecordValue types.String `tfsdk:"txt_record_value"`
}

// apiDomain mirrors the API's domain object.
type apiDomain struct {
	Hostname string `json:"hostname"`
	TenantID string `json:"tenant_id"`
	Verified bool   `json:"verified"`
	Token    string `json:"verification_token"`
}

func (r *domainResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_domain"
}

func (r *domainResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	resp.Schema = schema.Schema{
		Description: "A custom hostname of a tenant. Publish the TXT record given by `txt_record_name` and `txt_record_value`, then set `verify = true` to prove ownership.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "`<tenant_id>/<hostname>`.", PlanModifiers: keep,
			},
			"tenant_id": tenantIDAttribute(),
			"hostname": schema.StringAttribute{
				Required:      true,
				Description:   "Fully qualified hostname, e.g. `app.example.com`. Changing it replaces the domain.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"verify": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "When true, Terraform asks the server to verify the TXT record. If the record is not visible yet, apply succeeds with a warning and the next plan retries. Defaults to `false`.",
			},
			"verified":           schema.BoolAttribute{Computed: true, Description: "Whether ownership has been verified."},
			"verification_token": schema.StringAttribute{Computed: true, Description: "Verification token.", PlanModifiers: keep},
			"txt_record_name": schema.StringAttribute{
				Computed: true, Description: "Name of the TXT record to publish.", PlanModifiers: keep,
			},
			"txt_record_value": schema.StringAttribute{
				Computed: true, Description: "Value of the TXT record to publish.", PlanModifiers: keep,
			},
		},
	}
}

// ModifyPlan keeps verified stable, except that an unverified domain with
// verify = true plans an update so apply retries the verification.
func (r *domainResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var plan, state domainModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Verify.ValueBool() && !state.Verified.ValueBool() {
		plan.Verified = types.BoolUnknown()
	} else {
		plan.Verified = state.Verified
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

func (m *domainModel) fromAPI(d apiDomain) {
	if m.Hostname.IsNull() || m.Hostname.IsUnknown() || normalizeHostname(m.Hostname.ValueString()) != d.Hostname {
		m.Hostname = types.StringValue(d.Hostname)
	}
	m.ID = types.StringValue(m.TenantID.ValueString() + "/" + d.Hostname)
	m.Verified = types.BoolValue(d.Verified)
	m.Token = types.StringValue(d.Token)
	m.TXTRecordName = types.StringValue(challengePrefix + d.Hostname)
	m.TXTRecordValue = types.StringValue(d.Token)
	if m.Verify.IsNull() || m.Verify.IsUnknown() {
		m.Verify = types.BoolValue(false)
	}
}

func domainsPath(tenant string, rest ...string) string {
	p := "/v1/tenants/" + url.PathEscape(tenant) + "/domains"
	for _, s := range rest {
		p += "/" + url.PathEscape(s)
	}
	return p
}

func (r *domainResource) get(ctx context.Context, tenant, hostname string) (apiDomain, bool, error) {
	var out struct {
		Items []apiDomain `json:"items"`
	}
	if err := r.client.Do(ctx, http.MethodGet, domainsPath(tenant), nil, nil, &out); err != nil {
		return apiDomain{}, false, err
	}
	h := normalizeHostname(hostname)
	for _, d := range out.Items {
		if d.Hostname == h {
			return d, true, nil
		}
	}
	return apiDomain{}, false, nil
}

// verify asks the server to check the TXT record; a failed check is a
// warning so the domain stays in state and the next apply retries.
func (r *domainResource) verify(ctx context.Context, m *domainModel, diags interface {
	AddWarning(string, string)
	AddError(string, string)
}) {
	var d apiDomain
	err := r.client.Do(ctx, http.MethodPost, domainsPath(m.TenantID.ValueString(), normalizeHostname(m.Hostname.ValueString()), "verify"), nil, nil, &d)
	if e, ok := client.AsError(err); ok && e.Status == http.StatusUnprocessableEntity {
		diags.AddWarning("Domain not verified yet",
			"Publish TXT "+m.TXTRecordName.ValueString()+" = \""+m.TXTRecordValue.ValueString()+"\" and apply again. Server said: "+e.Message)
		m.Verified = types.BoolValue(false)
		return
	}
	if err != nil {
		diags.AddError("Tenarium API error: verify domain", err.Error())
		return
	}
	m.fromAPI(d)
}

func (r *domainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m domainModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var out struct {
		Domain apiDomain `json:"domain"`
	}
	err := r.client.Do(ctx, http.MethodPost, domainsPath(m.TenantID.ValueString()), nil,
		map[string]string{"hostname": m.Hostname.ValueString()}, &out)
	if err != nil {
		apiError(&resp.Diagnostics, "add domain", err)
		return
	}
	m.fromAPI(out.Domain)
	if m.Verify.ValueBool() {
		r.verify(ctx, &m, &resp.Diagnostics)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *domainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m domainModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	d, found, err := r.get(ctx, m.TenantID.ValueString(), m.Hostname.ValueString())
	if client.IsNotFound(err) || (err == nil && !found) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read domain", err)
		return
	}
	m.fromAPI(d)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *domainResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m, state domainModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	m.Verified = state.Verified
	if m.Verify.ValueBool() && !state.Verified.ValueBool() {
		r.verify(ctx, &m, &resp.Diagnostics)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *domainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m domainModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.client.Do(ctx, http.MethodDelete, domainsPath(m.TenantID.ValueString(), normalizeHostname(m.Hostname.ValueString())), nil, nil, nil)
	if err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "remove domain", err)
	}
}

func (r *domainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	importTenantChild(ctx, req, resp, "hostname", "<tenant>/<hostname>")
}
