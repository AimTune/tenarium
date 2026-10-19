package provider

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
)

var (
	_ resource.ResourceWithConfigure      = (*ssoResource)(nil)
	_ resource.ResourceWithImportState    = (*ssoResource)(nil)
	_ resource.ResourceWithValidateConfig = (*ssoResource)(nil)
)

type ssoResource struct{ resourceBase }

// NewSSOResource returns the tenarium_tenant_sso resource.
func NewSSOResource() resource.Resource { return &ssoResource{} }

type ssoModel struct {
	ID                 types.String `tfsdk:"id"`
	TenantID           types.String `tfsdk:"tenant_id"`
	Protocol           types.String `tfsdk:"protocol"`
	Issuer             types.String `tfsdk:"issuer"`
	ClientID           types.String `tfsdk:"client_id"`
	ClientSecret       types.String `tfsdk:"client_secret"`
	SAMLMetadata       types.String `tfsdk:"saml_metadata"`
	SAMLMetadataURL    types.String `tfsdk:"saml_metadata_url"`
	SAMLEmailAttribute types.String `tfsdk:"saml_email_attribute"`
	SAMLNameAttribute  types.String `tfsdk:"saml_name_attribute"`
	Domains            types.Set    `tfsdk:"domains"`
	Enforce            types.Bool   `tfsdk:"enforce"`
	AutoProvision      types.Bool   `tfsdk:"auto_provision"`
	DefaultRole        types.String `tfsdk:"default_role"`
	Enabled            types.Bool   `tfsdk:"enabled"`
}

type apiSSO struct {
	TenantID           string   `json:"tenant_id"`
	Protocol           string   `json:"protocol"`
	Issuer             string   `json:"issuer"`
	ClientID           string   `json:"client_id"`
	SAMLMetadataURL    string   `json:"saml_metadata_url"`
	SAMLEmailAttribute string   `json:"saml_email_attribute"`
	SAMLNameAttribute  string   `json:"saml_name_attribute"`
	Domains            []string `json:"domains"`
	Enforce            bool     `json:"enforce"`
	AutoProvision      bool     `json:"auto_provision"`
	DefaultRole        string   `json:"default_role"`
	Enabled            bool     `json:"enabled"`
}

func (r *ssoResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant_sso"
}

func (r *ssoResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The single sign-on (OIDC or SAML) connection of a tenant. A tenant has at most one. " +
			"Every email domain must be a verified `tenarium_tenant_domain` of the tenant.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, Description: "Same as `tenant_id`.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id": tenantIDAttribute(),
			"protocol": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("oidc"),
				Description: "`oidc` (default) or `saml`.",
				Validators:  []validator.String{stringvalidator.OneOf("oidc", "saml")},
			},
			"issuer": schema.StringAttribute{
				Optional: true, Computed: true,
				Description: "OIDC issuer URL (required for OIDC). For SAML it is the identity provider's entity ID, read from the metadata.",
			},
			"client_id": schema.StringAttribute{Optional: true, Description: "OIDC client ID (required for OIDC)."},
			"client_secret": schema.StringAttribute{
				Optional: true, Sensitive: true,
				Description: "OIDC client secret (required for OIDC). The API never returns it, so changes made outside Terraform are not detected.",
			},
			"saml_metadata": schema.StringAttribute{
				Optional:    true,
				Description: "SAML identity provider metadata XML. The API never returns it. One of `saml_metadata` and `saml_metadata_url` is required for SAML.",
			},
			"saml_metadata_url":    schema.StringAttribute{Optional: true, Description: "URL to fetch the SAML metadata from."},
			"saml_email_attribute": schema.StringAttribute{Optional: true, Description: "SAML attribute carrying the email address."},
			"saml_name_attribute":  schema.StringAttribute{Optional: true, Description: "SAML attribute carrying the display name."},
			"domains": schema.SetAttribute{
				Required: true, ElementType: types.StringType,
				Description: "Email domains whose users sign in through this connection. Each must be a verified domain of the tenant.",
			},
			"enforce": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Refuse password logins for users of the domains. Defaults to `false`.",
			},
			"auto_provision": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "Create users and memberships on first sign-in. Defaults to `false`.",
			},
			"default_role": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString("member"),
				Description: "Role given to auto-provisioned members. Defaults to `member`.",
			},
			"enabled": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				Description: "Whether the connection can be used. Defaults to `true`.",
			},
		},
	}
}

func (r *ssoResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var m ssoModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() || m.Protocol.IsUnknown() {
		return
	}
	if m.Protocol.IsNull() || m.Protocol.ValueString() == "oidc" {
		for _, a := range []struct {
			name string
			v    types.String
		}{{"issuer", m.Issuer}, {"client_id", m.ClientID}, {"client_secret", m.ClientSecret}} {
			if a.v.IsNull() {
				resp.Diagnostics.AddAttributeError(path.Root(a.name), "Missing attribute", a.name+" is required for OIDC connections.")
			}
		}
		return
	}
	if m.SAMLMetadata.IsNull() && m.SAMLMetadataURL.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("saml_metadata"), "Missing attribute",
			"One of saml_metadata and saml_metadata_url is required for SAML connections.")
	}
	if !m.ClientID.IsNull() || !m.ClientSecret.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("client_id"), "Unsupported attribute",
			"client_id and client_secret only apply to OIDC connections.")
	}
}

func ssoPath(tenant string) string { return "/v1/tenants/" + url.PathEscape(tenant) + "/sso" }

func (m *ssoModel) fromAPI(c apiSSO) {
	m.ID = types.StringValue(m.TenantID.ValueString())
	m.Protocol = types.StringValue(c.Protocol)
	if m.Issuer.IsNull() || m.Issuer.IsUnknown() || strings.TrimRight(strings.TrimSpace(m.Issuer.ValueString()), "/") != c.Issuer {
		m.Issuer = types.StringValue(c.Issuer)
	}
	m.ClientID = optionalString(c.ClientID, m.ClientID)
	m.SAMLMetadataURL = optionalString(c.SAMLMetadataURL, m.SAMLMetadataURL)
	m.SAMLEmailAttribute = optionalString(c.SAMLEmailAttribute, m.SAMLEmailAttribute)
	m.SAMLNameAttribute = optionalString(c.SAMLNameAttribute, m.SAMLNameAttribute)
	// Keep the configured spelling of domains when it normalizes to the
	// stored value.
	var configured []string
	for _, e := range m.Domains.Elements() {
		if s, ok := e.(types.String); ok {
			configured = append(configured, s.ValueString())
		}
	}
	same := len(configured) == len(c.Domains)
	if same {
		set := map[string]bool{}
		for _, d := range configured {
			set[normalizeHostname(d)] = true
		}
		for _, d := range c.Domains {
			if !set[d] {
				same = false
			}
		}
	}
	if !same {
		m.Domains = stringSetValue(c.Domains, m.Domains)
	}
	m.Enforce = types.BoolValue(c.Enforce)
	m.AutoProvision = types.BoolValue(c.AutoProvision)
	m.DefaultRole = types.StringValue(c.DefaultRole)
	m.Enabled = types.BoolValue(c.Enabled)
}

func (r *ssoResource) put(ctx context.Context, m *ssoModel, diags *diagnostics) {
	body := map[string]any{
		"protocol":             m.Protocol.ValueString(),
		"issuer":               m.Issuer.ValueString(),
		"client_id":            m.ClientID.ValueString(),
		"client_secret":        m.ClientSecret.ValueString(),
		"saml_metadata":        m.SAMLMetadata.ValueString(),
		"saml_metadata_url":    m.SAMLMetadataURL.ValueString(),
		"saml_email_attribute": m.SAMLEmailAttribute.ValueString(),
		"saml_name_attribute":  m.SAMLNameAttribute.ValueString(),
		"domains":              stringsFrom(ctx, m.Domains, diags),
		"enforce":              m.Enforce.ValueBool(),
		"auto_provision":       m.AutoProvision.ValueBool(),
		"default_role":         m.DefaultRole.ValueString(),
		"enabled":              m.Enabled.ValueBool(),
	}
	if diags.HasError() {
		return
	}
	var out apiSSO
	if err := r.client.Do(ctx, http.MethodPut, ssoPath(m.TenantID.ValueString()), nil, body, &out); err != nil {
		apiError(diags, "configure SSO", err)
		return
	}
	m.fromAPI(out)
}

func (r *ssoResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m ssoModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var existing apiSSO
	err := r.client.Do(ctx, http.MethodGet, ssoPath(m.TenantID.ValueString()), nil, nil, &existing)
	if err == nil {
		resp.Diagnostics.AddError("SSO already configured",
			"The tenant already has an SSO connection. Import it with `terraform import` instead.")
		return
	} else if !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "read SSO", err)
		return
	}
	r.put(ctx, &m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *ssoResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m ssoModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var c apiSSO
	err := r.client.Do(ctx, http.MethodGet, ssoPath(m.TenantID.ValueString()), nil, nil, &c)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read SSO", err)
		return
	}
	m.fromAPI(c)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *ssoResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m ssoModel
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

func (r *ssoResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m ssoModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.Do(ctx, http.MethodDelete, ssoPath(m.TenantID.ValueString()), nil, nil, nil); err != nil && !client.IsNotFound(err) {
		apiError(&resp.Diagnostics, "delete SSO", err)
	}
}

func (r *ssoResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("tenant_id"), req.ID)...)
}
