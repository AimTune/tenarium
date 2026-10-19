// Package provider implements the Tenarium Terraform provider.
package provider

import (
	"context"
	"os"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
)

// Environment variables read when the provider block leaves a value unset.
const (
	EnvURL    = "TENARIUM_URL"
	EnvAPIKey = "TENARIUM_API_KEY" //nolint:gosec // the name of an environment variable, not a credential
)

var _ provider.Provider = (*tenariumProvider)(nil)

type tenariumProvider struct{ version string }

// New returns a constructor for the provider, as providerserver expects.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &tenariumProvider{version: version} }
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	APIKey   types.String `tfsdk:"api_key"`
}

func (p *tenariumProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "tenarium"
	resp.Version = p.version
}

func (p *tenariumProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages tenants, plans and tenant configuration in a Tenarium control plane.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "Base URL of the Tenarium API, e.g. `https://tenarium.example.com`. Defaults to the `" + EnvURL + "` environment variable.",
			},
			"api_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "API key sent as a bearer token. Defaults to the `" + EnvAPIKey + "` environment variable.",
			},
		},
	}
}

func (p *tenariumProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if cfg.Endpoint.IsUnknown() || cfg.APIKey.IsUnknown() {
		resp.Diagnostics.AddError("Unknown provider configuration",
			"endpoint and api_key must be known when the provider is configured.")
		return
	}
	endpoint := os.Getenv(EnvURL)
	if !cfg.Endpoint.IsNull() {
		endpoint = cfg.Endpoint.ValueString()
	}
	apiKey := os.Getenv(EnvAPIKey)
	if !cfg.APIKey.IsNull() {
		apiKey = cfg.APIKey.ValueString()
	}
	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Missing Tenarium endpoint",
			"Set endpoint in the provider block or the "+EnvURL+" environment variable.")
		return
	}
	opts := []client.Option{
		client.WithUserAgent("terraform-provider-tenarium/" + p.version),
		client.WithRetry(3, 250*time.Millisecond),
	}
	if apiKey != "" {
		opts = append(opts, client.WithAPIKey(apiKey))
	}
	c, err := client.New(endpoint, opts...)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Invalid Tenarium endpoint", err.Error())
		return
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *tenariumProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewPlanResource,
		NewTenantResource,
		NewMemberResource,
		NewDomainResource,
		NewWebhookResource,
		NewRoleResource,
		NewGroupResource,
		NewSSOResource,
		NewAPIKeyResource,
		NewRolloutResource,
		NewTemplateResource,
	}
}

func (p *tenariumProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewTenantDataSource,
		NewPlanDataSource,
		NewEntitlementsDataSource,
		NewPlanRevisionsDataSource,
		NewTenantHealthDataSource,
	}
}
