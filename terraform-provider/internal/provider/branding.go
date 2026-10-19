package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// brandingModel is the branding nested attribute of tenants and templates.
type brandingModel struct {
	DisplayName  types.String `tfsdk:"display_name"`
	LogoURL      types.String `tfsdk:"logo_url"`
	IconURL      types.String `tfsdk:"icon_url"`
	PrimaryColor types.String `tfsdk:"primary_color"`
	AccentColor  types.String `tfsdk:"accent_color"`
	SupportEmail types.String `tfsdk:"support_email"`
	SupportURL   types.String `tfsdk:"support_url"`
}

var brandingAttrTypes = map[string]attr.Type{
	"display_name":  types.StringType,
	"logo_url":      types.StringType,
	"icon_url":      types.StringType,
	"primary_color": types.StringType,
	"accent_color":  types.StringType,
	"support_email": types.StringType,
	"support_url":   types.StringType,
}

// brandingAttribute is the schema of a branding attribute; description
// explains how an unset value behaves for the resource.
func brandingAttribute(description string, mods ...planmodifier.Object) schema.SingleNestedAttribute {
	str := func(d string) schema.StringAttribute { return schema.StringAttribute{Optional: true, Description: d} }
	return schema.SingleNestedAttribute{
		Optional: true, Computed: len(mods) > 0,
		Description:   description,
		PlanModifiers: mods,
		Attributes: map[string]schema.Attribute{
			"display_name":  str("Name shown instead of the tenant name."),
			"logo_url":      str("HTTPS URL of the logo."),
			"icon_url":      str("HTTPS URL of the icon (favicon)."),
			"primary_color": str("Primary color as `#rrggbb`."),
			"accent_color":  str("Accent color as `#rrggbb`."),
			"support_email": str("Support email address."),
			"support_url":   str("HTTPS URL of the support site."),
		},
	}
}

// brandingFrom converts the attribute into the API value; null and unknown
// give nil.
func brandingFrom(ctx context.Context, v types.Object, diags *diagnostics) *sdk.Branding {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	var m brandingModel
	diags.Append(v.As(ctx, &m, objectAsOptions)...)
	return &sdk.Branding{
		DisplayName:  m.DisplayName.ValueString(),
		LogoURL:      m.LogoURL.ValueString(),
		IconURL:      m.IconURL.ValueString(),
		PrimaryColor: m.PrimaryColor.ValueString(),
		AccentColor:  m.AccentColor.ValueString(),
		SupportEmail: m.SupportEmail.ValueString(),
		SupportURL:   m.SupportURL.ValueString(),
	}
}

// brandingValue converts the API value into the attribute. Unset fields are
// null unless the prior value spelled them as "". The API drops an empty
// branding, so a prior object without any value is kept for nil.
func brandingValue(ctx context.Context, b *sdk.Branding, prior types.Object, diags *diagnostics) types.Object {
	var pm brandingModel
	priorKnown := !prior.IsNull() && !prior.IsUnknown()
	if priorKnown {
		diags.Append(prior.As(ctx, &pm, objectAsOptions)...)
	}
	if b == nil {
		if !priorKnown || *brandingFrom(ctx, prior, diags) != (sdk.Branding{}) {
			return types.ObjectNull(brandingAttrTypes)
		}
		b = &sdk.Branding{}
	}
	m := brandingModel{
		DisplayName:  optionalString(b.DisplayName, pm.DisplayName),
		LogoURL:      optionalString(b.LogoURL, pm.LogoURL),
		IconURL:      optionalString(b.IconURL, pm.IconURL),
		PrimaryColor: optionalString(b.PrimaryColor, pm.PrimaryColor),
		AccentColor:  optionalString(b.AccentColor, pm.AccentColor),
		SupportEmail: optionalString(b.SupportEmail, pm.SupportEmail),
		SupportURL:   optionalString(b.SupportURL, pm.SupportURL),
	}
	v, d := types.ObjectValueFrom(ctx, brandingAttrTypes, m)
	diags.Append(d...)
	return v
}

// objectAsOptions converts objects into models strictly.
var objectAsOptions = basetypes.ObjectAsOptions{}
