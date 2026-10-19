package provider

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

var (
	_ resource.ResourceWithConfigure   = (*tenantResource)(nil)
	_ resource.ResourceWithImportState = (*tenantResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*tenantResource)(nil)
)

type tenantResource struct{ resourceBase }

// NewTenantResource returns the tenarium_tenant resource.
func NewTenantResource() resource.Resource { return &tenantResource{} }

type tenantModel struct {
	ID                 types.String         `tfsdk:"id"`
	Slug               types.String         `tfsdk:"slug"`
	Name               types.String         `tfsdk:"name"`
	Plan               types.String         `tfsdk:"plan"`
	PlanRevision       types.Int64          `tfsdk:"plan_revision"`
	AddOns             types.Set            `tfsdk:"add_ons"`
	ParentID           types.String         `tfsdk:"parent_id"`
	Region             types.String         `tfsdk:"region"`
	MoveReprovision    types.Bool           `tfsdk:"move_reprovision"`
	Template           types.String         `tfsdk:"template"`
	Labels             types.Map            `tfsdk:"labels"`
	Settings           jsontypes.Normalized `tfsdk:"settings"`
	Features           types.Map            `tfsdk:"features"`
	Limits             types.Map            `tfsdk:"limits"`
	BillingAnchor      types.String         `tfsdk:"billing_anchor"`
	Branding           types.Object         `tfsdk:"branding"`
	Status             types.String         `tfsdk:"status"`
	Version            types.Int64          `tfsdk:"version"`
	DeletionProtection types.Bool           `tfsdk:"deletion_protection"`
	ForceDelete        types.Bool           `tfsdk:"force_delete"`
}

func (r *tenantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tenant"
}

func tenantSchemaDescription() string {
	return "A tenant (customer, organization or workspace). Tenants can be nested with `parent_id`."
}

// fromTemplate is appended to the descriptions of attributes a template
// can fill in.
const fromTemplate = " When unset at creation with a `template`, the tenant gets and keeps the template's value (Terraform leaves it alone until you configure it). Otherwise an unset value is empty, and removing the attribute from the configuration clears it."

func (r *tenantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: tenantSchemaDescription(),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Tenant ID (UUID).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"slug": schema.StringAttribute{
				Required:      true,
				Description:   "URL-safe unique identifier. Changing it replaces the tenant.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{Required: true, Description: "Display name."},
			"plan": schema.StringAttribute{
				Optional: true, Computed: true,
				Description:   "ID of the plan the tenant subscribes to. When omitted, the server decides (child tenants inherit their parent's plan, a `template` may set one) and Terraform keeps whatever plan the tenant has; set it to `\"\"` to clear it.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"plan_revision": schema.Int64Attribute{
				Optional: true, Computed: true,
				Description: "Revision of the plan the tenant is pinned to (see the `tenarium_plan_revisions` data source); `0` follows the current plan. " +
					"When omitted, Terraform leaves the pin alone, for example one set by updating a plan with `grandfather_on_update`, and only reports it. " +
					"Changing `plan` resets the pin on the server. Requires `plans:write`.",
				Validators:    []validator.Int64{int64validator.AtLeast(0)},
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"add_ons": schema.SetAttribute{
				Optional: true, Computed: true, ElementType: types.StringType,
				Description:   "IDs of add-on plans stacked on the plan (at most 20; requires `plans:write`)." + fromTemplate,
				Validators:    []validator.Set{setvalidator.SizeAtMost(20)},
				PlanModifiers: []planmodifier.Set{templateComputed{}},
			},
			"parent_id": schema.StringAttribute{
				Optional:      true,
				Description:   "ID of the parent tenant, for hierarchies such as organization and workspace. Changing it replaces the tenant.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"region": schema.StringAttribute{
				Optional: true, Computed: true,
				Description: "Region the tenant is placed in (data residency). When omitted at creation, the parent's region, the template's region or the server's default region applies, and Terraform keeps whatever region the tenant has. " +
					"Changing it moves the tenant (`POST /v1/tenants/{id}/move`, requires `tenants:move`) instead of replacing it. A region cannot be removed.",
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"move_reprovision": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "When true, a change of `region` re-runs the provisioners in the new region inside a maintenance window (the tenant is `provisioning` until they succeed). Needs provisioner plugins on the server. Defaults to `false`.",
			},
			"template": schema.StringAttribute{
				Optional: true,
				Description: "ID of a tenant template (`tenarium_tenant_template`) that presets the tenant at creation: plan, add-ons, region, labels, settings, features, limits, branding and custom roles. " +
					"Attributes set in the configuration win: for those, the tenant ends up exactly as configured (template map entries and settings keys not in the configuration are removed). " +
					"Only used when the tenant is created; changing or removing it later has no effect and does not replace the tenant. Empty after an import.",
			},
			"labels": schema.MapAttribute{
				Optional: true, Computed: true, ElementType: types.StringType,
				Description:   "Key/value labels used for filtering." + fromTemplate,
				PlanModifiers: []planmodifier.Map{templateComputed{}},
			},
			"settings": schema.StringAttribute{
				Optional: true, Computed: true,
				CustomType:    jsontypes.NormalizedType{},
				PlanModifiers: []planmodifier.String{templateComputed{}, jsonSemanticPlan{}},
				Description:   "Tenant settings as a JSON object string, typically built with `jsonencode()`. Formatting and key order differences are ignored." + fromTemplate,
			},
			"features": schema.MapAttribute{
				Optional: true, Computed: true, ElementType: types.BoolType,
				Description:   "Feature overrides on top of the plan." + fromTemplate,
				PlanModifiers: []planmodifier.Map{templateComputed{}},
			},
			"limits": schema.MapAttribute{
				Optional: true, Computed: true, ElementType: types.Int64Type,
				Description:   "Limit overrides on top of the plan." + fromTemplate,
				PlanModifiers: []planmodifier.Map{templateComputed{}},
			},
			"billing_anchor": schema.StringAttribute{
				Optional: true, Computed: true,
				Description: "Start of the tenant's monthly billing cycles for `cycle` usage periods, as an RFC 3339 timestamp (requires `plans:write`). " +
					"Spellings of the same instant are equal. Set it to `\"\"` to remove the anchor (cycles then start at the creation time); when omitted, Terraform keeps whatever anchor the tenant has, e.g. one set by a billing plugin.",
				Validators:    []validator.String{rfc3339{}},
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown(), sameInstantPlan{}},
			},
			"branding": brandingAttribute("Look of the tenant's sign-in pages and emails. Every change replaces the whole branding."+fromTemplate, templateComputed{}),
			"status": schema.StringAttribute{
				Computed:      true,
				Description:   "Lifecycle status: `provisioning`, `active`, `suspended`, `failed`, `deleting` or `deleted`.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"version": schema.Int64Attribute{
				Computed:    true,
				Description: "Version of the tenant, incremented on every write. Updates send it as `If-Match`, so changes made outside Terraform since the last refresh fail instead of being overwritten.",
			},
			"deletion_protection": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "When true, `terraform destroy` (or a replacement) fails instead of deleting the tenant. Defaults to `false`.",
			},
			"force_delete": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				Description: "When true, deletion skips the server's deletion grace period (`?force=true`, requires the `tenants:purge` permission). Defaults to `false`.",
			},
		},
	}
}

// fromAPI copies the API representation into m, keeping the user's spelling
// of references (parent and plan) and timestamps when they resolve to the
// same object or instant.
func (m *tenantModel) fromAPI(ctx context.Context, t sdk.Tenant, diags *diagnostics) {
	m.ID = types.StringValue(t.ID)
	m.Slug = types.StringValue(t.Slug)
	m.Name = types.StringValue(t.Name)
	m.Plan = types.StringValue(t.Plan)
	m.PlanRevision = types.Int64Value(t.PlanRevision)
	m.AddOns = stringSetValue(t.AddOns, m.AddOns)
	if t.ParentID == "" {
		m.ParentID = types.StringNull()
	} else if m.ParentID.IsNull() || m.ParentID.IsUnknown() || m.ParentID.ValueString() == t.ParentID {
		m.ParentID = types.StringValue(t.ParentID)
	} // else: the configuration names the parent by slug; keep it.
	m.Region = optionalString(t.Region, m.Region)
	m.Labels = stringMapValue(t.Labels, m.Labels)
	m.Features = boolMapValue(t.Features, m.Features)
	m.Limits = int64MapValue(t.Limits, m.Limits)
	s, err := settingsValue(t.Settings, m.Settings)
	if err != nil {
		diags.AddError("Cannot encode tenant settings", err.Error())
	}
	m.Settings = s
	m.BillingAnchor = timeValue(t.BillingAnchor, m.BillingAnchor)
	m.Branding = brandingValue(ctx, t.Branding, m.Branding, diags)
	m.Status = types.StringValue(string(t.Status))
	m.Version = types.Int64Value(t.Version)
	for _, b := range []*types.Bool{&m.DeletionProtection, &m.ForceDelete, &m.MoveReprovision} {
		if b.IsNull() || b.IsUnknown() {
			*b = types.BoolValue(false)
		}
	}
}

func (r *tenantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m tenantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	settings, err := settingsMap(m.Settings)
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("settings"), "Invalid settings", err.Error())
		return
	}
	in := client.CreateTenantRequest{
		Slug:     m.Slug.ValueString(),
		Name:     m.Name.ValueString(),
		ParentID: m.ParentID.ValueString(),
		Plan:     m.Plan.ValueString(),
		Labels:   mapFrom[string](ctx, m.Labels, &resp.Diagnostics),
		Settings: settings,
		Features: mapFrom[bool](ctx, m.Features, &resp.Diagnostics),
		Limits:   mapFrom[int64](ctx, m.Limits, &resp.Diagnostics),
		AddOns:   stringsFrom(ctx, m.AddOns, &resp.Diagnostics),
		Region:   m.Region.ValueString(),
		Branding: brandingFrom(ctx, m.Branding, &resp.Diagnostics),
		Template: m.Template.ValueString(),
	}
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.client.Tenants.Create(ctx, in)
	if err != nil {
		apiError(&resp.Diagnostics, "create tenant", err)
		return
	}
	// Attributes left unset with a template keep the template's values.
	owned := map[string]bool{}
	for name, v := range m.templateAttrs() {
		if v.IsUnknown() {
			owned[name] = true
		}
	}
	resp.Diagnostics.Append(setTemplateOwned(ctx, resp.Private, owned)...)
	// Save the tenant before the follow-up calls, so a failure in them
	// leaves it in state (tainted) instead of orphaned.
	got := m
	got.fromAPI(ctx, t, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &got)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The create request cannot carry a billing anchor or empty values, and
	// template values may differ from the configured ones: patch the rest.
	if fix, changed := r.updateRequest(ctx, m, got, &resp.Diagnostics); changed && !resp.Diagnostics.HasError() {
		if t, err = r.client.Tenants.Update(ctx, t.ID, fix, client.IfMatch(t.Version)); err != nil {
			apiError(&resp.Diagnostics, "update tenant after creation", err)
			return
		}
	}
	if t, err = r.pinRevision(ctx, m, t); err != nil {
		apiError(&resp.Diagnostics, "set plan revision", err)
		return
	}
	m.fromAPI(ctx, t, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// templateAttrs returns the attributes a template can fill in, by name.
func (m *tenantModel) templateAttrs() map[string]attr.Value {
	return map[string]attr.Value{
		"add_ons": m.AddOns, "labels": m.Labels, "settings": m.Settings,
		"features": m.Features, "limits": m.Limits, "branding": m.Branding,
	}
}

// pinRevision pins t to the planned revision when one is known and differs.
func (r *tenantResource) pinRevision(ctx context.Context, m tenantModel, t sdk.Tenant) (sdk.Tenant, error) {
	if m.PlanRevision.IsUnknown() || m.PlanRevision.IsNull() || m.PlanRevision.ValueInt64() == t.PlanRevision {
		return t, nil
	}
	return r.client.Tenants.SetPlanRevision(ctx, t.ID, m.PlanRevision.ValueInt64())
}

func (r *tenantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m tenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.client.Tenants.Get(ctx, m.ID.ValueString())
	if client.IsNotFound(err) || (err == nil && t.Status == sdk.StatusDeleted) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		apiError(&resp.Diagnostics, "read tenant", err)
		return
	}
	m.fromAPI(ctx, t, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *tenantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m, state, config tenantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in, changed := r.updateRequest(ctx, m, state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	var t sdk.Tenant
	var err error
	if changed {
		t, err = r.client.Tenants.Update(ctx, id, in, client.IfMatch(state.Version.ValueInt64()))
		if err != nil {
			apiError(&resp.Diagnostics, "update tenant", err)
			return
		}
	} else if t, err = r.client.Tenants.Get(ctx, id); err != nil {
		// Only provider-side options (deletion_protection, force_delete, ...)
		// may have changed; refresh the remote attributes.
		apiError(&resp.Diagnostics, "read tenant", err)
		return
	}
	if region := m.Region.ValueString(); !m.Region.IsUnknown() && region != "" && region != t.Region {
		t, err = r.client.Tenants.Move(ctx, id, region, client.MoveOptions{Reprovision: m.MoveReprovision.ValueBool()})
		if err != nil {
			apiError(&resp.Diagnostics, "move tenant", err)
			return
		}
	}
	if t, err = r.pinRevision(ctx, m, t); err != nil {
		apiError(&resp.Diagnostics, "set plan revision", err)
		return
	}
	// Configuring an attribute ends the template's ownership of it.
	if owned := templateOwned(ctx, req.Private); len(owned) > 0 {
		for name, v := range config.templateAttrs() {
			if !v.IsNull() {
				delete(owned, name)
			}
		}
		resp.Diagnostics.Append(setTemplateOwned(ctx, resp.Private, owned)...)
	}
	m.ID = state.ID
	m.fromAPI(ctx, t, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// updateRequest builds the PATCH body from the planned and prior state
// (unknown planned values are left alone). It reports whether any
// attribute sent with PATCH changed.
func (r *tenantResource) updateRequest(ctx context.Context, m, state tenantModel, diags *diagnostics) (client.UpdateTenantRequest, bool) {
	var in client.UpdateTenantRequest
	changed := false
	if !m.Name.Equal(state.Name) {
		in.Name, changed = client.Ptr(m.Name.ValueString()), true
	}
	if !m.Plan.IsUnknown() && !m.Plan.Equal(state.Plan) {
		in.Plan, changed = client.Ptr(m.Plan.ValueString()), true
	}
	if !m.Labels.IsUnknown() && !m.Labels.Equal(state.Labels) {
		in.Labels, changed = mapPtr[string](ctx, m.Labels, diags), true
	}
	if !m.Features.IsUnknown() && !m.Features.Equal(state.Features) {
		in.Features, changed = mapPtr[bool](ctx, m.Features, diags), true
	}
	if !m.Limits.IsUnknown() && !m.Limits.Equal(state.Limits) {
		in.Limits, changed = mapPtr[int64](ctx, m.Limits, diags), true
	}
	if !m.AddOns.IsUnknown() && !m.AddOns.Equal(state.AddOns) {
		addOns := stringsFrom(ctx, m.AddOns, diags)
		if addOns == nil {
			addOns = []string{}
		}
		in.AddOns, changed = &addOns, true
	}
	if !m.Branding.IsUnknown() && !m.Branding.Equal(state.Branding) {
		b := brandingFrom(ctx, m.Branding, diags)
		if b == nil {
			b = &sdk.Branding{} // an empty branding removes it
		}
		in.Branding, changed = b, true
	}
	if a := parseTime(m.BillingAnchor); a != nil && !sameInstant(m.BillingAnchor, state.BillingAnchor) {
		in.BillingAnchor, changed = a, true
	} else if !m.BillingAnchor.IsUnknown() && m.BillingAnchor.ValueString() == "" && parseTime(state.BillingAnchor) != nil {
		in.ClearBillingAnchor, changed = true, true
	}
	if !m.Settings.IsUnknown() {
		oldSettings, err := settingsMap(state.Settings)
		if err != nil {
			diags.AddAttributeError(path.Root("settings"), "Invalid settings in state", err.Error())
		}
		newSettings, err := settingsMap(m.Settings)
		if err != nil {
			diags.AddAttributeError(path.Root("settings"), "Invalid settings", err.Error())
		}
		if patch := mergePatch(oldSettings, newSettings); patch != nil {
			in.Settings, changed = patch, true
		}
	}
	return in, changed
}

func (r *tenantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m tenantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if m.DeletionProtection.ValueBool() {
		resp.Diagnostics.AddError("Tenant is protected from deletion",
			"tenarium_tenant "+m.Slug.ValueString()+" has deletion_protection = true. "+
				"Set it to false and apply before destroying or replacing the tenant.")
		return
	}
	var q url.Values
	if m.ForceDelete.ValueBool() {
		q = url.Values{"force": {"true"}}
	}
	err := r.client.Do(ctx, http.MethodDelete, "/v1/tenants/"+url.PathEscape(m.ID.ValueString()), q, nil, nil)
	if err == nil || client.IsNotFound(err) {
		return
	}
	if client.IsConflict(err) {
		// Deleting a tenant that is already being deleted is not an error.
		if cur, gerr := r.client.Tenants.Get(ctx, m.ID.ValueString()); gerr == nil && !cur.IsLive() {
			return
		}
	}
	apiError(&resp.Diagnostics, "delete tenant", err)
}

func (r *tenantResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The ID may be a tenant ID or a slug; Read resolves both and stores the ID.
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ModifyPlan keeps version known when no API-side attribute changes (for
// example when only deletion_protection changes, or settings are merely
// reformatted), so such plans do not show a spurious version change. It
// also marks what the server recomputes as unknown: the plan revision when
// the plan changes (unless it is configured) and the status on a move.
func (r *tenantResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var plan, state tenantModel
	var configRevision types.Int64
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("plan_revision"), &configRevision)...)
	if resp.Diagnostics.HasError() {
		return
	}
	planChanged := plan.Plan.IsUnknown() || !plan.Plan.Equal(state.Plan)
	if planChanged && configRevision.IsNull() {
		plan.PlanRevision = types.Int64Unknown()
	}
	moving := plan.Region.IsUnknown() || !plan.Region.Equal(state.Region)
	if moving {
		plan.Status = types.StringUnknown()
	}
	if plan.Name.Equal(state.Name) && !planChanged && !moving &&
		plan.Labels.Equal(state.Labels) && plan.Features.Equal(state.Features) && plan.Limits.Equal(state.Limits) &&
		plan.AddOns.Equal(state.AddOns) && plan.Branding.Equal(state.Branding) &&
		plan.PlanRevision.Equal(state.PlanRevision) && sameInstant(plan.BillingAnchor, state.BillingAnchor) &&
		plan.Settings.Equal(state.Settings) {
		plan.Version = state.Version
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, &plan)...)
}

// --- timestamps ---------------------------------------------------------------

// parseTime returns the instant of a known RFC 3339 string, or nil.
func parseTime(v types.String) *time.Time {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	t, err := time.Parse(time.RFC3339, v.ValueString())
	if err != nil {
		return nil
	}
	return &t
}

// sameInstant reports whether two timestamp attributes denote the same
// instant (or are both null).
func sameInstant(a, b types.String) bool {
	ta, tb := parseTime(a), parseTime(b)
	if ta == nil || tb == nil {
		return a.Equal(b)
	}
	return ta.Equal(*tb)
}

// timeValue renders an API timestamp, keeping the prior spelling when it
// denotes the same instant.
func timeValue(t *time.Time, prior types.String) types.String {
	if t == nil {
		if !prior.IsNull() && !prior.IsUnknown() && prior.ValueString() == "" {
			return prior // configured as "" (no anchor)
		}
		return types.StringNull()
	}
	if p := parseTime(prior); p != nil && p.Equal(*t) {
		return prior
	}
	return types.StringValue(t.UTC().Format(time.RFC3339Nano))
}
