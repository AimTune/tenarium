package main

import (
	"context"
	"fmt"
	"iter"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func tenantsGroup() group {
	return group{
		name:    "tenants",
		summary: "Manage tenants",
		verbs: []command{
			{name: "list", summary: "List tenants", run: cmdTenantsList},
			{name: "get", args: "<tenant>", summary: "Show a tenant", run: cmdTenantsGet},
			{name: "create", args: "--slug S --name N", summary: "Create a tenant", run: cmdTenantsCreate},
			{name: "update", args: "<tenant>", summary: "Update a tenant", run: cmdTenantsUpdate},
			{name: "delete", args: "<tenant>", summary: "Delete a tenant", run: tenantTransition("Delete a tenant (resources are deprovisioned first when provisioners are configured).", (*client.TenantsService).Delete)},
			{name: "suspend", args: "<tenant> [--reason R]", summary: "Suspend a tenant", run: cmdTenantsSuspend},
			{name: "resume", args: "<tenant>", summary: "Resume a suspended tenant", run: tenantTransition("Resume a suspended tenant.", (*client.TenantsService).Resume)},
			{name: "retry-provisioning", args: "<tenant>", summary: "Retry failed provisioning", run: tenantTransition("Retry provisioning of a failed tenant.", (*client.TenantsService).RetryProvisioning)},
			{name: "children", args: "<tenant>", summary: "List a tenant's children", run: cmdTenantsChildren},
			{name: "entitlements", args: "<tenant>", summary: "Show effective features and limits", run: cmdTenantsEntitlements},
			{name: "move", args: "<tenant> --region R", summary: "Move a tenant to another region", run: cmdTenantsMove},
			{name: "clone", args: "<tenant> --slug S --name N", summary: "Copy a tenant's configuration", run: cmdTenantsClone},
			{name: "pin-revision", args: "<tenant> --revision N", summary: "Pin a plan revision (0 unpins)", run: cmdTenantsPinRevision},
			{name: "maintenance", args: "<tenant> start|end", summary: "Start or end a maintenance window", run: cmdTenantsMaintenance},
			{name: "health", args: "<tenant>", summary: "Show the health score", run: cmdTenantsHealth},
		},
	}
}

func (a *app) printTenants(seq iter.Seq2[sdk.Tenant, error], max int) error {
	var items []sdk.Tenant
	for t, err := range seq {
		if err != nil {
			return err
		}
		items = append(items, t)
		if max > 0 && len(items) >= max {
			break
		}
	}
	if items == nil {
		items = []sdk.Tenant{}
	}
	return a.print(items, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "ID\tSLUG\tNAME\tSTATUS\tPLAN\tPARENT\tVERSION")
		for _, t := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\n", t.ID, t.Slug, t.Name, t.Status, dash(t.Plan), dash(t.ParentID), t.Version)
		}
	})
}

func (a *app) printTenant(t sdk.Tenant) error {
	return a.print(t, func(w *tabwriter.Writer) {
		row := func(k, v string) { fmt.Fprintf(w, "%s:\t%s\n", k, v) }
		row("ID", t.ID)
		row("Slug", t.Slug)
		row("Name", t.Name)
		row("Status", string(t.Status))
		if t.StatusReason != "" {
			row("Status reason", t.StatusReason)
		}
		row("Parent", dash(t.ParentID))
		row("Plan", dash(t.Plan))
		if t.PlanRevision > 0 {
			row("Plan revision", fmt.Sprint(t.PlanRevision))
		}
		if len(t.AddOns) > 0 {
			row("Add-ons", strings.Join(t.AddOns, ", "))
		}
		if t.Region != "" {
			row("Region", t.Region)
		}
		if m := t.Maintenance; m != nil {
			row("Maintenance", dash(m.Message))
		}
		row("Labels", fmtStrMap(t.Labels))
		row("Features", fmtFeatures(t.Features))
		row("Limits", fmtLimits(t.Limits))
		if len(t.Settings) > 0 {
			row("Settings", mustJSON(t.Settings))
		}
		row("Version", fmt.Sprint(t.Version))
		row("Created", fmtTime(t.CreatedAt))
		row("Updated", fmtTime(t.UpdatedAt))
	})
}

func pageSize(max int) int {
	if max <= 0 || max > 500 {
		return 500
	}
	return max
}

func cmdTenantsList(a *app, path string, args []string) error {
	fs := a.newFlags(path, "[flags]", "List tenants, following pagination.")
	status := fs.String("status", "", "filter by status (active, suspended, ...)")
	plan := fs.String("plan", "", "filter by plan")
	parent := fs.String("parent", "", "list children of this tenant (ID or slug)")
	labels := kvFlag{}
	fs.Var(labels, "label", "filter by label key=value (repeatable)")
	deleted := fs.Bool("include-deleted", false, "include deleted tenants")
	max := fs.Int("limit", 0, "maximum number of tenants to show (0 = all)")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	return a.printTenants(c.Tenants.All(a.ctx, client.TenantListOptions{
		Status: sdk.TenantStatus(*status), Plan: *plan, ParentID: *parent, Labels: labels,
		IncludeDeleted: *deleted, Limit: pageSize(*max),
	}), *max)
}

func cmdTenantsGet(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant>", "Show a tenant by ID or slug.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	t, err := c.Tenants.Get(a.ctx, pos[0])
	if err != nil {
		return err
	}
	return a.printTenant(t)
}

func cmdTenantsCreate(a *app, path string, args []string) error {
	fs := a.newFlags(path, "--slug SLUG --name NAME [flags]", `Create a tenant.

Example:
  tenariumctl tenants create --slug acme --name "Acme Inc" --plan pro --label region=eu`)
	var req client.CreateTenantRequest
	fs.StringVar(&req.Slug, "slug", "", "URL-safe unique slug (required)")
	fs.StringVar(&req.Name, "name", "", "display name (required)")
	fs.StringVar(&req.ParentID, "parent", "", "parent tenant ID or slug")
	fs.StringVar(&req.Plan, "plan", "", "plan ID")
	labels, features, quotas := kvFlag{}, featureFlag{}, quotaFlag{}
	fs.Var(labels, "label", "label key=value (repeatable)")
	fs.Var(features, "feature", "feature override name[=true|false] (repeatable)")
	fs.Var(quotas, "quota", "limit override metric=N (repeatable)")
	var settings jsonObjectFlag
	fs.Var(&settings, "settings", "settings as a JSON object")
	var addOns listFlag
	fs.Var(&addOns, "add-on", "add-on plan ID (repeatable or comma-separated)")
	fs.StringVar(&req.Region, "region", "", "region (data residency)")
	fs.StringVar(&req.Template, "template", "", "tenant template whose values are defaults")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	if req.Slug == "" || req.Name == "" {
		return usagef(path, "--slug and --name are required")
	}
	if len(labels) > 0 {
		req.Labels = labels
	}
	if len(features) > 0 {
		req.Features = features
	}
	if len(quotas) > 0 {
		req.Limits = quotas
	}
	req.Settings = settings.v
	req.AddOns = addOns
	c, err := a.client()
	if err != nil {
		return err
	}
	t, err := c.Tenants.Create(a.ctx, req)
	if err != nil {
		return err
	}
	return a.printTenant(t)
}

func cmdTenantsUpdate(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant> [flags]", `Update a tenant. Only the given fields change; --label, --feature and
--quota replace the whole map. --settings is a JSON merge patch.

Example:
  tenariumctl tenants update acme --name "Acme Corp" --if-match 3`)
	name := fs.String("name", "", "new display name")
	plan := fs.String("plan", "", "new plan ID")
	labels, features, quotas := kvFlag{}, featureFlag{}, quotaFlag{}
	fs.Var(labels, "label", "label key=value (repeatable; replaces all labels)")
	clearLabels := fs.Bool("clear-labels", false, "remove all labels")
	fs.Var(features, "feature", "feature override name[=true|false] (repeatable; replaces all)")
	fs.Var(quotas, "quota", "limit override metric=N (repeatable; replaces all)")
	var settings jsonObjectFlag
	fs.Var(&settings, "settings", "JSON merge patch for settings")
	var addOns listFlag
	fs.Var(&addOns, "add-on", "add-on plan ID (repeatable; replaces all)")
	clearAddOns := fs.Bool("clear-add-ons", false, "remove all add-ons")
	anchor := fs.String("billing-anchor", "", "start of monthly billing cycles (RFC 3339)")
	clearAnchor := fs.Bool("clear-billing-anchor", false, "remove the billing anchor")
	ifMatch := fs.Int64("if-match", 0, "fail unless the tenant is at this version")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	var req client.UpdateTenantRequest
	if flagSet(fs, "name") {
		req.Name = name
	}
	if flagSet(fs, "plan") {
		req.Plan = plan
	}
	if flagSet(fs, "label") || *clearLabels {
		m := map[string]string(labels)
		req.Labels = &m
	}
	if flagSet(fs, "feature") {
		m := map[string]bool(features)
		req.Features = &m
	}
	if flagSet(fs, "quota") {
		m := map[string]int64(quotas)
		req.Limits = &m
	}
	req.Settings = settings.v
	if flagSet(fs, "add-on") || *clearAddOns {
		s := []string(addOns)
		if s == nil {
			s = []string{}
		}
		req.AddOns = &s
	}
	if flagSet(fs, "billing-anchor") {
		t, err := time.Parse(time.RFC3339, *anchor)
		if err != nil {
			return usagef(path, "--billing-anchor: %v", err)
		}
		req.BillingAnchor = &t
	}
	req.ClearBillingAnchor = *clearAnchor
	if req.Name == nil && req.Plan == nil && req.Labels == nil && req.Features == nil && req.Limits == nil && req.Settings == nil && req.AddOns == nil && req.BillingAnchor == nil && !req.ClearBillingAnchor {
		return usagef(path, "nothing to update")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var opts []client.CallOption
	if flagSet(fs, "if-match") {
		opts = append(opts, client.IfMatch(*ifMatch))
	}
	t, err := c.Tenants.Update(a.ctx, pos[0], req, opts...)
	if err != nil {
		return err
	}
	return a.printTenant(t)
}

func tenantTransition(summary string, fn func(*client.TenantsService, context.Context, string, ...client.CallOption) (sdk.Tenant, error)) func(a *app, path string, args []string) error {
	return func(a *app, path string, args []string) error {
		fs := a.newFlags(path, "<tenant>", summary)
		pos, err := a.parse(fs, args, 1, 1)
		if err != nil {
			return err
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		t, err := fn(c.Tenants, a.ctx, pos[0])
		if err != nil {
			return err
		}
		return a.printTenant(t)
	}
}

func cmdTenantsSuspend(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant> [--reason R]", "Suspend an active tenant.")
	reason := fs.String("reason", "", "why the tenant is suspended")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	t, err := c.Tenants.Suspend(a.ctx, pos[0], *reason)
	if err != nil {
		return err
	}
	return a.printTenant(t)
}

func cmdTenantsChildren(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant>", "List a tenant's direct children.")
	max := fs.Int("limit", 0, "maximum number of tenants to show (0 = all)")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	return a.printTenants(c.Tenants.AllChildren(a.ctx, pos[0], client.ListOptions{Limit: pageSize(*max)}), *max)
}

func cmdTenantsEntitlements(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant>", "Show a tenant's effective features and limits (plan plus overrides).")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	e, err := c.Tenants.Entitlements(a.ctx, pos[0])
	if err != nil {
		return err
	}
	return a.print(e, func(w *tabwriter.Writer) {
		fmt.Fprintf(w, "PLAN: %s\n\n", dash(e.Plan))
		fmt.Fprintln(w, "KIND\tNAME\tVALUE")
		for _, k := range sortedKeys(e.Features) {
			fmt.Fprintf(w, "feature\t%s\t%t\n", k, e.Features[k])
		}
		for _, k := range sortedKeys(e.Limits) {
			fmt.Fprintf(w, "limit\t%s\t%d\n", k, e.Limits[k])
		}
	})
}
