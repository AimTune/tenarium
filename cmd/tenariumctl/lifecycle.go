package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AimTune/tenarium/pkg/client"
)

func cmdTenantsMove(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant> --region R [--reprovision]", `Move a tenant to another region (platform-only).

With --reprovision the tenant enters a maintenance window and the provisioners of the
new region run; the window ends when they succeed.`)
	region := fs.String("region", "", "target region (required)")
	reprovision := fs.Bool("reprovision", false, "run the new region's provisioners")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if *region == "" {
		return usagef(path, "--region is required")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	t, err := c.Tenants.Move(a.ctx, pos[0], *region, client.MoveOptions{Reprovision: *reprovision})
	if err != nil {
		return err
	}
	return a.printTenant(t)
}

func cmdTenantsClone(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant> --slug S --name N [flags]", `Create a tenant with another tenant's plan, add-ons, region, labels,
settings, overrides, branding and custom roles.`)
	var req client.CloneTenantRequest
	fs.StringVar(&req.Slug, "slug", "", "slug of the copy (required)")
	fs.StringVar(&req.Name, "name", "", "name of the copy (required)")
	fs.StringVar(&req.ParentID, "parent", "", "parent tenant ID or slug")
	fs.BoolVar(&req.Members, "members", false, "also copy the active members")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if req.Slug == "" || req.Name == "" {
		return usagef(path, "--slug and --name are required")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	t, err := c.Tenants.Clone(a.ctx, pos[0], req)
	if err != nil {
		return err
	}
	return a.printTenant(t)
}

func cmdTenantsPinRevision(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant> --revision N", "Pin a tenant to a revision of its plan; --revision 0 follows the current plan.")
	rev := fs.Int64("revision", -1, "plan revision (0 = unpin)")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if *rev < 0 {
		return usagef(path, "--revision is required")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	t, err := c.Tenants.SetPlanRevision(a.ctx, pos[0], *rev)
	if err != nil {
		return err
	}
	return a.printTenant(t)
}

func cmdTenantsMaintenance(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant> start|end [--message M] [--for DURATION]", `Start or end a maintenance window. While it is open the tenant is
read-only for its own users.`)
	message := fs.String("message", "", "message shown to the tenant's users")
	dur := fs.Duration("for", 0, "end the window automatically after this long")
	pos, err := a.parse(fs, args, 2, 2)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	switch pos[1] {
	case "start":
		var until time.Time
		if *dur > 0 {
			until = time.Now().Add(*dur)
		}
		t, err := c.Tenants.StartMaintenance(a.ctx, pos[0], *message, until)
		if err != nil {
			return err
		}
		return a.printTenant(t)
	case "end":
		t, err := c.Tenants.EndMaintenance(a.ctx, pos[0])
		if err != nil {
			return err
		}
		return a.printTenant(t)
	default:
		return usagef(path, "the second argument must be start or end")
	}
}

func cmdTenantsHealth(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant>", "Show a tenant's health score and the factors behind it.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	h, err := c.Tenants.Health(a.ctx, pos[0])
	if err != nil {
		return err
	}
	return a.print(h, func(w *tabwriter.Writer) {
		fmt.Fprintf(w, "Score:\t%d (%s)\n", h.Score, h.Grade)
		for _, f := range h.Factors {
			fmt.Fprintf(w, "-%d\t%s: %s\n", f.Impact, f.Name, f.Detail)
		}
	})
}

func cmdPlansRevisions(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<plan>", "List a plan's revisions, newest first.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	revs, err := c.Plans.Revisions(a.ctx, pos[0])
	if err != nil {
		return err
	}
	return a.print(revs, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "REVISION\tCREATED\tFEATURES\tLIMITS")
		for _, r := range revs {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", r.Revision, fmtTime(r.CreatedAt), fmtFeatures(r.Features), fmtLimits(r.Limits))
		}
	})
}

// --- rollouts --------------------------------------------------------------------

func rolloutsGroup() group {
	return group{
		name:    "rollouts",
		summary: "Manage feature rollouts",
		verbs: []command{
			{name: "list", summary: "List rollouts", run: cmdRolloutsList},
			{name: "set", args: "<feature> --percent N", summary: "Create or replace a rollout", run: cmdRolloutsSet},
			{name: "delete", args: "<feature>", summary: "Delete a rollout", run: cmdRolloutsDelete},
		},
	}
}

func (a *app) printRollouts(rs []client.Rollout) error {
	return a.print(rs, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "FEATURE\tPERCENT\tENABLED\tPLANS\tREGIONS\tLABELS")
		for _, r := range rs {
			fmt.Fprintf(w, "%s\t%d\t%t\t%s\t%s\t%s\n", r.Feature, r.Percentage, r.Enabled,
				dash(strings.Join(r.Plans, ",")), dash(strings.Join(r.Regions, ",")), fmtStrMap(r.Labels))
		}
	})
}

func cmdRolloutsList(a *app, path string, args []string) error {
	fs := a.newFlags(path, "", "List feature rollouts.")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	rs, err := c.Rollouts.List(a.ctx)
	if err != nil {
		return err
	}
	return a.printRollouts(rs)
}

func cmdRolloutsSet(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<feature> --percent N [flags]", `Turn a feature on for a stable percentage of matching tenants.

Example:
  tenariumctl rollouts set new-editor --percent 20 --plan pro --region eu`)
	var r client.Rollout
	fs.IntVar(&r.Percentage, "percent", 0, "percentage of matching tenants (0-100)")
	var plans, regions, include, exclude listFlag
	fs.Var(&plans, "plan", "only tenants on this plan (repeatable)")
	fs.Var(&regions, "region", "only tenants in this region (repeatable)")
	fs.Var(&include, "include", "tenant ID that always gets the feature (repeatable)")
	fs.Var(&exclude, "exclude", "tenant ID that never gets it (repeatable)")
	labels := kvFlag{}
	fs.Var(labels, "label", "only tenants with label key=value (repeatable)")
	disabled := fs.Bool("disabled", false, "save the rollout switched off")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	r.Plans, r.Regions, r.Include, r.Exclude, r.Enabled = plans, regions, include, exclude, !*disabled
	if len(labels) > 0 {
		r.Labels = labels
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	out, err := c.Rollouts.Put(a.ctx, pos[0], r)
	if err != nil {
		return err
	}
	return a.printRollouts([]client.Rollout{out})
}

func cmdRolloutsDelete(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<feature>", "Delete a rollout.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	return c.Rollouts.Delete(a.ctx, pos[0])
}

// --- templates -------------------------------------------------------------------

func templatesGroup() group {
	return group{
		name:    "templates",
		summary: "Manage tenant templates",
		verbs: []command{
			{name: "list", summary: "List templates", run: cmdTemplatesList},
			{name: "get", args: "<template>", summary: "Show a template", run: cmdTemplatesGet},
			{name: "put", args: "<template> --file F", summary: "Create or replace a template from JSON", run: cmdTemplatesPut},
			{name: "delete", args: "<template>", summary: "Delete a template", run: cmdTemplatesDelete},
		},
	}
}

func cmdTemplatesList(a *app, path string, args []string) error {
	fs := a.newFlags(path, "", "List tenant templates.")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	ts, err := c.Templates.List(a.ctx)
	if err != nil {
		return err
	}
	return a.print(ts, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "ID\tNAME\tPLAN\tREGION\tROLES")
		for _, t := range ts {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", t.ID, t.Name, dash(t.Plan), dash(t.Region), len(t.Roles))
		}
	})
}

func cmdTemplatesGet(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<template>", "Show a tenant template as JSON.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	t, err := c.Templates.Get(a.ctx, pos[0])
	if err != nil {
		return err
	}
	return a.writeJSON(t)
}

func cmdTemplatesPut(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<template> --file F", `Create or replace a tenant template from a JSON file ("-" reads stdin), e.g.

  {"name": "Agency", "plan": "pro", "region": "eu", "labels": {"kind": "agency"},
   "roles": [{"name": "auditor", "actions": ["tenants:read", "events:read"]}]}`)
	file := fs.String("file", "", "JSON file (required; - for stdin)")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if *file == "" {
		return usagef(path, "--file is required")
	}
	var raw []byte
	if *file == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(*file)
	}
	if err != nil {
		return err
	}
	var t client.TenantTemplate
	if err := json.Unmarshal(raw, &t); err != nil {
		return fmt.Errorf("%s: %w", *file, err)
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	out, err := c.Templates.Put(a.ctx, pos[0], t)
	if err != nil {
		return err
	}
	return a.writeJSON(out)
}

func cmdTemplatesDelete(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<template>", "Delete a tenant template.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	return c.Templates.Delete(a.ctx, pos[0])
}
