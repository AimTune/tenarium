package main

import (
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func membersGroup() group {
	return group{
		name:    "members",
		summary: "Manage tenant members",
		verbs: []command{
			{name: "list", args: "<tenant>", summary: "List members and allowed roles", run: cmdMembersList},
			{name: "add", args: "<tenant> --email E --role R", summary: "Add or invite a member", run: cmdMembersAdd},
			{name: "remove", args: "<tenant> <member-id|email>", summary: "Remove a member", run: cmdMembersRemove},
			{name: "set-role", args: "<tenant> <member-id|email> <role>", summary: "Change a member's role", run: cmdMembersSetRole},
		},
	}
}

func (a *app) printMembers(items []sdk.Member) error {
	if items == nil {
		items = []sdk.Member{}
	}
	return a.print(items, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "ID\tEMAIL\tROLE\tSTATUS\tTENANT\tUSER")
		for _, m := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", m.ID, m.Email, m.Role, m.Status, m.TenantID, dash(m.UserID))
		}
	})
}

func cmdMembersList(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant>", "List a tenant's members.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	l, err := c.Members.List(a.ctx, pos[0])
	if err != nil {
		return err
	}
	if a.g.output == "json" {
		return a.writeJSON(l)
	}
	if err := a.printMembers(l.Items); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.out, "\nRoles: %s\n", strings.Join(l.Roles, ", "))
	return err
}

func cmdMembersAdd(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant> (--email EMAIL | --user-id ID) --role ROLE [--name NAME]", `Add a member. An unknown email creates an invited user who receives a
setup email; the membership becomes active once the user signs up.

Example:
  tenariumctl members add acme --email ada@example.com --role admin --name "Ada Lovelace"`)
	var req client.AddMemberRequest
	fs.StringVar(&req.Email, "email", "", "member email")
	fs.StringVar(&req.UserID, "user-id", "", "existing user ID")
	fs.StringVar(&req.Name, "name", "", "name for a newly created user")
	fs.StringVar(&req.Role, "role", "", "member role (see 'members list')")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	if req.Role == "" || (req.Email == "") == (req.UserID == "") {
		return usagef(path, "--role and exactly one of --email or --user-id are required")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	m, err := c.Members.Add(a.ctx, pos[0], req)
	if err != nil {
		return err
	}
	if a.g.output == "json" {
		return a.writeJSON(m)
	}
	return a.printMembers([]sdk.Member{m})
}

// resolveMember accepts a member ID or an email address.
func (a *app) resolveMember(c *client.Client, tenant, ref string) (string, error) {
	if !strings.Contains(ref, "@") {
		return ref, nil
	}
	l, err := c.Members.List(a.ctx, tenant)
	if err != nil {
		return "", err
	}
	for _, m := range l.Items {
		if strings.EqualFold(m.Email, ref) {
			return m.ID, nil
		}
	}
	return "", fmt.Errorf("%s is not a member of %s", ref, tenant)
}

func cmdMembersRemove(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant> <member-id|email>", "Remove a member from a tenant.")
	pos, err := a.parse(fs, args, 2, 2)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	id, err := a.resolveMember(c, pos[0], pos[1])
	if err != nil {
		return err
	}
	if err := c.Members.Remove(a.ctx, pos[0], id); err != nil {
		return err
	}
	return a.done(fmt.Sprintf("Removed member %s from %s.", pos[1], pos[0]), map[string]any{"removed": id, "tenant": pos[0]})
}

func cmdMembersSetRole(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant> <member-id|email> <role>", "Change a member's role.")
	pos, err := a.parse(fs, args, 3, 3)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	id, err := a.resolveMember(c, pos[0], pos[1])
	if err != nil {
		return err
	}
	m, err := c.Members.Update(a.ctx, pos[0], id, client.UpdateMemberRequest{Role: &pos[2]})
	if err != nil {
		return err
	}
	if a.g.output == "json" {
		return a.writeJSON(m)
	}
	return a.printMembers([]sdk.Member{m})
}

func usageGroup() group {
	return group{
		name:    "usage",
		summary: "Read and record metered usage",
		verbs: []command{
			{name: "get", args: "<tenant>", summary: "Show usage against limits", run: cmdUsageGet},
			{name: "record", args: "<tenant> <metric> [delta]", summary: "Add to a usage counter", run: cmdUsageRecord},
		},
	}
}

func (a *app) printUsage(items []client.UsageItem) error {
	if items == nil {
		items = []client.UsageItem{}
	}
	return a.print(items, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "METRIC\tVALUE\tLIMIT")
		for _, it := range items {
			limit := "unlimited"
			if it.Limit != nil {
				limit = strconv.FormatInt(*it.Limit, 10)
			}
			fmt.Fprintf(w, "%s\t%d\t%s\n", it.Metric, it.Value, limit)
		}
	})
}

func cmdUsageGet(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant>", "Show a tenant's metered usage next to its limits.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	items, err := c.Usage.Get(a.ctx, pos[0])
	if err != nil {
		return err
	}
	return a.printUsage(items)
}

func cmdUsageRecord(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<tenant> <metric> [delta] [--delta N]", `Add delta (default 1) to a usage counter. Use --delta for negative values.
Fails with quota_exceeded if the increment would pass the tenant's limit.

Example:
  tenariumctl usage record acme api_calls 10`)
	delta := fs.Int64("delta", 1, "amount to add (may be negative)")
	pos, err := a.parse(fs, args, 2, 3)
	if err != nil {
		return err
	}
	if len(pos) == 3 {
		if *delta, err = strconv.ParseInt(pos[2], 10, 64); err != nil {
			return usagef(path, "delta must be an integer, got %q", pos[2])
		}
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	it, err := c.Usage.Record(a.ctx, pos[0], pos[1], *delta)
	if err != nil {
		return err
	}
	if a.g.output == "json" {
		return a.writeJSON(it)
	}
	return a.printUsage([]client.UsageItem{it})
}
