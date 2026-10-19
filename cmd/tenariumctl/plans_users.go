package main

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func plansGroup() group {
	return group{
		name:    "plans",
		summary: "Manage plans",
		verbs: []command{
			{name: "list", summary: "List plans", run: cmdPlansList},
			{name: "get", args: "<plan>", summary: "Show a plan", run: cmdPlansGet},
			{name: "create", args: "--id ID --name N", summary: "Create a plan", run: cmdPlansCreate},
			{name: "update", args: "<plan>", summary: "Update a plan", run: cmdPlansUpdate},
			{name: "delete", args: "<plan>", summary: "Delete a plan", run: cmdPlansDelete},
			{name: "revisions", args: "<plan>", summary: "List a plan's revisions", run: cmdPlansRevisions},
		},
	}
}

func (a *app) printPlans(items []sdk.Plan, single bool) error {
	if items == nil {
		items = []sdk.Plan{}
	}
	var v any = items
	if single {
		v = items[0]
	}
	return a.print(v, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "ID\tNAME\tFEATURES\tLIMITS\tVERSION")
		for _, p := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", p.ID, p.Name, fmtFeatures(p.Features), fmtLimits(p.Limits), p.Version)
		}
	})
}

func cmdPlansList(a *app, path string, args []string) error {
	fs := a.newFlags(path, "", "List plans.")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	ps, err := c.Plans.List(a.ctx)
	if err != nil {
		return err
	}
	return a.printPlans(ps, false)
}

func cmdPlansGet(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<plan>", "Show a plan.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	p, err := c.Plans.Get(a.ctx, pos[0])
	if err != nil {
		return err
	}
	return a.printPlans([]sdk.Plan{p}, true)
}

func cmdPlansCreate(a *app, path string, args []string) error {
	fs := a.newFlags(path, "--id ID --name NAME [flags]", `Create a plan.

Example:
  tenariumctl plans create --id pro --name Pro --feature sso --quota members=50`)
	var req client.CreatePlanRequest
	fs.StringVar(&req.ID, "id", "", "plan ID, e.g. pro (required)")
	fs.StringVar(&req.Name, "name", "", "display name (required)")
	fs.StringVar(&req.Description, "description", "", "description")
	features, quotas := featureFlag{}, quotaFlag{}
	fs.Var(features, "feature", "feature name[=true|false] (repeatable)")
	fs.Var(quotas, "quota", "limit metric=N (repeatable)")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	if req.ID == "" || req.Name == "" {
		return usagef(path, "--id and --name are required")
	}
	if len(features) > 0 {
		req.Features = features
	}
	if len(quotas) > 0 {
		req.Limits = quotas
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	p, err := c.Plans.Create(a.ctx, req)
	if err != nil {
		return err
	}
	return a.printPlans([]sdk.Plan{p}, true)
}

func cmdPlansUpdate(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<plan> [flags]", "Update a plan. --feature and --quota replace the whole map.")
	name := fs.String("name", "", "new display name")
	desc := fs.String("description", "", "new description")
	features, quotas := featureFlag{}, quotaFlag{}
	fs.Var(features, "feature", "feature name[=true|false] (repeatable; replaces all)")
	fs.Var(quotas, "quota", "limit metric=N (repeatable; replaces all)")
	grandfather := fs.Bool("grandfather", false, "pin the tenants on the plan to its current revision first")
	ifMatch := fs.Int64("if-match", 0, "fail unless the plan is at this version")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	var req client.UpdatePlanRequest
	if flagSet(fs, "name") {
		req.Name = name
	}
	if flagSet(fs, "description") {
		req.Description = desc
	}
	if flagSet(fs, "feature") {
		m := map[string]bool(features)
		req.Features = &m
	}
	if flagSet(fs, "quota") {
		m := map[string]int64(quotas)
		req.Limits = &m
	}
	if req == (client.UpdatePlanRequest{}) {
		return usagef(path, "nothing to update")
	}
	req.Grandfather = *grandfather
	c, err := a.client()
	if err != nil {
		return err
	}
	var opts []client.CallOption
	if flagSet(fs, "if-match") {
		opts = append(opts, client.IfMatch(*ifMatch))
	}
	p, err := c.Plans.Update(a.ctx, pos[0], req, opts...)
	if err != nil {
		return err
	}
	return a.printPlans([]sdk.Plan{p}, true)
}

func cmdPlansDelete(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<plan>", "Delete a plan.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	if err := c.Plans.Delete(a.ctx, pos[0]); err != nil {
		return err
	}
	return a.done(fmt.Sprintf("Deleted plan %s.", pos[0]), map[string]any{"deleted": pos[0]})
}

// --- users ---------------------------------------------------------------------------

func usersGroup() group {
	return group{
		name:    "users",
		summary: "Manage platform users",
		verbs: []command{
			{name: "list", summary: "List users", run: cmdUsersList},
			{name: "get", args: "<user>", summary: "Show a user (ID or email)", run: cmdUsersGet},
			{name: "create", args: "--email E", summary: "Create a user", run: cmdUsersCreate},
			{name: "disable", args: "<user>", summary: "Disable a user and revoke sessions", run: userAction("Disable a user; their sessions are revoked.", (*client.UsersService).Disable)},
			{name: "enable", args: "<user>", summary: "Enable a disabled user", run: userAction("Enable a disabled user.", (*client.UsersService).Enable)},
			{name: "delete", args: "<user>", summary: "Delete a user", run: cmdUsersDelete},
			{name: "set-password", args: "<user>", summary: "Set a user's password (read from stdin)", run: cmdUsersSetPassword},
			{name: "invite", args: "<user|email>", summary: "Send an invitation (creates the user if needed)", run: cmdUsersInvite},
		},
	}
}

func (a *app) printUsers(items []sdk.User, single bool) error {
	if items == nil {
		items = []sdk.User{}
	}
	var v any = items
	if single {
		v = items[0]
	}
	return a.print(v, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "ID\tEMAIL\tNAME\tSTATUS\tROLES\tDIRECTORY")
		for _, u := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", u.ID, u.Email, dash(u.Name), u.Status, dash(strings.Join(u.Roles, ",")), u.Directory)
		}
	})
}

func cmdUsersList(a *app, path string, args []string) error {
	fs := a.newFlags(path, "[flags]", "List users, following pagination.")
	q := fs.String("q", "", "search in email and name")
	status := fs.String("status", "", "filter by status: invited, active, disabled")
	max := fs.Int("limit", 0, "maximum number of users to show (0 = all)")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	var items []sdk.User
	for u, err := range c.Users.All(a.ctx, client.UserListOptions{Query: *q, Status: sdk.UserStatus(*status), Limit: pageSize(*max)}) {
		if err != nil {
			return err
		}
		items = append(items, u)
		if *max > 0 && len(items) >= *max {
			break
		}
	}
	return a.printUsers(items, false)
}

func cmdUsersGet(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<user>", "Show a user by ID or email.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	u, err := c.Users.Get(a.ctx, pos[0])
	if err != nil {
		return err
	}
	return a.printUsers([]sdk.User{u}, true)
}

func cmdUsersCreate(a *app, path string, args []string) error {
	fs := a.newFlags(path, "--email EMAIL [flags]", `Create a user. Without --password-stdin the user is invited by email
(unless --no-invite).

Example:
  tenariumctl users create --email ops@example.com --name Ops --role admin
  echo "$PW" | tenariumctl users create --email bot@example.com --password-stdin`)
	var req client.CreateUserRequest
	fs.StringVar(&req.Email, "email", "", "email address (required)")
	fs.StringVar(&req.Name, "name", "", "display name")
	var roles listFlag
	fs.Var(&roles, "role", "platform role (repeatable or comma-separated)")
	pwStdin := fs.Bool("password-stdin", false, "read an initial password from stdin (activates the user)")
	noInvite := fs.Bool("no-invite", false, "do not send an invitation email")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	if req.Email == "" {
		return usagef(path, "--email is required")
	}
	req.Roles = roles
	if *pwStdin {
		pw, err := a.readSecret("Password", true)
		if err != nil {
			return err
		}
		req.Password = pw
	}
	if *noInvite {
		req.SendInvitation = client.Ptr(false)
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	u, err := c.Users.Create(a.ctx, req)
	if err != nil {
		return err
	}
	return a.printUsers([]sdk.User{u}, true)
}

func userAction(summary string, fn func(*client.UsersService, context.Context, string, ...client.CallOption) (sdk.User, error)) func(a *app, path string, args []string) error {
	return func(a *app, path string, args []string) error {
		fs := a.newFlags(path, "<user>", summary)
		pos, err := a.parse(fs, args, 1, 1)
		if err != nil {
			return err
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		u, err := fn(c.Users, a.ctx, pos[0])
		if err != nil {
			return err
		}
		return a.printUsers([]sdk.User{u}, true)
	}
}

func cmdUsersDelete(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<user>", "Delete a user.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	if err := c.Users.Delete(a.ctx, pos[0]); err != nil {
		return err
	}
	return a.done(fmt.Sprintf("Deleted user %s.", pos[0]), map[string]any{"deleted": pos[0]})
}

func cmdUsersSetPassword(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<user> [--password-stdin]", `Set a user's password. The password is read from stdin (prompted on a
terminal).

Example:
  echo "$PW" | tenariumctl users set-password ada@example.com --password-stdin`)
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin without prompting")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	pw, err := a.readSecret("New password", *pwStdin)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	if err := c.Users.SetPassword(a.ctx, pos[0], pw); err != nil {
		return err
	}
	return a.done(fmt.Sprintf("Password set for %s.", pos[0]), map[string]any{"user": pos[0], "status": "password_set"})
}

func cmdUsersInvite(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<user|email> [--name NAME]", `Send an invitation email. An existing invited user gets a new link; an
unknown email address is created as an invited user.`)
	name := fs.String("name", "", "display name when the user is created")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	err = c.Users.ResendInvitation(a.ctx, pos[0])
	if client.IsNotFound(err) && strings.Contains(pos[0], "@") {
		u, err := c.Users.Create(a.ctx, client.CreateUserRequest{Email: pos[0], Name: *name, SendInvitation: client.Ptr(true)})
		if err != nil {
			return err
		}
		return a.printUsers([]sdk.User{u}, true)
	}
	if err != nil {
		return err
	}
	return a.done(fmt.Sprintf("Invitation sent to %s.", pos[0]), map[string]any{"user": pos[0], "status": "sent"})
}
