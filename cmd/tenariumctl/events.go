package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AimTune/tenarium/pkg/client"
	"github.com/AimTune/tenarium/pkg/sdk"
)

func eventsGroup() group {
	return group{
		name:    "events",
		summary: "Read the event log",
		verbs: []command{
			{name: "list", summary: "List events", run: cmdEventsList},
			{name: "tail", summary: "Follow new events", run: cmdEventsTail},
		},
	}
}

const eventHeader = "SEQ\tTIME\tTYPE\tTENANT\tSUBJECT\tACTOR"

func eventRow(e sdk.Event) string {
	return fmt.Sprintf("%d\t%s\t%s\t%s\t%s\t%s", e.Seq, fmtTime(e.Time), e.Type, dash(e.TenantID), dash(e.Subject), dash(e.Actor))
}

// resolveTenantID turns a slug into an ID for event filters (which match IDs).
func (a *app) resolveTenantID(c *client.Client, ref string) (string, error) {
	if ref == "" {
		return "", nil
	}
	t, err := c.Tenants.Get(a.ctx, ref)
	if client.IsNotFound(err) || client.IsForbidden(err) {
		return ref, nil
	}
	return t.ID, err
}

func cmdEventsList(a *app, path string, args []string) error {
	fs := a.newFlags(path, "[flags]", `List events from the log, oldest first.

Example:
  tenariumctl events list --tenant acme --type 'tenant.*' --limit 20`)
	after := fs.Int64("after", 0, "start after this sequence number")
	tenant := fs.String("tenant", "", "only events of this tenant (ID or slug)")
	typ := fs.String("type", "", "only event types matching this glob, e.g. 'tenant.*'")
	max := fs.Int("limit", 100, "maximum number of events to show (0 = all)")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	tid, err := a.resolveTenantID(c, *tenant)
	if err != nil {
		return err
	}
	items := []sdk.Event{}
	for e, err := range c.Events.All(a.ctx, client.EventListOptions{After: *after, TenantID: tid, Type: *typ, Limit: 1000}) {
		if err != nil {
			return err
		}
		items = append(items, e)
		if *max > 0 && len(items) >= *max {
			break
		}
	}
	return a.print(items, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, eventHeader)
		for _, e := range items {
			fmt.Fprintln(w, eventRow(e))
		}
	})
}

var errStopTail = errors.New("stop tail")

func cmdEventsTail(a *app, path string, args []string) error {
	fs := a.newFlags(path, "[flags]", `Print new events as they are appended to the log until interrupted.
By default only events after the current end of the log are shown. With
--output json, each event is printed as one JSON line.

Example:
  tenariumctl events tail --type 'tenant.*'`)
	after := fs.Int64("after", -1, "start after this sequence number (default: the current end)")
	fromStart := fs.Bool("from-start", false, "replay the whole log first")
	tenant := fs.String("tenant", "", "only events of this tenant (ID or slug)")
	typ := fs.String("type", "", "only event types matching this glob")
	interval := fs.Duration("interval", time.Second, "poll interval")
	max := fs.Int("max", 0, "exit after this many events (0 = never)")
	timeout := fs.Duration("timeout", 0, "exit after this long (0 = never)")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	tid, err := a.resolveTenantID(c, *tenant)
	if err != nil {
		return err
	}
	start := *after
	switch {
	case *fromStart:
		start = 0
	case start < 0:
		if start, err = c.Events.LastSeq(a.ctx); err != nil {
			return err
		}
	}
	ctx := a.ctx
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	if a.g.output != "json" {
		fmt.Fprintln(a.out, strings.ReplaceAll(eventHeader, "\t", "  "))
	}
	n := 0
	err = c.Events.Tail(ctx, start, func(e sdk.Event) error {
		if a.g.output == "json" {
			b, err := json.Marshal(e)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.out, "%s\n", b)
		} else {
			fmt.Fprintln(a.out, strings.ReplaceAll(eventRow(e), "\t", "  "))
		}
		if n++; *max > 0 && n >= *max {
			return errStopTail
		}
		return nil
	}, client.TailTenant(tid), client.TailType(*typ), client.TailInterval(*interval))
	if errors.Is(err, errStopTail) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

// --- dead letters ------------------------------------------------------------------

func deadLettersGroup() group {
	return group{
		name:    "dead-letters",
		summary: "Inspect, replay and discard undeliverable events",
		verbs: []command{
			{name: "list", summary: "List dead letters", run: cmdDeadLettersList},
			{name: "get", args: "<id>", summary: "Show a dead letter", run: cmdDeadLettersGet},
			{name: "replay", args: "<id>...", summary: "Redeliver dead letters", run: cmdDeadLettersReplay},
			{name: "discard", args: "<id>...", summary: "Delete dead letters", run: cmdDeadLettersDiscard},
		},
	}
}

func (a *app) printDeadLetters(items []client.DeadLetter, v any) error {
	return a.print(v, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "ID\tSUBSCRIPTION\tEVENT\tSEQ\tATTEMPTS\tFAILED\tERROR")
		for _, d := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\t%s\t%s\n", d.ID, d.Subscription, d.Event.Type, d.Event.Seq, d.Attempts, fmtTime(d.FailedAt), truncate(d.Error, 60))
		}
	})
}

func cmdDeadLettersList(a *app, path string, args []string) error {
	fs := a.newFlags(path, "[--subscription NAME]", "List dead letters (at most 500).")
	sub := fs.String("subscription", "", "only this subscription (plugin-instance/name)")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	l, err := c.DeadLetters.List(a.ctx, *sub)
	if err != nil {
		return err
	}
	if l.Items == nil {
		l.Items = []client.DeadLetter{}
	}
	return a.printDeadLetters(l.Items, l)
}

func cmdDeadLettersGet(a *app, path string, args []string) error {
	fs := a.newFlags(path, "<id>", "Show a dead letter including its event.")
	pos, err := a.parse(fs, args, 1, 1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	d, err := c.DeadLetters.Get(a.ctx, pos[0])
	if err != nil {
		return err
	}
	if a.g.output == "json" {
		return a.writeJSON(d)
	}
	if err := a.printDeadLetters([]client.DeadLetter{d}, d); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.out, "\nError: %s\nEvent data: %s\n", d.Error, string(d.Event.Data))
	return err
}

func cmdDeadLettersReplay(a *app, path string, args []string) error {
	return a.eachDeadLetter(path, args, "Redeliver dead letters synchronously; delivered ones are removed.", "replayed",
		func(c *client.Client, id string) error { return c.DeadLetters.Replay(a.ctx, id) })
}

func cmdDeadLettersDiscard(a *app, path string, args []string) error {
	return a.eachDeadLetter(path, args, "Delete dead letters without redelivering them.", "discarded",
		func(c *client.Client, id string) error { return c.DeadLetters.Discard(a.ctx, id) })
}

// eachDeadLetter applies fn to each ID, reporting every result; it fails if
// any call failed.
func (a *app) eachDeadLetter(path string, args []string, summary, verb string, fn func(*client.Client, string) error) error {
	fs := a.newFlags(path, "<id>...", summary)
	pos, err := a.parse(fs, args, 1, -1)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	type result struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}
	var results []result
	failed := 0
	for _, id := range pos {
		r := result{ID: id, Status: verb}
		if err := fn(c, id); err != nil {
			failed++
			r.Status, r.Error = "failed", err.Error()
			if e, ok := client.AsError(err); ok {
				r.Error = formatAPIError(e)
			}
		}
		results = append(results, r)
	}
	err = a.print(results, func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "ID\tSTATUS\tERROR")
		for _, r := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\n", r.ID, r.Status, dash(r.Error))
		}
	})
	if err == nil && failed > 0 {
		err = fmt.Errorf("%d of %d dead letters could not be %s", failed, len(pos), verb)
	}
	return err
}

// --- plugins ---------------------------------------------------------------------------

func pluginsGroup() group {
	return group{
		name:    "plugins",
		summary: "Inspect loaded plugins",
		verbs:   []command{{name: "list", summary: "List loaded plugin instances", run: cmdPluginsList}},
	}
}

func cmdPluginsList(a *app, path string, args []string) error {
	fs := a.newFlags(path, "", "List loaded plugin instances and what they registered.")
	if _, err := a.parse(fs, args, 0, 0); err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	l, err := c.Plugins.List(a.ctx)
	if err != nil {
		return err
	}
	if a.g.output == "json" {
		return a.writeJSON(l)
	}
	err = a.table(func(w *tabwriter.Writer) {
		fmt.Fprintln(w, "NAME\tPLUGIN\tVERSION\tPROVIDES")
		for _, p := range l.Items {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, p.Manifest.ID, dash(p.Manifest.Version), dash(provides(p)))
		}
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.out, "\nAvailable: %s\n", strings.Join(l.Available, ", "))
	return err
}

func provides(p client.PluginInfo) string {
	var parts []string
	add := func(kind string, n int) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, kind))
		}
	}
	add("subscriptions", len(p.Subscriptions))
	add("hooks", len(p.Hooks))
	add("provisioners", len(p.Provisioners))
	add("routes", len(p.Routes))
	add("authenticators", len(p.Authenticators))
	add("authorizers", len(p.Authorizers))
	if p.UserDirectory != "" {
		parts = append(parts, "user directory")
	}
	if p.Mailer != "" {
		parts = append(parts, "mailer")
	}
	return strings.Join(parts, ", ")
}
