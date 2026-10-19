package chatnotify

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// Data is what message and title templates are executed with. Only the
// fields matching the event's payload are set.
type Data struct {
	Event sdk.Event
	// Tenant and Previous are set for tenant.* events carrying a tenant.
	Tenant   *sdk.Tenant
	Previous *sdk.Tenant
	// Member is set for tenant.member_* events.
	Member *sdk.Member
	// User is set for user.* events.
	User *sdk.User
	// Plan is set for plan.* events.
	Plan *sdk.Plan
	// Usage is set for tenant.usage_threshold_reached and
	// tenant.usage_period_closed.
	Usage *sdk.UsagePeriodData
	// Quota is set for tenant.quota_exceeded.
	Quota *sdk.UsageEventData
	// Data is the raw payload decoded as JSON.
	Data map[string]any
}

// TenantLabel is "Name (slug)" of the event's tenant, or its ID.
func (d Data) TenantLabel() string {
	switch {
	case d.Tenant != nil && d.Tenant.Name != "" && d.Tenant.Slug != "":
		return d.Tenant.Name + " (" + d.Tenant.Slug + ")"
	case d.Tenant != nil:
		return d.Tenant.Slug + d.Tenant.Name
	default:
		return d.Event.TenantID
	}
}

func newData(e sdk.Event) Data {
	d := Data{Event: e}
	if len(e.Data) == 0 {
		return d
	}
	_ = json.Unmarshal(e.Data, &d.Data)
	switch {
	case strings.HasPrefix(e.Type, "tenant.member_"):
		var m sdk.MemberEventData
		if json.Unmarshal(e.Data, &m) == nil {
			d.Member = &m.Member
		}
	case e.Type == sdk.EventTenantQuotaExceeded:
		var u sdk.UsageEventData
		if json.Unmarshal(e.Data, &u) == nil {
			d.Quota = &u
		}
	case e.Type == sdk.EventTenantUsageThreshold || e.Type == sdk.EventTenantUsagePeriodClosed:
		var u sdk.UsagePeriodData
		if json.Unmarshal(e.Data, &u) == nil {
			d.Usage = &u
		}
	case strings.HasPrefix(e.Type, "tenant."):
		var t sdk.TenantEventData
		if json.Unmarshal(e.Data, &t) == nil && t.Tenant.ID != "" {
			d.Tenant, d.Previous = &t.Tenant, t.Previous
		}
	case strings.HasPrefix(e.Type, "user."):
		var u sdk.UserEventData
		if json.Unmarshal(e.Data, &u) == nil && u.User.ID != "" {
			d.User = &u.User
		}
	case strings.HasPrefix(e.Type, "plan."):
		var p sdk.PlanEventData
		if json.Unmarshal(e.Data, &p) == nil && p.Plan.ID != "" {
			d.Plan = &p.Plan
		}
	}
	return d
}

var funcs = template.FuncMap{
	"upper": strings.ToUpper,
	"lower": strings.ToLower,
	"join":  func(sep string, v []string) string { return strings.Join(v, sep) },
	// default returns def when v is empty.
	"default": func(def string, v any) string {
		if s := fmt.Sprint(v); v != nil && s != "" && s != "<nil>" {
			return s
		}
		return def
	},
	"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	},
	"truncate": func(n int, s string) string {
		if r := []rune(s); len(r) > n {
			return string(r[:max(n-1, 0)]) + "…"
		}
		return s
	},
	"time": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 MST") },
}

func parseTemplate(name, text string) (*template.Template, error) {
	t, err := template.New(name).Funcs(funcs).Option("missingkey=zero").Parse(text)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return t, nil
}

// builtin are the default message templates. They use no markup so that
// they read well in Slack and Teams alike.
var builtin = map[string]string{
	sdk.EventTenantCreated:              `Tenant {{.TenantLabel}} was created{{with .Tenant.Plan}} on plan {{.}}{{end}}{{with .Event.Actor}} by {{.}}{{end}}.`,
	sdk.EventTenantUpdated:              `Tenant {{.TenantLabel}} was updated{{with .Event.Actor}} by {{.}}{{end}}.`,
	sdk.EventTenantProvisioned:          `Tenant {{.TenantLabel}} is provisioned and active.`,
	sdk.EventTenantProvisioningFailed:   `Provisioning of tenant {{.TenantLabel}} failed{{with .Tenant.StatusReason}}: {{.}}{{end}}.`,
	sdk.EventTenantDeprovisioningFailed: `Removing the resources of tenant {{.TenantLabel}} failed{{with .Tenant.StatusReason}}: {{.}}{{end}}.`,
	sdk.EventTenantSuspended:            `Tenant {{.TenantLabel}} was suspended{{with .Tenant.StatusReason}}: {{.}}{{end}}{{with .Event.Actor}} (by {{.}}){{end}}.`,
	sdk.EventTenantResumed:              `Tenant {{.TenantLabel}} was resumed{{with .Event.Actor}} by {{.}}{{end}}.`,
	sdk.EventTenantDeleting:             `Tenant {{.TenantLabel}} is being deleted{{with .Event.Actor}} (by {{.}}){{end}}.`,
	sdk.EventTenantDeleted:              `Tenant {{.TenantLabel}} was deleted{{with .Event.Actor}} by {{.}}{{end}}.`,
	sdk.EventTenantPlanChanged:          `Tenant {{.TenantLabel}} changed plan{{with .Previous}} from {{default "none" .Plan}}{{end}} to {{default "none" .Tenant.Plan}}{{with .Event.Actor}} (by {{.}}){{end}}.`,
	sdk.EventTenantRegionChanged:        `Tenant {{.TenantLabel}} moved{{with .Previous}} from region {{default "none" .Region}}{{end}} to {{default "none" .Tenant.Region}}{{with .Event.Actor}} (by {{.}}){{end}}.`,
	sdk.EventTenantQuotaExceeded:        `Tenant {{.TenantLabel}} hit its {{.Quota.Metric}} limit: {{.Quota.Current}} of {{.Quota.Limit}} used, {{.Quota.Requested}} more requested.`,
	sdk.EventTenantUsageThreshold:       `Tenant {{.TenantLabel}} reached {{.Usage.Percent}}% of its {{.Usage.Metric}} limit ({{.Usage.Value}}{{with .Usage.Limit}} of {{.}}{{end}}{{with .Usage.Period}}, period {{.}}{{end}}).`,
	sdk.EventTenantUsagePeriodClosed:    `Tenant {{.TenantLabel}} used {{.Usage.Value}} {{.Usage.Metric}} in period {{.Usage.Period}}.`,
	sdk.EventMemberAdded:                `{{.Member.Email}} was added to tenant {{.TenantLabel}} as {{.Member.Role}}{{with .Event.Actor}} by {{.}}{{end}}.`,
	sdk.EventMemberUpdated:              `Membership of {{.Member.Email}} in tenant {{.TenantLabel}} changed (role {{.Member.Role}}, {{.Member.Status}}).`,
	sdk.EventMemberRemoved:              `{{.Member.Email}} was removed from tenant {{.TenantLabel}}{{with .Event.Actor}} by {{.}}{{end}}.`,
	sdk.EventPlanCreated:                `Plan {{.Plan.Name}} ({{.Plan.ID}}) was created.`,
	sdk.EventPlanUpdated:                `Plan {{.Plan.Name}} ({{.Plan.ID}}) was updated.`,
	sdk.EventPlanDeleted:                `Plan {{.Plan.Name}} ({{.Plan.ID}}) was deleted.`,
}

// fallback is used for events without a template, and when a template
// fails to execute (e.g. it refers to a field the payload lacks).
const fallback = `{{.Event.Type}}{{with .TenantLabel}} for tenant {{.}}{{end}}{{with .User}} for user {{.Email}}{{end}}{{with .Event.Actor}} by {{.}}{{end}}`

var (
	builtinTemplates = map[string]*template.Template{}
	fallbackTemplate = template.Must(parseTemplate("fallback", fallback))
)

func init() {
	for typ, text := range builtin {
		builtinTemplates[typ] = template.Must(parseTemplate(typ, text))
	}
}

// templateFor picks the message template for an event type.
func (p *Plugin) templateFor(t *target, typ string) *template.Template {
	if t.template != nil {
		return t.template
	}
	for _, pt := range p.templates {
		if ok, _ := path.Match(pt.pattern, typ); ok {
			return pt.tmpl
		}
	}
	if tmpl, ok := builtinTemplates[typ]; ok {
		return tmpl
	}
	return fallbackTemplate
}

// render executes tmpl, falling back to the generic message if it fails or
// renders nothing, so a template mistake never blocks notifications.
func (p *Plugin) render(tmpl *template.Template, d Data) string {
	var b strings.Builder
	err := tmpl.Execute(&b, d)
	if s := strings.TrimSpace(b.String()); err == nil && s != "" {
		return s
	}
	if err != nil {
		p.log.Warn("notification template failed; using the generic message", "template", tmpl.Name(), "event", d.Event.Type, "err", err)
	}
	b.Reset()
	_ = fallbackTemplate.Execute(&b, d)
	return strings.TrimSpace(b.String())
}
