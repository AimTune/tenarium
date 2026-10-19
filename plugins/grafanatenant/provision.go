package grafanatenant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"text/template"
	"time"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// mainOrgID is Grafana's default organization, which is never managed.
const mainOrgID = 1

// Provision creates or claims the tenant's organization, marks it and
// applies quotas and data sources. Every step is idempotent.
func (p *Plugin) Provision(ctx context.Context, t sdk.Tenant) error {
	name, err := p.OrgName(t)
	if err != nil {
		return err
	}
	o, err := p.orgByName(ctx, name)
	if err != nil {
		return err
	}
	created := false
	if o == nil {
		id, err := p.createOrg(ctx, name)
		if err != nil {
			return err
		}
		created = id != 0 // 0: created concurrently, claim checks it
		if o, err = p.orgByName(ctx, name); err != nil {
			return err
		}
		if o == nil {
			return fmt.Errorf("grafana: organization %s disappeared after creation", name)
		}
	}
	if err := p.claim(ctx, o, t, created); err != nil {
		return err
	}
	if o.owner() != t.ID {
		a := o.Address
		a.Address1 = MarkerOwner + t.ID
		if err := p.setAddress(ctx, o.ID, a); err != nil {
			return err
		}
	}
	if err := p.applyQuota(ctx, o.ID, t); err != nil {
		return err
	}
	if len(p.ds) > 0 {
		err := p.withMembership(ctx, o.ID, func() error { return p.ensureDatasources(ctx, o, t) })
		if err != nil {
			return err
		}
	}
	return p.removeCreator(ctx, o.ID)
}

// claim checks that an existing organization may be used by t.
// Organizations marked for another tenant or retained from a deleted one
// are refused. Unmarked organizations are adopted only when empty: those
// are left by a Provision that stopped between creating and marking.
func (p *Plugin) claim(ctx context.Context, o *org, t sdk.Tenant, created bool) error {
	if o.ID == mainOrgID {
		return fmt.Errorf("organization %q is Grafana's main organization and cannot be used for a tenant", o.Name)
	}
	switch owner := o.owner(); {
	case owner == t.ID:
		return nil
	case owner != "":
		return fmt.Errorf("organization %q (id %d) already exists and belongs to another tenant (%s)", o.Name, o.ID, owner)
	case o.retainedFrom() != "":
		return fmt.Errorf("organization %q (id %d) holds data retained from deleted tenant %s; rename or delete it before provisioning a tenant with this name",
			o.Name, o.ID, o.retainedFrom())
	}
	if created {
		return nil
	}
	empty, err := p.isEmpty(ctx, o.ID)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("organization %q (id %d) already exists, is not empty and is not managed by tenarium", o.Name, o.ID)
	}
	return nil
}

// isEmpty reports whether the organization has no members besides the
// plugin's own account, no dashboards or folders and no data sources. When
// it cannot be verified, it reports false.
func (p *Plugin) isEmpty(ctx context.Context, id int64) (bool, error) {
	self, err := p.self(ctx)
	if err != nil {
		return false, err
	}
	users, err := p.orgUsers(ctx, id)
	if err != nil {
		return false, err
	}
	member := false
	for _, u := range users {
		if u.UserID != self {
			return false, nil
		}
		member = true
	}
	if !member {
		// Org-scoped calls need membership; fall back to quota usage, which
		// is only available with quotas enabled.
		qs, err := p.orgQuotas(ctx, id)
		if err != nil {
			p.log.Debug("cannot verify that an organization is empty", "org_id", id, "error", err)
			return false, nil
		}
		for _, q := range qs {
			if q.Used > 0 && q.Target != "org_user" {
				return false, nil
			}
		}
		return len(qs) > 0, nil
	}
	var hits []json.RawMessage
	if _, err := p.call(ctx, "search organization", http.MethodGet, "/api/search?limit=1", id, nil, &hits); err != nil {
		return false, err
	}
	if len(hits) > 0 {
		return false, nil
	}
	var ds []json.RawMessage
	if _, err := p.call(ctx, "list data sources", http.MethodGet, "/api/datasources", id, nil, &ds); err != nil {
		return false, err
	}
	return len(ds) == 0, nil
}

// Deprovision applies on_deprovision. A missing organization is treated as
// already deprovisioned.
func (p *Plugin) Deprovision(ctx context.Context, t sdk.Tenant) error {
	if p.cfg.OnDeprovision == DeprovisionKeep {
		return nil
	}
	name, err := p.OrgName(t)
	if err != nil {
		return err
	}
	o, err := p.orgByName(ctx, name)
	if err != nil || o == nil {
		return err
	}
	if o.ID == mainOrgID {
		p.log.Warn("not deprovisioning Grafana's main organization", "org", o.Name, "tenant_id", t.ID)
		return nil
	}
	switch owner := o.owner(); {
	case owner == t.ID:
	case owner != "":
		p.log.Warn("not deprovisioning an organization owned by another tenant",
			"org", o.Name, "org_id", o.ID, "tenant_id", t.ID, "owner", owner)
		return nil
	case o.retainedFrom() != "":
		if o.retainedFrom() != t.ID {
			p.log.Warn("not deprovisioning an organization retained from another tenant",
				"org", o.Name, "org_id", o.ID, "tenant_id", t.ID, "owner", o.retainedFrom())
			return nil
		}
		if p.cfg.OnDeprovision == DeprovisionRetain {
			// A previous attempt released ownership but did not rename.
			return p.renameOrg(ctx, o.ID, p.retainedName(name))
		}
		return nil
	default:
		// Unmarked: only an empty organization (left by an interrupted
		// Provision) is cleaned up; anything else is not ours.
		empty, err := p.isEmpty(ctx, o.ID)
		if err != nil {
			return err
		}
		if !empty {
			p.log.Warn("not deprovisioning an unmanaged organization", "org", o.Name, "org_id", o.ID, "tenant_id", t.ID)
			return nil
		}
		if p.cfg.OnDeprovision == DeprovisionRetain {
			return nil
		}
	}

	if p.cfg.OnDeprovision == DeprovisionRetain {
		// Release ownership first, so a crash before the rename never leaves
		// an organization that a new tenant could adopt.
		a := o.Address
		a.Address1 = MarkerDeleted + t.ID
		a.Address2 = MarkerDeletedAt + p.now().UTC().Format(time.RFC3339)
		if err := p.setAddress(ctx, o.ID, a); err != nil {
			return err
		}
		return p.renameOrg(ctx, o.ID, p.retainedName(name))
	}
	return p.deleteOrg(ctx, o.ID)
}

func (p *Plugin) retainedName(name string) string {
	return name + "-deleted-" + strconv.FormatInt(p.now().Unix(), 10)
}

// ownedOrg returns the tenant's organization if it exists and is marked
// for the tenant, else nil.
func (p *Plugin) ownedOrg(ctx context.Context, t sdk.Tenant) (*org, error) {
	name, err := p.OrgName(t)
	if err != nil {
		return nil, err
	}
	o, err := p.orgByName(ctx, name)
	if err != nil || o == nil {
		return nil, err
	}
	if owner := o.owner(); owner != t.ID {
		if owner != "" {
			p.log.Warn("ignoring an organization owned by another tenant", "org", name, "tenant_id", t.ID, "owner", owner)
		}
		return nil, nil
	}
	return o, nil
}

// --- quota ---

// applyQuota sets the configured organization quotas from the tenant's
// entitlement limits. Unlimited (absent) limits set -1.
func (p *Plugin) applyQuota(ctx context.Context, orgID int64, t sdk.Tenant) error {
	if len(p.cfg.Quota) == 0 {
		return nil
	}
	e, err := p.host.Entitlements(ctx, t.ID)
	if err != nil {
		return fmt.Errorf("entitlements: %w", err)
	}
	cur, err := p.orgQuotas(ctx, orgID)
	if err != nil {
		return fmt.Errorf("%w (are quotas enabled? set [quota] enabled = true in grafana.ini)", err)
	}
	have := map[string]int64{}
	for _, q := range cur {
		have[q.Target] = q.Limit
	}
	targets := make([]string, 0, len(p.cfg.Quota))
	for target := range p.cfg.Quota {
		targets = append(targets, target)
	}
	slices.Sort(targets)
	for _, target := range targets {
		limit, ok := e.Limit(p.cfg.Quota[target])
		if !ok {
			limit = -1
		}
		if v, ok := have[target]; ok && v == limit {
			continue
		}
		if err := p.setQuota(ctx, orgID, target, limit); err != nil {
			return err
		}
	}
	return nil
}

// syncQuota re-applies quotas when a tenant's plan or limits change.
func (p *Plugin) syncQuota(ctx context.Context, e sdk.Event) error {
	var data sdk.TenantEventData
	if err := json.Unmarshal(e.Data, &data); err != nil {
		return fmt.Errorf("decode %s event: %w", e.Type, err)
	}
	id := data.Tenant.ID
	if id == "" {
		id = e.TenantID
	}
	// Act on the current state: events may be replayed.
	t, err := p.host.GetTenant(ctx, id)
	if errors.Is(err, sdk.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if !t.IsLive() {
		return nil
	}
	o, err := p.ownedOrg(ctx, t)
	if err != nil || o == nil {
		return err
	}
	return p.applyQuota(ctx, o.ID, t)
}

// --- membership of the plugin's own account ---

// withMembership runs fn while the plugin's account is a member of the
// organization (org-scoped APIs require it), adding it temporarily if
// needed.
func (p *Plugin) withMembership(ctx context.Context, orgID int64, fn func() error) error {
	self, err := p.self(ctx)
	if err != nil {
		return err
	}
	users, err := p.orgUsers(ctx, orgID)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(users, func(u orgUser) bool { return u.UserID == self }) {
		return fn()
	}
	login, err := p.selfLogin(ctx)
	if err != nil {
		return err
	}
	if err := p.addOrgUser(ctx, orgID, login, RoleAdmin); err != nil {
		return err
	}
	ferr := fn()
	if err := p.removeOrgUser(ctx, orgID, self); err != nil && !isLastAdmin(err) {
		return errors.Join(ferr, err)
	}
	return ferr
}

func (p *Plugin) selfLogin(ctx context.Context) (string, error) {
	var u user
	if _, err := p.call(ctx, "get current user", http.MethodGet, "/api/user", 0, nil, &u); err != nil {
		return "", err
	}
	return u.Login, nil
}

// removeCreator removes the plugin's account from the organization when
// remove_creator is set. Grafana refuses to remove the last admin; then the
// account stays until a member gets the Admin role.
func (p *Plugin) removeCreator(ctx context.Context, orgID int64) error {
	if !p.cfg.RemoveCreator {
		return nil
	}
	self, err := p.self(ctx)
	if err != nil {
		return err
	}
	users, err := p.orgUsers(ctx, orgID)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(users, func(u orgUser) bool { return u.UserID == self }) {
		return nil
	}
	err = p.removeOrgUser(ctx, orgID, self)
	if isLastAdmin(err) {
		p.log.Debug("keeping the plugin account as the organization's last admin", "org_id", orgID)
		return nil
	}
	return err
}

// --- data sources ---

type datasourceTemplates struct {
	cfg      DatasourceConfig
	url      *template.Template
	database *template.Template
	user     *template.Template
	jsonData map[string]any // string leaves are *template.Template
	secure   map[string]*template.Template
}

// datasourceData is the template data of data source fields.
type datasourceData struct {
	Tenant  sdk.Tenant
	OrgID   int64
	OrgName string
}

func compileDatasource(d DatasourceConfig) (datasourceTemplates, error) {
	dt := datasourceTemplates{cfg: d, secure: map[string]*template.Template{}}
	var err error
	parse := func(field, s string) *template.Template {
		if err != nil {
			return nil
		}
		var t *template.Template
		t, err = template.New(field).Option("missingkey=error").Parse(s)
		if err != nil {
			err = fmt.Errorf("%s: %w", field, err)
		}
		return t
	}
	dt.url = parse("url", d.URL)
	dt.database = parse("database", d.Database)
	dt.user = parse("user", d.User)
	var walk func(field string, v any) any
	walk = func(field string, v any) any {
		switch x := v.(type) {
		case string:
			return parse(field, x)
		case map[string]any:
			out := make(map[string]any, len(x))
			for k, e := range x {
				out[k] = walk(field+"."+k, e)
			}
			return out
		case []any:
			out := make([]any, len(x))
			for i, e := range x {
				out[i] = walk(fmt.Sprintf("%s[%d]", field, i), e)
			}
			return out
		default:
			return v
		}
	}
	if d.JSONData != nil {
		dt.jsonData, _ = walk("json_data", d.JSONData).(map[string]any)
	}
	for k, v := range d.SecureJSONData {
		dt.secure[k] = parse("secure_json_data."+k, v)
	}
	if err != nil {
		return dt, err
	}
	if _, err := dt.render(datasourceData{Tenant: sample1, OrgID: 2, OrgName: "tenant-example-one"}); err != nil {
		return dt, err
	}
	return dt, nil
}

func execString(t *template.Template, data datasourceData) (string, error) {
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// render builds the Grafana data source request body.
func (dt datasourceTemplates) render(data datasourceData) (map[string]any, error) {
	body := map[string]any{
		"name":      dt.cfg.Name,
		"type":      dt.cfg.Type,
		"access":    dt.cfg.Access,
		"isDefault": dt.cfg.IsDefault,
	}
	for key, t := range map[string]*template.Template{"url": dt.url, "database": dt.database, "user": dt.user} {
		s, err := execString(t, data)
		if err != nil {
			return nil, err
		}
		body[key] = s
	}
	var walk func(v any) (any, error)
	walk = func(v any) (any, error) {
		switch x := v.(type) {
		case *template.Template:
			return execString(x, data)
		case map[string]any:
			out := make(map[string]any, len(x))
			for k, e := range x {
				r, err := walk(e)
				if err != nil {
					return nil, err
				}
				out[k] = r
			}
			return out, nil
		case []any:
			out := make([]any, len(x))
			for i, e := range x {
				r, err := walk(e)
				if err != nil {
					return nil, err
				}
				out[i] = r
			}
			return out, nil
		default:
			return v, nil
		}
	}
	if dt.jsonData != nil {
		jd, err := walk(dt.jsonData)
		if err != nil {
			return nil, err
		}
		body["jsonData"] = jd
	}
	if len(dt.secure) > 0 {
		sec := map[string]string{}
		for k, t := range dt.secure {
			s, err := execString(t, data)
			if err != nil {
				return nil, err
			}
			sec[k] = s
		}
		body["secureJsonData"] = sec
	}
	return body, nil
}

// ensureDatasources creates or updates the configured data sources in the
// organization. The caller must be a member of it.
func (p *Plugin) ensureDatasources(ctx context.Context, o *org, t sdk.Tenant) error {
	data := datasourceData{Tenant: t, OrgID: o.ID, OrgName: o.Name}
	for _, dt := range p.ds {
		body, err := dt.render(data)
		if err != nil {
			return fmt.Errorf("datasource %s: %w", dt.cfg.Name, err)
		}
		var cur struct {
			UID string `json:"uid"`
		}
		status, err := p.call(ctx, "get data source "+dt.cfg.Name, http.MethodGet,
			"/api/datasources/name/"+url.PathEscape(dt.cfg.Name), o.ID, nil, &cur, http.StatusNotFound)
		if err != nil {
			return err
		}
		if status == http.StatusNotFound {
			_, err = p.call(ctx, "create data source "+dt.cfg.Name, http.MethodPost, "/api/datasources", o.ID, body, nil)
		} else {
			_, err = p.call(ctx, "update data source "+dt.cfg.Name, http.MethodPut,
				"/api/datasources/uid/"+url.PathEscape(cur.UID), o.ID, body, nil)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
