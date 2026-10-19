package opensearchtenant

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// objectKind is a kind of cluster object carrying an ownership marker.
type objectKind string

const (
	kindTemplate objectKind = "index template"
	kindRole     objectKind = "role"
	kindMapping  objectKind = "role mapping"
	kindUser     objectKind = "user"
)

// object is the ownership state of a cluster object.
type object struct {
	Kind   objectKind
	Name   string
	Path   string // REST path of the object
	Exists bool
	// TenantID is the live owner ("" if unmarked or retained).
	TenantID string
	// DeletedTenantID and DeletedAt are set on retained objects.
	DeletedTenantID string
	DeletedAt       string
}

// claim reports whether o is marked for tenantID and returns an error if
// o exists but may not be used by it.
func (o object) claim(tenantID string) (bool, error) {
	switch {
	case !o.Exists:
		return false, nil
	case o.TenantID == tenantID:
		return true, nil
	case o.TenantID != "":
		return false, fmt.Errorf("%s %s already exists and belongs to another tenant (%s)", o.Kind, o.Name, o.TenantID)
	case o.DeletedTenantID != "":
		return false, fmt.Errorf("%s %s holds data retained from deleted tenant %s (deleted at %s); remove the indices and the template before provisioning a tenant with this prefix",
			o.Kind, o.Name, o.DeletedTenantID, o.DeletedAt)
	default:
		return false, fmt.Errorf("%s %s already exists and is not managed by tenarium", o.Kind, o.Name)
	}
}

// Paths of the security APIs.
const (
	osSecurityAPI = "/_plugins/_security/api"
	esSecurityAPI = "/_security"
)

func (p *Plugin) objectPath(k objectKind, name string) string {
	es := p.cfg.Flavor == FlavorElasticsearch
	switch k {
	case kindTemplate:
		return "/_index_template/" + name
	case kindRole:
		if es {
			return esSecurityAPI + "/role/" + name
		}
		return osSecurityAPI + "/roles/" + name
	case kindMapping:
		return osSecurityAPI + "/rolesmapping/" + name
	default: // kindUser
		if es {
			return esSecurityAPI + "/user/" + name
		}
		return osSecurityAPI + "/internalusers/" + name
	}
}

// inspect reads the ownership state of every object the configuration
// maintains for n.
func (p *Plugin) inspect(ctx context.Context, n names) (map[objectKind]object, error) {
	want := map[objectKind]string{}
	if p.templateEnabled() {
		want[kindTemplate] = n.Template
	}
	if p.cfg.Security.Enabled {
		want[kindRole] = n.Role
		if n.User != "" {
			want[kindUser] = n.User
		}
		if p.needsMapping() {
			want[kindMapping] = n.Role
		}
	}
	out := make(map[objectKind]object, len(want))
	for k, name := range want {
		o, err := p.getObject(ctx, k, name)
		if err != nil {
			return nil, err
		}
		out[k] = o
	}
	return out, nil
}

// markerRe finds the tenant ID in an OpenSearch security description.
var markerRe = regexp.MustCompile(`tenarium-tenant-id=([^\s;]+)`)

func markerDescription(tenantID string) string {
	return "tenarium-tenant-id=" + tenantID + "; managed by tenarium"
}

func (p *Plugin) getObject(ctx context.Context, k objectKind, name string) (object, error) {
	o := object{Kind: k, Name: name, Path: p.objectPath(k, name)}
	if k == kindTemplate {
		var resp struct {
			IndexTemplates []struct {
				Name          string `json:"name"`
				IndexTemplate struct {
					Meta map[string]any `json:"_meta"`
				} `json:"index_template"`
			} `json:"index_templates"`
		}
		err := p.client.do(ctx, http.MethodGet, o.Path, nil, nil, &resp)
		if isNotFound(err) {
			return o, nil
		} else if err != nil {
			return o, fmt.Errorf("get %s %s: %w", k, name, err)
		}
		for _, it := range resp.IndexTemplates {
			if it.Name == name {
				o.Exists = true
				m := it.IndexTemplate.Meta
				o.TenantID, o.DeletedTenantID, o.DeletedAt = str(m[MetaTenantID]), str(m[MetaDeletedTenantID]), str(m[MetaDeletedAt])
			}
		}
		return o, nil
	}

	var resp map[string]struct {
		Description string         `json:"description"`
		Attributes  map[string]any `json:"attributes"` // OpenSearch users
		Metadata    map[string]any `json:"metadata"`   // Elasticsearch
	}
	err := p.client.do(ctx, http.MethodGet, o.Path, nil, nil, &resp)
	if isNotFound(err) {
		return o, nil
	} else if err != nil {
		return o, fmt.Errorf("get %s %s: %w", k, name, err)
	}
	v, ok := resp[name]
	if !ok {
		return o, nil
	}
	o.Exists = true
	switch {
	case str(v.Metadata[MetaTenantID]) != "":
		o.TenantID = str(v.Metadata[MetaTenantID])
	case str(v.Attributes[MetaTenantID]) != "":
		o.TenantID = str(v.Attributes[MetaTenantID])
	default:
		if m := markerRe.FindStringSubmatch(v.Description); m != nil {
			o.TenantID = m[1]
		}
	}
	return o, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func (p *Plugin) deleteObject(ctx context.Context, o object) error {
	err := p.client.do(ctx, http.MethodDelete, o.Path, nil, nil, nil)
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("delete %s %s: %w", o.Kind, o.Name, err)
	}
	return nil
}

// templateBody is the index template for n with the given _meta.
func (p *Plugin) templateBody(n names, meta map[string]any) map[string]any {
	it := p.cfg.IndexTemplate
	body := map[string]any{
		"index_patterns": []string{n.Pattern},
		"priority":       *it.Priority,
		"_meta":          meta,
	}
	settings := maps.Clone(it.Settings)
	if settings == nil {
		settings = map[string]any{}
	}
	if it.Shards != nil {
		settings["index.number_of_shards"] = *it.Shards
	}
	if it.Replicas != nil {
		settings["index.number_of_replicas"] = *it.Replicas
	}
	tmpl := map[string]any{}
	if len(settings) > 0 {
		tmpl["settings"] = settings
	}
	if len(it.Mappings) > 0 {
		tmpl["mappings"] = it.Mappings
	}
	if len(tmpl) > 0 {
		body["template"] = tmpl
	}
	return body
}

// putTemplate writes the index template. With create it fails instead of
// overwriting a template created concurrently.
func (p *Plugin) putTemplate(ctx context.Context, n names, meta map[string]any, create bool) error {
	var q url.Values
	if create {
		q = url.Values{"create": {"true"}}
	}
	path := p.objectPath(kindTemplate, n.Template)
	if err := p.client.do(ctx, http.MethodPut, path, q, p.templateBody(n, meta), nil); err != nil {
		return fmt.Errorf("put index template %s: %w", n.Template, err)
	}
	return nil
}

// listIndices returns the concrete indices (open, closed and hidden)
// matching pattern.
func (p *Plugin) listIndices(ctx context.Context, pattern string) ([]string, error) {
	var rows []struct {
		Index string `json:"index"`
	}
	q := url.Values{"format": {"json"}, "h": {"index"}, "expand_wildcards": {"all"}}
	err := p.client.do(ctx, http.MethodGet, "/_cat/indices/"+pattern, q, nil, &rows)
	if isNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("list indices %s: %w", pattern, err)
	}
	prefix := strings.TrimSuffix(pattern, "*")
	var out []string
	for _, r := range rows {
		if strings.HasPrefix(r.Index, prefix) {
			out = append(out, r.Index)
		}
	}
	return out, nil
}

// deleteIndices deletes every index matching pattern, one concrete name at
// a time: wildcard deletes are refused by clusters with
// action.destructive_requires_name (the default since Elasticsearch 8).
func (p *Plugin) deleteIndices(ctx context.Context, pattern string) error {
	idx, err := p.listIndices(ctx, pattern)
	if err != nil {
		return err
	}
	for _, name := range idx {
		err := p.client.do(ctx, http.MethodDelete, "/"+name, nil, nil, nil)
		if err != nil && !isNotFound(err) {
			return fmt.Errorf("delete index %s: %w", name, err)
		}
	}
	return nil
}

// createIndex creates the initial index (and its write alias) unless it
// exists.
func (p *Plugin) createIndex(ctx context.Context, n names) error {
	var body map[string]any
	if n.Alias != "" {
		body = map[string]any{"aliases": map[string]any{n.Alias: map[string]any{"is_write_index": true}}}
	}
	err := p.client.do(ctx, http.MethodPut, "/"+n.Index, nil, body, nil)
	switch {
	case err == nil:
		return nil
	case errorType(err) != "resource_already_exists_exception":
		return fmt.Errorf("create index %s: %w", n.Index, err)
	case n.Alias == "":
		return nil
	}
	// The index exists (an earlier run or the tenant created it); make sure
	// the alias does too.
	err = p.client.do(ctx, http.MethodPut, "/"+n.Index+"/_alias/"+n.Alias, nil,
		map[string]any{"is_write_index": true}, nil)
	if err != nil {
		return fmt.Errorf("put alias %s on %s: %w", n.Alias, n.Index, err)
	}
	return nil
}

func (p *Plugin) putRole(ctx context.Context, n names, t sdk.Tenant) error {
	s := p.cfg.Security
	var body map[string]any
	cluster := s.ClusterPermissions
	if cluster == nil {
		cluster = []string{}
	}
	if p.cfg.Flavor == FlavorElasticsearch {
		body = map[string]any{
			"cluster":  cluster,
			"indices":  []map[string]any{{"names": []string{n.Pattern}, "privileges": s.IndexPermissions}},
			"metadata": map[string]any{MetaTenantID: t.ID, MetaManagedBy: "tenarium"},
		}
	} else {
		body = map[string]any{
			"description":         markerDescription(t.ID),
			"cluster_permissions": cluster,
			"index_permissions": []map[string]any{{
				"index_patterns": []string{n.Pattern}, "allowed_actions": s.IndexPermissions,
			}},
		}
	}
	return p.put(ctx, kindRole, n.Role, body)
}

func (p *Plugin) putUser(ctx context.Context, n names, t sdk.Tenant) error {
	pw := TenantPassword(p.cfg.Security.PasswordSecret, t.ID)
	var body map[string]any
	if p.cfg.Flavor == FlavorElasticsearch {
		body = map[string]any{
			"password": pw,
			"roles":    []string{n.Role},
			"metadata": map[string]any{MetaTenantID: t.ID, MetaManagedBy: "tenarium"},
		}
	} else {
		body = map[string]any{
			"password":    pw,
			"description": markerDescription(t.ID),
			"attributes":  map[string]string{MetaTenantID: t.ID},
		}
	}
	return p.put(ctx, kindUser, n.User, body)
}

// putMapping maps the tenant user and backend roles to the role
// (OpenSearch only).
func (p *Plugin) putMapping(ctx context.Context, n names, t sdk.Tenant) error {
	users := []string{}
	if n.User != "" {
		users = append(users, n.User)
	}
	backend := p.cfg.Security.BackendRoles
	if backend == nil {
		backend = []string{}
	}
	return p.put(ctx, kindMapping, n.Role, map[string]any{
		"description":   markerDescription(t.ID),
		"users":         users,
		"backend_roles": backend,
	})
}

func (p *Plugin) put(ctx context.Context, k objectKind, name string, body map[string]any) error {
	if err := p.client.do(ctx, http.MethodPut, p.objectPath(k, name), nil, body, nil); err != nil {
		return fmt.Errorf("put %s %s: %w", k, name, err)
	}
	return nil
}
