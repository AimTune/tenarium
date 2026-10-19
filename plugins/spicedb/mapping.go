package spicedb

import (
	"fmt"
	"strings"

	"github.com/AimTune/tenarium/pkg/sdk"
)

// requestVars are the placeholders available in user, relation and object
// templates.
var requestVars = map[string]bool{
	"principal.kind": true, "principal.subject": true, "principal.authenticator": true, "principal.tenant_id": true,
	"action": true, "action.resource": true, "action.verb": true,
	"resource.type": true, "resource.id": true, "resource.tenant_id": true, "resource.id_or_tenant": true,
}

// memberVars are the placeholders available in the member user template.
var memberVars = map[string]bool{"member.user_id": true, "member.email": true, "member.id": true, "member.tenant_id": true}

// template is a string with {placeholder} references.
type template struct {
	src   string
	parts []tmplPart
}

type tmplPart struct {
	lit string
	ref string // placeholder name; empty for literals
}

func parseTemplate(src string, allowed map[string]bool) (*template, error) {
	t := &template{src: src}
	rest := src
	for rest != "" {
		i := strings.IndexByte(rest, '{')
		if i < 0 {
			t.parts = append(t.parts, tmplPart{lit: rest})
			break
		}
		if i > 0 {
			t.parts = append(t.parts, tmplPart{lit: rest[:i]})
		}
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			return nil, fmt.Errorf("template %q: unterminated placeholder", src)
		}
		name := rest[i+1 : i+j]
		if !allowed[name] {
			return nil, fmt.Errorf("template %q: unknown placeholder {%s}", src, name)
		}
		t.parts = append(t.parts, tmplPart{ref: name})
		rest = rest[i+j+1:]
	}
	return t, nil
}

// expand substitutes vars. It reports false, naming the placeholder, when a
// referenced value is empty: an identifier like "tenant:" is never sent.
func (t *template) expand(vars map[string]string) (string, string, bool) {
	var b strings.Builder
	for _, p := range t.parts {
		if p.ref == "" {
			b.WriteString(p.lit)
			continue
		}
		v := vars[p.ref]
		if v == "" {
			return "", p.ref, false
		}
		b.WriteString(v)
	}
	return b.String(), "", true
}

func varsFor(p *sdk.Principal, action sdk.Action, res sdk.Resource) map[string]string {
	resource, verb, _ := strings.Cut(string(action), ":")
	idOrTenant := res.ID
	if idOrTenant == "" {
		idOrTenant = res.TenantID
	}
	return map[string]string{
		"principal.kind": p.Kind, "principal.subject": p.Subject,
		"principal.authenticator": p.Authenticator, "principal.tenant_id": p.TenantID,
		"action": string(action), "action.resource": resource, "action.verb": verb,
		"resource.type": res.Type, "resource.id": res.ID, "resource.tenant_id": res.TenantID,
		"resource.id_or_tenant": idOrTenant,
	}
}

// mapper turns a Tenarium request into an SpiceDB (subject, permission, resource).
type mapper struct {
	user         *template
	relation     *template
	relations    map[string]string
	object       *template
	objects      map[string]*template
	globalObject string
}

func newMapper(cfg Config) (*mapper, error) {
	m := &mapper{relations: cfg.Permissions, objects: map[string]*template{}, globalObject: cfg.GlobalResource}
	var err error
	if m.user, err = parseTemplate(cfg.Subject, requestVars); err != nil {
		return nil, fmt.Errorf("subject: %w", err)
	}
	if m.relation, err = parseTemplate(cfg.Permission, requestVars); err != nil {
		return nil, fmt.Errorf("permission: %w", err)
	}
	if m.object, err = parseTemplate(cfg.Resource, requestVars); err != nil {
		return nil, fmt.Errorf("resource: %w", err)
	}
	for typ, src := range cfg.Resources {
		t, err := parseTemplate(src, requestVars)
		if err != nil {
			return nil, fmt.Errorf("resources.%s: %w", typ, err)
		}
		if err := checkTypedID(src); err != nil {
			return nil, fmt.Errorf("resources.%s: %w", typ, err)
		}
		m.objects[typ] = t
	}
	for _, s := range []struct{ name, v string }{{"subject", cfg.Subject}, {"resource", cfg.Resource}} {
		if err := checkTypedID(s.v); err != nil {
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	if cfg.GlobalResource != "" && !strings.Contains(cfg.GlobalResource, ":") {
		return nil, fmt.Errorf("global_resource %q must look like type:id", cfg.GlobalResource)
	}
	return m, nil
}

// checkTypedID requires a literal "type:" prefix or a ':' somewhere, so a
// template cannot produce an untyped identifier.
func checkTypedID(src string) error {
	if !strings.Contains(src, ":") {
		return fmt.Errorf("%q must look like type:id", src)
	}
	return nil
}

type check struct {
	user, relation, object string
}

// resolve maps a request. When the request cannot be expressed (no
// relation for the action, or an identifier would be empty) it returns
// ok=false and a reason; the authorizer then abstains.
func (m *mapper) resolve(p *sdk.Principal, action sdk.Action, res sdk.Resource) (c check, reason string, ok bool) {
	vars := varsFor(p, action, res)
	if rel, found := m.relations[string(action)]; found {
		if rel == "" {
			return c, "action " + string(action) + " is not mapped", false
		}
		c.relation = rel
	} else {
		rel, missing, ok := m.relation.expand(vars)
		if !ok {
			return c, "permission template needs {" + missing + "}", false
		}
		c.relation = rel
	}
	user, missing, ok := m.user.expand(vars)
	if !ok {
		return c, "subject template needs {" + missing + "}", false
	}
	c.user = user
	objT := m.object
	if t, found := m.objects[res.Type]; found {
		objT = t
	}
	obj, missing, ok := objT.expand(vars)
	if !ok {
		if m.globalObject == "" {
			return c, "resource template needs {" + missing + "}", false
		}
		obj = m.globalObject
	}
	c.object = obj
	return c, "", true
}
