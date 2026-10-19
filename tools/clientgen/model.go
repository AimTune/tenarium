package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// model is the language-neutral view of the spec that the emitters render.
// Inline object schemas are hoisted into named types so both TypeScript and
// Python (whose TypedDicts cannot be anonymous) see the same type names.
type model struct {
	schemas map[string]*schema
	ops     []*op

	bodyCache map[string]*schema
	respCache map[string]*schema
}

type op struct {
	ID          string
	Method      string
	Path        string
	Summary     string
	Description string
	Deprecated  bool

	PathParams  []*param // in the order they appear in Path
	QueryParams []*param // in spec order
	IfMatch     bool     // declares an If-Match header
	Public      bool     // security: [] (no credentials are sent)
	AutoIdem    bool     // gets an automatic Idempotency-Key when retries are on

	Body            *schema // nil without a request body
	BodyRequired    bool
	BodyContentType string

	Status string  // success status code, e.g. "200"
	Result *schema // nil when the success response has no content

	Paging *paging
}

type param struct {
	Name        string
	Description string
	Required    bool
	Schema      *schema
}

// paging describes a cursor-paginated list: the response has items and
// next, and next is passed back as the Cursor query parameter.
type paging struct {
	Cursor string // "after" or "before"
	Item   *schema
}

// autoIdempotent lists POST operations that are not creates (no 201) but
// are not safe to repeat either, so they get an automatic Idempotency-Key
// like the Go client gives them.
var autoIdempotent = map[string]bool{
	"recordUsage": true,
}

const schemaRef = "#/components/schemas/"

func buildModel(d *document) (*model, error) {
	m := &model{
		schemas:   map[string]*schema{},
		bodyCache: map[string]*schema{},
		respCache: map[string]*schema{},
	}
	for name, s := range d.Components.Schemas {
		if !isIdent(name) {
			return nil, fmt.Errorf("schema name %q is not a valid identifier", name)
		}
		m.schemas[name] = s
	}
	for _, name := range sortedKeys(d.Components.Schemas) {
		s, err := m.hoistMembers(d.Components.Schemas[name], name)
		if err != nil {
			return nil, fmt.Errorf("schema %s: %w", name, err)
		}
		m.schemas[name] = s
	}

	seen := map[string]string{}
	for _, path := range sortedKeys(d.Paths) {
		item := d.Paths[path]
		ops := item.operations()
		for _, method := range sortedKeys(ops) {
			o := ops[method]
			if o.OperationID == "" {
				continue // e.g. /healthz; reachable through the raw request method
			}
			if prev, dup := seen[o.OperationID]; dup {
				return nil, fmt.Errorf("operationId %s is used by %s and %s %s", o.OperationID, prev, method, path)
			}
			seen[o.OperationID] = method + " " + path
			x, err := m.buildOp(d, method, path, item, o)
			if err != nil {
				return nil, fmt.Errorf("%s %s (%s): %w", method, path, o.OperationID, err)
			}
			m.ops = append(m.ops, x)
		}
	}
	sort.Slice(m.ops, func(i, j int) bool { return m.ops[i].ID < m.ops[j].ID })
	return m, nil
}

func (m *model) buildOp(d *document, method, path string, item *pathItem, o *operation) (*op, error) {
	x := &op{
		ID: o.OperationID, Method: method, Path: path,
		Summary: o.Summary, Description: o.Description, Deprecated: o.Deprecated,
		Public: o.Security != nil && len(*o.Security) == 0,
	}
	if !isIdent(x.ID) {
		return nil, fmt.Errorf("operationId is not a valid identifier")
	}
	opName := pascal(x.ID)

	// Operation parameters override path-level ones with the same name and location.
	var params []*parameter
	index := map[string]int{}
	for _, list := range [][]*parameter{item.Parameters, o.Parameters} {
		for _, p := range list {
			r, err := d.parameter(p)
			if err != nil {
				return nil, err
			}
			key := r.In + ":" + r.Name
			if i, ok := index[key]; ok {
				params[i] = r
				continue
			}
			index[key] = len(params)
			params = append(params, r)
		}
	}
	var idemHeader bool
	for _, p := range params {
		s, err := m.hoist(p.Schema, opName+pascal(p.Name))
		if err != nil {
			return nil, err
		}
		pp := &param{Name: p.Name, Description: p.Description, Required: p.Required, Schema: s}
		switch p.In {
		case "path":
			pp.Required = true
			x.PathParams = append(x.PathParams, pp)
		case "query":
			x.QueryParams = append(x.QueryParams, pp)
		case "header":
			switch strings.ToLower(p.Name) {
			case "if-match":
				x.IfMatch = true
			case "idempotency-key":
				idemHeader = true
			}
			// Other headers can be sent with the per-call headers option.
		}
	}
	for _, p := range x.PathParams {
		if !strings.Contains(path, "{"+p.Name+"}") {
			return nil, fmt.Errorf("path parameter %s is not in the path", p.Name)
		}
	}
	sort.SliceStable(x.PathParams, func(i, j int) bool {
		return strings.Index(path, "{"+x.PathParams[i].Name+"}") < strings.Index(path, "{"+x.PathParams[j].Name+"}")
	})
	if n := strings.Count(path, "{"); n != len(x.PathParams) {
		return nil, fmt.Errorf("path has %d placeholders but %d path parameters", n, len(x.PathParams))
	}

	if o.RequestBody != nil {
		rb, compName, err := d.requestBody(o.RequestBody)
		if err != nil {
			return nil, err
		}
		ct, mt, ok := pickContent(rb.Content)
		if !ok {
			return nil, fmt.Errorf("request body has no content type")
		}
		x.BodyContentType = ct
		x.BodyRequired = rb.Required
		if compName != "" {
			s, ok := m.bodyCache[compName]
			if !ok {
				if s, err = m.hoist(mt.Schema, compName+"Request"); err != nil {
					return nil, err
				}
				m.bodyCache[compName] = s
			}
			x.Body = s
		} else if x.Body, err = m.hoist(mt.Schema, opName+"Request"); err != nil {
			return nil, err
		}
		if x.Body == nil {
			x.Body = &schema{Type: typeSet{"object"}}
		}
	}

	codes := sortedKeys(o.Responses)
	for _, code := range codes {
		if len(code) == 3 && code[0] == '2' {
			x.Status = code
			break
		}
	}
	if x.Status != "" {
		r, compName, err := d.response(o.Responses[x.Status])
		if err != nil {
			return nil, err
		}
		if _, mt, ok := pickContent(r.Content); ok && mt.Schema != nil {
			if compName != "" {
				s, ok := m.respCache[compName]
				if !ok {
					name := compName
					if _, taken := m.schemas[name]; taken {
						name += "Response"
					}
					if s, err = m.hoist(mt.Schema, name); err != nil {
						return nil, err
					}
					m.respCache[compName] = s
				}
				x.Result = s
			} else if x.Result, err = m.hoist(mt.Schema, opName+"Response"); err != nil {
				return nil, err
			}
		}
	}

	x.AutoIdem = method == "POST" && !x.Public && (x.Status == "201" || idemHeader || autoIdempotent[x.ID])
	if method == "GET" && x.Result != nil {
		x.Paging = m.detectPaging(x)
	}
	return x, nil
}

func (m *model) detectPaging(x *op) *paging {
	res := m.deref(x.Result)
	if res == nil {
		return nil
	}
	var items, next *schema
	for _, p := range res.Properties {
		switch p.Name {
		case "items":
			items = m.deref(p.Schema)
		case "next":
			next = m.deref(p.Schema)
		}
	}
	if items == nil || next == nil || items.Items == nil || !items.Type.has("array") || !next.Type.has("string") {
		return nil
	}
	for _, cursor := range []string{"after", "before"} {
		for _, q := range x.QueryParams {
			if q.Name == cursor {
				return &paging{Cursor: cursor, Item: items.Items}
			}
		}
	}
	return nil
}

// deref follows a schema reference to the named type.
func (m *model) deref(s *schema) *schema {
	for s != nil && s.Ref != "" {
		name := strings.TrimPrefix(s.Ref, schemaRef)
		s = m.schemas[name]
	}
	return s
}

// pickContent picks the media type the clients use for a body:
// application/json if present, then another +json type, then a form,
// then the first remaining one. The runtimes encode JSON and form bodies
// and send anything else as given; responses that are not JSON are
// returned as text.
func pickContent(c map[string]mediaType) (string, mediaType, bool) {
	if mt, ok := c["application/json"]; ok {
		return "application/json", mt, true
	}
	keys := sortedKeys(c)
	for _, ct := range keys {
		if strings.HasSuffix(ct, "+json") {
			return ct, c[ct], true
		}
	}
	if mt, ok := c["application/x-www-form-urlencoded"]; ok {
		return "application/x-www-form-urlencoded", mt, true
	}
	if len(keys) > 0 {
		return keys[0], c[keys[0]], true
	}
	return "", mediaType{}, false
}

// --- hoisting -------------------------------------------------------------------

// hasProps reports whether s becomes a named record type (an interface or
// a TypedDict) rather than an alias.
func hasProps(s *schema) bool {
	if s == nil || s.Ref != "" {
		return false
	}
	if len(s.Properties) > 0 {
		return true
	}
	if len(s.AllOf) > 0 {
		for _, a := range s.AllOf {
			if a.Ref == "" && len(a.Properties) == 0 {
				return false
			}
		}
		return true
	}
	return false
}

// hoist returns s with every inline record schema, including s itself,
// replaced by a reference to a named type derived from name.
func (m *model) hoist(s *schema, name string) (*schema, error) {
	if s == nil || s.Ref != "" {
		return s, nil
	}
	if !hasProps(s) {
		return m.hoistMembers(s, name)
	}
	if _, taken := m.schemas[name]; taken {
		return nil, fmt.Errorf("generated type name %s collides with an existing type", name)
	}
	m.schemas[name] = nil // reserve before recursing
	body, err := m.hoistMembers(s, name)
	if err != nil {
		return nil, err
	}
	m.schemas[name] = body
	return &schema{Ref: schemaRef + name}, nil
}

// hoistMembers hoists the nested schemas of s and keeps s itself inline.
// It never modifies s.
func (m *model) hoistMembers(s *schema, name string) (*schema, error) {
	if s == nil || s.Ref != "" {
		return s, nil
	}
	c := *s
	var err error
	if len(s.Properties) > 0 {
		c.Properties = make(properties, len(s.Properties))
		for i, p := range s.Properties {
			base := name + pascal(p.Name)
			ps := p.Schema
			if ps != nil && ps.Ref == "" && ps.Type.has("array") && !hasProps(ps) {
				cp := *ps
				if cp.Items, err = m.hoist(ps.Items, singular(base)); err != nil {
					return nil, err
				}
				ps = &cp
			} else if ps, err = m.hoist(ps, base); err != nil {
				return nil, err
			}
			c.Properties[i] = property{Name: p.Name, Schema: ps}
		}
	}
	if s.Items != nil {
		if c.Items, err = m.hoist(s.Items, name+"Item"); err != nil {
			return nil, err
		}
	}
	if s.AdditionalProperties != nil && s.AdditionalProperties.Schema != nil {
		v, err := m.hoist(s.AdditionalProperties.Schema, name+"Value")
		if err != nil {
			return nil, err
		}
		c.AdditionalProperties = &additional{Schema: v}
	}
	if len(s.AllOf) > 0 {
		c.AllOf = make([]*schema, len(s.AllOf))
		for i, a := range s.AllOf {
			if c.AllOf[i], err = m.hoistMembers(a, name); err != nil {
				return nil, err
			}
		}
	}
	for _, list := range []*[]*schema{&c.OneOf, &c.AnyOf} {
		if len(*list) == 0 {
			continue
		}
		out := make([]*schema, len(*list))
		for i, a := range *list {
			if out[i], err = m.hoist(a, name+strconv.Itoa(i+1)); err != nil {
				return nil, err
			}
		}
		*list = out
	}
	return &c, nil
}

// --- naming helpers --------------------------------------------------------------

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r == '_' || r < unicode.MaxASCII && unicode.IsLetter(r) || i > 0 && r < unicode.MaxASCII && unicode.IsDigit(r) {
			continue
		}
		return false
	}
	return true
}

// pascal turns "recovery_codes", "If-Match" or "listTenants" into
// "RecoveryCodes", "IfMatch" and "ListTenants".
func pascal(s string) string {
	var b strings.Builder
	upper := true
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			upper = true
			continue
		}
		if upper {
			r = unicode.ToUpper(r)
			upper = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// camel is pascal with a lower-case first letter.
func camel(s string) string {
	p := pascal(s)
	if p == "" {
		return p
	}
	return strings.ToLower(p[:1]) + p[1:]
}

// snake turns "listTenantAPIKeys", "startIndex" or "getSSO" into
// "list_tenant_api_keys", "start_index" and "get_sso".
func snake(s string) string {
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		if r == '-' || r == ' ' || r == '.' {
			b.WriteByte('_')
			continue
		}
		if unicode.IsUpper(r) && i > 0 {
			prev := rs[i-1]
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if unicode.IsLower(prev) || unicode.IsDigit(prev) || unicode.IsUpper(prev) && nextLower {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

func singular(s string) string {
	if strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss") && len(s) > 1 {
		return s[:len(s)-1]
	}
	return s + "Item"
}

// oneLine returns the first paragraph of a description, with
// line breaks folded, for one-line comments.
func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n\n"); i >= 0 {
		s = s[:i]
	}
	return strings.Join(strings.Fields(s), " ")
}

// paragraphs normalizes a multi-line description: trims each line and
// drops trailing blank lines.
func paragraphs(s string) []string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	return lines
}

// appendParagraph appends lines to a doc comment, separated from earlier
// content by a blank line.
func appendParagraph(doc []string, lines ...string) []string {
	if len(doc) > 0 {
		doc = append(doc, "")
	}
	return append(doc, lines...)
}
