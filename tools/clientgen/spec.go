package main

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// This file holds the subset of the OpenAPI 3.1 document model that the
// generator understands. Unknown keywords are ignored.

type document struct {
	Paths      map[string]*pathItem `yaml:"paths"`
	Components struct {
		Schemas       map[string]*schema      `yaml:"schemas"`
		Parameters    map[string]*parameter   `yaml:"parameters"`
		RequestBodies map[string]*requestBody `yaml:"requestBodies"`
		Responses     map[string]*response    `yaml:"responses"`
	} `yaml:"components"`
}

type pathItem struct {
	Parameters []*parameter `yaml:"parameters"`
	Get        *operation   `yaml:"get"`
	Put        *operation   `yaml:"put"`
	Post       *operation   `yaml:"post"`
	Patch      *operation   `yaml:"patch"`
	Delete     *operation   `yaml:"delete"`
	Head       *operation   `yaml:"head"`
	Options    *operation   `yaml:"options"`
}

func (p *pathItem) operations() map[string]*operation {
	m := map[string]*operation{}
	for method, o := range map[string]*operation{
		"GET": p.Get, "PUT": p.Put, "POST": p.Post, "PATCH": p.Patch,
		"DELETE": p.Delete, "HEAD": p.Head, "OPTIONS": p.Options,
	} {
		if o != nil {
			m[method] = o
		}
	}
	return m
}

type operation struct {
	OperationID string               `yaml:"operationId"`
	Summary     string               `yaml:"summary"`
	Description string               `yaml:"description"`
	Deprecated  bool                 `yaml:"deprecated"`
	Parameters  []*parameter         `yaml:"parameters"`
	RequestBody *requestBody         `yaml:"requestBody"`
	Responses   map[string]*response `yaml:"responses"`
	// Security is nil when the operation inherits the global requirement and
	// empty when it is public (security: []).
	Security *[]map[string][]string `yaml:"security"`
}

type parameter struct {
	Ref         string  `yaml:"$ref"`
	Name        string  `yaml:"name"`
	In          string  `yaml:"in"`
	Description string  `yaml:"description"`
	Required    bool    `yaml:"required"`
	Deprecated  bool    `yaml:"deprecated"`
	Schema      *schema `yaml:"schema"`
}

type requestBody struct {
	Ref         string               `yaml:"$ref"`
	Description string               `yaml:"description"`
	Required    bool                 `yaml:"required"`
	Content     map[string]mediaType `yaml:"content"`
}

type response struct {
	Ref         string               `yaml:"$ref"`
	Description string               `yaml:"description"`
	Content     map[string]mediaType `yaml:"content"`
}

type mediaType struct {
	Schema *schema `yaml:"schema"`
}

type schema struct {
	Ref                  string      `yaml:"$ref"`
	Type                 typeSet     `yaml:"type"`
	Format               string      `yaml:"format"`
	Description          string      `yaml:"description"`
	Enum                 []any       `yaml:"enum"`
	Const                any         `yaml:"const"`
	Items                *schema     `yaml:"items"`
	Properties           properties  `yaml:"properties"`
	Required             []string    `yaml:"required"`
	AdditionalProperties *additional `yaml:"additionalProperties"`
	AllOf                []*schema   `yaml:"allOf"`
	OneOf                []*schema   `yaml:"oneOf"`
	AnyOf                []*schema   `yaml:"anyOf"`
	Nullable             bool        `yaml:"nullable"`
	Deprecated           bool        `yaml:"deprecated"`
}

// typeSet is the "type" keyword: a single name or, in OpenAPI 3.1, a list
// such as [string, "null"].
type typeSet []string

func (t *typeSet) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		*t = typeSet{n.Value}
		return nil
	case yaml.SequenceNode:
		var l []string
		if err := n.Decode(&l); err != nil {
			return err
		}
		*t = l
		return nil
	}
	return fmt.Errorf("line %d: type must be a string or a list", n.Line)
}

func (t typeSet) has(name string) bool {
	for _, v := range t {
		if v == name {
			return true
		}
	}
	return false
}

// nonNull returns the types other than "null".
func (t typeSet) nonNull() []string {
	var out []string
	for _, v := range t {
		if v != "null" {
			out = append(out, v)
		}
	}
	return out
}

// properties keeps the order in which properties appear in the spec, so
// generated interfaces read like the spec.
type properties []property

type property struct {
	Name   string
	Schema *schema
}

func (p *properties) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: properties must be a mapping", n.Line)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		var s schema
		if err := n.Content[i+1].Decode(&s); err != nil {
			return err
		}
		*p = append(*p, property{Name: n.Content[i].Value, Schema: &s})
	}
	return nil
}

// additional is additionalProperties: a boolean or a schema.
type additional struct {
	Allowed *bool
	Schema  *schema
}

func (a *additional) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!bool" {
		var b bool
		if err := n.Decode(&b); err != nil {
			return err
		}
		a.Allowed = &b
		return nil
	}
	var s schema
	if err := n.Decode(&s); err != nil {
		return err
	}
	a.Schema = &s
	return nil
}

func parseSpec(data []byte) (*document, error) {
	var d document
	if err := yaml.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	if len(d.Paths) == 0 {
		return nil, fmt.Errorf("parse spec: no paths")
	}
	return &d, nil
}

// refName returns the last segment of a local reference of the given
// component kind, e.g. "#/components/schemas/Tenant" -> "Tenant".
func refName(ref, kind string) (string, error) {
	prefix := "#/components/" + kind + "/"
	if !strings.HasPrefix(ref, prefix) {
		return "", fmt.Errorf("unsupported reference %q (want %s...)", ref, prefix)
	}
	return strings.TrimPrefix(ref, prefix), nil
}

func (d *document) parameter(p *parameter) (*parameter, error) {
	if p.Ref == "" {
		return p, nil
	}
	name, err := refName(p.Ref, "parameters")
	if err != nil {
		return nil, err
	}
	r, ok := d.Components.Parameters[name]
	if !ok {
		return nil, fmt.Errorf("unknown parameter %q", p.Ref)
	}
	return r, nil
}

func (d *document) requestBody(b *requestBody) (*requestBody, string, error) {
	if b.Ref == "" {
		return b, "", nil
	}
	name, err := refName(b.Ref, "requestBodies")
	if err != nil {
		return nil, "", err
	}
	r, ok := d.Components.RequestBodies[name]
	if !ok {
		return nil, "", fmt.Errorf("unknown request body %q", b.Ref)
	}
	return r, name, nil
}

func (d *document) response(r *response) (*response, string, error) {
	if r.Ref == "" {
		return r, "", nil
	}
	name, err := refName(r.Ref, "responses")
	if err != nil {
		return nil, "", err
	}
	x, ok := d.Components.Responses[name]
	if !ok {
		return nil, "", fmt.Errorf("unknown response %q", r.Ref)
	}
	return x, name, nil
}
