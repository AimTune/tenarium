package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// pyReserved are Python keywords plus the names the generated methods use
// for their own parameters.
var pyReserved = map[string]bool{
	"False": true, "None": true, "True": true, "and": true, "as": true, "assert": true,
	"async": true, "await": true, "break": true, "class": true, "continue": true, "def": true,
	"del": true, "elif": true, "else": true, "except": true, "finally": true, "for": true,
	"from": true, "global": true, "if": true, "import": true, "in": true, "is": true,
	"lambda": true, "nonlocal": true, "not": true, "or": true, "pass": true, "raise": true,
	"return": true, "try": true, "while": true, "with": true, "yield": true,
	"self": true, "body": true, "headers": true, "if_match": true, "idempotency_key": true, "cursor": true,
}

type pyGen struct{ m *model }

// genPython renders tenarium_client/_generated.py.
func genPython(m *model) ([]byte, error) {
	g := &pyGen{m: m}
	var b strings.Builder
	b.WriteString("# " + generatedHeader + "\n")
	b.WriteString(strings.ReplaceAll(`"""Types and operations of the Tenarium REST API.

The types are ''TypedDict'' classes (plain dicts at runtime) for the schemas
of the spec and for inline request and response bodies. ''Operations'' has
one method per operationId; ''Client'' supplies the transport.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterator, List, Literal, Mapping, Optional, TypedDict, Union  # noqa: F401

`, "''", "``"))

	names := sortedKeys(g.m.schemas)
	var exported []string
	exported = append(exported, names...)
	exported = append(exported, "Operations")
	sort.Strings(exported)
	b.WriteString("__all__ = [\n")
	for _, n := range exported {
		b.WriteString("    " + strconv.Quote(n) + ",\n")
	}
	b.WriteString("]\n")

	// Aliases first; their references are quoted, so order does not matter.
	for _, name := range names {
		s := g.m.schemas[name]
		if hasProps(s) {
			continue
		}
		b.WriteString("\n")
		for _, l := range descLines(s.Description) {
			b.WriteString(strings.TrimRight("# "+l, " ") + "\n")
		}
		b.WriteString(name + " = " + g.typ(s, true) + "\n")
	}

	// Record types, with allOf bases declared before the types extending them.
	done := map[string]bool{}
	var visit func(name string) error
	visit = func(name string) error {
		if done[name] {
			return nil
		}
		done[name] = true
		s := g.m.schemas[name]
		for _, a := range s.AllOf {
			if a.Ref == "" {
				continue
			}
			base := strings.TrimPrefix(a.Ref, schemaRef)
			if !hasProps(g.m.schemas[base]) {
				return fmt.Errorf("schema %s: allOf member %s is not an object type", name, base)
			}
			if err := visit(base); err != nil {
				return err
			}
		}
		b.WriteString("\n\n")
		g.record(&b, name, s)
		return nil
	}
	for _, name := range names {
		if hasProps(g.m.schemas[name]) {
			if err := visit(name); err != nil {
				return nil, err
			}
		}
	}

	if err := g.operations(&b); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

// record renders a TypedDict. Required and optional keys are split into a
// base class and a total=False subclass (NotRequired needs Python 3.11).
func (g *pyGen) record(b *strings.Builder, name string, s *schema) {
	props, required := mergeRecord(s)
	var bases []string
	for _, a := range s.AllOf {
		if a.Ref != "" {
			bases = append(bases, strings.TrimPrefix(a.Ref, schemaRef))
		}
	}
	var req, opt properties
	for _, p := range props {
		if !isIdent(p.Name) || isPyKeyword(p.Name) {
			g.functional(b, name, s, props, bases)
			return
		}
		if required[p.Name] {
			req = append(req, p)
		} else {
			opt = append(opt, p)
		}
	}
	doc := descLines(s.Description)
	baseList := "TypedDict"
	if len(bases) > 0 {
		baseList = strings.Join(bases, ", ")
	}
	switch {
	case len(req) > 0 && len(opt) > 0:
		inner := "_" + name + "Required"
		b.WriteString("class " + inner + "(" + baseList + "):\n")
		g.fields(b, req)
		b.WriteString("\n\nclass " + name + "(" + inner + ", total=False):\n")
		pyDocstring(b, "    ", doc)
		g.fields(b, opt)
	case len(opt) > 0:
		b.WriteString("class " + name + "(" + baseList + ", total=False):\n")
		pyDocstring(b, "    ", doc)
		g.fields(b, opt)
	default:
		b.WriteString("class " + name + "(" + baseList + "):\n")
		pyDocstring(b, "    ", doc)
		if len(req) == 0 && len(doc) == 0 {
			b.WriteString("    pass\n")
		}
		g.fields(b, req)
	}
}

// functional renders a TypedDict whose keys are not valid identifiers.
// Required-ness is not expressible in this form on Python 3.9.
func (g *pyGen) functional(b *strings.Builder, name string, s *schema, props properties, bases []string) {
	if len(bases) > 0 {
		b.WriteString("# Inherits " + strings.Join(bases, ", ") + "; the functional form cannot express it.\n")
	}
	for _, l := range descLines(s.Description) {
		b.WriteString(strings.TrimRight("# "+l, " ") + "\n")
	}
	b.WriteString(name + " = TypedDict(\n    " + strconv.Quote(name) + ",\n    {\n")
	for _, p := range props {
		b.WriteString("        " + strconv.Quote(p.Name) + ": " + g.typ(p.Schema, true) + ",\n")
	}
	b.WriteString("    },\n    total=False,\n)\n")
}

func (g *pyGen) fields(b *strings.Builder, props properties) {
	for _, p := range props {
		if d := oneLine(p.Schema.Description); d != "" {
			b.WriteString("    #: " + d + "\n")
		}
		b.WriteString("    " + p.Name + ": " + g.typ(p.Schema, false) + "\n")
	}
}

// typ renders a schema as a type hint. With quote, references to named
// types are strings so module-level aliases need no declaration order.
func (g *pyGen) typ(s *schema, quote bool) string {
	if s == nil {
		return "Any"
	}
	if s.Ref != "" {
		name := strings.TrimPrefix(s.Ref, schemaRef)
		if quote {
			name = strconv.Quote(name)
		}
		return optional(name, s.Nullable)
	}
	nullable := s.Nullable || s.Type.has("null")
	switch {
	case s.Const != nil:
		return optional("Literal["+pyLiteral(s.Const)+"]", nullable)
	case len(s.Enum) > 0:
		var lits []string
		for _, v := range s.Enum {
			if v == nil {
				nullable = true
				continue
			}
			lits = append(lits, pyLiteral(v))
		}
		return optional("Literal["+strings.Join(lits, ", ")+"]", nullable)
	case len(s.OneOf) > 0 || len(s.AnyOf) > 0:
		var parts []string
		for _, x := range append(append([]*schema{}, s.OneOf...), s.AnyOf...) {
			parts = append(parts, g.typ(x, quote))
		}
		return optional(union(parts), nullable)
	case len(s.AllOf) == 1 && len(s.Properties) == 0:
		return optional(g.typ(s.AllOf[0], quote), nullable)
	case len(s.AllOf) > 0:
		return optional("Dict[str, Any]", nullable) // intersections have no Python spelling
	}
	var parts []string
	for _, t := range s.Type.nonNull() {
		parts = append(parts, g.primitive(t, s, quote))
	}
	if len(parts) == 0 {
		switch {
		case len(s.Properties) > 0 || s.AdditionalProperties != nil:
			parts = append(parts, g.primitive("object", s, quote))
		case s.Items != nil:
			parts = append(parts, g.primitive("array", s, quote))
		default:
			parts = append(parts, "Any")
		}
	}
	return optional(union(parts), nullable)
}

func (g *pyGen) primitive(t string, s *schema, quote bool) string {
	switch t {
	case "string":
		return "str"
	case "integer":
		return "int"
	case "number":
		return "float"
	case "boolean":
		return "bool"
	case "array":
		return "List[" + g.typ(s.Items, quote) + "]"
	case "object":
		if ap := s.AdditionalProperties; ap != nil && ap.Schema != nil {
			return "Dict[str, " + g.typ(ap.Schema, quote) + "]"
		}
		return "Dict[str, Any]"
	}
	return "Any"
}

// paramType is the hint of a path or query parameter; int64 parameters
// also accept strings (cursors come back as strings in `next`).
func (g *pyGen) paramType(s *schema) string {
	t := g.typ(s, false)
	if s != nil && s.Ref == "" && s.Type.has("integer") && s.Format == "int64" {
		return "Union[" + t + ", str]"
	}
	return t
}

func (g *pyGen) operations(b *strings.Builder) error {
	b.WriteString(strings.ReplaceAll(`

class Operations:
    """One method per operation of the Tenarium API.

    Method names are the snake_case operationIds. ''Client'' extends this
    class and supplies ''_request'' and ''_paginate''.
    """

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:  # pragma: no cover
        raise NotImplementedError

    def _paginate(self, fetch: Callable[[Optional[str]], Any]) -> Iterator[Any]:  # pragma: no cover
        raise NotImplementedError
`, "''", "``"))
	names := map[string]string{}
	claim := func(name, id string) error {
		if prev, ok := names[name]; ok {
			return fmt.Errorf("python method %s is generated for both %s and %s", name, prev, id)
		}
		names[name] = id
		return nil
	}
	for _, o := range g.m.ops {
		if err := claim(snake(o.ID), o.ID); err != nil {
			return err
		}
	}
	for _, o := range g.m.ops {
		if err := g.method(b, o, claim); err != nil {
			return fmt.Errorf("%s: %w", o.ID, err)
		}
	}
	return nil
}

type pyArg struct {
	decl  string // "name: Type = default"
	name  string // Python parameter name
	wire  string // name on the wire (query and path parameters)
	query bool
}

func (g *pyGen) method(b *strings.Builder, o *op, claim func(name, id string) error) error {
	taken := map[string]bool{}
	var pos, kw []pyArg
	var pathArgs []string
	for _, p := range o.PathParams {
		v := pyVar(p.Name, taken)
		pos = append(pos, pyArg{decl: v + ": " + g.paramType(p.Schema), name: v, wire: p.Name})
		pathArgs = append(pathArgs, strconv.Quote(p.Name)+": "+v)
	}
	if o.Body != nil {
		t := g.typ(o.Body, false)
		if o.BodyRequired {
			pos = append(pos, pyArg{decl: "body: " + t, name: "body"})
		} else {
			pos = append(pos, pyArg{decl: "body: Optional[" + t + "] = None", name: "body"})
		}
	}
	var queryArgs []string
	// Required keyword-only parameters first, for readability.
	qs := append([]*param{}, o.QueryParams...)
	sort.SliceStable(qs, func(i, j int) bool { return qs[i].Required && !qs[j].Required })
	for _, p := range qs {
		v := pyVar(p.Name, taken)
		decl := v + ": " + g.paramType(p.Schema)
		if !p.Required {
			decl = v + ": Optional[" + g.paramType(p.Schema) + "] = None"
		}
		kw = append(kw, pyArg{decl: decl, name: v, wire: p.Name, query: true})
	}
	for _, p := range o.QueryParams {
		for _, a := range kw {
			if a.wire == p.Name {
				queryArgs = append(queryArgs, strconv.Quote(p.Name)+": "+a.name)
			}
		}
	}
	if o.IfMatch {
		kw = append(kw, pyArg{decl: "if_match: Union[str, int, None] = None", name: "if_match"})
	}
	if o.Method == "POST" {
		kw = append(kw, pyArg{decl: "idempotency_key: Optional[str] = None", name: "idempotency_key"})
	}
	kw = append(kw, pyArg{decl: "headers: Optional[Mapping[str, str]] = None", name: "headers"})

	result := "Any"
	switch {
	case o.Result != nil:
		result = g.typ(o.Result, false)
	case o.Status == "204":
		result = "None"
	}

	var doc []string
	if o.Summary != "" {
		doc = append(doc, strings.TrimSuffix(o.Summary, ".")+".")
	}
	if o.Description != "" {
		doc = appendParagraph(doc, paragraphs(o.Description)...)
	}
	doc = appendParagraph(doc, "``"+o.Method+" "+o.Path+"``")
	if o.Deprecated {
		doc = append(doc, "", "Deprecated.")
	}

	name := snake(o.ID)
	writeSig := func(name, result string) {
		b.WriteString("\n    def " + name + "(\n        self,\n")
		for _, a := range pos {
			b.WriteString("        " + a.decl + ",\n")
		}
		b.WriteString("        *,\n")
		for _, a := range kw {
			b.WriteString("        " + a.decl + ",\n")
		}
		b.WriteString("    ) -> " + result + ":\n")
	}
	writeSig(name, result)
	pyDocstring(b, "        ", doc)
	b.WriteString("        return self._request(\n")
	b.WriteString("            " + strconv.Quote(o.Method) + ",\n")
	b.WriteString("            " + strconv.Quote(o.Path) + ",\n")
	if len(pathArgs) > 0 {
		b.WriteString("            path_params={" + strings.Join(pathArgs, ", ") + "},\n")
	}
	if len(queryArgs) > 0 {
		b.WriteString("            query={\n")
		for _, q := range queryArgs {
			b.WriteString("                " + q + ",\n")
		}
		b.WriteString("            },\n")
	}
	if o.Body != nil {
		b.WriteString("            body=body,\n")
		b.WriteString("            content_type=" + strconv.Quote(o.BodyContentType) + ",\n")
	}
	if o.Public {
		b.WriteString("            public=True,\n")
	}
	if o.AutoIdem {
		b.WriteString("            auto_idempotency_key=True,\n")
	}
	for _, a := range kw {
		if !a.query {
			b.WriteString("            " + a.name + "=" + a.name + ",\n")
		}
	}
	b.WriteString("        )\n")

	if o.Paging == nil {
		return nil
	}
	iterName := "iter_" + strings.TrimPrefix(name, "list_")
	if err := claim(iterName, o.ID); err != nil {
		return err
	}
	writeSig(iterName, "Iterator["+g.typ(o.Paging.Item, false)+"]")
	pyDocstring(b, "        ", []string{
		"Iterate over every item of :meth:`" + name + "`, fetching pages as needed.",
		"",
		"``next`` is sent back as ``" + o.Paging.Cursor + "``.",
	})
	b.WriteString("        return self._paginate(\n            lambda cursor: self." + name + "(\n")
	for _, a := range pos {
		b.WriteString("                " + a.name + ",\n")
	}
	for _, a := range kw {
		if a.wire == o.Paging.Cursor && a.query {
			b.WriteString("                " + a.name + "=" + a.name + " if cursor is None else cursor,\n")
		} else {
			b.WriteString("                " + a.name + "=" + a.name + ",\n")
		}
	}
	b.WriteString("            )\n        )\n")
	return nil
}

// --- helpers ------------------------------------------------------------------------

var pyKeywords = map[string]bool{}

func init() {
	for k := range pyReserved {
		switch k {
		case "self", "body", "headers", "if_match", "idempotency_key", "cursor":
		default:
			pyKeywords[k] = true
		}
	}
}

func isPyKeyword(s string) bool { return pyKeywords[s] }

func pyVar(name string, taken map[string]bool) string {
	v := snake(name)
	if !isIdent(v) || pyReserved[v] {
		v += "_"
	}
	for taken[v] {
		v += "_"
	}
	taken[v] = true
	return v
}

func pyLiteral(v any) string {
	switch x := v.(type) {
	case string:
		return strconv.Quote(x)
	case bool:
		if x {
			return "True"
		}
		return "False"
	default:
		return fmt.Sprint(x)
	}
}

func optional(t string, nullable bool) string {
	if nullable && t != "Any" {
		return "Optional[" + t + "]"
	}
	return t
}

func union(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return "Union[" + strings.Join(parts, ", ") + "]"
}

func pyDocstring(b *strings.Builder, indent string, lines []string) {
	if len(lines) == 0 {
		return
	}
	esc := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		return strings.ReplaceAll(s, `"""`, `\"\"\"`)
	}
	if len(lines) == 1 {
		b.WriteString(indent + `"""` + esc(lines[0]) + `"""` + "\n")
		return
	}
	b.WriteString(indent + `"""` + esc(lines[0]) + "\n")
	for _, l := range lines[1:] {
		if l == "" {
			b.WriteString("\n")
		} else {
			b.WriteString(indent + esc(l) + "\n")
		}
	}
	b.WriteString(indent + `"""` + "\n")
}
