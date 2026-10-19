package eventschema

import (
	"encoding"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"time"
)

// Draft is the JSON Schema dialect of every schema this package produces.
const Draft = "https://json-schema.org/draft/2020-12/schema"

var (
	timeType      = reflect.TypeFor[time.Time]()
	rawType       = reflect.TypeFor[json.RawMessage]()
	marshalerType = reflect.TypeFor[json.Marshaler]()
	textType      = reflect.TypeFor[encoding.TextMarshaler]()
)

// Schema is a JSON Schema document. It marshals with sorted keys, so the
// output is deterministic.
type Schema = map[string]any

// Generate returns the JSON Schema (draft 2020-12) of the JSON encoding
// that encoding/json produces for values of type t. It follows the rules of
// encoding/json:
//
//   - field names come from `json` tags; `json:"-"` and unexported fields
//     are skipped; fields of embedded structs without a tag name are
//     flattened into the parent (the shallowest field of a name wins);
//   - fields are required unless tagged omitempty or omitzero (or promoted
//     through an embedded pointer, which may be nil);
//   - pointers, and slices and maps not tagged omitempty, are nullable;
//   - time.Time is a date-time string, []byte a base64 string,
//     json.RawMessage, interfaces and other json.Marshalers accept any
//     value, and encoding.TextMarshalers are strings;
//   - maps become objects with additionalProperties, slices and arrays
//     arrays with items; the `,string` option turns numbers and booleans
//     into strings.
//
// Objects do not set additionalProperties: false, so adding a field is a
// compatible change (see the package documentation). Recursive types are
// cut at the second occurrence with an unconstrained schema.
func Generate(t reflect.Type) Schema {
	s := (&generator{seen: map[reflect.Type]bool{}}).schema(t)
	s["$schema"] = Draft
	return s
}

type generator struct{ seen map[reflect.Type]bool }

func (g *generator) schema(t reflect.Type) Schema {
	switch {
	case t == timeType:
		return Schema{"type": "string", "format": "date-time"}
	case t == rawType:
		return Schema{}
	case t.Kind() != reflect.Pointer && (t.Implements(marshalerType) || reflect.PointerTo(t).Implements(marshalerType)):
		return Schema{}
	case t.Kind() != reflect.Pointer && (t.Implements(textType) || reflect.PointerTo(t).Implements(textType)):
		return Schema{"type": "string"}
	}
	switch t.Kind() {
	case reflect.Bool:
		return Schema{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return Schema{"type": "integer"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return Schema{"type": "integer", "minimum": 0}
	case reflect.Float32, reflect.Float64:
		return Schema{"type": "number"}
	case reflect.String:
		return Schema{"type": "string"}
	case reflect.Pointer:
		return nullable(g.schema(t.Elem()))
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 && t.Kind() == reflect.Slice {
			return Schema{"type": "string", "contentEncoding": "base64"}
		}
		s := Schema{"type": "array", "items": g.schema(t.Elem())}
		if t.Kind() == reflect.Array {
			s["minItems"], s["maxItems"] = t.Len(), t.Len()
		}
		return s
	case reflect.Map:
		return Schema{"type": "object", "additionalProperties": g.schema(t.Elem())}
	case reflect.Struct:
		if g.seen[t] {
			return Schema{}
		}
		g.seen[t] = true
		defer delete(g.seen, t)
		return g.object(t)
	default: // interfaces, and kinds encoding/json cannot encode
		return Schema{}
	}
}

// field is a JSON property found while walking a struct.
type field struct {
	name     string
	depth    int
	required bool
	schema   Schema
}

func (g *generator) object(t reflect.Type) Schema {
	var fields []field
	g.collect(t, 0, true, &fields)
	props, byName := Schema{}, map[string]field{}
	for _, f := range fields {
		if prev, ok := byName[f.name]; ok && prev.depth <= f.depth {
			continue
		}
		byName[f.name] = f
		props[f.name] = f.schema
	}
	required := []string{}
	for _, f := range fields {
		if byName[f.name].depth == f.depth && f.required && !slices.Contains(required, f.name) {
			required = append(required, f.name)
		}
	}
	s := Schema{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func (g *generator) collect(t reflect.Type, depth int, canRequire bool, out *[]field) {
	for i := range t.NumField() {
		sf := t.Field(i)
		tag := sf.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		ft := sf.Type
		if sf.Anonymous && name == "" {
			et, viaPtr := ft, false
			if et.Kind() == reflect.Pointer {
				et, viaPtr = et.Elem(), true
			}
			if et.Kind() == reflect.Struct && et != timeType {
				g.collect(et, depth+1, canRequire && !viaPtr, out)
				continue
			}
		}
		if !sf.IsExported() {
			continue
		}
		if name == "" {
			name = sf.Name
		}
		omit := hasOpt(opts, "omitempty") || hasOpt(opts, "omitzero")
		s := g.schema(ft)
		if hasOpt(opts, "string") {
			s = stringOpt(ft, s)
		}
		if k := ft.Kind(); !omit && (k == reflect.Slice || k == reflect.Map) {
			s = nullable(s) // nil slices and maps encode as null
		}
		*out = append(*out, field{name: name, depth: depth, required: canRequire && !omit, schema: s})
	}
}

// stringOpt applies the `,string` tag option, which encodes scalars as
// JSON strings.
func stringOpt(t reflect.Type, s Schema) Schema {
	base := t
	if base.Kind() == reflect.Pointer {
		base = base.Elem()
	}
	switch base.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		if t.Kind() == reflect.Pointer {
			return Schema{"type": []any{"string", "null"}}
		}
		return Schema{"type": "string"}
	}
	return s
}

// nullable makes s also accept null.
func nullable(s Schema) Schema {
	switch typ := s["type"].(type) {
	case nil:
		if len(s) == 0 {
			return s // already accepts anything
		}
	case string:
		s["type"] = []any{typ, "null"}
		return s
	case []any:
		if !slices.Contains(typ, any("null")) {
			s["type"] = append(typ, "null")
		}
		return s
	}
	return Schema{"anyOf": []any{s, Schema{"type": "null"}}}
}

func hasOpt(opts, name string) bool {
	for o := range strings.SplitSeq(opts, ",") {
		if o == name {
			return true
		}
	}
	return false
}
