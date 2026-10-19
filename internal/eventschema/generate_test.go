package eventschema

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

type Inner struct {
	A string `json:"a"`
	B int    `json:"b,omitempty"`
}

type shadow struct {
	X    string `json:"x"`
	Deep string `json:"deep"`
}

type embedded struct {
	shadow
	E string `json:"e"`
	X int    `json:"x"` // shadows shadow.X
}

type PtrEmbedded struct {
	P string `json:"p"`
}

type custom struct{}

func (custom) MarshalJSON() ([]byte, error) { return []byte(`1`), nil }

type node struct {
	Name     string  `json:"name"`
	Children []*node `json:"children,omitempty"`
}

type kitchenSink struct {
	embedded
	*PtrEmbedded
	Str      string            `json:"str"`
	Opt      string            `json:"opt,omitempty"`
	Zero     int               `json:"zero,omitzero"`
	Bool     bool              `json:"bool"`
	Uint     uint16            `json:"uint"`
	Float    float64           `json:"float"`
	Time     time.Time         `json:"time"`
	TimePtr  *time.Time        `json:"time_ptr,omitempty"`
	Raw      json.RawMessage   `json:"raw"`
	Bytes    []byte            `json:"bytes,omitempty"`
	Any      any               `json:"any"`
	Custom   custom            `json:"custom"`
	Addr     netip.Addr        `json:"addr"`
	Ptr      *Inner            `json:"ptr"`
	Slice    []Inner           `json:"slice"`
	OptSlice []string          `json:"opt_slice,omitempty"`
	Map      map[string]int64  `json:"map,omitempty"`
	NilMap   map[string]string `json:"nil_map"`
	Array    [2]bool           `json:"array"`
	Quoted   int64             `json:"quoted,string"`
	Named    Inner             `json:"named"`
	Tagged   Inner             `json:"tagged_inner"`
	NoTag    string
	Skipped  string `json:"-"`
	Dash     string `json:"-,"`
	hidden   string
	Tree     node `json:"tree"`
}

func TestGenerate(t *testing.T) {
	_ = kitchenSink{}.hidden
	got, err := json.Marshal(Generate(reflect.TypeFor[kitchenSink]()))
	if err != nil {
		t.Fatal(err)
	}
	inner := `{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"integer"}},"required":["a"]}`
	nodeS := `{"type":"object","properties":{"children":{"type":"array","items":{}},"name":{"type":"string"}},"required":["name"]}`
	want := `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"properties": {
			"x": {"type": "integer"},
			"deep": {"type": "string"},
			"e": {"type": "string"},
			"p": {"type": "string"},
			"str": {"type": "string"},
			"opt": {"type": "string"},
			"zero": {"type": "integer"},
			"bool": {"type": "boolean"},
			"uint": {"type": "integer", "minimum": 0},
			"float": {"type": "number"},
			"time": {"type": "string", "format": "date-time"},
			"time_ptr": {"type": ["string", "null"], "format": "date-time"},
			"raw": {},
			"bytes": {"type": "string", "contentEncoding": "base64"},
			"any": {},
			"custom": {},
			"addr": {"type": "string"},
			"ptr": {"type": ["object", "null"], "properties": {"a":{"type":"string"},"b":{"type":"integer"}}, "required": ["a"]},
			"slice": {"type": ["array", "null"], "items": ` + inner + `},
			"opt_slice": {"type": "array", "items": {"type": "string"}},
			"map": {"type": "object", "additionalProperties": {"type": "integer"}},
			"nil_map": {"type": ["object", "null"], "additionalProperties": {"type": "string"}},
			"array": {"type": "array", "items": {"type": "boolean"}, "minItems": 2, "maxItems": 2},
			"quoted": {"type": "string"},
			"named": ` + inner + `,
			"tagged_inner": ` + inner + `,
			"NoTag": {"type": "string"},
			"-": {"type": "string"},
			"tree": ` + nodeS + `
		},
		"required": ["deep", "e", "x", "str", "bool", "uint", "float", "time", "raw", "any", "custom", "addr",
			"ptr", "slice", "nil_map", "array", "quoted", "named", "tagged_inner", "NoTag", "-", "tree"]
	}`
	assertJSONEqual(t, got, want)
}

func TestGenerateRequiredOrderIsDeterministic(t *testing.T) {
	a, _ := json.Marshal(Generate(reflect.TypeFor[kitchenSink]()))
	b, _ := json.Marshal(Generate(reflect.TypeFor[kitchenSink]()))
	if string(a) != string(b) {
		t.Fatal("output differs between runs")
	}
}

func TestGenerateTopLevelKinds(t *testing.T) {
	for _, tc := range []struct {
		typ  reflect.Type
		want string
	}{
		{reflect.TypeFor[string](), `{"type":"string"}`},
		{reflect.TypeFor[*int](), `{"type":["integer","null"]}`},
		{reflect.TypeFor[[]string](), `{"type":"array","items":{"type":"string"}}`},
		{reflect.TypeFor[map[string]any](), `{"type":"object","additionalProperties":{}}`},
		{reflect.TypeFor[*json.RawMessage](), `{}`},
		{reflect.TypeFor[*custom](), `{}`},
		{reflect.TypeFor[chan int](), `{}`},
	} {
		s := Generate(tc.typ)
		if s["$schema"] != Draft {
			t.Errorf("%s: $schema = %v", tc.typ, s["$schema"])
		}
		delete(s, "$schema")
		got, _ := json.Marshal(s)
		assertJSONEqual(t, got, tc.want)
	}
}

func TestNullable(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`{"type":"string"}`, `{"type":["string","null"]}`},
		{`{"type":["string","null"]}`, `{"type":["string","null"]}`},
		{`{"type":["string","integer"]}`, `{"type":["string","integer","null"]}`},
		{`{}`, `{}`},
		{`{"const":"a"}`, `{"anyOf":[{"const":"a"},{"type":"null"}]}`},
	} {
		var s Schema
		if err := json.Unmarshal([]byte(tc.in), &s); err != nil {
			t.Fatal(err)
		}
		got, _ := json.Marshal(nullable(s))
		assertJSONEqual(t, got, tc.want)
	}
}

// TestGenerateMatchesEncoding validates encoding/json output of filled and
// zero values against the generated schema.
func TestGenerateMatchesEncoding(t *testing.T) {
	typ := reflect.TypeFor[kitchenSink]()
	raw, _ := json.Marshal(Generate(typ))
	sch := compile(t, "kitchen.json", raw)
	for name, v := range map[string]any{"zero": reflect.Zero(typ).Interface(), "filled": sample(typ).Interface()} {
		validate(t, sch, name, v)
	}
}

func assertJSONEqual(t *testing.T, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("got: %v", err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("want: %v", err)
	}
	// Compare "required" as sets: its order follows field order.
	normalize(g)
	normalize(w)
	if !reflect.DeepEqual(g, w) {
		gi, _ := json.MarshalIndent(g, "", "  ")
		wi, _ := json.MarshalIndent(w, "", "  ")
		t.Errorf("schema mismatch\ngot:  %s\nwant: %s", gi, wi)
	}
}

func normalize(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if r, ok := e.([]any); ok && k == "required" {
				m := map[string]any{}
				for _, n := range r {
					m[n.(string)] = true
				}
				x[k] = m
				continue
			}
			normalize(e)
		}
	case []any:
		for _, e := range x {
			normalize(e)
		}
	}
}
