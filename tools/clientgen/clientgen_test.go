package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repoRoot = "../.."

// TestGeneratedClientsAreFresh regenerates the clients into a temporary
// directory and compares them with the committed files, so a spec change
// without a regeneration fails CI (like the OpenAPI route coverage test).
func TestGeneratedClientsAreFresh(t *testing.T) {
	dir := t.TempDir()
	if err := run(filepath.Join(repoRoot, specPath), dir); err != nil {
		t.Fatal(err)
	}
	for _, rel := range outputs() {
		want, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("%s is missing; run `go run ./tools/clientgen` from the repository root", rel)
			continue
		}
		got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n")) // tolerate autocrlf checkouts
		if !bytes.Equal(got, want) {
			line, g, w := firstDiff(string(got), string(want))
			t.Errorf("%s is stale; run `go run ./tools/clientgen` from the repository root\nfirst difference at line %d:\n  committed: %q\n  generated: %q", rel, line, g, w)
		}
	}
}

func firstDiff(a, b string) (int, string, string) {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y || i >= len(al) || i >= len(bl) {
			return i + 1, x, y
		}
	}
	return 0, "", ""
}

func TestGenerateIsDeterministic(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join(repoRoot, specPath))
	if err != nil {
		t.Fatal(err)
	}
	first, err := generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := generate(spec)
		if err != nil {
			t.Fatal(err)
		}
		for path, b := range first {
			if !bytes.Equal(b, again[path]) {
				t.Fatalf("%s differs between runs", path)
			}
		}
	}
}

func TestNames(t *testing.T) {
	for in, want := range map[string]string{
		"listTenantAPIKeys": "list_tenant_api_keys",
		"getSSO":            "get_sso",
		"beginTOTP":         "begin_totp",
		"startIndex":        "start_index",
		"samlACS":           "saml_acs",
		"parent_id":         "parent_id",
		"If-Match":          "if_match",
		"me":                "me",
	} {
		if got := snake(in); got != want {
			t.Errorf("snake(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"listTenants":    "ListTenants",
		"recovery_codes": "RecoveryCodes",
		"If-Match":       "IfMatch",
	} {
		if got := pascal(in); got != want {
			t.Errorf("pascal(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSchemaMapping covers schema features the Tenarium spec does not use
// (yet): oneOf, nullable in both 3.0 and 3.1 style, records with
// additionalProperties, nested inline objects and form bodies.
func TestSchemaMapping(t *testing.T) {
	spec := `
openapi: 3.1.0
paths:
  /v1/things/{id}:
    parameters: [{name: id, in: path, required: true, schema: {type: string}}]
    put:
      operationId: putThing
      parameters:
        - {name: If-Match, in: header, schema: {type: string}}
        - {name: dry_run, in: query, required: true, schema: {type: boolean}}
        - {name: from, in: query, schema: {type: integer, format: int64}}
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: "#/components/schemas/Thing"}
      responses:
        "200":
          content:
            application/json:
              schema:
                type: object
                properties:
                  thing: {$ref: "#/components/schemas/Thing"}
                  tags:
                    type: array
                    items:
                      type: object
                      required: [k]
                      properties: {k: {type: string}}
  /v1/hooks:
    post:
      operationId: postHook
      security: []
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema: {type: object, properties: {a: {type: string}}}
      responses:
        "201": {content: {application/json: {schema: {$ref: "#/components/schemas/Shape"}}}}
components:
  schemas:
    Shape:
      oneOf:
        - {$ref: "#/components/schemas/Thing"}
        - {type: string, enum: [none]}
    Thing:
      type: object
      required: [name]
      properties:
        name: {type: string}
        note: {type: [string, "null"]}
        old: {type: integer, nullable: true}
        meta: {type: object, additionalProperties: {type: integer}}
        nested:
          type: object
          properties: {deep: {type: boolean}}
`
	files, err := generate([]byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	ts := string(files[tsTypesPath]) + string(files[tsOpsPath])
	py := string(files[pyGenPath])
	for _, want := range []string{
		`export type Shape = Thing | "none";`,
		"  name: string;",
		"  note?: string | null;",
		"  old?: number | null;",
		"  meta?: Record<string, number>;",
		"  nested?: ThingNested;",
		"export interface ThingNested {",
		"  tags?: PutThingResponseTag[];",
		"export interface PutThingResponseTag {\n  k: string;",
		"export interface PutThingQuery {\n  dry_run: boolean;\n  from?: number | string;",
		"putThing(id: string, body: Thing, query: PutThingQuery, options: RequestOptions = {}): Promise<PutThingResponse>",
		`contentType: "application/x-www-form-urlencoded", public: true, options })`,
	} {
		if !strings.Contains(ts, want) {
			t.Errorf("TypeScript output lacks %q", want)
		}
	}
	for _, want := range []string{
		`Shape = Union["Thing", Literal["none"]]`,
		"class _ThingRequired(TypedDict):\n    name: str",
		"class Thing(_ThingRequired, total=False):",
		"    note: Optional[str]",
		"    meta: Dict[str, int]",
		"    nested: ThingNested",
		"        dry_run: bool,",
		"        from_: Optional[Union[int, str]] = None,",
		"        if_match: Union[str, int, None] = None,",
		`"from": from_,`,
		"def post_hook(",
		"            public=True,\n            idempotency_key=idempotency_key,",
	} {
		if !strings.Contains(py, want) {
			t.Errorf("Python output lacks %q", want)
		}
	}
	if t.Failed() {
		t.Logf("TypeScript:\n%s\nPython:\n%s", ts, py)
	}
}

func TestRejectsCollisions(t *testing.T) {
	spec := `
paths:
  /a:
    get:
      operationId: getA
      responses:
        "200": {content: {application/json: {schema: {type: object, properties: {x: {type: string}}}}}}
components:
  schemas:
    GetAResponse: {type: string}
`
	if _, err := generate([]byte(spec)); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("want a collision error, got %v", err)
	}
}
