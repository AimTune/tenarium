package eventschema

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// retired lists event types the code no longer emits whose schemas stay
// published for consumers of old events.
var retired = map[string]bool{}

var (
	eventTypeRe = regexp.MustCompile(`^[a-z_]+\.[a-z_]+$`)
	// emitterRe matches functions that take an event type: appendEvent,
	// RecordEvent, appendTenantEvent, appendUserEvent, mfaEvent,
	// passkeyEvent, webhooks' record, ...
	emitterRe = regexp.MustCompile(`(?i)(event|events)$|^(record|emit)$`)
)

// TestRegistryCoversEmittedEvents fails when the code emits an event type
// without a registry entry, or the registry has an entry for a type the
// code no longer emits.
func TestRegistryCoversEmittedEvents(t *testing.T) {
	emitted := scanEventTypes(t, moduleRoot(t))
	if len(emitted) < 40 || emitted["tenant.created"] == "" || emitted["user.erased"] == "" {
		t.Fatalf("scan found only %d event types; is the scanner broken?", len(emitted))
	}
	for _, typ := range slices.Sorted(maps.Keys(emitted)) {
		if _, ok := Get(typ); !ok {
			t.Errorf("event type %q (%s) has no schema: add it to the table in registry.go", typ, emitted[typ])
		}
	}
	for _, typ := range Types() {
		if emitted[typ] == "" && !retired[typ] {
			t.Errorf("registry has %q but the code no longer emits it: remove the row, or list the type as retired in coverage_test.go", typ)
		}
	}
}

func TestScannerFindsAllForms(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/m\n")
	write("a/a.go", `package a
const (
	EventThingCreated = "thing.created"
	EventSource = "tenarium"
	OtherConst = "not.an_event"
)
func f(s *S) {
	s.appendEvent(nil, nil, "thing.literal", "", "", nil)
	s.RecordEvent(nil, "other.recorded", "", "", nil)
	record(nil, "web.hook")
	log("ignored.call")
	_ = Event{Type: "composite.type"}
	_ = sdk.Event{Type: "composite.selector"}
	_ = Event{Type: "Not.Matching"}
}
`)
	write("a/a_test.go", `package a
const EventTestOnly = "test.only"`)
	write("a/storetest/s.go", `package storetest
const EventHelper = "helper.only"`)
	write("sub/go.mod", "module example.com/sub\n")
	write("sub/s.go", `package sub
const EventSub = "sub.module"`)

	got := slices.Sorted(maps.Keys(scanEventTypes(t, dir)))
	want := []string{"composite.selector", "composite.type", "other.recorded", "thing.created", "thing.literal", "web.hook"}
	if !slices.Equal(got, want) {
		t.Errorf("scan = %v, want %v", got, want)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// scanEventTypes parses the non-test Go files of the module rooted at root
// and returns the event types found, each with one position it appears at.
// It finds Event* string constants, string literals passed to emitter
// functions, and Type fields of Event composite literals. Nested modules,
// test helpers (directories ending in "test" or "tests"), testdata and this
// package are skipped.
func scanEventTypes(t *testing.T, root string) map[string]string {
	t.Helper()
	self, _ := os.Getwd()
	found := map[string]string{}
	fset := token.NewFileSet()
	add := func(lit ast.Expr) {
		bl, ok := lit.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return
		}
		s, err := strconv.Unquote(bl.Value)
		if err != nil || !eventTypeRe.MatchString(s) {
			return
		}
		if _, dup := found[s]; !dup {
			p := fset.Position(bl.Pos())
			rel, _ := filepath.Rel(root, p.Filename)
			found[s] = filepath.ToSlash(rel) + ":" + strconv.Itoa(p.Line)
		}
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path == root {
				return nil
			}
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" || name == "node_modules" ||
				strings.HasSuffix(name, "test") || name == "tests" || sameDir(path, self) {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir // another module
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.GenDecl:
				if n.Tok != token.CONST {
					return true
				}
				for _, spec := range n.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, id := range vs.Names {
						if strings.HasPrefix(id.Name, "Event") && i < len(vs.Values) {
							add(vs.Values[i])
						}
					}
				}
			case *ast.CallExpr:
				if emitterRe.MatchString(exprName(n.Fun)) {
					for _, a := range n.Args {
						add(a)
					}
				}
			case *ast.CompositeLit:
				if n.Type != nil && exprName(n.Type) == "Event" {
					for _, el := range n.Elts {
						if kv, ok := el.(*ast.KeyValueExpr); ok && exprName(kv.Key) == "Type" {
							add(kv.Value)
						}
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func exprName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

func sameDir(a, b string) bool {
	if b == "" {
		return false
	}
	ra, err1 := filepath.Abs(a)
	rb, err2 := filepath.Abs(b)
	return err1 == nil && err2 == nil && strings.EqualFold(ra, rb)
}
