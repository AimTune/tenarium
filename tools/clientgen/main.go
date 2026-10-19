// Command clientgen generates the TypeScript and Python API clients from the
// OpenAPI spec in internal/api/openapi.yaml.
//
// Run it from the repository root after changing the spec:
//
//	go run ./tools/clientgen
//
// It writes
//
//	sdks/typescript-client/src/generated/types.ts
//	sdks/typescript-client/src/generated/operations.ts
//	sdks/python-client/tenarium_client/_generated.py
//
// The output is deterministic, and TestGeneratedClientsAreFresh fails when
// the committed files are stale. The hand-written runtimes around the
// generated code live next to it in each SDK.
package main

//go:generate go run . -root ../..

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Output paths, relative to the repository root.
const (
	specPath     = "internal/api/openapi.yaml"
	tsTypesPath  = "sdks/typescript-client/src/generated/types.ts"
	tsOpsPath    = "sdks/typescript-client/src/generated/operations.ts"
	pyGenPath    = "sdks/python-client/tenarium_client/_generated.py"
	defaultRoot  = "."
	outFilesMode = 0o644
)

func main() {
	root := flag.String("root", defaultRoot, "repository root")
	spec := flag.String("spec", "", "OpenAPI spec (default <root>/"+specPath+")")
	out := flag.String("out", "", "output root (default <root>)")
	flag.Parse()
	if *spec == "" {
		*spec = filepath.Join(*root, specPath)
	}
	if *out == "" {
		*out = *root
	}
	if err := run(*spec, *out); err != nil {
		fmt.Fprintln(os.Stderr, "clientgen:", err)
		os.Exit(1)
	}
}

func run(specFile, outRoot string) error {
	data, err := os.ReadFile(specFile)
	if err != nil {
		return err
	}
	files, err := generate(data)
	if err != nil {
		return err
	}
	for _, rel := range sortedKeys(files) {
		dst := filepath.Join(outRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, files[rel], outFilesMode); err != nil {
			return err
		}
	}
	return nil
}

// generate returns the generated files, keyed by slash-separated paths
// relative to the repository root.
func generate(spec []byte) (map[string][]byte, error) {
	d, err := parseSpec(spec)
	if err != nil {
		return nil, err
	}
	m, err := buildModel(d)
	if err != nil {
		return nil, err
	}
	types, ops, err := genTypeScript(m)
	if err != nil {
		return nil, err
	}
	py, err := genPython(m)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{tsTypesPath: types, tsOpsPath: ops, pyGenPath: py}, nil
}

// outputs lists the generated paths in a stable order.
func outputs() []string {
	l := []string{tsTypesPath, tsOpsPath, pyGenPath}
	sort.Strings(l)
	return l
}
