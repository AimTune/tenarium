package api

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestOpenAPICoversRoutes keeps the spec in sync with the router: every
// route registered in Handler must be documented, and vice versa.
func TestOpenAPICoversRoutes(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(OpenAPISpec, &spec); err != nil {
		t.Fatalf("spec is not valid YAML: %v", err)
	}
	documented := map[string]bool{}
	for path, ops := range spec.Paths {
		for method := range ops {
			if method != "parameters" {
				documented[strings.ToUpper(method)+" "+path] = true
			}
		}
	}

	var src []byte
	// ../social mounts its routes through Handler.Routes.
	for _, f := range []string{"api.go", "users.go", "scim.go", "../social/social.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src = append(src, b...)
	}
	re := regexp.MustCompile(`(?:h\(|routed\(|\{)"([A-Z]+) (/v1/[^"]*)"`)
	registered := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		key := m[1] + " " + m[2]
		registered[key] = true
		if !documented[key] {
			t.Errorf("route %s is not documented in openapi.yaml", key)
		}
	}
	if len(registered) < 20 {
		t.Fatalf("found only %d routes; did the registration style change?", len(registered))
	}
	for key := range documented {
		if strings.Contains(key, "/v1/") && !registered[key] {
			t.Errorf("openapi.yaml documents %s, which is not registered", key)
		}
	}
}
