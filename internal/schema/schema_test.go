package schema

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	s, err := Compile([]byte(`{
		"type": "object",
		"properties": {
			"theme": {"type": "object", "properties": {"color": {"enum": ["blue", "red"]}}},
			"seats": {"type": "integer", "minimum": 1}
		},
		"additionalProperties": false
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(map[string]any{"theme": map[string]any{"color": "blue"}, "seats": 3}); err != nil {
		t.Fatalf("valid doc rejected: %v", err)
	}
	err = s.Validate(map[string]any{"theme": map[string]any{"color": "green"}, "seats": 0, "x": 1})
	if err == nil {
		t.Fatal("invalid doc accepted")
	}
	for _, want := range []string{"/theme/color", "/seats", "x"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
	if _, err := Compile([]byte(`{"type": 5}`)); err == nil {
		t.Fatal("invalid schema compiled")
	}
}
