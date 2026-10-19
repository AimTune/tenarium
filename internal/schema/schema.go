// Package schema validates JSON-like values against JSON Schema (2020-12).
package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// Schema is a compiled JSON Schema.
type Schema struct {
	s *jsonschema.Schema
}

// Compile compiles a schema document.
func Compile(raw []byte) (*Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("schema is not valid JSON: %w", err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource("mem://schema.json", doc); err != nil {
		return nil, err
	}
	s, err := c.Compile("mem://schema.json")
	if err != nil {
		return nil, err
	}
	return &Schema{s: s}, nil
}

// Validate checks v (any JSON-marshalable value). The error lists every
// violation as "/json/pointer: message".
func (s *Schema) Validate(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	err = s.s.Validate(inst)
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return err
	}
	var msgs []string
	collect(ve, &msgs)
	return errors.New(strings.Join(msgs, "; "))
}

var printer = message.NewPrinter(language.English)

func collect(e *jsonschema.ValidationError, out *[]string) {
	if len(e.Causes) == 0 {
		*out = append(*out, "/"+strings.Join(e.InstanceLocation, "/")+": "+e.ErrorKind.LocalizedString(printer))
		return
	}
	for _, c := range e.Causes {
		collect(c, out)
	}
}
