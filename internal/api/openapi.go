package api

import _ "embed"

// OpenAPISpec is the OpenAPI 3.1 description of the v1 API.
//
//go:embed openapi.yaml
var OpenAPISpec []byte
