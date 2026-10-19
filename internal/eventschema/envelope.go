package eventschema

import (
	"encoding/json"
	"slices"
)

// envelope describes sdk.CloudEvent: the CloudEvents 1.0 structured-mode
// JSON form Tenarium delivers (webhooks, sinks, the event stream).
const envelope = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Tenarium CloudEvent",
  "description": "CloudEvents 1.0 structured-mode JSON envelope of every Tenarium event. data is described by the schema of the event's type and version.",
  "type": "object",
  "required": ["specversion", "id", "source", "type", "time", "sequence"],
  "properties": {
    "specversion": {"const": "1.0", "description": "CloudEvents specification version."},
    "id": {"type": "string", "minLength": 1, "description": "Unique event ID; consumers deduplicate on it."},
    "source": {"type": "string", "minLength": 1, "format": "uri-reference", "description": "Event producer, \"tenarium\" for the core."},
    "type": {"type": "string", "pattern": "^[a-z_]+\\.[a-z_]+$", "description": "Event type, e.g. \"tenant.created\"."},
    "subject": {"type": "string", "description": "Resource the event is about, e.g. \"tenants/{id}\"."},
    "time": {"type": "string", "format": "date-time", "description": "When the event happened (RFC 3339, UTC)."},
    "datacontenttype": {"const": "application/json", "description": "Present when data is."},
    "dataschema": {"type": "string", "format": "uri", "description": "URI of the schema of data (see DataSchemaURI)."},
    "tenantid": {"type": "string", "description": "Extension: tenant the event belongs to; absent for platform-wide events."},
    "actor": {"type": "string", "description": "Extension: who caused the event, \"{authenticator}:{subject}\" or \"system\"."},
    "sequence": {"type": "string", "pattern": "^[0-9]+$", "description": "Extension: position in the global event log, as a decimal string."},
    "traceparent": {"type": "string", "pattern": "^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$", "description": "Extension (CloudEvents distributed tracing): W3C trace context of the request that caused the event."},
    "tracestate": {"type": "string", "description": "Extension: W3C trace state accompanying traceparent."},
    "data": {"description": "Event payload; see the schema of the event's type."}
  }
}`

// EnvelopeSchema returns the JSON Schema of the CloudEvents envelope.
func EnvelopeSchema() json.RawMessage { return slices.Clone(json.RawMessage(envelope)) }
