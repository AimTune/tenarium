// Package eventschema is the event schema registry: a JSON Schema (draft
// 2020-12) for the data of every event type Tenarium emits, per version,
// and one for the CloudEvents envelope around it.
//
// # Usage
//
//	for _, e := range eventschema.All() { ... }           // list
//	e, ok := eventschema.Get("tenant.created")            // latest version
//	e, ok = eventschema.GetVersion("tenant.created", "1") // a given version
//	env := eventschema.EnvelopeSchema()                   // CloudEvent envelope
//
// Entry.Schema is a ready-to-serve JSON document. An HTTP layer would
// publish it at DataSchemaURI(base, type, version), i.e.
// {base}/v1/event-schemas/{type}/{version}, and the core can set that URI
// as the CloudEvents "dataschema" attribute of each event it emits.
//
// Schemas are generated from the Go types the events' data is marshaled
// from (see Generate), so they cannot drift from the code. Payloads the
// code builds as anonymous maps (user.erased, tenant.purged, user.impersonat*,
// user.passkey_*, signing_key.retired, webhook.test) are described by small
// mirror structs in registry.go, which must be kept in step with the code.
//
// This package imports only pkg/sdk, internal/store and internal/identity,
// so internal/tenant, internal/webhooks and internal/api may import it.
//
// # Adding an event type
//
// Add a row to the table in registry.go. TestRegistryCoversEmittedEvents
// scans the module's source for Event* constants and for type literals
// passed to appendEvent, RecordEvent and similar helpers, and fails for
// any type without a row. It also fails for rows whose type is no longer
// emitted, unless the type is listed as retired in that test.
//
// # Versioning policy
//
// Every type starts at version "1". Versions are positive integers and
// only grow.
//
//   - Additive changes keep the version: a new optional or always-present
//     field, a new value of an open-ended string, a relaxed constraint. The
//     schema is updated in place. Schemas therefore never set
//     additionalProperties: false, and consumers must ignore fields they
//     do not know.
//   - Breaking changes get a new version: removing or renaming a field,
//     changing its type or meaning, making an optional field required, or
//     emitting null where a value was guaranteed. Keep the old row, add a
//     row with the next version (and a separate payload type), and emit
//     the new dataschema URI. Old versions stay published so consumers can
//     still validate events they stored earlier.
//
// Removing an event type is a breaking change too: announce it, and keep
// its schemas published.
package eventschema
