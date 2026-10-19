# Event schema registry

Every event type Tenarium emits has a published JSON Schema (draft 2020-12) for its `data`,
per version, plus one schema for the CloudEvents envelope around it. Use them to validate
events in consumers, generate types, or document integrations.

```sh
curl -s $API/v1/event-schemas -H "$AUTH"                         # every type and version, plus "envelope"
curl -s $API/v1/event-schemas/tenant.created -H "$AUTH"          # latest version
curl -s $API/v1/event-schemas/tenant.created/1 -H "$AUTH"        # a given version
```

```json
{"type": "tenant.created", "version": "1", "description": "A tenant was created.",
 "schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", ...}}
```

Any authenticated caller may read the registry; single schemas are sent with
`Cache-Control: public, max-age=3600`. Unknown types or versions answer 404.

## What is covered

All event types of the core: tenant lifecycle (`tenant.*`, including `tenant.region_changed`,
`tenant.purged` and the maintenance events), usage, scheduled actions, memberships, plans and
rollouts, users (including passkeys, sessions,
impersonation and erasure), domains, API keys, SSO, roles and groups, webhooks (including
`webhook.test`, which is only sent to the webhook and never stored), OAuth clients and signing
keys. Events emitted by plugins are not in the registry.

Schemas are generated from the Go types the payloads are marshaled from, so they follow the
code. A test fails when the code emits a type that has no schema, or when a schema's type is no
longer emitted. Secrets never appear in event data: API key hashes, webhook secrets, SSO client
secrets, SAML metadata and OAuth client secret hashes are left out of the payloads and the
schemas.

## Versioning

Every type starts at version `1`. Versions are positive integers and only grow.

- **Additive changes keep the version**: a new field, a new value of an open-ended string, a
  relaxed constraint. The schema is updated in place. Schemas therefore never set
  `additionalProperties: false`, and consumers must ignore fields they do not know.
- **Breaking changes get a new version**: removing or renaming a field, changing its type or
  meaning, making an optional field required, or emitting `null` where a value was guaranteed.
  The old version stays published, so events stored earlier can still be validated.
- Removing an event type is a breaking change too: it is announced, and its schemas stay
  published.

The schema of a type's version lives at `<users.public_url>/v1/event-schemas/<type>/<version>`
(the `/v1/` is the API version, not the schema version). Every event carries it in the CloudEvents
`dataschema` attribute (and `dataschema` in the event log), so consumers can pick the schema
version the payload follows; today every type is at version `1`.

## For contributors

Adding an event type to the core means adding a row to the table in
`internal/eventschema/registry.go`; `TestRegistryCoversEmittedEvents` finds emitted types without
a row. Payloads built as anonymous maps are described by small mirror structs in the same file,
which must be kept in step with the code. See the package documentation in
[`internal/eventschema/doc.go`](https://github.com/AimTune/tenarium/blob/main/internal/eventschema/doc.go).
