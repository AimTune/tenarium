-- URI of the JSON Schema each event's data follows (CloudEvents dataschema).
ALTER TABLE events ADD COLUMN dataschema text NOT NULL DEFAULT '';
