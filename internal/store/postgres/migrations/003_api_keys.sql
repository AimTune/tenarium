CREATE TABLE api_keys (
    id           uuid PRIMARY KEY,
    tenant_id    text        NOT NULL DEFAULT '',
    name         text        NOT NULL,
    prefix       text        NOT NULL,
    hash         text        NOT NULL UNIQUE,
    roles        jsonb       NOT NULL DEFAULT '[]',
    created_by   text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NULL,
    last_used_at timestamptz NULL,
    revoked_at   timestamptz NULL
);
CREATE INDEX api_keys_tenant ON api_keys (tenant_id);
