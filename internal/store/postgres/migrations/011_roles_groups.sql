CREATE TABLE tenant_roles (
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    actions     text[]      NOT NULL,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, name)
);

CREATE TABLE tenant_groups (
    id          uuid PRIMARY KEY,
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    roles       text[]      NOT NULL DEFAULT '{}',
    members     text[]      NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL
);
CREATE UNIQUE INDEX tenant_groups_name ON tenant_groups (tenant_id, name);
