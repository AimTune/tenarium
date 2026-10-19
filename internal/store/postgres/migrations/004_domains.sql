CREATE TABLE domains (
    hostname    text PRIMARY KEY,
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    verified    boolean     NOT NULL DEFAULT false,
    token       text        NOT NULL,
    created_at  timestamptz NOT NULL,
    verified_at timestamptz NULL
);
CREATE INDEX domains_tenant ON domains (tenant_id);
