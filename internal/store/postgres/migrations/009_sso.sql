CREATE TABLE sso_connections (
    tenant_id      uuid PRIMARY KEY REFERENCES tenants (id),
    issuer         text        NOT NULL,
    client_id      text        NOT NULL,
    client_secret  text        NOT NULL,
    enforce        boolean     NOT NULL DEFAULT false,
    auto_provision boolean     NOT NULL DEFAULT false,
    default_role   text        NOT NULL DEFAULT '',
    enabled        boolean     NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL
);

-- An email domain belongs to at most one connection.
CREATE TABLE sso_domains (
    domain    text PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES sso_connections (tenant_id) ON DELETE CASCADE
);
CREATE INDEX sso_domains_tenant ON sso_domains (tenant_id);
