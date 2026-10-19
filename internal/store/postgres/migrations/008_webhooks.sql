CREATE TABLE webhooks (
    id          uuid PRIMARY KEY,
    tenant_id   uuid        NOT NULL REFERENCES tenants (id),
    url         text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    secret      text        NOT NULL,
    types       text[]      NOT NULL DEFAULT '{}',
    enabled     boolean     NOT NULL,
    failures    integer     NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL
);
CREATE INDEX webhooks_tenant ON webhooks (tenant_id);

CREATE TABLE webhook_deliveries (
    id          uuid PRIMARY KEY,
    webhook_id  uuid        NOT NULL REFERENCES webhooks (id) ON DELETE CASCADE,
    tenant_id   uuid        NOT NULL,
    event_id    text        NOT NULL,
    event_type  text        NOT NULL,
    payload     jsonb       NULL,
    attempts    integer     NOT NULL,
    status_code integer     NOT NULL DEFAULT 0,
    error       text        NOT NULL DEFAULT '',
    success     boolean     NOT NULL,
    duration_ms bigint      NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL
);
CREATE INDEX webhook_deliveries_webhook ON webhook_deliveries (webhook_id, id DESC);
CREATE INDEX webhook_deliveries_created ON webhook_deliveries (created_at);
