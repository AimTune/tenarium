CREATE TABLE tenants (
    id            uuid PRIMARY KEY,
    slug          text        NOT NULL,
    name          text        NOT NULL,
    parent_id     uuid        NULL REFERENCES tenants (id),
    status        text        NOT NULL,
    status_reason text        NOT NULL DEFAULT '',
    plan          text        NOT NULL DEFAULT '',
    labels        jsonb       NOT NULL DEFAULT '{}',
    settings      jsonb       NOT NULL DEFAULT '{}',
    features      jsonb       NOT NULL DEFAULT '{}',
    limits        jsonb       NOT NULL DEFAULT '{}',
    version       bigint      NOT NULL,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL,
    deleted_at    timestamptz NULL
);
-- Slugs are unique among tenants that are not deleted, so a slug can be
-- reused after deletion.
CREATE UNIQUE INDEX tenants_slug_live ON tenants (slug) WHERE status <> 'deleted';
CREATE INDEX tenants_parent ON tenants (parent_id);
CREATE INDEX tenants_plan ON tenants (plan);
CREATE INDEX tenants_labels ON tenants USING gin (labels);

CREATE TABLE plans (
    id          text PRIMARY KEY,
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    features    jsonb       NOT NULL DEFAULT '{}',
    limits      jsonb       NOT NULL DEFAULT '{}',
    version     bigint      NOT NULL,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL
);

CREATE TABLE members (
    id         uuid PRIMARY KEY,
    tenant_id  uuid        NOT NULL REFERENCES tenants (id),
    user_id    text        NOT NULL DEFAULT '',
    email      text        NOT NULL,
    role       text        NOT NULL,
    status     text        NOT NULL,
    invited_by text        NOT NULL DEFAULT '',
    version    bigint      NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX members_tenant_email ON members (tenant_id, lower(email));

CREATE TABLE usage (
    tenant_id  uuid        NOT NULL,
    metric     text        NOT NULL,
    value      bigint      NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, metric)
);

-- The outbox. seq is assigned under a transaction-scoped advisory lock so
-- that seq order equals commit order (see AppendEvents).
CREATE SEQUENCE events_seq;
CREATE TABLE events (
    seq       bigint PRIMARY KEY,
    id        uuid        NOT NULL UNIQUE,
    type      text        NOT NULL,
    source    text        NOT NULL,
    subject   text        NOT NULL DEFAULT '',
    tenant_id text        NOT NULL DEFAULT '',
    actor     text        NOT NULL DEFAULT '',
    time      timestamptz NOT NULL,
    data      jsonb       NULL
);

CREATE TABLE cursors (
    subscription text PRIMARY KEY,
    seq          bigint      NOT NULL,
    updated_at   timestamptz NOT NULL
);

CREATE TABLE leases (
    name       text PRIMARY KEY,
    owner      text        NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE TABLE dead_letters (
    id           uuid PRIMARY KEY,
    subscription text        NOT NULL,
    event        jsonb       NOT NULL,
    error        text        NOT NULL,
    attempts     int         NOT NULL,
    failed_at    timestamptz NOT NULL
);
CREATE INDEX dead_letters_subscription ON dead_letters (subscription, failed_at);

CREATE TABLE idempotency_keys (
    key          text PRIMARY KEY,
    request_hash text        NOT NULL,
    status_code  int         NOT NULL,
    body         bytea       NOT NULL,
    created_at   timestamptz NOT NULL
);
