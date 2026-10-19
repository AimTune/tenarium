CREATE TABLE scheduled_actions (
    id         uuid PRIMARY KEY,
    tenant_id  uuid        NOT NULL REFERENCES tenants (id),
    action     text        NOT NULL,
    plan       text        NOT NULL DEFAULT '',
    reason     text        NOT NULL DEFAULT '',
    run_at     timestamptz NOT NULL,
    status     text        NOT NULL,
    error      text        NOT NULL DEFAULT '',
    created_by text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    claimed_at timestamptz NULL,
    done_at    timestamptz NULL
);
CREATE INDEX scheduled_actions_tenant ON scheduled_actions (tenant_id, run_at);
CREATE INDEX scheduled_actions_due ON scheduled_actions (run_at) WHERE status IN ('pending', 'running');
