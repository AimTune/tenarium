ALTER TABLE tenants ADD COLUMN plan_revision bigint NOT NULL DEFAULT 0;
ALTER TABLE tenants ADD COLUMN add_ons text[] NOT NULL DEFAULT '{}';
ALTER TABLE tenants ADD COLUMN region text NOT NULL DEFAULT '';
CREATE INDEX tenants_region ON tenants (region) WHERE region <> '';

CREATE TABLE plan_revisions (
    plan_id    text        NOT NULL,
    revision   bigint      NOT NULL,
    features   jsonb       NOT NULL DEFAULT '{}',
    limits     jsonb       NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL,
    PRIMARY KEY (plan_id, revision)
);

CREATE TABLE rollouts (
    feature    text PRIMARY KEY,
    data       jsonb       NOT NULL,
    updated_at timestamptz NOT NULL
);
