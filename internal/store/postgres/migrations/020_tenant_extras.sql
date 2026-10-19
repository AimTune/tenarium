-- Tenant branding, maintenance windows and templates.
ALTER TABLE tenants ADD COLUMN branding jsonb;
ALTER TABLE tenants ADD COLUMN maintenance jsonb;

CREATE TABLE tenant_templates (
    id         text PRIMARY KEY,
    data       jsonb       NOT NULL,
    updated_at timestamptz NOT NULL
);
