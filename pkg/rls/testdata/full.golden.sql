BEGIN;

CREATE OR REPLACE FUNCTION "app"."current_tenant"() RETURNS uuid
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;

-- "public"."orders": tenant isolation on "tenant_id"
ALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."orders" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "tenant_isolation" ON "public"."orders";
CREATE POLICY "tenant_isolation" ON "public"."orders"
    AS PERMISSIVE FOR ALL TO "app_user"
    USING ("tenant_id" = "app"."current_tenant"())
    WITH CHECK ("tenant_id" = "app"."current_tenant"());
DROP POLICY IF EXISTS "tenant_isolation_bypass" ON "public"."orders";
CREATE POLICY "tenant_isolation_bypass" ON "public"."orders"
    AS PERMISSIVE FOR ALL TO "migrator", "support"
    USING (true)
    WITH CHECK (true);
ALTER TABLE "public"."orders" ALTER COLUMN "tenant_id" SET DEFAULT "app"."current_tenant"();
CREATE INDEX IF NOT EXISTS "orders_tenant_id_idx" ON "public"."orders" ("tenant_id");

-- "billing"."invoices": tenant isolation on "account_id"
ALTER TABLE "billing"."invoices" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "billing"."invoices" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "tenant_isolation" ON "billing"."invoices";
CREATE POLICY "tenant_isolation" ON "billing"."invoices"
    AS PERMISSIVE FOR ALL TO "app_user"
    USING ("account_id" = "app"."current_tenant"())
    WITH CHECK ("account_id" = "app"."current_tenant"());
DROP POLICY IF EXISTS "tenant_isolation_bypass" ON "billing"."invoices";
CREATE POLICY "tenant_isolation_bypass" ON "billing"."invoices"
    AS PERMISSIVE FOR ALL TO "migrator", "support"
    USING (true)
    WITH CHECK (true);
ALTER TABLE "billing"."invoices" ALTER COLUMN "account_id" SET DEFAULT "app"."current_tenant"();
CREATE INDEX IF NOT EXISTS "invoices_account_id_idx" ON "billing"."invoices" ("account_id");

COMMIT;
