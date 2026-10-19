BEGIN;

-- "orders": tenant isolation on "tenant_id"
ALTER TABLE "orders" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "orders" FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "tenant_isolation" ON "orders";
CREATE POLICY "tenant_isolation" ON "orders"
    AS PERMISSIVE FOR ALL TO PUBLIC
    USING ("tenant_id" = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK ("tenant_id" = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
DROP POLICY IF EXISTS "tenant_isolation_bypass" ON "orders";

COMMIT;
