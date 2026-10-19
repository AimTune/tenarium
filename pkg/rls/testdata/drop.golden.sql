BEGIN;

-- "public"."orders": remove tenant isolation
DROP POLICY IF EXISTS "tenant_isolation_bypass" ON "public"."orders";
DROP POLICY IF EXISTS "tenant_isolation" ON "public"."orders";
ALTER TABLE "public"."orders" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "public"."orders" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "public"."orders" ALTER COLUMN "tenant_id" DROP DEFAULT;

-- "billing"."invoices": remove tenant isolation
DROP POLICY IF EXISTS "tenant_isolation_bypass" ON "billing"."invoices";
DROP POLICY IF EXISTS "tenant_isolation" ON "billing"."invoices";
ALTER TABLE "billing"."invoices" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "billing"."invoices" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "billing"."invoices" ALTER COLUMN "account_id" DROP DEFAULT;

DROP FUNCTION IF EXISTS "app"."current_tenant"();

COMMIT;
