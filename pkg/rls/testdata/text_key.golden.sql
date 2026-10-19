BEGIN;

-- "Events": tenant isolation on "org"
ALTER TABLE "Events" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Events" NO FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "org_isolation" ON "Events";
CREATE POLICY "org_isolation" ON "Events"
    AS PERMISSIVE FOR ALL TO PUBLIC
    USING ("org" = NULLIF(current_setting('tenarium.tenant', true), '')::text)
    WITH CHECK ("org" = NULLIF(current_setting('tenarium.tenant', true), '')::text);
DROP POLICY IF EXISTS "org_isolation_bypass" ON "Events";

COMMIT;
