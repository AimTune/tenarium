-- Audit queries filter by tenant or actor and page newest first; retention
-- prunes by time.
CREATE INDEX events_tenant_seq ON events (tenant_id, seq DESC) WHERE tenant_id <> '';
CREATE INDEX events_actor_seq ON events (actor, seq DESC);
CREATE INDEX events_time ON events (time);
