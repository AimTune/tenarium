-- Usage counters per period ("" = never resets), kept after the period
-- ends so totals can be reported (and exported to billing) once.
ALTER TABLE usage ADD COLUMN period text NOT NULL DEFAULT '';
ALTER TABLE usage ADD COLUMN period_end timestamptz NULL;
ALTER TABLE usage ADD COLUMN closed_at timestamptz NULL;
ALTER TABLE usage DROP CONSTRAINT usage_pkey;
ALTER TABLE usage ADD PRIMARY KEY (tenant_id, metric, period);
CREATE INDEX usage_ended ON usage (period_end) WHERE period_end IS NOT NULL AND closed_at IS NULL;
