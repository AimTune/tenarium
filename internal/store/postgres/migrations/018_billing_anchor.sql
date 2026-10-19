-- Billing cycle anchor for usage periods aligned to a tenant's subscription.
ALTER TABLE tenants ADD COLUMN billing_anchor timestamptz;
