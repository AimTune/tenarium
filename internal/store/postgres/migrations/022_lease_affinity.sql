-- Whether a lease holder runs in the subscription's preferred region; a
-- preferred instance takes over leases of non-preferred ones.
ALTER TABLE leases ADD COLUMN preferred boolean NOT NULL DEFAULT false;
