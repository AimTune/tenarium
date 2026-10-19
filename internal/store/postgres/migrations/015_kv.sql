CREATE TABLE kv (
    key        text PRIMARY KEY,
    value      bytea       NOT NULL,
    updated_at timestamptz NOT NULL
);
