CREATE TABLE webauthn_credentials (
    id           text PRIMARY KEY,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text        NOT NULL DEFAULT '',
    data         bytea       NOT NULL,
    created_at   timestamptz NOT NULL,
    last_used_at timestamptz NULL
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id);
