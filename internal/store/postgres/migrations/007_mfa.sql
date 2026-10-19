CREATE TABLE user_mfa (
    user_id         uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    totp_secret     text        NOT NULL,
    enabled         boolean     NOT NULL DEFAULT false,
    last_step       bigint      NOT NULL DEFAULT 0,
    recovery_hashes text[]      NOT NULL DEFAULT '{}',
    updated_at      timestamptz NOT NULL
);
