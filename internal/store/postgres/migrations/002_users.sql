CREATE TABLE users (
    id             uuid PRIMARY KEY,
    email          text        NOT NULL,
    name           text        NOT NULL DEFAULT '',
    status         text        NOT NULL,
    email_verified boolean     NOT NULL DEFAULT false,
    roles          jsonb       NOT NULL DEFAULT '[]',
    directory      text        NOT NULL,
    external_id    text        NOT NULL DEFAULT '',
    attributes     jsonb       NOT NULL DEFAULT '{}',
    version        bigint      NOT NULL,
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    last_login_at  timestamptz NULL,
    -- Credentials live in the same row but are never selected with the user.
    password_hash  text        NOT NULL DEFAULT '',
    failed_logins  int         NOT NULL DEFAULT 0,
    locked_until   timestamptz NULL
);
CREATE UNIQUE INDEX users_email ON users (lower(email));
CREATE INDEX users_external ON users (directory, external_id) WHERE external_id <> '';

CREATE INDEX members_user ON members (user_id) WHERE user_id <> '';

-- Single-use emailed tokens (invitation, password reset); only hashes.
CREATE TABLE action_tokens (
    hash       text PRIMARY KEY,
    kind       text        NOT NULL,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    used_at    timestamptz NULL
);

CREATE TABLE refresh_tokens (
    hash       text PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id  text        NOT NULL DEFAULT '',
    family     text        NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    rotated_at timestamptz NULL,
    revoked_at timestamptz NULL
);
CREATE INDEX refresh_tokens_family ON refresh_tokens (family);
CREATE INDEX refresh_tokens_user ON refresh_tokens (user_id);

CREATE TABLE signing_keys (
    id          text PRIMARY KEY,
    algorithm   text        NOT NULL,
    private_pem bytea       NOT NULL,
    created_at  timestamptz NOT NULL
);
