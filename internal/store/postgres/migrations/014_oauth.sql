CREATE TABLE oauth_clients (
    id                        text PRIMARY KEY,
    name                      text        NOT NULL,
    secret_hash               text        NOT NULL DEFAULT '',
    redirect_uris             text[]      NOT NULL DEFAULT '{}',
    post_logout_redirect_uris text[]      NOT NULL DEFAULT '{}',
    tenant_id                 text        NOT NULL DEFAULT '',
    scopes                    text[]      NOT NULL DEFAULT '{}',
    first_party               boolean     NOT NULL DEFAULT false,
    created_at                timestamptz NOT NULL,
    updated_at                timestamptz NOT NULL
);

CREATE TABLE oauth_consents (
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  text        NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    scopes     text[]      NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, client_id)
);
