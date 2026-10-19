-- Client details of sessions (and the OAuth client a session belongs to),
-- and kind-specific data of emailed tokens.
ALTER TABLE refresh_tokens ADD COLUMN user_agent text NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN ip text NOT NULL DEFAULT '';
ALTER TABLE action_tokens ADD COLUMN data text NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN client_id text NOT NULL DEFAULT '';
