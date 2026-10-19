ALTER TABLE sso_connections ADD COLUMN protocol text NOT NULL DEFAULT 'oidc';
ALTER TABLE sso_connections ADD COLUMN saml_metadata text NOT NULL DEFAULT '';
ALTER TABLE sso_connections ADD COLUMN saml_metadata_url text NOT NULL DEFAULT '';
ALTER TABLE sso_connections ADD COLUMN saml_email_attribute text NOT NULL DEFAULT '';
ALTER TABLE sso_connections ADD COLUMN saml_name_attribute text NOT NULL DEFAULT '';
