resource "tenarium_tenant_sso" "oidc" {
  tenant_id      = tenarium_tenant.acme.id
  issuer         = "https://login.acme.example/realms/acme"
  client_id      = "tenarium"
  client_secret  = var.oidc_client_secret
  domains        = [tenarium_tenant_domain.app.hostname]
  enforce        = true
  auto_provision = true
  default_role   = "member"
}

# SAML: give the identity provider's metadata as XML or a URL.
resource "tenarium_tenant_sso" "saml" {
  tenant_id            = tenarium_tenant.globex.id
  protocol             = "saml"
  saml_metadata_url    = "https://idp.globex.example/metadata.xml"
  saml_email_attribute = "email"
  domains              = ["globex.example"]
}

variable "oidc_client_secret" {
  type      = string
  sensitive = true
}
