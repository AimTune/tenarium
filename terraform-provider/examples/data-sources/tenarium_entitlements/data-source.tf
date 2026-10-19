data "tenarium_entitlements" "acme" {
  tenant_id = "acme"
}

output "acme_has_sso" {
  value = lookup(data.tenarium_entitlements.acme.features, "sso", false)
}
