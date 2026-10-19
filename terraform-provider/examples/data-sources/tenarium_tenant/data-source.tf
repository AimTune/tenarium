data "tenarium_tenant" "acme" {
  slug = "acme"
}

output "acme_theme" {
  value = jsondecode(data.tenarium_tenant.acme.settings).theme
}
