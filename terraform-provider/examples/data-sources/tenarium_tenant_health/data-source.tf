data "tenarium_tenant_health" "acme" {
  tenant_id = "acme"
}

output "acme_health" {
  value = "${data.tenarium_tenant_health.acme.grade} (${data.tenarium_tenant_health.acme.score})"
}
