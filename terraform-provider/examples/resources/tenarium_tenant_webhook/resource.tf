resource "tenarium_tenant_webhook" "events" {
  tenant_id   = tenarium_tenant.acme.id
  url         = "https://hooks.acme.example/tenarium"
  description = "Membership and tenant changes"
  types       = ["tenant.*", "tenant.member_*"]
}

# Hand the signing secret to the receiving service.
output "webhook_secret" {
  value     = tenarium_tenant_webhook.events.secret
  sensitive = true
}
