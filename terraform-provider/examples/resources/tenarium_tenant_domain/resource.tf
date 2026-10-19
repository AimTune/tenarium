resource "tenarium_tenant_domain" "app" {
  tenant_id = tenarium_tenant.acme.id
  hostname  = "app.acme.example"
  verify    = true
}

# Publish the challenge, e.g. with the AWS provider.
resource "aws_route53_record" "tenarium_challenge" {
  zone_id = var.zone_id
  name    = tenarium_tenant_domain.app.txt_record_name
  type    = "TXT"
  ttl     = 60
  records = [tenarium_tenant_domain.app.txt_record_value]
}

variable "zone_id" {
  type = string
}
