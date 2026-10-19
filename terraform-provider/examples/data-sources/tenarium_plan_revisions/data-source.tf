data "tenarium_plan_revisions" "pro" {
  plan_id = "pro"
}

output "pro_latest_revision" {
  value = data.tenarium_plan_revisions.pro.latest
}
