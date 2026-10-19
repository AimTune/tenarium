terraform {
  required_providers {
    tenarium = {
      source = "aimtune/tenarium"
    }
  }
}

# endpoint and api_key default to TENARIUM_URL and TENARIUM_API_KEY.
provider "tenarium" {
  endpoint = "https://tenarium.example.com"
  api_key  = var.tenarium_api_key
}

variable "tenarium_api_key" {
  type      = string
  sensitive = true
}
