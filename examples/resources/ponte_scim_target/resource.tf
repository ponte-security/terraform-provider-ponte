variable "iga_scim_token" {
  type      = string
  sensitive = true
}

resource "ponte_scim_target" "iga" {
  name         = "IGA"
  base_url     = "https://iga.example.com/scim/v2"
  bearer_token = var.iga_scim_token
}
