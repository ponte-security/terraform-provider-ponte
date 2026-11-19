resource "ponte_agent_group" "claims" {
  name        = "Claims"
  description = "Claims handling agents"
  owner       = "claims-platform@example.com"
  tags        = ["finance", "prod"]
}
