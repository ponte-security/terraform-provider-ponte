# Active agents carrying both labels.
data "ponte_agents" "prod_claims" {
  labels = { team = "claims", env = "prod" }
}

output "prod_claims_agents" {
  value = data.ponte_agents.prod_claims.names
}
