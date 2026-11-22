# Used by .github/workflows/live-signin.yml: signs in to a Ponte stack with the pipeline's own
# identity (no secret) and reads the agent inventory. It creates nothing.
terraform {
  required_providers {
    ponte = {
      source  = "ponte-security/ponte"
      version = ">= 0.3.0"
    }
  }
}

# Endpoint and identity come from the environment: PONTE_API_URL and PONTE_IDENTITY_ID.
provider "ponte" {}

data "ponte_agents" "all" {
  status = "any"
}

output "agents_visible" {
  value = length(data.ponte_agents.all.ids)
}
