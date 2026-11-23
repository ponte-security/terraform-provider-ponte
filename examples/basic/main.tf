# A group, two members, a policy in observe mode, and a direct binding.
#
#   export PONTE_API_URL=https://api.ponte.ai/control
#   export PONTE_OPERATOR_TOKEN=…
#   terraform init && terraform apply

terraform {
  required_providers {
    ponte = { source = "ponte-security/ponte" }
  }
}

provider "ponte" {}

variable "agent_ids" {
  description = "Agents to put in the group (agt_…)."
  type        = list(string)
}

resource "ponte_agent_group" "claims" {
  name        = "Claims"
  description = "Claims handling agents"
  trust_level = "trusted"
  owner       = "claims-platform@example.com"
  tags        = ["finance"]
}

resource "ponte_agent_group_member" "claims" {
  for_each = toset(var.agent_ids)
  group_id = ponte_agent_group.claims.id
  agent_id = each.value
}

resource "ponte_policy" "drift_guard" {
  ppl              = file("${path.module}/../../../policies/examples/behaviour-drift-guard.yaml")
  enforcement_mode = "observe"
}

resource "ponte_policy_binding" "drift_guard" {
  for_each  = toset(var.agent_ids)
  agent_id  = each.value
  policy_id = ponte_policy.drift_guard.policy_id
}

output "group_id" {
  value = ponte_agent_group.claims.id
}

output "policy" {
  value = { name = ponte_policy.drift_guard.name, id = ponte_policy.drift_guard.policy_id, version = ponte_policy.drift_guard.version }
}

# An MCP server the fleet may use. Policies can refuse servers that are not registered.
resource "ponte_mcp_server" "crm" {
  name                = "CRM"
  endpoint_url        = "https://mcp.example.com/crm"
  data_classification = "confidential"
  environment         = "production"
  owner               = "crm-platform@example.com"
  require_tool_review = true # a newly seen tool is denied until an operator approves it
}

# Declare what a tool can do, once the server has been synced and the tool is pinned.
resource "ponte_mcp_tool_risk_tier" "crm_delete_account" {
  server_id = ponte_mcp_server.crm.id
  tool      = "delete_account"
  risk_tier = "destructive"
}
