# A group, two members, a policy in observe mode, and a direct binding.
#
#   export PONTE_API_URL=https://app.ponte.ai/api/control
#   export PONTE_OPERATOR_TOKEN=…
#   terraform init && terraform apply

terraform {
  required_providers {
    ponte = { source = "ponte-ai/ponte" }
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
