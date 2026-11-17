# terraform-provider-ponte

Ponte authorization resources as code: policies, agent groups, memberships and policy bindings, through the control plane's operator API.

```hcl
terraform {
  required_providers {
    ponte = { source = "ponte-ai/ponte" }
  }
}

provider "ponte" {
  endpoint = "https://app.ponte.ai/api/control"   # or PONTE_API_URL
  # token  = …                                      # or PONTE_OPERATOR_TOKEN
}

resource "ponte_agent_group" "claims" {
  name        = "Claims"
  description = "Claims handling agents"
  trust_level = "trusted"
  owner       = "claims-platform@example.com"
  tags        = ["finance", "prod"]
}

resource "ponte_agent_group_member" "claims_bot" {
  group_id = ponte_agent_group.claims.id
  agent_id = "agt_f524a3efaeff"
}

resource "ponte_policy" "budget_guard" {
  ppl              = file("${path.module}/policies/model-budget-guard.yaml")
  enforcement_mode = "observe"   # enforce once you have watched it
}

resource "ponte_policy_binding" "claims_bot_budget" {
  agent_id  = "agt_f524a3efaeff"
  policy_id = ponte_policy.budget_guard.policy_id
}
```

## Resources

| Resource | Identity | Notes |
|---|---|---|
| `ponte_policy` | the policy's `metadata.name` | `ppl` is the PPL YAML. Each change saves a **new version** (new `policy_id`, previous version archived); agents bound to the name follow. `enforcement_mode` is `enforce` or `observe`. Destroy archives the active version. Import by name, then set `ppl`. |
| `ponte_agent_group` | `grp_…` | name, description, trust_level, owner, tags, max_concurrent_agents. Import by id. |
| `ponte_agent_group_member` | `group_id/agent_id` | one agent in one group. |
| `ponte_policy_binding` | `agent_id/policy_id` | binds a policy to one agent directly. Takes `ponte_policy.x.policy_id`; when the policy gets a new version the binding is replaced, and both halves are idempotent because the server moves bindings with the name. |

## Authentication

The provider acts as an **operator**: a signed-in operator's access token (`PONTE_OPERATOR_TOKEN`, the same the `ponte` CLI uses). An agent's token is refused by the control plane for every write here. Tokens are short-lived; for CI, mint one at the start of the job from your identity provider as a user with the operator role. There is no long-lived operator API key by design.

## Developing

```bash
go build -o terraform-provider-ponte .
TF_ACC=1 go test ./...            # acceptance tests against a fake control plane; needs terraform on PATH
```

To use the local build in a configuration, add to `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides { "ponte-ai/ponte" = "/path/to/terraform-provider-ponte" }
  direct {}
}
```

Publishing to the Terraform Registry needs a release workflow (goreleaser, GPG-signed) and is not set up yet.

## Not yet covered

Registry resources (MCP servers) and tool approvals, webhooks, spend budgets, SCIM targets, recert policies, data sources for agents. Each is a few hundred lines in `internal/provider`; the client in `internal/client` is the only place that knows the API.
