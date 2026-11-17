# terraform-provider-ponte

Ponte authorization resources as code: policies, agent groups, memberships, policy bindings, webhooks, spend budgets and MCP servers, through the operator API.

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
| `ponte_webhook` | `wh_…` | an outbound subscription: name, url, event_types (`["*"]` for all), headers (sensitive, not read back), enabled, format `ponte` or `udm`, format_config. `signing_secret` is computed on create and kept in state (sensitive). |
| `ponte_spend_budget` | `scope:ref` | a monthly model-spend budget on `org` (ref omitted), `team`, `owner` (`user:…` / `group:…`), `agent`, or `model`; `monthly_usd` and/or `monthly_tokens`. Destroy clears it. |

| `ponte_mcp_server` | `res_…` | a registered MCP server: name, endpoint_url, data_classification, environment, owner, require_tool_review. Policies can refuse unregistered servers. A changed `endpoint_url` replaces the resource (pinned tools belong to the endpoint); everything else is edited in place and keeps the pins. Destroy deregisters the server and deletes its pins, proxy configuration and sync credential. Import by id. |
| `ponte_mcp_tool_risk_tier` | `server_id/tool` | the declared risk tier of one tool: `read`, `write`, `external_send`, `destructive` or `code_exec`. Policies read the declared tier. The tool must be pinned first (sync the server), otherwise apply fails with "tool not pinned". Destroy leaves the declaration in Ponte (there is no clear) and warns. |

Webhooks, budgets and MCP servers live on the api (`…/api`) rather than the control plane (`…/api/control`); the provider derives the api base from `endpoint`, or takes `api_endpoint` / `PONTE_API_BASE_URL`. The same operator token authorizes both.

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

MCP proxy configuration and sync credentials, tool approvals (an approval is a human review of one definition, so it stays in the console), SCIM targets, recert policies, data sources for agents. Each is a few hundred lines in `internal/provider`; the client in `internal/client` is the only place that knows the API.
