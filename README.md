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
| `ponte_webhook` | `wh_…` | an outbound subscription: name, url, event_types (`["*"]` for all), headers (sensitive, not read back), enabled, format `ponte` or `udm`, format_config, `min_severity` (`critical`, `high` default, or `medium`: the lowest level of security finding delivered). `signing_secret` is computed on create and kept in state (sensitive). |
| `ponte_spend_budget` | `scope:ref` | a monthly model-spend budget on `org` (ref omitted), `team`, `owner` (`user:…` / `group:…`), `agent`, or `model`; `monthly_usd` and/or `monthly_tokens`. Destroy clears it. |

| `ponte_mcp_server` | `res_…` | a registered MCP server: name, endpoint_url, data_classification, environment, owner, require_tool_review. Policies can refuse unregistered servers. A changed `endpoint_url` replaces the resource (pinned tools belong to the endpoint); everything else is edited in place and keeps the pins. Destroy deregisters the server and deletes its pins, proxy configuration and sync credential. Import by id. |
| `ponte_mcp_tool_risk_tier` | `server_id/tool` | the declared risk tier of one tool: `read`, `write`, `external_send`, `destructive` or `code_exec`. Policies read the declared tier. The tool must be pinned first (sync the server), otherwise apply fails with "tool not pinned". Destroy leaves the declaration in Ponte (there is no clear) and warns. |

## Data sources

| Data source | Finds | Notes |
|---|---|---|
| `ponte_agent` | one agent, by `agent_id` or by `name` | The name is matched exactly (case-insensitive). No match, or more than one, is an error that lists the candidates. Gives `id`, `status`, `framework`, `trust_tier`, `labels`, `tools`. |
| `ponte_agents` | the agents carrying every given label | `status` defaults to `active` (`"any"` for all). Gives `ids` (sorted) and `names`, for `for_each` over memberships or bindings. |

Agents are registered and onboarded in Ponte, not in Terraform: they carry credentials, owners and attestations that do not belong in state.

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

## Releasing

The Terraform Registry reads a public GitHub repository named `terraform-provider-ponte` with releases at its root, so this directory is laid out to be that repository: `.goreleaser.yml`, `terraform-registry-manifest.json` and `.github/workflows/release.yml` are here, and do nothing while the provider lives inside the monorepo.

1. Mirror this directory to the public repository (`git subtree split --prefix terraform-provider-ponte`).
2. Register a GPG public key with the Registry namespace; add `GPG_PRIVATE_KEY` and `PASSPHRASE` as repository secrets.
3. Generate the documentation pages from the schema and `examples/` (`tfplugindocs generate --provider-name ponte`) and commit `docs/`.
4. Push a tag `vX.Y.Z`: the workflow runs the acceptance tests, then builds, signs and publishes.

Tested against a live stack (app.ponte.ai, 2026-11-18): create, update in place, re-plan with no changes and destroy for every resource except `ponte_mcp_tool_risk_tier`; import for groups, MCP servers and budgets.

## Not yet covered

MCP proxy configuration and sync credentials, tool approvals (an approval is a human review of one definition, so it stays in the console), SCIM targets, recert policies, target audit log integrations. Each is a few hundred lines in `internal/provider`; the client in `internal/client` is the only place that knows the API.
