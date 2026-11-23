# terraform-provider-ponte

Ponte authorization resources as code: policies, agent groups, memberships, policy bindings, webhooks, spend budgets, MCP servers, SCIM targets and recertification review policies, through the operator API.

```hcl
terraform {
  required_providers {
    ponte = { source = "ponte-security/ponte" }
  }
}

provider "ponte" {
  endpoint = "https://api.ponte.ai/control"   # or PONTE_API_URL
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
  agent_id = "agt_0123456789ab"
}

resource "ponte_policy" "budget_guard" {
  ppl              = file("${path.module}/policies/model-budget-guard.yaml")
  enforcement_mode = "observe"   # enforce once you have watched it
}

resource "ponte_policy_binding" "claims_bot_budget" {
  agent_id  = "agt_0123456789ab"
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
| `ponte_scim_target` | `scimtg_…` | a system Ponte pushes its agents to over SCIM: name, base_url, bearer_token (sensitive, never read back), enabled. Only `enabled` changes in place; anything else replaces the target. Import by id; the first apply after an import records the credential without replacing the target. |
| `ponte_recert_policy` | `rp_…` | how a recertification campaign is reviewed: reviewer, second review, deadline and reminder, what happens when overdue and on a denial, auto-certify conditions. Edited in place. A policy a schedule or rule uses cannot be destroyed. Import by id. |

## Data sources

| Data source | Finds | Notes |
|---|---|---|
| `ponte_agent` | one agent, by `agent_id` or by `name` | The name is matched exactly (case-insensitive). No match, or more than one, is an error that lists the candidates. Gives `id`, `status`, `framework`, `trust_tier`, `labels`, `tools`. |
| `ponte_agents` | the agents carrying every given label | `status` defaults to `active` (`"any"` for all). Gives `ids` (sorted) and `names`, for `for_each` over memberships or bindings. |

Agents are registered and onboarded in Ponte, not in Terraform: they carry credentials, owners and attestations that do not belong in state.

Webhooks, budgets and MCP servers live on the api (`…/api`) rather than the control plane (`…/api/control`); the provider derives the api base from `endpoint`, or takes `api_endpoint` / `PONTE_API_BASE_URL`. The same operator token authorizes both.

## Authentication

Three ways to sign in. The first that is set is used, the configuration before the environment.

| For | Set | Notes |
|---|---|---|
| A person at a terminal | `PONTE_OPERATOR_TOKEN` | A signed-in operator's access token. It lasts minutes. |
| A pipeline, with no secret | `PONTE_IDENTITY_ID` | An automation identity (Settings → Automation) with a trust rule for the pipeline. The provider presents the pipeline's own OIDC token. |
| A pipeline or script, with a key | `PONTE_API_KEY` | An automation identity's API key. Store it as a secret. |

With an automation identity the provider exchanges its credential for a ten-minute session and renews it during a long run. An automation identity holds a role (Operator for applies, Read-only admin for drift checks) and cannot decide approvals, touch credentials or change roles. An agent's token is refused.

### GitHub Actions, no secret

In Ponte, add an automation identity with **Sign in with the pipeline's own identity**: issuer `https://token.actions.githubusercontent.com`, audience your Ponte API URL (`https://api.ponte.ai`), claims `repository = your-org/your-repo` and `ref = refs/heads/main`.

```yaml
permissions:
  id-token: write   # lets the job request its identity token
  contents: read
jobs:
  apply:
    runs-on: ubuntu-latest
    env:
      PONTE_API_URL: https://api.ponte.ai/control
      PONTE_IDENTITY_ID: auto_0123456789abcdef
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init && terraform apply -auto-approve
```

Elsewhere, hand the provider the pipeline's token: `PONTE_OIDC_TOKEN` or `PONTE_OIDC_TOKEN_FILE` (GitLab CI: an `id_tokens` entry with `aud` set to your Ponte API URL). HCP Terraform's `TFC_WORKLOAD_IDENTITY_TOKEN` is read as is.

## Developing

```bash
go build -o terraform-provider-ponte .
TF_ACC=1 go test ./...            # acceptance tests against a fake control plane; needs terraform on PATH
```

To use the local build in a configuration, add to `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides { "ponte-security/ponte" = "/path/to/terraform-provider-ponte" }
  direct {}
}
```

## Releasing

Published on the Terraform Registry as [`ponte-security/ponte`](https://registry.terraform.io/providers/ponte-security/ponte/latest). Changes are listed in [CHANGELOG.md](CHANGELOG.md).

1. Add the version to `CHANGELOG.md`.
2. If a schema or an example changed, regenerate the documentation pages (`tfplugindocs generate --provider-name ponte`) and commit `docs/`.
3. Push to `main`; the `test` workflow must pass.
4. Push a tag `vX.Y.Z`. The `release` workflow runs the tests again, then builds, signs and publishes. It needs the repository secrets `GPG_PRIVATE_KEY` and `PASSPHRASE` for the key registered with the Registry namespace.

Tested against a live stack (app.ponte.ai, 2026-11-22): create, update in place, re-plan with no changes, import and destroy for every resource; and an apply signed in with an automation identity's API key. `ponte_mcp_tool_risk_tier` was run by declaring a tier a tool already had, because a declared tier cannot be cleared.

## Licence

[MPL-2.0](LICENSE).

## Not yet covered

MCP proxy configuration and sync credentials, tool approvals (an approval is a human review of one definition, so it stays in the console), recertification schedules and rules, target audit log integrations. The client in `internal/client` is the only place that knows the API.
