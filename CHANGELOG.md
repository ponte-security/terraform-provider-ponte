# Changelog

## 0.3.0

Unattended runs: the provider signs in as an automation identity (Settings → Automation in Ponte).

- `identity_id` / `PONTE_IDENTITY_ID`: sign in with the pipeline's own OIDC identity, with no secret stored. The pipeline's token comes from `oidc_token`, `oidc_token_file`, `TFC_WORKLOAD_IDENTITY_TOKEN`, or is requested from GitHub Actions.
- `api_key` / `PONTE_API_KEY`: sign in with an automation identity's API key.
- The session is renewed during a long run, so an apply no longer fails when a token runs out.
- An operator token (`PONTE_OPERATOR_TOKEN`) still works for a person.

## 0.2.0

New resources:

- `ponte_scim_target`: a system Ponte pushes its agents to over SCIM.
- `ponte_recert_policy`: how a recertification campaign is reviewed.

## 0.1.1

Fixes:

- `ponte_policy`: a policy with `enforcement_mode = "observe"` is stored observing by the create call. Before, every new version enforced until a second call changed its mode, and stayed enforcing if that call failed. Needs a control plane that accepts the mode on create; an older one is still handled with the second call.
- `ponte_policy`: a version saved outside Terraform (in the console) is detected, and the next apply puts the configured policy back.
- `ponte_policy`: importing a policy no longer saves a duplicate version on the next apply.
- `ponte_policy`: a change only to comments, spacing or key order in the YAML no longer saves a new version.
- `ponte_policy`: a policy whose mode could not be set is kept in state instead of being left unmanaged.
- `ponte_spend_budget`: a scope written with a capital letter is refused at plan time instead of failing after apply with an inconsistent result.
- `ponte_webhook`: removing `format_config` clears the overrides.
- Ids are escaped in every request path.

Changes:

- `ponte_webhook.event_types` and `ponte_agent_group.tags` are sets: their order no longer matters. Existing state is read as is.
- Values the API refuses are refused at plan time: `enforcement_mode`, `risk_tier`, `data_classification`, budget `scope` and `ref`, webhook `format` and `min_severity`, a budget with no limit.
- An expired operator token is reported when the provider starts, with its expiry time. A 401 during a run says whether the token expired.
- Reads, replaces and deletes are retried on a dropped connection and on 502, 503 and 504; any request is retried on 429.
- Licensed under MPL-2.0.

## 0.1.0

First release: `ponte_policy`, `ponte_agent_group`, `ponte_agent_group_member`, `ponte_policy_binding`, `ponte_webhook`, `ponte_spend_budget`, `ponte_mcp_server`, `ponte_mcp_tool_risk_tier`, and the data sources `ponte_agent` and `ponte_agents`.
