# Every active agent labelled team=claims joins the group.
data "ponte_agents" "claims" {
  labels = { team = "claims" }
}

resource "ponte_agent_group_member" "claims" {
  for_each = toset(data.ponte_agents.claims.ids)
  group_id = ponte_agent_group.claims.id
  agent_id = each.value
}
