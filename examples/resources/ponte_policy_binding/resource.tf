resource "ponte_policy_binding" "claims_bot_refunds" {
  agent_id  = data.ponte_agent.claims_bot.id
  policy_id = ponte_policy.refund_guard.policy_id
}
