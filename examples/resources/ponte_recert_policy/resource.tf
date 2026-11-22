resource "ponte_recert_policy" "quarterly" {
  name = "Quarterly access review"

  reviewer      = "owner"
  second_review = "high_risk"
  second_group  = "security"

  due_days       = 14
  remind_days    = 3
  on_overdue     = "escalate"
  escalate_group = "security-leads"
  on_deny        = "suspend"

  auto_certify = [
    { field = "risk_tier", op = "eq", value = "low" },
  ]
}
