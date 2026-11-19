resource "ponte_spend_budget" "claims_team" {
  scope       = "team"
  ref         = "claims"
  monthly_usd = 500
}

resource "ponte_spend_budget" "org" {
  scope          = "org"
  monthly_tokens = 50000000
}
