resource "ponte_webhook" "siem" {
  name         = "SIEM"
  url          = "https://siem.example.com/hooks/ponte"
  event_types  = ["governance.alert", "authz.decision", "receipt.issued"]
  min_severity = "high" # security findings: critical and high
}

# The secret Ponte signs deliveries with, for the receiving side.
output "siem_signing_secret" {
  value     = ponte_webhook.siem.signing_secret
  sensitive = true
}
