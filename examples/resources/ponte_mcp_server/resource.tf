resource "ponte_mcp_server" "crm" {
  name                = "CRM"
  endpoint_url        = "https://mcp.example.com/crm"
  data_classification = "confidential"
  environment         = "production"
  owner               = "crm-platform@example.com"
  require_tool_review = true # a newly seen tool is denied until an operator approves it
}
