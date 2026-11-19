# The server must have been synced, so the tool is pinned.
resource "ponte_mcp_tool_risk_tier" "crm_delete_account" {
  server_id = ponte_mcp_server.crm.id
  tool      = "delete_account"
  risk_tier = "destructive"
}
