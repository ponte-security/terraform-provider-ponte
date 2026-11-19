package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Acceptance tests run the real Terraform CLI against the provider, with the fake control plane
// behind it. TF_ACC=1 go test ./... (terraform must be on PATH).

const testToken = "operator-token"

func providerFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"ponte": providerserver.NewProtocol6WithError(New("test")()),
	}
}

func providerBlock(endpoint string) string {
	return fmt.Sprintf(`provider "ponte" {
  endpoint = %q
  token    = %q
}
`, endpoint+"/api/control", testToken)
}

func policyYAML(name, description, tool string) string {
	return fmt.Sprintf(`apiVersion: ponte.io/v1
kind: AgentPolicy
metadata:
  name: %s
spec:
  description: %s
  subjects:
    match: {}
  rules:
    - effect: deny
      tools: ["%s"]
`, name, description, tool)
}

func TestAccPolicy(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	cfg := func(desc, tool, mode string) string {
		return providerBlock(ts.URL) + fmt.Sprintf(`
resource "ponte_policy" "guard" {
  ppl              = <<-EOT
%s
EOT
  enforcement_mode = %q
}
`, policyYAML("guard", desc, tool), mode)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: cfg("first", "mail:send", "enforce"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ponte_policy.guard", "name", "guard"),
					resource.TestCheckResourceAttr("ponte_policy.guard", "id", "guard"),
					resource.TestCheckResourceAttr("ponte_policy.guard", "version", "1"),
					resource.TestCheckResourceAttr("ponte_policy.guard", "description", "first"),
					resource.TestCheckResourceAttr("ponte_policy.guard", "enforcement_mode", "enforce"),
					resource.TestMatchResourceAttr("ponte_policy.guard", "policy_id", regexp.MustCompile(`^pol_`)),
				),
			},
			{
				// Only the mode changes: no new version.
				Config: cfg("first", "mail:send", "observe"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ponte_policy.guard", "version", "1"),
					resource.TestCheckResourceAttr("ponte_policy.guard", "enforcement_mode", "observe"),
				),
			},
			{
				// The YAML changes: a new version, new id, the mode re-applied.
				Config: cfg("second", "db:drop", "observe"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ponte_policy.guard", "version", "2"),
					resource.TestCheckResourceAttr("ponte_policy.guard", "description", "second"),
					resource.TestCheckResourceAttr("ponte_policy.guard", "enforcement_mode", "observe"),
					func(_ *terraformState) error {
						f.mu.Lock()
						defer f.mu.Unlock()
						active := 0
						for _, p := range f.policies {
							if p.Name == "guard" && p.Status == "active" {
								active++
							}
						}
						if active != 1 || len(f.policies) != 2 {
							return fmt.Errorf("one active version of two: %d active, %d total", active, len(f.policies))
						}
						return nil
					},
				),
			},
			{
				ResourceName:            "ponte_policy.guard",
				ImportState:             true,
				ImportStateId:           "guard",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"ppl"},
			},
		},
	})
	// Destroy archived the active version.
	if p := f.activeByName("guard"); p != nil {
		t.Fatalf("destroy left an active version: %+v", p)
	}
}

func TestAccGroupMembersAndBinding(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	cfg := func(groupName, tool string, members []string) string {
		out := providerBlock(ts.URL) + fmt.Sprintf(`
resource "ponte_agent_group" "claims" {
  name        = %q
  description = "claims handling agents"
  trust_level = "trusted"
  owner       = "claims-platform@example.com"
  tags        = ["finance", "prod"]
  max_concurrent_agents = 5
}

resource "ponte_policy" "guard" {
  ppl = <<-EOT
%s
EOT
}

resource "ponte_policy_binding" "a1" {
  agent_id  = "agt_1"
  policy_id = ponte_policy.guard.policy_id
}
`, groupName, policyYAML("claims-guard", "guard", tool))
		for i, m := range members {
			out += fmt.Sprintf(`
resource "ponte_agent_group_member" "m%d" {
  group_id = ponte_agent_group.claims.id
  agent_id = %q
}
`, i, m)
		}
		return out
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: cfg("Claims", "mail:send", []string{"agt_1", "agt_2"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("ponte_agent_group.claims", "id", regexp.MustCompile(`^grp_`)),
					resource.TestCheckResourceAttr("ponte_agent_group.claims", "trust_level", "trusted"),
					resource.TestCheckResourceAttr("ponte_agent_group.claims", "tags.#", "2"),
					resource.TestCheckResourceAttr("ponte_agent_group.claims", "max_concurrent_agents", "5"),
					resource.TestCheckResourceAttr("ponte_agent_group_member.m0", "agent_id", "agt_1"),
					func(_ *terraformState) error {
						f.mu.Lock()
						defer f.mu.Unlock()
						for _, set := range f.members {
							if len(set) != 2 {
								return fmt.Errorf("two members, got %d", len(set))
							}
						}
						if len(f.bindings["agt_1"]) != 1 {
							return fmt.Errorf("agt_1 bound once: %v", f.bindings["agt_1"])
						}
						return nil
					},
				),
			},
			{
				// Rename the group in place; drop a member; change the policy (new version: the
				// server moves the binding, Terraform replaces its resource; both idempotent).
				Config: cfg("Claims EU", "db:drop", []string{"agt_1"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ponte_agent_group.claims", "name", "Claims EU"),
					resource.TestCheckResourceAttr("ponte_policy.guard", "version", "2"),
					func(_ *terraformState) error {
						f.mu.Lock()
						defer f.mu.Unlock()
						for _, set := range f.members {
							if len(set) != 1 || !set["agt_1"] {
								return fmt.Errorf("one member agt_1: %v", set)
							}
						}
						active := f.activeByName("claims-guard")
						if active == nil || len(f.bindings["agt_1"]) != 1 || !f.bindings["agt_1"][active.PolicyID] {
							return fmt.Errorf("agt_1 bound to the active version only: %v", f.bindings["agt_1"])
						}
						return nil
					},
				),
			},
			{
				ResourceName:      "ponte_agent_group.claims",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
	if len(f.groups) != 0 || len(f.bindings["agt_1"]) != 0 {
		t.Fatalf("destroy cleans up: groups %d bindings %v", len(f.groups), f.bindings["agt_1"])
	}
}

// terraformState is the plugin-testing state type, aliased so checks read plainly.
type terraformState = terraform.State

func TestAccWebhookAndBudget(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	cfg := func(name string, usd float64, enabled bool) string {
		minSeverity := ""
		if !enabled {
			minSeverity = `min_severity = "medium"`
		}
		return providerBlock(ts.URL) + fmt.Sprintf(`
resource "ponte_webhook" "siem" {
  name        = %q
  url         = "https://siem.example.com/hooks/ponte"
  event_types = ["authz.decision", "receipt.issued"]
  headers     = { Authorization = "Bearer siem-token" }
  enabled     = %t
  %s
}

resource "ponte_spend_budget" "team" {
  scope       = "team"
  ref         = "claims"
  monthly_usd = %v
}

resource "ponte_spend_budget" "org" {
  scope          = "org"
  monthly_tokens = 5000000
}
`, name, enabled, minSeverity, usd)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: cfg("SIEM", 100, true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("ponte_webhook.siem", "id", regexp.MustCompile(`^wh_`)),
					resource.TestMatchResourceAttr("ponte_webhook.siem", "signing_secret", regexp.MustCompile(`^whsec_`)),
					resource.TestCheckResourceAttr("ponte_webhook.siem", "event_types.#", "2"),
					resource.TestCheckResourceAttr("ponte_webhook.siem", "format", "ponte"),
					// Security findings: critical and high unless the configuration asks for more.
					resource.TestCheckResourceAttr("ponte_webhook.siem", "min_severity", "high"),
					resource.TestCheckResourceAttr("ponte_spend_budget.team", "id", "team:claims"),
					resource.TestCheckResourceAttr("ponte_spend_budget.org", "ref", "*"),
					resource.TestCheckResourceAttr("ponte_spend_budget.org", "monthly_tokens", "5000000"),
				),
			},
			{
				// Rename and pause the webhook (the secret is kept), raise the budget.
				Config: cfg("SIEM (paused)", 250, false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ponte_webhook.siem", "name", "SIEM (paused)"),
					resource.TestCheckResourceAttr("ponte_webhook.siem", "enabled", "false"),
					resource.TestCheckResourceAttr("ponte_webhook.siem", "min_severity", "medium"),
					resource.TestMatchResourceAttr("ponte_webhook.siem", "signing_secret", regexp.MustCompile(`^whsec_`)),
					resource.TestCheckResourceAttr("ponte_spend_budget.team", "monthly_usd", "250"),
				),
			},
			{
				ResourceName:      "ponte_spend_budget.team",
				ImportState:       true,
				ImportStateId:     "team:claims",
				ImportStateVerify: true,
			},
			{
				// The secret is shown once and headers are never returned, so neither can be imported.
				ResourceName:            "ponte_webhook.siem",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"signing_secret", "headers"},
			},
		},
	})
	if len(f.webhooks) != 0 || len(f.budgets) != 0 {
		t.Fatalf("destroy cleans up: webhooks %d budgets %d", len(f.webhooks), len(f.budgets))
	}
}

func TestAccMCPServerAndRiskTier(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	server := func(name, classification string, review bool) string {
		return providerBlock(ts.URL) + fmt.Sprintf(`
resource "ponte_mcp_server" "crm" {
  name                = %q
  endpoint_url        = "https://mcp.example.com/crm"
  data_classification = %q
  environment         = "production"
  owner               = "crm-platform@example.com"
  require_tool_review = %t
}
`, name, classification, review)
	}
	tier := func(tier string) string {
		return fmt.Sprintf(`
resource "ponte_mcp_tool_risk_tier" "delete_account" {
  server_id = ponte_mcp_server.crm.id
  tool      = "delete_account"
  risk_tier = %q
}
`, tier)
	}
	var serverID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				Config: server("CRM", "confidential", true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("ponte_mcp_server.crm", "id", regexp.MustCompile(`^res_`)),
					resource.TestCheckResourceAttr("ponte_mcp_server.crm", "status", "active"),
					resource.TestCheckResourceAttr("ponte_mcp_server.crm", "require_tool_review", "true"),
					func(s *terraform.State) error {
						serverID = s.RootModule().Resources["ponte_mcp_server.crm"].Primary.ID
						return nil
					},
				),
			},
			{
				// A tier cannot be declared for a tool Ponte has not pinned.
				Config:      server("CRM", "confidential", true) + tier("destructive"),
				ExpectError: regexp.MustCompile(`tool not pinned`),
			},
			{
				// After a sync the tool is pinned. Rename and reclassify in place: the pins, the
				// tool list and the server-owned metadata survive the registry's whole-record update.
				PreConfig: func() { f.pinTools(serverID, "delete_account", "get_account") },
				Config:    server("CRM (prod)", "restricted", false) + tier("destructive"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ponte_mcp_server.crm", "name", "CRM (prod)"),
					resource.TestCheckResourceAttr("ponte_mcp_server.crm", "data_classification", "restricted"),
					resource.TestCheckResourceAttr("ponte_mcp_server.crm", "require_tool_review", "false"),
					resource.TestCheckResourceAttr("ponte_mcp_tool_risk_tier.delete_account", "risk_tier", "destructive"),
					func(s *terraform.State) error {
						if s.RootModule().Resources["ponte_mcp_server.crm"].Primary.ID != serverID {
							return fmt.Errorf("the server was replaced, not updated in place")
						}
						srv := f.mcpByName("CRM (prod)")
						if srv == nil {
							return fmt.Errorf("server not renamed")
						}
						meta := srv.Record["metadata"].(map[string]any)
						if meta["mcp_proxy_identity"] == nil || meta["sync"] == nil {
							return fmt.Errorf("server-owned metadata lost in the update: %v", meta)
						}
						if len(srv.Nulls) != 0 {
							return fmt.Errorf("the update left out %v, which the registry stores as null", srv.Nulls)
						}
						if tools, _ := srv.Record["tools_exposed"].([]any); len(tools) != 2 {
							return fmt.Errorf("tool list lost in the update: %v", srv.Record["tools_exposed"])
						}
						if len(srv.Pins) != 2 || srv.Pins["delete_account"] != "destructive" || srv.Pins["get_account"] != "" {
							return fmt.Errorf("pins: %v", srv.Pins)
						}
						return nil
					},
				),
			},
			{
				// Only the review mode changes: no registry update is sent.
				Config: server("CRM (prod)", "restricted", true) + tier("code_exec"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ponte_mcp_server.crm", "require_tool_review", "true"),
					resource.TestCheckResourceAttr("ponte_mcp_tool_risk_tier.delete_account", "risk_tier", "code_exec"),
					func(*terraform.State) error {
						if n := f.mcpByName("CRM (prod)").Replaced; n != 1 {
							return fmt.Errorf("registry updates: %d, want 1", n)
						}
						return nil
					},
				),
			},
			{
				ResourceName:      "ponte_mcp_server.crm",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "ponte_mcp_tool_risk_tier.delete_account",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
	if len(f.mcp) != 0 {
		t.Fatalf("destroy deregisters the server: %d left", len(f.mcp))
	}
}

func TestAccAgentDataSources(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	// More agents than one page holds; the ones looked for are on the last page.
	for i := 0; i < 230; i++ {
		f.agents = append(f.agents, fakeAgent{AgentID: fmt.Sprintf("agt_fill%03d", i), DisplayName: fmt.Sprintf("filler-%03d", i), Framework: "custom", Status: "active", Labels: map[string]string{}})
	}
	f.agents = append(f.agents,
		fakeAgent{AgentID: "agt_claims1", DisplayName: "Claims Bot", Framework: "langgraph", Status: "active", TrustTier: "T1", Labels: map[string]string{"team": "claims", "env": "prod"}, Tools: []string{"mcp:get_claim"}},
		fakeAgent{AgentID: "agt_claims2", DisplayName: "Claims Bot Reviewer", Framework: "custom", Status: "active", Labels: map[string]string{"team": "claims", "env": "prod"}},
		fakeAgent{AgentID: "agt_claims3", DisplayName: "claims-dev", Framework: "custom", Status: "active", Labels: map[string]string{"team": "claims", "env": "dev"}},
		fakeAgent{AgentID: "agt_claims4", DisplayName: "claims-old", Framework: "custom", Status: "revoked", Labels: map[string]string{"team": "claims", "env": "prod"}},
		fakeAgent{AgentID: "agt_dup1", DisplayName: "Twin", Status: "active", Labels: map[string]string{}},
		fakeAgent{AgentID: "agt_dup2", DisplayName: "twin", Status: "inactive", Labels: map[string]string{}},
	)
	base := providerBlock(ts.URL)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				// By name (exact, though the api's search is a contains-match), by id, and by
				// labels, feeding the ids to memberships.
				Config: base + `
data "ponte_agent" "by_name" { name = "claims bot" }
data "ponte_agent" "by_id"   { agent_id = "agt_claims3" }
data "ponte_agents" "prod_claims" {
  labels = { team = "claims", env = "prod" }
}
data "ponte_agents" "all_claims" {
  labels = { team = "claims" }
  status = "any"
}
data "ponte_agents" "everyone" {}
resource "ponte_agent_group" "claims" { name = "Claims" }
resource "ponte_agent_group_member" "each" {
  count    = length(data.ponte_agents.prod_claims.ids)
  group_id = ponte_agent_group.claims.id
  agent_id = data.ponte_agents.prod_claims.ids[count.index]
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ponte_agent.by_name", "id", "agt_claims1"),
					resource.TestCheckResourceAttr("data.ponte_agent.by_name", "name", "Claims Bot"),
					resource.TestCheckResourceAttr("data.ponte_agent.by_name", "labels.team", "claims"),
					resource.TestCheckResourceAttr("data.ponte_agent.by_name", "tools.0", "mcp:get_claim"),
					resource.TestCheckResourceAttr("data.ponte_agent.by_name", "trust_tier", "T1"),
					resource.TestCheckResourceAttr("data.ponte_agent.by_id", "name", "claims-dev"),
					// Active only by default: the revoked agent is left out.
					resource.TestCheckResourceAttr("data.ponte_agents.prod_claims", "ids.#", "2"),
					resource.TestCheckResourceAttr("data.ponte_agents.prod_claims", "ids.0", "agt_claims1"),
					resource.TestCheckResourceAttr("data.ponte_agents.prod_claims", "names.agt_claims2", "Claims Bot Reviewer"),
					resource.TestCheckResourceAttr("data.ponte_agents.all_claims", "ids.#", "4"),
					// Every page was read: 230 fillers, 3 active claims agents, 1 active twin.
					resource.TestCheckResourceAttr("data.ponte_agents.everyone", "ids.#", "234"),
					func(*terraform.State) error {
						for _, m := range f.members {
							if len(m) != 2 || !m["agt_claims1"] || !m["agt_claims2"] {
								return fmt.Errorf("members: %v", m)
							}
						}
						return nil
					},
				),
			},
			{
				Config:      base + `data "ponte_agent" "x" { name = "Twin" }`,
				ExpectError: regexp.MustCompile(`More than one agent has that name`),
			},
			{
				Config:      base + `data "ponte_agent" "x" { name = "nobody" }`,
				ExpectError: regexp.MustCompile(`No agent is named`),
			},
			{
				Config:      base + `data "ponte_agent" "x" { agent_id = "agt_missing" }`,
				ExpectError: regexp.MustCompile(`No agent has the id`),
			},
			{
				Config:      base + `data "ponte_agent" "x" {}`,
				ExpectError: regexp.MustCompile(`Set agent_id or name`),
			},
		},
	})
}
