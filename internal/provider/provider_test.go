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
`, endpoint, testToken)
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
