package provider

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func policyResourceConfig(endpoint, yaml, mode string) string {
	return providerBlock(endpoint) + fmt.Sprintf(`
resource "ponte_policy" "guard" {
  ppl              = <<-EOT
%s
EOT
  enforcement_mode = %q
}
`, yaml, mode)
}

// An observe policy is stored observing by the create itself, on the first version and on
// every later one: it never enforces between two calls.
func TestAccPolicyObserveNeverEnforcesFirst(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: policyResourceConfig(ts.URL, policyYAML("guard", "first", "mail:send"), "observe"),
				Check: resource.TestCheckResourceAttr("ponte_policy.guard", "enforcement_mode", "observe")},
			{Config: policyResourceConfig(ts.URL, policyYAML("guard", "second", "db:drop"), "observe"),
				Check: resource.TestCheckResourceAttr("ponte_policy.guard", "version", "2")},
		},
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := strings.Join(f.createdModes, ","); got != "observe,observe" {
		t.Fatalf("versions were stored as %q, want observe,observe", got)
	}
	if f.modePatches != 0 {
		t.Fatalf("%d mode changes after create, want none", f.modePatches)
	}
}

// A control plane that predates the mode on create still ends in the mode asked for.
func TestAccPolicyObserveOnOlderControlPlane(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	f.ignoreModeOnCreate = true
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: policyResourceConfig(ts.URL, policyYAML("guard", "first", "mail:send"), "observe"),
				Check: resource.TestCheckResourceAttr("ponte_policy.guard", "enforcement_mode", "observe")},
		},
	})
	if f.modePatches != 1 {
		t.Fatalf("%d mode changes, want 1", f.modePatches)
	}
}

// A change to the text that is not a change to the policy plans nothing; a version saved
// outside Terraform is noticed and the configured policy is put back.
func TestAccPolicyMeaningAndConsoleEdit(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	original := policyYAML("guard", "first", "mail:send")
	// The same policy: a comment, a blank line and the two top-level keys the other way round.
	reworded := "# reviewed by the platform team\nkind: AgentPolicy\napiVersion: ponte.io/v1\n\n" + strings.SplitN(original, "kind: AgentPolicy\n", 2)[1]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: policyResourceConfig(ts.URL, original, "enforce"),
				Check: resource.TestCheckResourceAttr("ponte_policy.guard", "version", "1")},
			{Config: policyResourceConfig(ts.URL, reworded, "enforce"), PlanOnly: true},
			{Config: policyResourceConfig(ts.URL, reworded, "enforce"),
				Check: resource.TestCheckResourceAttr("ponte_policy.guard", "version", "1")},
			{
				// Someone allows the tool in the console: version 2, not Terraform's.
				PreConfig: func() { f.consoleEdit(policyYAML("guard", "first", "anything:else")) },
				Config:    policyResourceConfig(ts.URL, reworded, "enforce"),
				Check:     resource.TestCheckResourceAttr("ponte_policy.guard", "version", "3"),
			},
		},
	})
}

// Importing a policy and then applying a configuration that says the same thing saves nothing.
func TestAccPolicyImportSavesNoSecondVersion(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	yaml := policyYAML("guard", "first", "mail:send")
	f.consoleEdit(yaml) // the policy exists before Terraform knows it
	cfg := policyResourceConfig(ts.URL, yaml, "enforce")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: cfg, ResourceName: "ponte_policy.guard", ImportState: true, ImportStateId: "guard", ImportStatePersist: true},
			{Config: cfg, Check: resource.TestCheckResourceAttr("ponte_policy.guard", "version", "1")},
		},
	})
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.policies) != 1 {
		t.Fatalf("%d versions after import and apply, want 1", len(f.policies))
	}
}

// Values the API refuses are refused when Terraform plans, not half way through an apply.
func TestAccPlanTimeValidation(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	_, ts := startFake(testToken)
	defer ts.Close()
	cases := []struct{ name, body, want string }{
		{"budget scope spelled with a capital", `resource "ponte_spend_budget" "b" {
  scope = "Org"
  monthly_usd = 5
}`, `"Org" is not one of`},
		{"budget with no limit", `resource "ponte_spend_budget" "b" {
  scope = "org"
}`, `A budget needs a limit`},
		{"team budget with no ref", `resource "ponte_spend_budget" "b" {
  scope = "team"
  monthly_usd = 5
}`, `ref is required`},
		{"policy mode", policyResourceConfig("", policyYAML("g", "d", "t"), "audit"), `"audit" is not one of`},
		{"webhook severity", `resource "ponte_webhook" "w" {
  name = "w"
  url = "https://example.com/h"
  event_types = ["*"]
  min_severity = "low"
}`, `"low" is not one of`},
		{"risk tier", `resource "ponte_mcp_tool_risk_tier" "t" {
  server_id = "res_1"
  tool = "x"
  risk_tier = "admin"
}`, `"admin" is not one of`},
		{"data classification", `resource "ponte_mcp_server" "s" {
  name = "srv"
  endpoint_url = "https://mcp.example.com"
  data_classification = "secret"
}`, `"secret" is not one of`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := c.body
			if !strings.Contains(body, `provider "ponte"`) {
				body = providerBlock(ts.URL) + body
			} else {
				body = strings.Replace(body, `endpoint = "/api/control"`, fmt.Sprintf("endpoint = %q", ts.URL+"/api/control"), 1)
			}
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: providerFactories(),
				Steps:                    []resource.TestStep{{Config: body, PlanOnly: true, ExpectError: regexp.MustCompile(regexp.QuoteMeta(c.want))}},
			})
		})
	}
}

// The order of event types and tags carries no meaning, and removing format_config clears it.
func TestAccWebhookOrderAndFormatConfig(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	cfg := func(events, tags, formatConfig string) string {
		return providerBlock(ts.URL) + fmt.Sprintf(`
resource "ponte_webhook" "siem" {
  name        = "siem"
  url         = "https://siem.example.com/hooks/ponte"
  event_types = %s
  format      = "udm"
  %s
}

resource "ponte_agent_group" "g" {
  name = "Claims"
  tags = %s
}
`, events, formatConfig, tags)
	}
	withConfig := `format_config = jsonencode({ product_name = "Ponte" })`
	formatConfigOf := func() string {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, w := range f.webhooks {
			if w.FormatConfig != nil {
				return string(*w.FormatConfig)
			}
		}
		return ""
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: cfg(`["receipt.issued", "authz.decision"]`, `["prod", "finance"]`, withConfig),
				Check: func(_ *terraformState) error {
					if got := formatConfigOf(); !strings.Contains(got, "Ponte") {
						return fmt.Errorf("format_config = %q, want the overrides", got)
					}
					return nil
				}},
			{Config: cfg(`["authz.decision", "receipt.issued"]`, `["finance", "prod"]`, withConfig), PlanOnly: true},
			{Config: cfg(`["authz.decision", "receipt.issued"]`, `["finance", "prod"]`, ""),
				Check: func(_ *terraformState) error {
					if got := formatConfigOf(); got != "{}" {
						return fmt.Errorf("format_config = %q after removing it, want {}", got)
					}
					return nil
				}},
		},
	})
}

func TestSamePolicy(t *testing.T) {
	base := policyYAML("guard", "first", "mail:send")
	for _, c := range []struct {
		name string
		a, b string
		want bool
	}{
		{"identical", base, base, true},
		{"comment and blank line", base, "# note\n\n" + base, true},
		{"the control plane's copy, with an empty member added", base, renderPolicy(parsedPolicy(base)), true},
		{"a different tool", base, policyYAML("guard", "first", "db:drop"), false},
		{"a different name", base, policyYAML("other", "first", "mail:send"), false},
		{"false is not the same as absent", "a: 1\nb: false\n", "a: 1\n", false},
		{"5 and 5.0", "limit: 5\n", "limit: 5.0\n", true},
		{"unreadable text only equals itself", "a: [", "a: [ ", false},
	} {
		if got := samePolicy(c.a, c.b); got != c.want {
			t.Errorf("%s: samePolicy = %v, want %v", c.name, got, c.want)
		}
	}
}
