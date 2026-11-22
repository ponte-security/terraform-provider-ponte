package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccSCIMTarget(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	cfg := func(name, token string, enabled bool) string {
		return providerBlock(ts.URL) + fmt.Sprintf(`
resource "ponte_scim_target" "iga" {
  name         = %q
  base_url     = "https://iga.example.com/scim/v2"
  bearer_token = %q
  enabled      = %t
}
`, name, token, enabled)
	}
	only := func() *fakeSCIMTarget {
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.scimTargets) != 1 {
			return nil
		}
		for _, t := range f.scimTargets {
			return t
		}
		return nil
	}
	var firstID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				// Created disabled: the control plane creates it enabled, and it is turned off.
				Config: cfg("IGA", "secret-1", false),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("ponte_scim_target.iga", "id", regexp.MustCompile(`^scimtg_`)),
					resource.TestCheckResourceAttr("ponte_scim_target.iga", "enabled", "false"),
					func(_ *terraformState) error {
						x := only()
						if x == nil || x.Enabled || x.token != "secret-1" {
							return fmt.Errorf("target on the control plane: %+v", x)
						}
						firstID = x.TargetID
						return nil
					},
				),
			},
			{
				// enabled changes in place.
				Config: cfg("IGA", "secret-1", true),
				Check: func(_ *terraformState) error {
					if x := only(); x == nil || !x.Enabled || x.TargetID != firstID {
						return fmt.Errorf("enabling replaced or missed the target: %+v", x)
					}
					return nil
				},
			},
			{
				// The credential is never returned, so the import cannot verify it.
				ResourceName: "ponte_scim_target.iga", ImportState: true, ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{"bearer_token"},
			},
			{
				// A new credential replaces the target: there is no way to change one in place.
				Config: cfg("IGA", "secret-2", true),
				Check: func(_ *terraformState) error {
					if x := only(); x == nil || x.token != "secret-2" || x.TargetID == firstID {
						return fmt.Errorf("a changed credential did not replace the target: %+v", x)
					}
					return nil
				},
			},
		},
	})
	if x := only(); x != nil {
		t.Fatalf("destroy left a target: %+v", x)
	}
}

// An imported target has no credential in state. The first apply records the configured one
// and must not delete a working target to do it.
func TestAccSCIMTargetImportKeepsTheTarget(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	f.scimTargets = map[string]*fakeSCIMTarget{"scimtg_existing": {TargetID: "scimtg_existing", Name: "IGA", BaseURL: "https://iga.example.com/scim/v2", Enabled: true, token: "set-in-console"}}
	cfg := providerBlock(ts.URL) + `
resource "ponte_scim_target" "iga" {
  name         = "IGA"
  base_url     = "https://iga.example.com/scim/v2"
  bearer_token = "set-in-console"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{Config: cfg, ResourceName: "ponte_scim_target.iga", ImportState: true, ImportStateId: "scimtg_existing", ImportStatePersist: true},
			{Config: cfg, Check: resource.TestCheckResourceAttr("ponte_scim_target.iga", "id", "scimtg_existing")},
			{Config: cfg, PlanOnly: true},
		},
	})
}

func TestAccRecertPolicy(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake(testToken)
	defer ts.Close()
	minimal := providerBlock(ts.URL) + `
resource "ponte_recert_policy" "quarterly" {
  name = "Quarterly"
}
`
	full := providerBlock(ts.URL) + `
resource "ponte_recert_policy" "quarterly" {
  name           = "Quarterly access review"
  reviewer       = "group"
  reviewer_ref   = "iga-reviewers"
  second_review  = "high_risk"
  second_group   = "security"
  due_days       = 14
  remind_days    = 3
  on_overdue     = "escalate"
  escalate_group = "security-leads"
  on_deny        = "suspend"
  auto_certify = [
    { field = "risk_tier", op = "eq", value = "low" },
    { field = "stale_days", op = "lt", value = "30" },
  ]
}
`
	stored := func() *fakeRecertPolicy {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, p := range f.recertPolicies {
			return p
		}
		return nil
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: providerFactories(),
		Steps: []resource.TestStep{
			{
				// Only a name: the defaults are today's behaviour (the owner reviews, a denial revokes).
				Config: minimal,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("ponte_recert_policy.quarterly", "id", regexp.MustCompile(`^rp_`)),
					resource.TestCheckResourceAttr("ponte_recert_policy.quarterly", "reviewer", "owner"),
					resource.TestCheckResourceAttr("ponte_recert_policy.quarterly", "second_review", "none"),
					resource.TestCheckResourceAttr("ponte_recert_policy.quarterly", "on_overdue", "keep_open"),
					resource.TestCheckResourceAttr("ponte_recert_policy.quarterly", "on_deny", "revoke"),
					resource.TestCheckResourceAttr("ponte_recert_policy.quarterly", "escalate_days", "0"),
				),
			},
			{Config: minimal, ResourceName: "ponte_recert_policy.quarterly", ImportState: true, ImportStateVerify: true},
			{
				// Everything set, in place: same id; the control plane fills the escalation days.
				Config: full,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ponte_recert_policy.quarterly", "escalate_days", "7"),
					resource.TestCheckResourceAttr("ponte_recert_policy.quarterly", "auto_certify.#", "2"),
					func(_ *terraformState) error {
						p := stored()
						if p == nil || p.Name != "Quarterly access review" || p.Spec.SecondReview != "high_risk" || p.Spec.OnDeny != "suspend" ||
							len(p.Spec.AutoCertify) != 2 || p.Spec.AutoCertify[1]["field"] != "stale_days" || len(f.recertPolicies) != 1 {
							return fmt.Errorf("stored policy: %+v", p)
						}
						return nil
					},
				),
			},
			{Config: full, PlanOnly: true},
			{Config: full, ResourceName: "ponte_recert_policy.quarterly", ImportState: true, ImportStateVerify: true},
			{
				// Back to the minimum: every member is cleared, not left behind.
				Config: minimal,
				Check: func(_ *terraformState) error {
					p := stored()
					if p == nil || p.Spec.Reviewer != "owner" || p.Spec.SecondReview != "" || p.Spec.DueDays != 0 || len(p.Spec.AutoCertify) != 0 || p.Spec.EscalateGroup != "" {
						return fmt.Errorf("members left behind: %+v", p)
					}
					return nil
				},
			},
			{
				// In use by a schedule: destroy is refused with what to do about it.
				PreConfig:   func() { stored().UsedBy = 1 },
				Config:      providerBlock(ts.URL),
				ExpectError: regexp.MustCompile(`in use`),
			},
			{PreConfig: func() { stored().UsedBy = 0 }, Config: minimal},
		},
	})
	if p := stored(); p != nil {
		t.Fatalf("destroy left a policy: %+v", p)
	}
}

func TestAccRecertPolicyValidation(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	_, ts := startFake(testToken)
	defer ts.Close()
	for _, c := range []struct{ name, attrs, want string }{
		{"group reviewer without a group", `reviewer = "group"`, "reviewer_ref is required"},
		{"second review without a group", `second_review = "all"`, "second_group is required"},
		{"reminder without a deadline", `remind_days = 2`, "A reminder needs a deadline"},
		{"reminder after the deadline", "due_days = 5\n  remind_days = 5", "must come before the deadline"},
		{"deadline action without a deadline", `on_overdue = "revoke"`, "needs a deadline"},
		{"escalation without a group", "due_days = 5\n  on_overdue = \"escalate\"", "escalate_group is required"},
		{"an unknown reviewer", `reviewer = "manager"`, `"manager" is not one of`},
		{"an unknown denial action", `on_deny = "delete"`, `"delete" is not one of`},
	} {
		t.Run(c.name, func(t *testing.T) {
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: providerFactories(),
				Steps: []resource.TestStep{{
					Config:      providerBlock(ts.URL) + "resource \"ponte_recert_policy\" \"p\" {\n  name = \"p\"\n  " + c.attrs + "\n}\n",
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(regexp.QuoteMeta(c.want)),
				}},
			})
		})
	}
}
