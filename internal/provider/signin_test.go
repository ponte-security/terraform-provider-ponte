package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const groupResource = `
resource "ponte_agent_group" "g" {
  name = "Claims"
}
`

// An unattended run signs in as an automation identity: with its API key, or with the
// pipeline's own identity and no secret at all.
func TestAccSignInAsAutomationIdentity(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	tokenFile := filepath.Join(t.TempDir(), "oidc-token")
	if err := os.WriteFile(tokenFile, []byte("pipeline-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]string{
		"an API key":                     `api_key = "pak_test_key"`,
		"the pipeline's token":           "identity_id = \"auto_ci\"\n  oidc_token = \"pipeline-jwt\"",
		"the pipeline's token in a file": fmt.Sprintf("identity_id = \"auto_ci\"\n  oidc_token_file = %q", tokenFile),
	} {
		t.Run(name, func(t *testing.T) {
			f, ts := startFake("an-operator-token-nobody-has")
			defer ts.Close()
			f.apiKey, f.identityID, f.pipelineToken = "pak_test_key", "auto_ci", "pipeline-jwt"
			cfg := fmt.Sprintf("provider \"ponte\" {\n  endpoint = %q\n  %s\n}\n", ts.URL+"/api/control", block) + groupResource
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: providerFactories(),
				Steps:                    []resource.TestStep{{Config: cfg, Check: resource.TestMatchResourceAttr("ponte_agent_group.g", "id", regexp.MustCompile(`^grp_`))}},
			})
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.signIns == 0 {
				t.Fatal("the provider never signed in")
			}
		})
	}
}

func TestAccSignInProblemsAreSaidPlainly(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	f, ts := startFake("an-operator-token-nobody-has")
	defer ts.Close()
	f.apiKey = "pak_test_key"
	for _, k := range []string{"PONTE_OPERATOR_TOKEN", "PONTE_API_KEY", "PONTE_IDENTITY_ID", "PONTE_OIDC_TOKEN", "PONTE_OIDC_TOKEN_FILE",
		"TFC_WORKLOAD_IDENTITY_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"} {
		t.Setenv(k, "")
	}
	for name, c := range map[string]struct{ block, want string }{
		"nothing to sign in with":            {``, `No way to sign in to Ponte is set`},
		"a key Ponte does not know":          {`api_key = "pak_wrong"`, `signing in to Ponte`},
		"an identity with no pipeline token": {`identity_id = "auto_ci"`, `pipeline's identity token was not found`},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := fmt.Sprintf("provider \"ponte\" {\n  endpoint = %q\n  %s\n}\n", ts.URL+"/api/control", c.block) + groupResource
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: providerFactories(),
				Steps:                    []resource.TestStep{{Config: cfg, ExpectError: regexp.MustCompile(regexp.QuoteMeta(c.want))}},
			})
		})
	}
}
