// Package provider is the Terraform provider for Ponte: policies, agent groups and their
// members, and policy bindings, as code. It speaks to the control plane's operator API with
// an operator token (the same PONTE_OPERATOR_TOKEN the ponte CLI uses).
package provider

import (
	"context"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ponte-security/terraform-provider-ponte/internal/client"
)

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &ponteProvider{version: version} }
}

type ponteProvider struct {
	version string
}

type providerModel struct {
	Endpoint    types.String `tfsdk:"endpoint"`
	APIEndpoint types.String `tfsdk:"api_endpoint"`
	Token       types.String `tfsdk:"token"`
	APIKey      types.String `tfsdk:"api_key"`
	IdentityID  types.String `tfsdk:"identity_id"`
	OIDCToken   types.String `tfsdk:"oidc_token"`
	OIDCFile    types.String `tfsdk:"oidc_token_file"`
	OIDCAud     types.String `tfsdk:"oidc_audience"`
}

func (p *ponteProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ponte"
	resp.Version = p.version
}

func (p *ponteProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Ponte authorization resources: policies, agent groups, memberships, policy bindings, webhooks, spend budgets, MCP servers, SCIM targets and recertification review policies.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "The control plane base URL, e.g. https://api.ponte.ai/control. Defaults to PONTE_API_URL.",
			},
			"api_endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "The api base URL for webhooks, budgets and MCP servers, e.g. https://api.ponte.ai. Defaults to the endpoint without its /control suffix (or PONTE_API_BASE_URL).",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "An operator token (a signed-in operator's access token), for a person running Terraform. Defaults to PONTE_OPERATOR_TOKEN. It lasts minutes. An agent's token is refused by the control plane.",
			},
			"api_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "An automation identity's API key (Settings → Automation), for unattended runs. Defaults to PONTE_API_KEY. The provider exchanges it for a short session and renews the session during a long run.",
			},
			"identity_id": schema.StringAttribute{
				Optional:    true,
				Description: "The automation identity to sign in as with the pipeline's own OIDC identity (auto_…), so no secret is stored. Defaults to PONTE_IDENTITY_ID. The pipeline's token is read from oidc_token, oidc_token_file, TFC_WORKLOAD_IDENTITY_TOKEN, or requested from GitHub Actions (permissions: id-token: write).",
			},
			"oidc_token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "The pipeline's OIDC token. Defaults to PONTE_OIDC_TOKEN. Used with identity_id.",
			},
			"oidc_token_file": schema.StringAttribute{
				Optional:    true,
				Description: "A file holding the pipeline's OIDC token, read at every sign-in. Defaults to PONTE_OIDC_TOKEN_FILE. Used with identity_id.",
			},
			"oidc_audience": schema.StringAttribute{
				Optional:    true,
				Description: "The audience to ask GitHub Actions for, matching the identity's trust rule. Defaults to PONTE_OIDC_AUDIENCE, then to the scheme and host of the endpoint.",
			},
		},
	}
}

func (p *ponteProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// A value that is only known after another resource is applied cannot configure the
	// provider now, and falling back to the environment would quietly use a different stack.
	if cfg.Endpoint.IsUnknown() || cfg.APIEndpoint.IsUnknown() || cfg.Token.IsUnknown() || cfg.APIKey.IsUnknown() ||
		cfg.IdentityID.IsUnknown() || cfg.OIDCToken.IsUnknown() || cfg.OIDCFile.IsUnknown() || cfg.OIDCAud.IsUnknown() {
		resp.Diagnostics.AddError("Provider configuration is not known yet",
			"The provider's settings must be known when Terraform plans. Use a variable or the environment, not another resource's output.")
		return
	}
	endpoint := strings.TrimSpace(cfg.Endpoint.ValueString())
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("PONTE_API_URL"))
	}
	// How to sign in. What the configuration names wins over the environment; within each, an
	// operator token, then an API key, then the pipeline's own identity.
	val := func(v types.String, env string, fromEnv bool) string {
		if fromEnv {
			return strings.TrimSpace(os.Getenv(env))
		}
		return strings.TrimSpace(v.ValueString())
	}
	var token, apiKey, identityID string
	for _, fromEnv := range []bool{false, true} {
		token = val(cfg.Token, "PONTE_OPERATOR_TOKEN", fromEnv)
		apiKey = val(cfg.APIKey, "PONTE_API_KEY", fromEnv)
		identityID = val(cfg.IdentityID, "PONTE_IDENTITY_ID", fromEnv)
		if token != "" || apiKey != "" || identityID != "" {
			break
		}
	}
	if endpoint == "" {
		resp.Diagnostics.AddError("Ponte endpoint is not set", "Set provider \"endpoint\" or PONTE_API_URL, e.g. https://api.ponte.ai/control.")
	}
	if token == "" && apiKey == "" && identityID == "" {
		resp.Diagnostics.AddError("No way to sign in to Ponte is set",
			"Set one of: PONTE_OPERATOR_TOKEN (a person's token), PONTE_API_KEY (an automation identity's key), or PONTE_IDENTITY_ID (sign in with the pipeline's own identity).")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	c := client.New(endpoint, token, "terraform-provider-ponte/"+p.version)
	if api := strings.TrimSpace(cfg.APIEndpoint.ValueString()); api != "" {
		c.SetAPIEndpoint(api)
	} else if api := strings.TrimSpace(os.Getenv("PONTE_API_BASE_URL")); api != "" {
		c.SetAPIEndpoint(api)
	}
	switch {
	case token != "":
		// Operator tokens last minutes. Saying so here beats a 401 from the first resource.
		if at, ok := client.TokenExpiry(token); ok {
			switch left := time.Until(at); {
			case left <= 0:
				resp.Diagnostics.AddError("The operator token has expired",
					"It expired at "+at.UTC().Format(time.RFC3339)+". Get a new one and set PONTE_OPERATOR_TOKEN (or provider \"token\"). For unattended runs use an automation identity: api_key or identity_id.")
				return
			case left < time.Minute:
				resp.Diagnostics.AddWarning("The operator token is about to expire",
					"It expires at "+at.UTC().Format(time.RFC3339)+". A run that takes longer will fail part way with a 401.")
			}
		}
	case apiKey != "":
		c.UseAPIKey(apiKey)
	default:
		pipeline := client.PipelineTokenSource{
			Token: firstSet(cfg.OIDCToken.ValueString(), os.Getenv("PONTE_OIDC_TOKEN"), os.Getenv("TFC_WORKLOAD_IDENTITY_TOKEN")),
			File:  firstSet(cfg.OIDCFile.ValueString(), os.Getenv("PONTE_OIDC_TOKEN_FILE")),
			// GitHub Actions hands a job these two when it has "id-token: write".
			RequestURL:   strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")),
			RequestToken: strings.TrimSpace(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")),
			Audience:     firstSet(cfg.OIDCAud.ValueString(), os.Getenv("PONTE_OIDC_AUDIENCE"), originOf(endpoint)),
		}
		if !pipeline.Configured() {
			resp.Diagnostics.AddError("The pipeline's identity token was not found",
				"identity_id is set, so the provider signs in with the pipeline's own OIDC token, and none is available. Set oidc_token or oidc_token_file (PONTE_OIDC_TOKEN, PONTE_OIDC_TOKEN_FILE); on GitHub Actions give the job \"permissions: id-token: write\".")
			return
		}
		c.UsePipelineIdentity(identityID, func(ctx context.Context) (string, error) { return pipeline.Fetch(ctx, c.HTTP) })
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *ponteProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newPolicyResource,
		newAgentGroupResource,
		newAgentGroupMemberResource,
		newPolicyBindingResource,
		newWebhookResource,
		newSpendBudgetResource,
		newMCPServerResource,
		newMCPToolRiskTierResource,
		newSCIMTargetResource,
		newRecertPolicyResource,
	}
}

func (p *ponteProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{newAgentDataSource, newAgentsDataSource}
}

// clientFrom pulls the configured client out of a resource configure request.
func clientFrom(data any) *client.Client {
	c, _ := data.(*client.Client)
	return c
}

// firstSet returns the first value that is not empty.
func firstSet(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// originOf is the scheme and host of a URL: the audience a pipeline's token is asked for by
// default, which is what the console suggests in an identity's trust rule.
func originOf(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
