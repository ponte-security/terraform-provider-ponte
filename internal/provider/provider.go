// Package provider is the Terraform provider for Ponte: policies, agent groups and their
// members, and policy bindings, as code. It speaks to the control plane's operator API with
// an operator token (the same PONTE_OPERATOR_TOKEN the ponte CLI uses).
package provider

import (
	"context"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ponte-ai/terraform-provider-ponte/internal/client"
)

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &ponteProvider{version: version} }
}

type ponteProvider struct {
	version string
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
}

func (p *ponteProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ponte"
	resp.Version = p.version
}

func (p *ponteProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage Ponte authorization resources: policies, agent groups, memberships and policy bindings.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "The control plane base URL, e.g. https://app.ponte.ai/api/control. Defaults to PONTE_API_URL.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "An operator token (a signed-in operator's access token). Defaults to PONTE_OPERATOR_TOKEN. An agent's token is refused by the control plane.",
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
	endpoint := strings.TrimSpace(cfg.Endpoint.ValueString())
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("PONTE_API_URL"))
	}
	token := strings.TrimSpace(cfg.Token.ValueString())
	if token == "" {
		token = strings.TrimSpace(os.Getenv("PONTE_OPERATOR_TOKEN"))
	}
	if endpoint == "" {
		resp.Diagnostics.AddError("Ponte endpoint is not set", "Set provider \"endpoint\" or PONTE_API_URL, e.g. https://app.ponte.ai/api/control.")
	}
	if token == "" {
		resp.Diagnostics.AddError("Ponte operator token is not set", "Set provider \"token\" or PONTE_OPERATOR_TOKEN to an operator's access token.")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	c := client.New(endpoint, token, "terraform-provider-ponte/"+p.version)
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *ponteProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newPolicyResource,
		newAgentGroupResource,
		newAgentGroupMemberResource,
		newPolicyBindingResource,
	}
}

func (p *ponteProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

// clientFrom pulls the configured client out of a resource configure request.
func clientFrom(data any) *client.Client {
	c, _ := data.(*client.Client)
	return c
}
