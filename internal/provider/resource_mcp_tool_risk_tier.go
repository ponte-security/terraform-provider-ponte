package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ponte-security/terraform-provider-ponte/internal/client"
)

// ponte_mcp_tool_risk_tier: the declared risk tier of one tool on one MCP server. The declared
// tier is what a risk-tier policy reads; the tier Ponte infers from the tool's name is only a
// suggestion. The tool must already be pinned (the server has been synced).
//
// The api has no way to clear a declaration, so destroy leaves it in place and says so: an
// undeclared tool is what a policy refuses for being unreviewed, and the provider does not
// turn a reviewed tool back into one by omission.

type mcpToolRiskTierResource struct {
	c *client.Client
}

type mcpToolRiskTierModel struct {
	ID       types.String `tfsdk:"id"`
	ServerID types.String `tfsdk:"server_id"`
	Tool     types.String `tfsdk:"tool"`
	RiskTier types.String `tfsdk:"risk_tier"`
}

func newMCPToolRiskTierResource() resource.Resource { return &mcpToolRiskTierResource{} }

func (r *mcpToolRiskTierResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mcp_tool_risk_tier"
}

func (r *mcpToolRiskTierResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The declared risk tier of one tool on a registered MCP server. Policies read the declared tier. The tool must be pinned first (sync the server). Destroy removes the resource from state and leaves the declaration in Ponte.",
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true, Description: "server_id/tool", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"server_id": schema.StringAttribute{Required: true, Description: "ponte_mcp_server id.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"tool":      schema.StringAttribute{Required: true, Description: "The tool's name as the server lists it.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"risk_tier": schema.StringAttribute{Required: true, Description: "read, write, external_send, destructive or code_exec."},
		},
	}
}

func (r *mcpToolRiskTierResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

func (r *mcpToolRiskTierResource) declare(ctx context.Context, m *mcpToolRiskTierModel) error {
	server, tool := m.ServerID.ValueString(), m.Tool.ValueString()
	if err := r.c.DeclareToolRiskTier(ctx, server, tool, m.RiskTier.ValueString()); err != nil {
		return err
	}
	m.ID = types.StringValue(server + "/" + tool)
	return nil
}

func (r *mcpToolRiskTierResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan mcpToolRiskTierModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.declare(ctx, &plan); err != nil {
		detail := err.Error()
		if client.IsNotFound(err) {
			detail += "\n\nA tier can only be declared for a tool Ponte has pinned. Sync the MCP server (MCP Servers → Sync, or POST /api/v1/mcp-servers/{id}/sync) and apply again."
		}
		resp.Diagnostics.AddError("Declaring the risk tier failed", detail)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mcpToolRiskTierResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state mcpToolRiskTierModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tier, err := r.c.ToolRiskTier(ctx, state.ServerID.ValueString(), state.Tool.ValueString())
	if client.IsNotFound(err) || (err == nil && tier == "") {
		// The tool (or its server) is gone, or the declaration was cleared: plan a create.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the risk tier failed", err.Error())
		return
	}
	state.RiskTier = types.StringValue(tier)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *mcpToolRiskTierResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan mcpToolRiskTierModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.declare(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Declaring the risk tier failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mcpToolRiskTierResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state mcpToolRiskTierModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.AddWarning("The risk tier stays declared in Ponte",
		"Ponte has no way to clear a declared tier, so "+state.Tool.ValueString()+" keeps tier "+state.RiskTier.ValueString()+
			" until it is declared again or its MCP server is deregistered. Terraform no longer manages it.")
}

func (r *mcpToolRiskTierResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	server, tool, ok := strings.Cut(req.ID, "/")
	if !ok || server == "" || tool == "" {
		resp.Diagnostics.AddError("Invalid import id", "Use server_id/tool.")
		return
	}
	tier, err := r.c.ToolRiskTier(ctx, server, tool)
	if err != nil {
		resp.Diagnostics.AddError("Reading the risk tier failed", err.Error())
		return
	}
	if tier == "" {
		resp.Diagnostics.AddError("No declared tier to import", tool+" has no declared risk tier on "+server+".")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &mcpToolRiskTierModel{
		ID: types.StringValue(req.ID), ServerID: types.StringValue(server), Tool: types.StringValue(tool), RiskTier: types.StringValue(tier),
	})...)
}
