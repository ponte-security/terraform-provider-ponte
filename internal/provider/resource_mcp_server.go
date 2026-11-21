package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ponte-security/terraform-provider-ponte/internal/client"
)

// ponte_mcp_server: a registered MCP server. Registration is in the authorization path (the
// PDP stamps input.mcp_server.registered), so declaring the fleet's servers here is what lets
// a policy refuse the ones nobody declared.
//
// The endpoint is the server's identity: its pinned tool definitions belong to that endpoint,
// so a changed endpoint replaces the resource. Everything else is edited in place.

type mcpServerResource struct {
	c *client.Client
}

type mcpServerModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	EndpointURL        types.String `tfsdk:"endpoint_url"`
	DataClassification types.String `tfsdk:"data_classification"`
	Environment        types.String `tfsdk:"environment"`
	Owner              types.String `tfsdk:"owner"`
	RequireToolReview  types.Bool   `tfsdk:"require_tool_review"`
	Status             types.String `tfsdk:"status"`
}

func newMCPServerResource() resource.Resource { return &mcpServerResource{} }

func (r *mcpServerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_mcp_server"
}

func (r *mcpServerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A registered MCP server. Policies can refuse servers that are not registered. Destroy deregisters the server and deletes its pinned tool definitions, proxy configuration and sync credential.",
		Attributes: map[string]schema.Attribute{
			"id":   schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Required: true, Description: "3 to 64 characters."},
			"endpoint_url": schema.StringAttribute{Required: true, Description: "https URL (http only for localhost). One registration per endpoint. Changing it replaces the resource: pinned tools belong to the endpoint.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"data_classification": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("internal"), Validators: []validator.String{oneOf("public", "internal", "confidential", "restricted", "pii")}, Description: "public, internal, confidential, restricted or pii."},
			"environment":         schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("development")},
			"owner":               schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"require_tool_review": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(false), Description: "true: a newly seen tool is denied until an operator approves it. false: a new tool is trusted on first use."},
			"status":              schema.StringAttribute{Computed: true, PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		},
	}
}

func (r *mcpServerResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

func (m *mcpServerModel) input() client.MCPServerInput {
	return client.MCPServerInput{Name: m.Name.ValueString(), EndpointURL: m.EndpointURL.ValueString(),
		DataClassification: m.DataClassification.ValueString(), Environment: m.Environment.ValueString(), Owner: m.Owner.ValueString()}
}

func (m *mcpServerModel) fill(s *client.MCPServer) {
	m.ID = types.StringValue(s.ResourceID)
	m.Name = types.StringValue(s.Name)
	m.EndpointURL = types.StringValue(s.EndpointURL)
	m.DataClassification = types.StringValue(s.DataClassification)
	m.Environment = types.StringValue(s.Environment)
	m.Owner = types.StringValue(s.Owner)
	m.RequireToolReview = types.BoolValue(s.RequireToolReview)
	m.Status = types.StringValue(s.Status)
}

func (r *mcpServerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan mcpServerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.c.RegisterMCPServer(ctx, plan.input())
	if err != nil {
		resp.Diagnostics.AddError("Registering the MCP server failed", err.Error())
		return
	}
	// The server exists from here on: keep its id in state even if a later step fails, so the
	// next apply finishes the job instead of hitting "this endpoint is already registered".
	plan.ID = types.StringValue(id)
	plan.Status = types.StringValue("active")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if plan.RequireToolReview.ValueBool() {
		if err := r.c.SetMCPServerReviewMode(ctx, id, true); err != nil {
			resp.Diagnostics.AddError("Setting the review mode failed", err.Error())
			return
		}
	}
	s, err := r.c.GetMCPServer(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Reading the MCP server failed", err.Error())
		return
	}
	plan.fill(s)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mcpServerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state mcpServerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	s, err := r.c.GetMCPServer(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the MCP server failed", err.Error())
		return
	}
	state.fill(s)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *mcpServerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state mcpServerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ID.ValueString()
	if plan.input() != state.input() {
		if err := r.c.UpdateMCPServer(ctx, id, plan.input()); err != nil {
			resp.Diagnostics.AddError("Updating the MCP server failed", err.Error())
			return
		}
	}
	if plan.RequireToolReview.ValueBool() != state.RequireToolReview.ValueBool() {
		if err := r.c.SetMCPServerReviewMode(ctx, id, plan.RequireToolReview.ValueBool()); err != nil {
			resp.Diagnostics.AddError("Setting the review mode failed", err.Error())
			return
		}
	}
	s, err := r.c.GetMCPServer(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Reading the MCP server failed", err.Error())
		return
	}
	plan.fill(s)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *mcpServerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state mcpServerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.DeleteMCPServer(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Deregistering the MCP server failed", err.Error())
	}
}

func (r *mcpServerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	s, err := r.c.GetMCPServer(ctx, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Reading the MCP server failed", err.Error())
		return
	}
	var m mcpServerModel
	m.fill(s)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
