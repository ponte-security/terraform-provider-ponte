package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ponte-ai/terraform-provider-ponte/internal/client"
)

// ── ponte_agent_group_member: one agent in one group ──

type agentGroupMemberResource struct {
	c *client.Client
}

type agentGroupMemberModel struct {
	ID      types.String `tfsdk:"id"`
	GroupID types.String `tfsdk:"group_id"`
	AgentID types.String `tfsdk:"agent_id"`
}

func newAgentGroupMemberResource() resource.Resource { return &agentGroupMemberResource{} }

func (r *agentGroupMemberResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_group_member"
}

func (r *agentGroupMemberResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Membership of one agent in one agent group.",
		Attributes: map[string]schema.Attribute{
			"id":       schema.StringAttribute{Computed: true, Description: "group_id/agent_id.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"group_id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"agent_id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		},
	}
}

func (r *agentGroupMemberResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

func (r *agentGroupMemberResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan agentGroupMemberModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.AddGroupMember(ctx, plan.GroupID.ValueString(), plan.AgentID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Adding the agent to the group failed", err.Error())
		return
	}
	plan.ID = types.StringValue(plan.GroupID.ValueString() + "/" + plan.AgentID.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *agentGroupMemberResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state agentGroupMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	members, err := r.c.GroupMembers(ctx, state.GroupID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the group's members failed", err.Error())
		return
	}
	for _, id := range members {
		if id == state.AgentID.ValueString() {
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}

func (r *agentGroupMemberResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	// Both attributes require replacement; nothing updates in place.
}

func (r *agentGroupMemberResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state agentGroupMemberModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.RemoveGroupMember(ctx, state.GroupID.ValueString(), state.AgentID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Removing the agent from the group failed", err.Error())
	}
}

func (r *agentGroupMemberResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	g, a, ok := strings.Cut(req.ID, "/")
	if !ok || g == "" || a == "" {
		resp.Diagnostics.AddError("Import id must be group_id/agent_id", req.ID)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &agentGroupMemberModel{ID: types.StringValue(req.ID), GroupID: types.StringValue(g), AgentID: types.StringValue(a)})...)
}

// ── ponte_policy_binding: one policy bound directly to one agent ──
//
// Bindings follow the policy NAME across versions on the server: when a new version is saved,
// the agent is bound to the new policy_id. The resource takes the policy_id from ponte_policy,
// which changes on every edit, so Terraform replaces the binding; both halves are idempotent
// (the old id is already gone, the new id is already bound).

type policyBindingResource struct {
	c *client.Client
}

type policyBindingModel struct {
	ID       types.String `tfsdk:"id"`
	AgentID  types.String `tfsdk:"agent_id"`
	PolicyID types.String `tfsdk:"policy_id"`
}

func newPolicyBindingResource() resource.Resource { return &policyBindingResource{} }

func (r *policyBindingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy_binding"
}

func (r *policyBindingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Binds a policy to one agent directly (beside the policy's subject selector). Use ponte_policy.x.policy_id; the binding follows the policy across versions.",
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true, Description: "agent_id/policy_id.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"agent_id":  schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"policy_id": schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		},
	}
}

func (r *policyBindingResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

func (r *policyBindingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyBindingModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.BindPolicy(ctx, plan.AgentID.ValueString(), plan.PolicyID.ValueString()); err != nil {
		// Already bound (the server moved the binding to this version): fine.
		bound, lerr := r.c.AgentPolicyBindings(ctx, plan.AgentID.ValueString())
		if lerr != nil || !contains(bound, plan.PolicyID.ValueString()) {
			resp.Diagnostics.AddError("Binding the policy failed", err.Error())
			return
		}
	}
	plan.ID = types.StringValue(plan.AgentID.ValueString() + "/" + plan.PolicyID.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyBindingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyBindingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	bound, err := r.c.AgentPolicyBindings(ctx, state.AgentID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the agent's bindings failed", err.Error())
		return
	}
	if !contains(bound, state.PolicyID.ValueString()) {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *policyBindingResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {}

func (r *policyBindingResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyBindingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.UnbindPolicy(ctx, state.AgentID.ValueString(), state.PolicyID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unbinding the policy failed", err.Error())
	}
}

func (r *policyBindingResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	a, p, ok := strings.Cut(req.ID, "/")
	if !ok || a == "" || p == "" {
		resp.Diagnostics.AddError("Import id must be agent_id/policy_id", req.ID)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &policyBindingModel{ID: types.StringValue(req.ID), AgentID: types.StringValue(a), PolicyID: types.StringValue(p)})...)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
