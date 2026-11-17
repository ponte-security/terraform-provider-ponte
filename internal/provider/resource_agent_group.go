package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ponte-ai/terraform-provider-ponte/internal/client"
)

// ponte_agent_group: a group agents are members of, which policies target (subjects.groups).

type agentGroupResource struct {
	c *client.Client
}

type agentGroupModel struct {
	ID                  types.String `tfsdk:"id"`
	Name                types.String `tfsdk:"name"`
	Description         types.String `tfsdk:"description"`
	TrustLevel          types.String `tfsdk:"trust_level"`
	Owner               types.String `tfsdk:"owner"`
	Tags                types.List   `tfsdk:"tags"`
	MaxConcurrentAgents types.Int64  `tfsdk:"max_concurrent_agents"`
}

func newAgentGroupResource() resource.Resource { return &agentGroupResource{} }

func (r *agentGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_group"
}

func (r *agentGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An agent group. Policies target groups through subjects; agents join through ponte_agent_group_member.",
		Attributes: map[string]schema.Attribute{
			"id":                    schema.StringAttribute{Computed: true, Description: "The group id (grp_…).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":                  schema.StringAttribute{Required: true, Description: "Display name."},
			"description":           schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("")},
			"trust_level":           schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("associate"), Description: "The group's trust level (associate by default)."},
			"owner":                 schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("unknown"), Description: "The owning person or team."},
			"tags":                  schema.ListAttribute{ElementType: types.StringType, Optional: true, Description: "Free-form tags."},
			"max_concurrent_agents": schema.Int64Attribute{Optional: true, Description: "Cap on simultaneously active member agents."},
		},
	}
}

func (r *agentGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

func (m *agentGroupModel) input(ctx context.Context) client.GroupInput {
	in := client.GroupInput{Name: m.Name.ValueString(), Description: m.Description.ValueString(), TrustLevel: m.TrustLevel.ValueString(), Owner: m.Owner.ValueString(), Tags: []string{}}
	if !m.Tags.IsNull() && !m.Tags.IsUnknown() {
		_ = m.Tags.ElementsAs(ctx, &in.Tags, false)
	}
	if !m.MaxConcurrentAgents.IsNull() && !m.MaxConcurrentAgents.IsUnknown() {
		v := int(m.MaxConcurrentAgents.ValueInt64())
		in.MaxConcurrentAgents = &v
	}
	return in
}

func (m *agentGroupModel) fill(ctx context.Context, g *client.Group) {
	m.ID = types.StringValue(g.GroupID)
	m.Name = types.StringValue(g.Name)
	m.Description = types.StringValue(g.Description)
	m.TrustLevel = types.StringValue(g.TrustLevel)
	m.Owner = types.StringValue(g.Owner)
	if len(g.Tags) > 0 || !m.Tags.IsNull() {
		tags, _ := types.ListValueFrom(ctx, types.StringType, g.Tags)
		if len(g.Tags) == 0 {
			tags, _ = types.ListValueFrom(ctx, types.StringType, []string{})
		}
		m.Tags = tags
	}
	if g.MaxConcurrentAgents != nil {
		m.MaxConcurrentAgents = types.Int64Value(int64(*g.MaxConcurrentAgents))
	} else {
		m.MaxConcurrentAgents = types.Int64Null()
	}
}

func (r *agentGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan agentGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	g, err := r.c.CreateGroup(ctx, plan.input(ctx))
	if err != nil {
		resp.Diagnostics.AddError("Creating the agent group failed", err.Error())
		return
	}
	plan.fill(ctx, g)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *agentGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state agentGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	g, err := r.c.GetGroup(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the agent group failed", err.Error())
		return
	}
	state.fill(ctx, g)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *agentGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state agentGroupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	g, err := r.c.UpdateGroup(ctx, state.ID.ValueString(), plan.input(ctx))
	if err != nil {
		resp.Diagnostics.AddError("Updating the agent group failed", err.Error())
		return
	}
	plan.fill(ctx, g)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *agentGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state agentGroupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.DeleteGroup(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Deleting the agent group failed", err.Error())
	}
}

func (r *agentGroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	g, err := r.c.GetGroup(ctx, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Reading the agent group failed", err.Error())
		return
	}
	var m agentGroupModel
	m.fill(ctx, g)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
