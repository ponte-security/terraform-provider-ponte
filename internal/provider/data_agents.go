package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ponte-security/terraform-provider-ponte/internal/client"
)

// Data sources for agents. Agents are registered and onboarded in Ponte (they carry
// credentials, owners and attestations Terraform should not hold), so the provider reads them:
// ponte_agent finds one by id or by name, ponte_agents finds those carrying a set of labels.
// Their ids feed ponte_agent_group_member and ponte_policy_binding.

// ── ponte_agent ──

type agentDataSource struct{ c *client.Client }

type agentModel struct {
	ID        types.String `tfsdk:"id"`
	AgentID   types.String `tfsdk:"agent_id"`
	Name      types.String `tfsdk:"name"`
	Framework types.String `tfsdk:"framework"`
	Status    types.String `tfsdk:"status"`
	TrustTier types.String `tfsdk:"trust_tier"`
	Labels    types.Map    `tfsdk:"labels"`
	Tools     types.List   `tfsdk:"tools"`
}

func newAgentDataSource() datasource.DataSource { return &agentDataSource{} }

func (d *agentDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent"
}

func (d *agentDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "One registered agent, by agent_id or by name. A name that matches no agent, or more than one, is an error.",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true, Description: "The agent id."},
			"agent_id":   schema.StringAttribute{Optional: true, Computed: true, Description: "The agent id (agt_…). Set this or name."},
			"name":       schema.StringAttribute{Optional: true, Computed: true, Description: "The agent's display name, matched exactly (case-insensitive). Set this or agent_id."},
			"framework":  schema.StringAttribute{Computed: true},
			"status":     schema.StringAttribute{Computed: true, Description: "active, inactive, revoked or killed."},
			"trust_tier": schema.StringAttribute{Computed: true},
			"labels":     schema.MapAttribute{ElementType: types.StringType, Computed: true, Description: "The labels policies match on."},
			"tools":      schema.ListAttribute{ElementType: types.StringType, Computed: true, Description: "The agent's declared tools."},
		},
	}
}

func (d *agentDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	d.c = clientFrom(req.ProviderData)
}

func fillAgent(ctx context.Context, m *agentModel, a *client.Agent) {
	m.ID = types.StringValue(a.AgentID)
	m.AgentID = types.StringValue(a.AgentID)
	m.Name = types.StringValue(a.DisplayName)
	m.Framework = types.StringValue(a.Framework)
	m.Status = types.StringValue(a.Status)
	m.TrustTier = types.StringValue(a.TrustTier)
	labels := a.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	m.Labels, _ = types.MapValueFrom(ctx, types.StringType, labels)
	tools := a.Tools
	if tools == nil {
		tools = []string{}
	}
	m.Tools, _ = types.ListValueFrom(ctx, types.StringType, tools)
}

func (d *agentDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg agentModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, name := strings.TrimSpace(cfg.AgentID.ValueString()), strings.TrimSpace(cfg.Name.ValueString())
	switch {
	case id == "" && name == "":
		resp.Diagnostics.AddError("Which agent?", "Set agent_id or name.")
		return
	case id != "" && name != "":
		resp.Diagnostics.AddError("Which agent?", "Set agent_id or name, not both.")
		return
	}
	var found *client.Agent
	if id != "" {
		a, err := d.c.GetAgent(ctx, id)
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError("No such agent", "No agent has the id "+id+".")
			return
		}
		if err != nil {
			resp.Diagnostics.AddError("Reading the agent failed", err.Error())
			return
		}
		found = a
	} else {
		// The api's search is a contains-match; the name must match exactly.
		list, err := d.c.ListAgents(ctx, name, "")
		if err != nil {
			resp.Diagnostics.AddError("Listing agents failed", err.Error())
			return
		}
		var matches []client.Agent
		for _, a := range list {
			if strings.EqualFold(strings.TrimSpace(a.DisplayName), name) {
				matches = append(matches, a)
			}
		}
		switch len(matches) {
		case 0:
			resp.Diagnostics.AddError("No such agent", fmt.Sprintf("No agent is named %q.", name))
			return
		case 1:
			found = &matches[0]
		default:
			ids := make([]string, len(matches))
			for i, a := range matches {
				ids[i] = a.AgentID + " (" + a.Status + ")"
			}
			sort.Strings(ids)
			resp.Diagnostics.AddError("More than one agent has that name",
				fmt.Sprintf("%d agents are named %q: %s. Use agent_id.", len(matches), name, strings.Join(ids, ", ")))
			return
		}
	}
	var m agentModel
	fillAgent(ctx, &m, found)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ── ponte_agents ──

type agentsDataSource struct{ c *client.Client }

type agentsModel struct {
	ID     types.String `tfsdk:"id"`
	Labels types.Map    `tfsdk:"labels"`
	Status types.String `tfsdk:"status"`
	IDs    types.List   `tfsdk:"ids"`
	Names  types.Map    `tfsdk:"names"`
}

func newAgentsDataSource() datasource.DataSource { return &agentsDataSource{} }

func (d *agentsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agents"
}

func (d *agentsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The agents that carry every one of the given labels, for for_each over memberships or bindings. No labels means every agent.",
		Attributes: map[string]schema.Attribute{
			"id":     schema.StringAttribute{Computed: true},
			"labels": schema.MapAttribute{ElementType: types.StringType, Optional: true, Description: "Label = value pairs an agent must all carry."},
			"status": schema.StringAttribute{Optional: true, Description: "Only agents in this status. Defaults to active; set to \"any\" for all."},
			"ids":    schema.ListAttribute{ElementType: types.StringType, Computed: true, Description: "The matching agent ids, sorted."},
			"names":  schema.MapAttribute{ElementType: types.StringType, Computed: true, Description: "Agent id to display name."},
		},
	}
}

func (d *agentsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	d.c = clientFrom(req.ProviderData)
}

func (d *agentsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg agentsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	want := map[string]string{}
	if !cfg.Labels.IsNull() && !cfg.Labels.IsUnknown() {
		resp.Diagnostics.Append(cfg.Labels.ElementsAs(ctx, &want, false)...)
	}
	status := strings.TrimSpace(cfg.Status.ValueString())
	if status == "" {
		status = "active"
	}
	apiStatus := status
	if status == "any" {
		apiStatus = ""
	}
	list, err := d.c.ListAgents(ctx, "", apiStatus)
	if err != nil {
		resp.Diagnostics.AddError("Listing agents failed", err.Error())
		return
	}
	ids, names := []string{}, map[string]string{}
	for _, a := range list {
		// The status is checked here too: the filter is this data source's promise, whatever
		// the api does with the parameter.
		if apiStatus != "" && a.Status != apiStatus {
			continue
		}
		ok := true
		for k, v := range want {
			if a.Labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			ids = append(ids, a.AgentID)
			names[a.AgentID] = a.DisplayName
		}
	}
	sort.Strings(ids)
	m := agentsModel{ID: types.StringValue("agents"), Labels: cfg.Labels, Status: cfg.Status}
	m.IDs, _ = types.ListValueFrom(ctx, types.StringType, ids)
	m.Names, _ = types.MapValueFrom(ctx, types.StringType, names)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
