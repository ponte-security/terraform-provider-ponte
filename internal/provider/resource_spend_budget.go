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

// ponte_spend_budget: a monthly model-spend budget on a scope (org, team, owner, agent, model).
// The PDP measures every agent under the scope against it (input.spend.*).

type spendBudgetResource struct {
	c *client.Client
}

type spendBudgetModel struct {
	ID            types.String  `tfsdk:"id"`
	Scope         types.String  `tfsdk:"scope"`
	Ref           types.String  `tfsdk:"ref"`
	MonthlyUSD    types.Float64 `tfsdk:"monthly_usd"`
	MonthlyTokens types.Int64   `tfsdk:"monthly_tokens"`
}

func newSpendBudgetResource() resource.Resource { return &spendBudgetResource{} }

func (r *spendBudgetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_spend_budget"
}

func (r *spendBudgetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A monthly model-spend budget on a scope. org (ref *), team (the agents' team label), owner (user:<ref> or group:<ref>), agent (an agent id), model (provider/model, model, or a prefix ending in *). At least one limit.",
		Attributes: map[string]schema.Attribute{
			"id":             schema.StringAttribute{Computed: true, Description: "scope:ref", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"scope":          schema.StringAttribute{Required: true, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"ref":            schema.StringAttribute{Optional: true, Computed: true, Description: "Omitted for scope org.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}},
			"monthly_usd":    schema.Float64Attribute{Optional: true},
			"monthly_tokens": schema.Int64Attribute{Optional: true},
		},
	}
}

func (r *spendBudgetResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

func (m *spendBudgetModel) budget() client.Budget {
	b := client.Budget{Scope: strings.ToLower(strings.TrimSpace(m.Scope.ValueString())), Ref: strings.TrimSpace(m.Ref.ValueString())}
	if b.Scope == "org" {
		b.Ref = "*"
	}
	if !m.MonthlyUSD.IsNull() && !m.MonthlyUSD.IsUnknown() {
		v := m.MonthlyUSD.ValueFloat64()
		b.MonthlyUSD = &v
	}
	if !m.MonthlyTokens.IsNull() && !m.MonthlyTokens.IsUnknown() {
		v := m.MonthlyTokens.ValueInt64()
		b.MonthlyTokens = &v
	}
	return b
}

func (m *spendBudgetModel) fill(b *client.Budget) {
	m.ID = types.StringValue(b.Scope + ":" + b.Ref)
	m.Scope = types.StringValue(b.Scope)
	m.Ref = types.StringValue(b.Ref)
	if b.MonthlyUSD != nil {
		m.MonthlyUSD = types.Float64Value(*b.MonthlyUSD)
	} else {
		m.MonthlyUSD = types.Float64Null()
	}
	if b.MonthlyTokens != nil {
		m.MonthlyTokens = types.Int64Value(*b.MonthlyTokens)
	} else {
		m.MonthlyTokens = types.Int64Null()
	}
}

func (r *spendBudgetResource) write(ctx context.Context, m *spendBudgetModel, what string, diags interface{ AddError(string, string) }) bool {
	b := m.budget()
	if b.MonthlyUSD == nil && b.MonthlyTokens == nil {
		diags.AddError("A budget needs a limit", "Set monthly_usd, monthly_tokens, or both.")
		return false
	}
	if err := r.c.PutBudget(ctx, b); err != nil {
		diags.AddError(what+" the budget failed", err.Error())
		return false
	}
	got, err := r.c.GetBudget(ctx, b.Scope, b.Ref)
	if err != nil || got == nil {
		diags.AddError("Reading the budget back failed", "the budget was written but the api does not list it")
		return false
	}
	m.fill(got)
	return true
}

func (r *spendBudgetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan spendBudgetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !r.write(ctx, &plan, "Setting", &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *spendBudgetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state spendBudgetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	b := state.budget()
	got, err := r.c.GetBudget(ctx, b.Scope, b.Ref)
	if err != nil {
		resp.Diagnostics.AddError("Reading the budget failed", err.Error())
		return
	}
	if got == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fill(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *spendBudgetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan spendBudgetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !r.write(ctx, &plan, "Updating", &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *spendBudgetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state spendBudgetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	b := state.budget()
	b.MonthlyUSD, b.MonthlyTokens = nil, nil // both null clears
	if err := r.c.PutBudget(ctx, b); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Clearing the budget failed", err.Error())
	}
}

func (r *spendBudgetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	scope, ref, ok := strings.Cut(req.ID, ":")
	if !ok || scope == "" || ref == "" {
		resp.Diagnostics.AddError("Import id must be scope:ref", req.ID)
		return
	}
	got, err := r.c.GetBudget(ctx, scope, ref)
	if err != nil || got == nil {
		resp.Diagnostics.AddError("No such budget", req.ID)
		return
	}
	var m spendBudgetModel
	m.fill(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
