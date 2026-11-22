package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ponte-security/terraform-provider-ponte/internal/client"
)

// ponte_recert_policy: how an access recertification campaign is reviewed: who decides, in how
// many steps, by when, what happens at the deadline, what a denial does, and which agents are
// certified without review. Schedules and rules open campaigns with it.

type recertPolicyResource struct {
	c *client.Client
}

type recertPolicyModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Reviewer      types.String `tfsdk:"reviewer"`
	ReviewerRef   types.String `tfsdk:"reviewer_ref"`
	FallbackGroup types.String `tfsdk:"fallback_group"`
	SecondReview  types.String `tfsdk:"second_review"`
	SecondGroup   types.String `tfsdk:"second_group"`
	DueDays       types.Int64  `tfsdk:"due_days"`
	RemindDays    types.Int64  `tfsdk:"remind_days"`
	OnOverdue     types.String `tfsdk:"on_overdue"`
	EscalateGroup types.String `tfsdk:"escalate_group"`
	EscalateDays  types.Int64  `tfsdk:"escalate_days"`
	OnDeny        types.String `tfsdk:"on_deny"`
	AutoCertify   types.List   `tfsdk:"auto_certify"`
}

type recertConditionModel struct {
	Field types.String `tfsdk:"field"`
	Op    types.String `tfsdk:"op"`
	Value types.String `tfsdk:"value"`
}

var recertConditionType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"field": types.StringType, "op": types.StringType, "value": types.StringType,
}}

func newRecertPolicyResource() resource.Resource { return &recertPolicyResource{} }

func (r *recertPolicyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_recert_policy"
}

func (r *recertPolicyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	str := func(def, desc string, allowed ...string) schema.StringAttribute {
		a := schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString(def), Description: desc}
		if len(allowed) > 0 {
			a.Validators = []validator.String{oneOf(allowed...)}
		}
		return a
	}
	days := func(desc string) schema.Int64Attribute {
		return schema.Int64Attribute{Optional: true, Computed: true, Default: int64default.StaticInt64(0), Description: desc}
	}
	resp.Schema = schema.Schema{
		Description: "A recertification review policy: who reviews a campaign's agents, in how many steps, by when, and what happens at the deadline and on a denial. A policy that a schedule or rule uses cannot be destroyed.",
		Attributes: map[string]schema.Attribute{
			"id":             schema.StringAttribute{Computed: true, Description: "The policy id (rp_…).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":           schema.StringAttribute{Required: true, Description: "Unique in the organisation."},
			"reviewer":       str("owner", "Who reviews: owner (the agent's owner), group or person.", "owner", "group", "person"),
			"reviewer_ref":   str("", "The group or person, for reviewer group or person."),
			"fallback_group": str("", "Who reviews agents that have no owner. Empty uses the service default."),
			"second_review":  str("none", "A second step after the first reviewer certifies: none, all or high_risk (agents of risk tier high or critical).", "none", "all", "high_risk"),
			"second_group":   str("", "The group that decides the second step. Never the person who approved the first."),
			"due_days":       days("Days each item has before its deadline. 0 is no deadline."),
			"remind_days":    days("Send a reminder this many days before the deadline. 0 sends none."),
			"on_overdue":     str("keep_open", "At the deadline: keep_open, escalate, suspend or revoke.", "keep_open", "escalate", "suspend", "revoke"),
			"escalate_group": str("", "The group an overdue item is escalated to, for on_overdue escalate."),
			"escalate_days":  schema.Int64Attribute{Optional: true, Computed: true, Description: "Days the escalation group has. Defaults to 7 when on_overdue is escalate."},
			"on_deny":        str("revoke", "A denial: revoke (credentials and grants) or suspend (reversible).", "revoke", "suspend"),
			"auto_certify": schema.ListNestedAttribute{Optional: true,
				Description: "Agents matching every condition are certified without review. Never applied to an agent with no owner or with access recommended for removal.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"field": schema.StringAttribute{Required: true, Description: "An agent field, e.g. risk_tier, stale_days, entitlement_count."},
					"op":    schema.StringAttribute{Required: true, Description: "eq, ne, in, lt or gt, as the field allows."},
					"value": schema.StringAttribute{Required: true, Description: "The value; comma-separated for in."},
				}}},
		},
	}
}

func (r *recertPolicyResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

// ValidateConfig refuses at plan time the combinations the control plane refuses on save.
func (r *recertPolicyResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var c recertPolicyModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &c)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// A value that is not known yet cannot be judged; one that is absent has its default.
	known := func(vs ...attr.Value) bool {
		for _, v := range vs {
			if v.IsUnknown() {
				return false
			}
		}
		return true
	}
	missing := func(v types.String) bool { return v.IsNull() || v.ValueString() == "" }
	fail := func(attrName, summary, detail string) {
		resp.Diagnostics.AddAttributeError(path.Root(attrName), summary, detail)
	}
	if rv := c.Reviewer.ValueString(); known(c.Reviewer, c.ReviewerRef) && (rv == "group" || rv == "person") && missing(c.ReviewerRef) {
		fail("reviewer_ref", "reviewer_ref is required", "Name the "+rv+" who reviews.")
	}
	if sr := c.SecondReview.ValueString(); known(c.SecondReview, c.SecondGroup) && (sr == "all" || sr == "high_risk") && missing(c.SecondGroup) {
		fail("second_group", "second_group is required", "Name the group for the second review.")
	}
	if !known(c.DueDays, c.RemindDays, c.EscalateDays, c.OnOverdue, c.EscalateGroup) {
		return
	}
	due, remind := c.DueDays.ValueInt64(), c.RemindDays.ValueInt64()
	if due < 0 || remind < 0 || c.EscalateDays.ValueInt64() < 0 {
		fail("due_days", "Days cannot be negative", "due_days, remind_days and escalate_days are 0 or more.")
	}
	if remind > 0 && due == 0 {
		fail("remind_days", "A reminder needs a deadline", "Set due_days.")
	} else if remind > 0 && remind >= due {
		fail("remind_days", "The reminder must come before the deadline", "remind_days must be less than due_days.")
	}
	if ov := c.OnOverdue.ValueString(); ov == "escalate" || ov == "suspend" || ov == "revoke" {
		if due == 0 {
			fail("on_overdue", "An action at the deadline needs a deadline", "Set due_days.")
		}
		if ov == "escalate" && missing(c.EscalateGroup) {
			fail("escalate_group", "escalate_group is required", "Name the group to escalate to.")
		}
	}
}

func (m *recertPolicyModel) spec(ctx context.Context) (client.RecertPolicySpec, diag.Diagnostics) {
	s := client.RecertPolicySpec{
		Reviewer: m.Reviewer.ValueString(), ReviewerRef: m.ReviewerRef.ValueString(), FallbackGroup: m.FallbackGroup.ValueString(),
		SecondReview: m.SecondReview.ValueString(), SecondGroup: m.SecondGroup.ValueString(),
		DueDays: m.DueDays.ValueInt64(), RemindDays: m.RemindDays.ValueInt64(),
		OnOverdue: m.OnOverdue.ValueString(), EscalateGroup: m.EscalateGroup.ValueString(), EscalateDays: m.EscalateDays.ValueInt64(),
		OnDeny: m.OnDeny.ValueString(), AutoCertify: []client.RecertCondition{},
	}
	var diags diag.Diagnostics
	if !m.AutoCertify.IsNull() && !m.AutoCertify.IsUnknown() {
		var conds []recertConditionModel
		diags = m.AutoCertify.ElementsAs(ctx, &conds, false)
		for _, c := range conds {
			s.AutoCertify = append(s.AutoCertify, client.RecertCondition{Field: c.Field.ValueString(), Op: c.Op.ValueString(), Value: c.Value.ValueString()})
		}
	}
	return s, diags
}

func (m *recertPolicyModel) fill(ctx context.Context, p *client.RecertPolicy) diag.Diagnostics {
	s := p.Spec
	m.ID = types.StringValue(p.PolicyID)
	m.Name = types.StringValue(p.Name)
	// The control plane stores the defaults as it spells them: no second review is "".
	or := func(v, def string) types.String {
		if v == "" {
			v = def
		}
		return types.StringValue(v)
	}
	m.Reviewer = or(s.Reviewer, "owner")
	m.ReviewerRef = types.StringValue(s.ReviewerRef)
	m.FallbackGroup = types.StringValue(s.FallbackGroup)
	m.SecondReview = or(s.SecondReview, "none")
	m.SecondGroup = types.StringValue(s.SecondGroup)
	m.DueDays = types.Int64Value(s.DueDays)
	m.RemindDays = types.Int64Value(s.RemindDays)
	m.OnOverdue = or(s.OnOverdue, "keep_open")
	m.EscalateGroup = types.StringValue(s.EscalateGroup)
	m.EscalateDays = types.Int64Value(s.EscalateDays)
	m.OnDeny = or(s.OnDeny, "revoke")
	if len(s.AutoCertify) == 0 && m.AutoCertify.IsNull() {
		return nil // not configured and nothing stored: stays unset
	}
	conds := make([]recertConditionModel, 0, len(s.AutoCertify))
	for _, c := range s.AutoCertify {
		conds = append(conds, recertConditionModel{Field: types.StringValue(c.Field), Op: types.StringValue(c.Op), Value: types.StringValue(c.Value)})
	}
	list, diags := types.ListValueFrom(ctx, recertConditionType, conds)
	m.AutoCertify = list
	return diags
}

func (r *recertPolicyResource) save(ctx context.Context, id string, m *recertPolicyModel, diags *diag.Diagnostics, what string) bool {
	spec, d := m.spec(ctx)
	diags.Append(d...)
	if diags.HasError() {
		return false
	}
	p, err := r.c.SaveRecertPolicy(ctx, id, m.Name.ValueString(), spec)
	if err != nil {
		diags.AddError(what+" the review policy failed", err.Error())
		return false
	}
	diags.Append(m.fill(ctx, p)...)
	return !diags.HasError()
}

func (r *recertPolicyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan recertPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || !r.save(ctx, "", &plan, &resp.Diagnostics, "Creating") {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *recertPolicyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state recertPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	p, err := r.c.GetRecertPolicy(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the review policy failed", err.Error())
		return
	}
	resp.Diagnostics.Append(state.fill(ctx, p)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *recertPolicyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state recertPolicyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() || !r.save(ctx, state.ID.ValueString(), &plan, &resp.Diagnostics, "Updating") {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *recertPolicyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state recertPolicyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	err := r.c.DeleteRecertPolicy(ctx, state.ID.ValueString())
	switch {
	case err == nil || client.IsNotFound(err):
	case client.IsConflict(err):
		resp.Diagnostics.AddError("The review policy is in use",
			"A recertification schedule or rule opens campaigns with "+state.Name.ValueString()+". Point it at another policy in Ponte, then destroy this one.")
	default:
		resp.Diagnostics.AddError("Deleting the review policy failed", err.Error())
	}
}

func (r *recertPolicyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	p, err := r.c.GetRecertPolicy(ctx, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Reading the review policy failed", err.Error())
		return
	}
	m := recertPolicyModel{AutoCertify: types.ListNull(recertConditionType)}
	resp.Diagnostics.Append(m.fill(ctx, p)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
