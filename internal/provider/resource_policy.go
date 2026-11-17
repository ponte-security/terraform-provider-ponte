package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"gopkg.in/yaml.v3"

	"github.com/ponte-ai/terraform-provider-ponte/internal/client"
)

// ponte_policy: one policy by NAME. Ponte keeps a version history per name: saving new PPL
// creates a new version with a new policy_id and archives the previous one, and the agents
// bound to the name follow. The resource's identity is therefore the name; policy_id and
// version are computed and change on every edit.

type policyResource struct {
	c *client.Client
}

type policyModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	PPL             types.String `tfsdk:"ppl"`
	EnforcementMode types.String `tfsdk:"enforcement_mode"`
	PolicyID        types.String `tfsdk:"policy_id"`
	Version         types.Int64  `tfsdk:"version"`
	Description     types.String `tfsdk:"description"`
}

func newPolicyResource() resource.Resource { return &policyResource{} }

func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A Ponte policy (PPL YAML). Identified by its metadata.name; every change to the YAML saves a new version and archives the previous one. Agents bound to the policy follow the name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "The policy name.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name": schema.StringAttribute{Computed: true, Description: "metadata.name from the YAML.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"ppl": schema.StringAttribute{Required: true, Description: "The policy as PPL YAML (apiVersion ponte.io/v1, kind AgentPolicy). Changing it saves a new version."},
			"enforcement_mode": schema.StringAttribute{Optional: true, Computed: true, Default: stringdefault.StaticString("enforce"),
				Description: "enforce (the verdict binds decisions) or observe (evaluated and recorded, never binding)."},
			"policy_id":   schema.StringAttribute{Computed: true, Description: "The id of the active version. Changes on every edit."},
			"version":     schema.Int64Attribute{Computed: true, Description: "The active version number."},
			"description": schema.StringAttribute{Computed: true, Description: "spec.description from the YAML."},
		},
	}
}

func (r *policyResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

// nameOf reads metadata.name from the YAML, so the plan knows the identity before the API does.
func nameOf(ppl string) (string, error) {
	var doc struct {
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal([]byte(ppl), &doc); err != nil {
		return "", fmt.Errorf("ppl is not valid YAML: %w", err)
	}
	if strings.TrimSpace(doc.Metadata.Name) == "" {
		return "", fmt.Errorf("ppl has no metadata.name")
	}
	return strings.TrimSpace(doc.Metadata.Name), nil
}

// ModifyPlan sets name and id from the YAML at plan time, and marks the versioned attributes
// unknown when the YAML changes.
func (r *policyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || plan.PPL.IsUnknown() {
		return
	}
	name, err := nameOf(plan.PPL.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("ppl"), "Invalid policy", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("id"), name)...)
	if !req.State.Raw.IsNull() {
		var state policyModel
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if state.Name.ValueString() != name {
			resp.RequiresReplace = append(resp.RequiresReplace, path.Root("name"))
		}
		if state.PPL.ValueString() != plan.PPL.ValueString() {
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("policy_id"), types.StringUnknown())...)
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("version"), types.Int64Unknown())...)
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("description"), types.StringUnknown())...)
		}
	}
}

func (r *policyResource) save(ctx context.Context, m *policyModel) error {
	p, err := r.c.CreatePolicy(ctx, m.PPL.ValueString())
	if err != nil {
		return err
	}
	mode := m.EnforcementMode.ValueString()
	if mode == "" {
		mode = "enforce"
	}
	if p.EnforcementMode != mode {
		if err := r.c.SetPolicyMode(ctx, p.PolicyID, mode); err != nil {
			return fmt.Errorf("the policy was saved as %s but its mode could not be set: %w", p.PolicyID, err)
		}
		p.EnforcementMode = mode
	}
	m.fill(p)
	return nil
}

func (m *policyModel) fill(p *client.Policy) {
	m.ID = types.StringValue(p.Name)
	m.Name = types.StringValue(p.Name)
	m.PolicyID = types.StringValue(p.PolicyID)
	m.Version = types.Int64Value(int64(p.Version))
	m.Description = types.StringValue(p.Description)
	mode := p.EnforcementMode
	if mode == "" {
		mode = "enforce"
	}
	m.EnforcementMode = types.StringValue(mode)
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.save(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Creating the policy failed", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The active version of the name is the truth: someone may have saved a version outside
	// Terraform (new policy_id) or archived it (gone).
	p, err := r.c.ActivePolicyByName(ctx, state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Reading the policy failed", err.Error())
		return
	}
	if p == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fill(p)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state policyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.PPL.ValueString() != state.PPL.ValueString() {
		if err := r.save(ctx, &plan); err != nil {
			resp.Diagnostics.AddError("Saving the policy version failed", err.Error())
			return
		}
	} else {
		// Only the mode changed.
		plan.PolicyID, plan.Version, plan.Description, plan.Name, plan.ID = state.PolicyID, state.Version, state.Description, state.Name, state.ID
		if plan.EnforcementMode.ValueString() != state.EnforcementMode.ValueString() {
			if err := r.c.SetPolicyMode(ctx, state.PolicyID.ValueString(), plan.EnforcementMode.ValueString()); err != nil {
				resp.Diagnostics.AddError("Setting the policy mode failed", err.Error())
				return
			}
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Archive whatever version is active for the name, not only the one in state.
	p, err := r.c.ActivePolicyByName(ctx, state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Reading the policy failed", err.Error())
		return
	}
	if p == nil {
		return
	}
	if err := r.c.DeletePolicy(ctx, p.PolicyID); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Archiving the policy failed", err.Error())
	}
}

// ImportState imports by name; the next plan asks for the YAML.
func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	p, err := r.c.ActivePolicyByName(ctx, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Reading the policy failed", err.Error())
		return
	}
	if p == nil {
		resp.Diagnostics.AddError("No active policy named "+req.ID, "Import takes the policy name (metadata.name).")
		return
	}
	var m policyModel
	m.fill(p)
	m.PPL = types.StringValue("")
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
