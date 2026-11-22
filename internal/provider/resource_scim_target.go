package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ponte-security/terraform-provider-ponte/internal/client"
)

// ponte_scim_target: a system Ponte pushes its agents to over SCIM (an IGA or an identity
// provider that keeps a record of every agent).
//
// The control plane has one in-place change, enabled. A name, a URL or a credential that
// changes replaces the target. The credential is write-only on the control plane, so it cannot
// be compared with what is stored: the resource trusts its state.

type scimTargetResource struct {
	c *client.Client
}

type scimTargetModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	BaseURL     types.String `tfsdk:"base_url"`
	BearerToken types.String `tfsdk:"bearer_token"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func newSCIMTargetResource() resource.Resource { return &scimTargetResource{} }

func (r *scimTargetResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_scim_target"
}

// replaceUnlessImported replaces the target when the credential changes, except right after an
// import: an imported target has no credential in state (the control plane never returns it),
// and the configuration's value is then recorded, not sent. Replacing would delete a working
// target only because Terraform had not seen its credential.
func replaceUnlessImported() planmodifier.String {
	return stringplanmodifier.RequiresReplaceIf(
		func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
			resp.RequiresReplace = !req.StateValue.IsNull()
		},
		"A changed credential replaces the target, except on the first apply after an import.",
		"A changed credential replaces the target, except on the first apply after an import.",
	)
}

func (r *scimTargetResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A system Ponte pushes its agents to over SCIM. Only enabled changes in place; a changed name, URL or credential replaces the target. Destroy removes the target and its stored credential.",
		Attributes: map[string]schema.Attribute{
			"id":       schema.StringAttribute{Computed: true, Description: "The target id (scimtg_…).", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"name":     schema.StringAttribute{Required: true, Description: "Up to 80 characters.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"base_url": schema.StringAttribute{Required: true, Description: "The target's SCIM base URL (https), without a trailing slash.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
			"bearer_token": schema.StringAttribute{Required: true, Sensitive: true,
				Description:   "The bearer credential Ponte presents to the target. Ponte keeps it in its secret store and never returns it, so a change made outside Terraform is not detected. It is stored in the Terraform state: keep the state encrypted.",
				PlanModifiers: []planmodifier.String{replaceUnlessImported()}},
			"enabled": schema.BoolAttribute{Optional: true, Computed: true, Default: booldefault.StaticBool(true), Description: "false stops pushes to the target without removing it."},
		},
	}
}

func (r *scimTargetResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	r.c = clientFrom(req.ProviderData)
}

func (m *scimTargetModel) fill(t *client.SCIMTarget) {
	m.ID = types.StringValue(t.TargetID)
	m.Name = types.StringValue(t.Name)
	m.BaseURL = types.StringValue(t.BaseURL)
	m.Enabled = types.BoolValue(t.Enabled)
}

func (r *scimTargetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan scimTargetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.c.CreateSCIMTarget(ctx, plan.Name.ValueString(), plan.BaseURL.ValueString(), plan.BearerToken.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Creating the SCIM target failed", err.Error())
		return
	}
	want := plan.Enabled.ValueBool()
	plan.fill(t)
	// The target exists from here on: keep it in state even if turning it off fails.
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	if t.Enabled != want {
		if err := r.c.SetSCIMTargetEnabled(ctx, t.TargetID, want); err != nil {
			resp.Diagnostics.AddError("Setting enabled failed", "The target was created enabled. "+err.Error())
			return
		}
		plan.Enabled = types.BoolValue(want)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
	}
}

func (r *scimTargetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state scimTargetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	t, err := r.c.GetSCIMTarget(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Reading the SCIM target failed", err.Error())
		return
	}
	state.fill(t)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *scimTargetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state scimTargetModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Only enabled reaches the control plane. A credential that differs here is the first one
	// recorded after an import (see replaceUnlessImported): it is kept in state, not sent.
	if plan.Enabled.ValueBool() != state.Enabled.ValueBool() {
		if err := r.c.SetSCIMTargetEnabled(ctx, state.ID.ValueString(), plan.Enabled.ValueBool()); err != nil {
			resp.Diagnostics.AddError("Setting enabled failed", err.Error())
			return
		}
	}
	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *scimTargetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state scimTargetModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.DeleteSCIMTarget(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Deleting the SCIM target failed", err.Error())
	}
}

func (r *scimTargetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	t, err := r.c.GetSCIMTarget(ctx, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Reading the SCIM target failed", err.Error())
		return
	}
	m := scimTargetModel{BearerToken: types.StringNull()}
	m.fill(t)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
