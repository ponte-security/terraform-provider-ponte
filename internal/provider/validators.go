package provider

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// oneOf refuses, at plan time, a value the API would refuse at apply time. The values are the
// API's own, spelled as it stores them: "Org" is refused here because the API would store "org"
// and Terraform would then see a result that differs from its plan.
type oneOfValidator struct{ allowed []string }

func oneOf(allowed ...string) validator.String { return oneOfValidator{allowed: allowed} }

func (v oneOfValidator) Description(context.Context) string {
	return "one of: " + strings.Join(v.allowed, ", ")
}

func (v oneOfValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (v oneOfValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	got := req.ConfigValue.ValueString()
	for _, a := range v.allowed {
		if got == a {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Value not allowed",
		"\""+got+"\" is not one of: "+strings.Join(v.allowed, ", ")+".")
}
