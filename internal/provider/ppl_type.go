package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"gopkg.in/yaml.v3"
)

// A policy is YAML, and two YAML texts can say the same thing: a comment, a blank line or the
// order of keys changes the text and not the policy. Every saved text is a new policy version,
// so the ppl attribute compares what the YAML says. Only a change of meaning plans a change.

type pplType struct{ basetypes.StringType }

type pplValue struct{ basetypes.StringValue }

var (
	_ basetypes.StringTypable                    = pplType{}
	_ basetypes.StringValuableWithSemanticEquals = pplValue{}
)

func (t pplType) Equal(o attr.Type) bool {
	other, ok := o.(pplType)
	return ok && t.StringType.Equal(other.StringType)
}

func (t pplType) String() string { return "pplType" }

func (t pplType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return pplValue{StringValue: in}, nil
}

func (t pplType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	v, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	s, ok := v.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T", v)
	}
	return pplValue{StringValue: s}, nil
}

func (t pplType) ValueType(context.Context) attr.Value { return pplValue{} }

func (v pplValue) Type(context.Context) attr.Type { return pplType{} }

func (v pplValue) Equal(o attr.Value) bool {
	other, ok := o.(pplValue)
	return ok && v.StringValue.Equal(other.StringValue)
}

func (v pplValue) StringSemanticEquals(_ context.Context, other basetypes.StringValuable) (bool, diag.Diagnostics) {
	o, ok := other.(pplValue)
	if !ok {
		return false, nil
	}
	return samePolicy(v.ValueString(), o.ValueString()), nil
}

func newPPL(s string) pplValue { return pplValue{StringValue: basetypes.NewStringValue(s)} }

// samePolicy reports whether two YAML texts describe the same policy. Texts that cannot be
// read are the same only when they are identical.
func samePolicy(a, b string) bool {
	if a == b {
		return true
	}
	ca, errA := canonicalPolicy([]byte(a))
	cb, errB := canonicalPolicy([]byte(b))
	return errA == nil && errB == nil && ca != "" && ca == cb
}

// canonicalPolicy turns YAML (or JSON, which is YAML) into one comparable text: keys sorted,
// and members that say nothing (null, "", an empty list or map) left out, because the control
// plane's copy of a policy omits them. false and 0 are kept: leaving one out can mean a
// different default, and a missed difference would be a policy change Terraform never plans.
func canonicalPolicy(src []byte) (string, error) {
	var doc any
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return "", err
	}
	pruned, _ := prune(doc)
	out, err := json.Marshal(pruned) // maps marshal with sorted keys
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// prune drops the members that say nothing. keep is false when the value itself is one.
func prune(v any) (out any, keep bool) {
	switch t := v.(type) {
	case nil:
		return nil, false
	case string:
		return t, t != ""
	case map[string]any:
		m := map[string]any{}
		for k, val := range t {
			if p, ok := prune(val); ok {
				m[k] = p
			}
		}
		return m, len(m) > 0
	case map[any]any:
		m := map[string]any{}
		for k, val := range t {
			if p, ok := prune(val); ok {
				m[fmt.Sprint(k)] = p
			}
		}
		return m, len(m) > 0
	case []any:
		l := make([]any, 0, len(t))
		for _, val := range t {
			p, _ := prune(val) // a list keeps its positions
			l = append(l, p)
		}
		return l, len(l) > 0
	case int:
		return float64(t), true // 5 and 5.0 are the same limit
	case int64:
		return float64(t), true
	case uint64:
		return float64(t), true
	default:
		return t, true
	}
}

// renderPolicy writes the control plane's copy of a policy (JSON) as YAML, for the state of a
// policy Terraform did not write: an import, or a version someone saved in the console.
func renderPolicy(parsed json.RawMessage) string {
	if len(parsed) == 0 {
		return ""
	}
	var doc any
	if err := json.Unmarshal(parsed, &doc); err != nil {
		return ""
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return ""
	}
	return string(out)
}
