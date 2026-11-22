package provider

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

// The fake's SCIM targets and recertification review policies, behaving as the control plane
// does: a target's credential is taken and never returned, a new target is enabled, only
// enabled changes in place; a review policy is normalised and validated on save, its spec is
// answered without the members that are empty, and one in use cannot be deleted.

type fakeSCIMTarget struct {
	TargetID string `json:"target_id"`
	Name     string `json:"name"`
	BaseURL  string `json:"base_url"`
	Enabled  bool   `json:"enabled"`
	token    string
}

type fakeRecertSpec struct {
	Reviewer      string              `json:"reviewer,omitempty"`
	ReviewerRef   string              `json:"reviewer_ref,omitempty"`
	FallbackGroup string              `json:"fallback_group,omitempty"`
	SecondReview  string              `json:"second_review,omitempty"`
	SecondGroup   string              `json:"second_group,omitempty"`
	DueDays       int                 `json:"due_days,omitempty"`
	RemindDays    int                 `json:"remind_days,omitempty"`
	OnOverdue     string              `json:"on_overdue,omitempty"`
	EscalateGroup string              `json:"escalate_group,omitempty"`
	EscalateDays  int                 `json:"escalate_days,omitempty"`
	OnDeny        string              `json:"on_deny,omitempty"`
	AutoCertify   []map[string]string `json:"auto_certify,omitempty"`
}

type fakeRecertPolicy struct {
	PolicyID string         `json:"policy_id"`
	Name     string         `json:"name"`
	Spec     fakeRecertSpec `json:"spec"`
	UsedBy   int            `json:"used_by"`
}

// normalizeRecert mirrors recert.Policy.Normalize and Validate.
func normalizeRecert(s fakeRecertSpec) (fakeRecertSpec, string) {
	low := func(v string) string { return strings.ToLower(strings.TrimSpace(v)) }
	s.Reviewer, s.SecondReview, s.OnOverdue, s.OnDeny = low(s.Reviewer), low(s.SecondReview), low(s.OnOverdue), low(s.OnDeny)
	if s.Reviewer == "" {
		s.Reviewer = "owner"
	}
	if s.SecondReview == "none" {
		s.SecondReview = ""
	}
	if s.OnOverdue == "" {
		s.OnOverdue = "keep_open"
	}
	if s.OnDeny == "" {
		s.OnDeny = "revoke"
	}
	if s.OnOverdue == "escalate" && s.EscalateDays <= 0 {
		s.EscalateDays = 7
	}
	switch {
	case s.Reviewer != "owner" && s.Reviewer != "group" && s.Reviewer != "person":
		return s, "reviewer must be owner, group or person"
	case s.Reviewer != "owner" && s.ReviewerRef == "":
		return s, "name the " + s.Reviewer + " who reviews"
	case s.SecondReview != "" && s.SecondReview != "all" && s.SecondReview != "high_risk":
		return s, "second review must be none, all or high_risk"
	case s.SecondReview != "" && s.SecondGroup == "":
		return s, "name the group for the second review"
	case s.RemindDays > 0 && s.DueDays == 0:
		return s, "a reminder needs a deadline"
	case s.RemindDays > 0 && s.RemindDays >= s.DueDays:
		return s, "the reminder must come before the deadline"
	case s.OnOverdue != "keep_open" && s.DueDays == 0:
		return s, "an action at the deadline needs a deadline"
	case s.OnOverdue == "escalate" && s.EscalateGroup == "":
		return s, "name the group to escalate to"
	case s.OnDeny != "revoke" && s.OnDeny != "suspend":
		return s, "on deny must be revoke or suspend"
	}
	return s, ""
}

func (f *fakeAPI) serveGovernance(w http.ResponseWriter, r *http.Request, p string, parts []string) bool {
	if f.scimTargets == nil {
		f.scimTargets = map[string]*fakeSCIMTarget{}
	}
	if f.recertPolicies == nil {
		f.recertPolicies = map[string]*fakeRecertPolicy{}
	}
	switch {
	case p == "/scim/targets" && r.Method == http.MethodGet:
		list := []*fakeSCIMTarget{}
		for _, t := range f.scimTargets {
			list = append(list, t)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].TargetID < list[j].TargetID })
		jsonOut(w, 200, map[string]any{"targets": list, "enabled": true})
	case p == "/scim/targets" && r.Method == http.MethodPost:
		var in struct {
			Name, BaseURL, BearerToken string
		}
		var raw map[string]string
		_ = json.NewDecoder(r.Body).Decode(&raw)
		in.Name, in.BaseURL, in.BearerToken = strings.TrimSpace(raw["name"]), strings.TrimRight(strings.TrimSpace(raw["base_url"]), "/"), strings.TrimSpace(raw["bearer_token"])
		if in.Name == "" || !strings.HasPrefix(in.BaseURL, "https://") || in.BearerToken == "" {
			jsonOut(w, 400, map[string]any{"error": "name, base_url and bearer_token are required"})
			return true
		}
		t := &fakeSCIMTarget{TargetID: f.id("scimtg"), Name: in.Name, BaseURL: in.BaseURL, Enabled: true, token: in.BearerToken}
		f.scimTargets[t.TargetID] = t
		jsonOut(w, 201, map[string]any{"ok": true, "target": t})
	case len(parts) == 3 && parts[0] == "scim" && parts[1] == "targets" && r.Method == http.MethodPatch:
		t := f.scimTargets[parts[2]]
		var in struct {
			Enabled *bool `json:"enabled"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if t == nil {
			jsonOut(w, 404, map[string]any{"error": "no such target"})
			return true
		}
		if in.Enabled == nil {
			jsonOut(w, 400, map[string]any{"error": "body must be JSON with enabled"})
			return true
		}
		t.Enabled = *in.Enabled
		jsonOut(w, 200, map[string]any{"ok": true, "enabled": t.Enabled})
	case len(parts) == 3 && parts[0] == "scim" && parts[1] == "targets" && r.Method == http.MethodDelete:
		if f.scimTargets[parts[2]] == nil {
			jsonOut(w, 404, map[string]any{"error": "no such target"})
			return true
		}
		delete(f.scimTargets, parts[2])
		jsonOut(w, 200, map[string]any{"ok": true})

	case p == "/recert/policies" && r.Method == http.MethodGet:
		list := []*fakeRecertPolicy{}
		for _, x := range f.recertPolicies {
			list = append(list, x)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].PolicyID < list[j].PolicyID })
		jsonOut(w, 200, map[string]any{"policies": list})
	case len(parts) >= 2 && parts[0] == "recert" && parts[1] == "policies" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		var in struct {
			Name string         `json:"name"`
			Spec fakeRecertSpec `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		spec, problem := normalizeRecert(in.Spec)
		if in.Name = strings.TrimSpace(in.Name); in.Name == "" {
			problem = "name is required"
		}
		if problem != "" {
			jsonOut(w, 400, map[string]any{"error": problem})
			return true
		}
		var x *fakeRecertPolicy
		if r.Method == http.MethodPost && len(parts) == 2 {
			x = &fakeRecertPolicy{PolicyID: f.id("rp")}
			f.recertPolicies[x.PolicyID] = x
		} else if len(parts) == 3 {
			x = f.recertPolicies[parts[2]]
		}
		if x == nil {
			jsonOut(w, 404, map[string]any{"error": "review policy not found"})
			return true
		}
		x.Name, x.Spec = in.Name, spec
		status := 200
		if r.Method == http.MethodPost {
			status = 201
		}
		jsonOut(w, status, map[string]any{"policy": x})
	case len(parts) == 3 && parts[0] == "recert" && parts[1] == "policies" && r.Method == http.MethodDelete:
		x := f.recertPolicies[parts[2]]
		switch {
		case x == nil:
			jsonOut(w, 404, map[string]any{"error": "review policy not found"})
		case x.UsedBy > 0:
			jsonOut(w, 409, map[string]any{"error": "a schedule or rule uses this policy"})
		default:
			delete(f.recertPolicies, parts[2])
			jsonOut(w, 200, map[string]any{"ok": true})
		}
	default:
		return false
	}
	return true
}
