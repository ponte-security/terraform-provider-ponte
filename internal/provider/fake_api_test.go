package provider

// A fake Ponte control plane with the behaviours the resources depend on: policies versioned
// by name (a new save archives the old version, bindings follow the name), groups with
// members, bindings per agent, and a bearer check.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type fakePolicy struct {
	PolicyID        string `json:"policy_id"`
	Name            string `json:"name"`
	Version         int    `json:"version"`
	Description     string `json:"description"`
	Status          string `json:"status"`
	EnforcementMode string `json:"enforcement_mode"`
	PPL             string `json:"-"`
	// PPLSource is the policy as parsed, the way the control plane answers: JSON, with the
	// members it always writes even when empty.
	PPLSource json.RawMessage `json:"ppl_source"`
}

// parsedPolicy is the fake's copy of a policy as the control plane stores it.
func parsedPolicy(src string) json.RawMessage {
	var doc map[string]any
	if yaml.Unmarshal([]byte(src), &doc) != nil {
		return nil
	}
	if meta, ok := doc["metadata"].(map[string]any); ok && meta["labels"] == nil {
		meta["labels"] = map[string]any{} // an empty member the YAML did not have
	}
	out, _ := json.Marshal(doc)
	return out
}

// savePolicy stores a version the way POST /policies does. Caller holds f.mu.
func (f *fakeAPI) savePolicy(src, mode string) (*fakePolicy, bool) {
	var doc struct {
		Metadata struct {
			Name string `yaml:"name"`
		} `yaml:"metadata"`
		Spec struct {
			Description string `yaml:"description"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil || doc.Metadata.Name == "" {
		return nil, false
	}
	version := 1
	if old := f.activeByName(doc.Metadata.Name); old != nil {
		version = old.Version + 1
		old.Status = "archived"
		// Bindings follow the name.
		np := f.id("pol")
		for _, set := range f.bindings {
			if set[old.PolicyID] {
				delete(set, old.PolicyID)
				set[np] = true
			}
		}
		f.n--
	}
	if mode != "observe" {
		mode = "enforce"
	}
	np := &fakePolicy{PolicyID: f.id("pol"), Name: doc.Metadata.Name, Version: version, Description: strings.TrimSpace(doc.Spec.Description),
		Status: "active", EnforcementMode: mode, PPL: src, PPLSource: parsedPolicy(src)}
	f.policies[np.PolicyID] = np
	f.createdModes = append(f.createdModes, mode)
	return np, true
}

// consoleEdit saves a version outside Terraform, as an operator would in the console.
func (f *fakeAPI) consoleEdit(src string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.savePolicy(src, "enforce")
}

type fakeGroup struct {
	GroupID             string   `json:"group_id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	TrustLevel          string   `json:"trust_level"`
	Owner               string   `json:"owner"`
	Tags                []string `json:"tags"`
	MaxConcurrentAgents *int     `json:"max_concurrent_agents,omitempty"`
}

type fakeWebhook struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	EventTypes  []string `json:"event_types"`
	Description string   `json:"description"`
	Enabled     *bool    `json:"enabled"`
	Format      string   `json:"format"`
	MinSeverity string   `json:"min_severity"`
	// A pointer: PATCH changes it only when the member is sent, as the api does.
	FormatConfig *json.RawMessage `json:"format_config"`
}

type fakeBudget struct {
	Scope         string   `json:"scope"`
	Ref           string   `json:"ref"`
	MonthlyUSD    *float64 `json:"monthly_usd"`
	MonthlyTokens *int64   `json:"monthly_tokens"`
}

type fakeAPI struct {
	// ignoreModeOnCreate makes POST /policies behave like a control plane that predates
	// enforcement_mode on create. createdModes is the mode each version was stored in;
	// modePatches counts PATCH …/mode calls.
	ignoreModeOnCreate bool
	createdModes       []string
	modePatches        int

	// Automation sign-in: the API key and the pipeline identity the fake accepts, the session
	// tokens it has handed out, and how many sign-ins it has seen.
	apiKey        string
	identityID    string
	pipelineToken string
	sessions      map[string]bool
	signIns       int
	sessionSecs   int

	scimTargets    map[string]*fakeSCIMTarget
	recertPolicies map[string]*fakeRecertPolicy

	mu       sync.Mutex
	webhooks map[string]*fakeWebhook
	budgets  map[string]*fakeBudget
	token    string
	n        int
	policies map[string]*fakePolicy // by policy id
	groups   map[string]*fakeGroup
	members  map[string]map[string]bool // group → agent set
	bindings map[string]map[string]bool // agent → policy id set
	calls    []string
	mcp      map[string]*fakeMCPServer
	agents   []fakeAgent
}

type fakeAgent struct {
	AgentID     string            `json:"agent_id"`
	DisplayName string            `json:"display_name"`
	Framework   string            `json:"framework"`
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	TrustTier   string            `json:"trust_tier,omitempty"`
	Tools       []string          `json:"tool_manifest"`
}

func newFakeAPI(token string) *fakeAPI {
	return &fakeAPI{token: token, policies: map[string]*fakePolicy{}, groups: map[string]*fakeGroup{}, members: map[string]map[string]bool{}, bindings: map[string]map[string]bool{},
		webhooks: map[string]*fakeWebhook{}, budgets: map[string]*fakeBudget{}}
}

func (f *fakeAPI) id(prefix string) string {
	f.n++
	return fmt.Sprintf("%s_%04d", prefix, f.n)
}

func (f *fakeAPI) activeByName(name string) *fakePolicy {
	for _, p := range f.policies {
		if p.Name == name && p.Status == "active" {
			return p
		}
	}
	return nil
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// The sign-in exchange for automation identities carries its own credential.
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/automation/token") {
		f.serveSignIn(w, r)
		return
	}
	if bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); bearer != f.token && !f.sessions[bearer] {
		jsonOut(w, 401, map[string]any{"error": "unauthorized"})
		return
	}
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	p := r.URL.Path
	p = strings.TrimPrefix(p, "/api/control")
	p = strings.TrimPrefix(p, "/api")
	p = strings.TrimPrefix(p, "/v1")
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/webhooks" && r.Method == http.MethodPost:
		var in fakeWebhook
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Name == "" || !strings.HasPrefix(in.URL, "https://") || len(in.EventTypes) == 0 {
			jsonOut(w, 400, map[string]any{"error": "name, https url and event_types are required"})
			return
		}
		in.ID = f.id("wh")
		if in.Format == "" {
			in.Format = "ponte"
		}
		if in.Enabled == nil {
			t := true
			in.Enabled = &t
		}
		switch in.MinSeverity {
		case "":
			in.MinSeverity = "high"
		case "critical", "high", "medium":
		default:
			jsonOut(w, 400, map[string]any{"error": "min_severity must be critical, high or medium"})
			return
		}
		f.webhooks[in.ID] = &in
		jsonOut(w, 201, map[string]any{"id": in.ID, "signing_secret": "whsec_" + in.ID})
	case p == "/webhooks" && r.Method == http.MethodGet:
		list := []map[string]any{}
		for _, x := range f.webhooks {
			// Sorted, not as sent: the order of event types carries no meaning.
			events := append([]string{}, x.EventTypes...)
			sort.Strings(events)
			list = append(list, map[string]any{"id": x.ID, "name": x.Name, "url": x.URL, "event_types": events, "headers": map[string]string{}, // redacted
				"enabled": *x.Enabled, "description": x.Description, "format": x.Format, "min_severity": x.MinSeverity})
		}
		sort.Slice(list, func(i, j int) bool { return list[i]["id"].(string) < list[j]["id"].(string) })
		jsonOut(w, 200, map[string]any{"subscriptions": list})
	case len(parts) == 2 && parts[0] == "webhooks" && r.Method == http.MethodPatch:
		x := f.webhooks[parts[1]]
		if x == nil {
			jsonOut(w, 404, map[string]any{"error": "not found"})
			return
		}
		var in fakeWebhook
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Name != "" {
			x.Name = in.Name
		}
		if in.URL != "" {
			x.URL = in.URL
		}
		if in.EventTypes != nil {
			x.EventTypes = in.EventTypes
		}
		if in.Enabled != nil {
			x.Enabled = in.Enabled
		}
		x.Description = in.Description
		if in.Format != "" {
			x.Format = in.Format
		}
		if in.MinSeverity != "" {
			x.MinSeverity = in.MinSeverity
		}
		if in.FormatConfig != nil {
			x.FormatConfig = in.FormatConfig
		}
		jsonOut(w, 200, map[string]any{"updated": true})
	case len(parts) == 2 && parts[0] == "webhooks" && r.Method == http.MethodDelete:
		if f.webhooks[parts[1]] == nil {
			jsonOut(w, 404, map[string]any{"error": "not found"})
			return
		}
		delete(f.webhooks, parts[1])
		jsonOut(w, 200, map[string]any{"deleted": true})
	case p == "/spend/budgets" && r.Method == http.MethodPut:
		var b fakeBudget
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Scope == "" || b.Ref == "" {
			jsonOut(w, 400, map[string]any{"error": "scope and ref"})
			return
		}
		if b.MonthlyUSD == nil && b.MonthlyTokens == nil {
			delete(f.budgets, b.Scope+":"+b.Ref)
		} else {
			f.budgets[b.Scope+":"+b.Ref] = &b
		}
		jsonOut(w, 200, b)
	case p == "/spend/budgets" && r.Method == http.MethodGet:
		list := []*fakeBudget{}
		for _, b := range f.budgets {
			list = append(list, b)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Scope+list[i].Ref < list[j].Scope+list[j].Ref })
		jsonOut(w, 200, map[string]any{"budgets": list})
	case p == "/policies" && r.Method == http.MethodPost:
		var body struct {
			PPL  string `json:"ppl_source"`
			Mode string `json:"enforcement_mode"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if f.ignoreModeOnCreate {
			body.Mode = "" // a control plane that predates the field
		}
		np, ok := f.savePolicy(body.PPL, body.Mode)
		if !ok {
			jsonOut(w, 400, map[string]any{"error": "invalid policy"})
			return
		}
		jsonOut(w, 201, np)
	case p == "/policies" && r.Method == http.MethodGet:
		var list []*fakePolicy
		for _, x := range f.policies {
			if x.Status == "active" {
				list = append(list, x)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].PolicyID < list[j].PolicyID })
		if list == nil {
			list = []*fakePolicy{}
		}
		jsonOut(w, 200, map[string]any{"policies": list, "status": "active"})
	case len(parts) == 2 && parts[0] == "policies" && r.Method == http.MethodGet:
		if x := f.policies[parts[1]]; x != nil {
			jsonOut(w, 200, x)
			return
		}
		jsonOut(w, 404, map[string]any{"error": "not found"})
	case len(parts) == 2 && parts[0] == "policies" && r.Method == http.MethodDelete:
		if x := f.policies[parts[1]]; x != nil {
			x.Status = "archived"
			w.WriteHeader(204)
			return
		}
		jsonOut(w, 404, map[string]any{"error": "not found"})
	case len(parts) == 3 && parts[0] == "policies" && parts[2] == "mode" && r.Method == http.MethodPatch:
		var body struct {
			Mode string `json:"mode"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		x := f.policies[parts[1]]
		if x == nil {
			jsonOut(w, 404, map[string]any{"error": "not found"})
			return
		}
		if body.Mode != "enforce" && body.Mode != "observe" {
			jsonOut(w, 400, map[string]any{"error": "mode"})
			return
		}
		x.EnforcementMode = body.Mode
		f.modePatches++
		jsonOut(w, 200, x)
	case p == "/registry/groups" && r.Method == http.MethodPost:
		var g fakeGroup
		_ = json.NewDecoder(r.Body).Decode(&g)
		if g.Name == "" {
			jsonOut(w, 400, map[string]any{"error": "name is required"})
			return
		}
		g.GroupID = f.id("grp")
		if g.Tags == nil {
			g.Tags = []string{}
		}
		f.groups[g.GroupID] = &g
		f.members[g.GroupID] = map[string]bool{}
		jsonOut(w, 201, g)
	case len(parts) == 3 && parts[0] == "registry" && parts[1] == "groups" && r.Method == http.MethodGet:
		if g := f.groups[parts[2]]; g != nil {
			jsonOut(w, 200, g)
			return
		}
		jsonOut(w, 404, map[string]any{"error": "group not found"})
	case len(parts) == 3 && parts[0] == "registry" && parts[1] == "groups" && r.Method == http.MethodPut:
		g := f.groups[parts[2]]
		if g == nil {
			jsonOut(w, 404, map[string]any{"error": "group not found"})
			return
		}
		var in fakeGroup
		_ = json.NewDecoder(r.Body).Decode(&in)
		in.GroupID = g.GroupID
		if in.Tags == nil {
			in.Tags = []string{}
		}
		*g = in
		jsonOut(w, 200, g)
	case len(parts) == 3 && parts[0] == "registry" && parts[1] == "groups" && r.Method == http.MethodDelete:
		if f.groups[parts[2]] == nil {
			jsonOut(w, 404, map[string]any{"error": "group not found"})
			return
		}
		delete(f.groups, parts[2])
		delete(f.members, parts[2])
		w.WriteHeader(204)
	case len(parts) == 4 && parts[0] == "registry" && parts[3] == "members" && r.Method == http.MethodGet:
		set, ok := f.members[parts[2]]
		if !ok {
			jsonOut(w, 404, map[string]any{"error": "group not found"})
			return
		}
		ids := []string{}
		for a := range set {
			ids = append(ids, a)
		}
		sort.Strings(ids)
		jsonOut(w, 200, map[string]any{"agent_ids": ids, "count": len(ids)})
	case len(parts) == 4 && parts[0] == "registry" && parts[3] == "members" && r.Method == http.MethodPost:
		set, ok := f.members[parts[2]]
		if !ok {
			jsonOut(w, 404, map[string]any{"error": "group not found"})
			return
		}
		var body struct {
			AgentID string `json:"agent_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		set[body.AgentID] = true
		jsonOut(w, 201, map[string]any{"ok": true})
	case len(parts) == 5 && parts[0] == "registry" && parts[3] == "members" && r.Method == http.MethodDelete:
		set, ok := f.members[parts[2]]
		if !ok || !set[parts[4]] {
			jsonOut(w, 404, map[string]any{"error": "membership not found"})
			return
		}
		delete(set, parts[4])
		w.WriteHeader(204)
	case len(parts) == 3 && parts[0] == "agents" && parts[2] == "policy-bindings" && r.Method == http.MethodGet:
		ids := []string{}
		for id := range f.bindings[parts[1]] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		jsonOut(w, 200, map[string]any{"policy_ids": ids})
	case len(parts) == 3 && parts[0] == "agents" && parts[2] == "policy-bindings" && r.Method == http.MethodPost:
		var body struct {
			PolicyID string `json:"policy_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		x := f.policies[body.PolicyID]
		if x == nil || x.Status != "active" {
			jsonOut(w, 400, map[string]any{"error": "policy not found or not active"})
			return
		}
		if f.bindings[parts[1]] == nil {
			f.bindings[parts[1]] = map[string]bool{}
		}
		if f.bindings[parts[1]][body.PolicyID] {
			jsonOut(w, 409, map[string]any{"error": "already bound"})
			return
		}
		f.bindings[parts[1]][body.PolicyID] = true
		jsonOut(w, 201, map[string]any{"ok": true})
	case len(parts) == 4 && parts[0] == "agents" && parts[2] == "policy-bindings" && r.Method == http.MethodDelete:
		if !f.bindings[parts[1]][parts[3]] {
			jsonOut(w, 404, map[string]any{"error": "binding not found"})
			return
		}
		delete(f.bindings[parts[1]], parts[3])
		w.WriteHeader(204)
	case p == "/agents" && r.Method == http.MethodGet:
		// Like the api: q is a contains-match on the name, status an exact filter, paged.
		q, status := strings.ToLower(r.URL.Query().Get("q")), r.URL.Query().Get("status")
		var limit, offset int
		fmt.Sscan(r.URL.Query().Get("limit"), &limit)
		fmt.Sscan(r.URL.Query().Get("offset"), &offset)
		if limit <= 0 || limit > 100 {
			limit = 50 // the api's clamp: out of range means the default, not the maximum
		}
		match := []fakeAgent{}
		for _, a := range f.agents {
			if (q == "" || strings.Contains(strings.ToLower(a.DisplayName), q)) && (status == "" || a.Status == status) {
				match = append(match, a)
			}
		}
		if offset > len(match) {
			offset = len(match)
		}
		end := offset + limit
		if end > len(match) {
			end = len(match)
		}
		jsonOut(w, 200, map[string]any{"agents": match[offset:end], "count": end - offset})
	case len(parts) == 2 && parts[0] == "agents" && r.Method == http.MethodGet:
		for _, a := range f.agents {
			if a.AgentID == parts[1] {
				jsonOut(w, 200, a)
				return
			}
		}
		jsonOut(w, 404, map[string]any{"error": "agent not found"})
	default:
		if f.serveMCP(w, r, parts) || f.serveGovernance(w, r, p, parts) {
			return
		}
		jsonOut(w, 404, map[string]any{"error": "no route " + r.Method + " " + r.URL.Path})
	}
}

func startFake(token string) (*fakeAPI, *httptest.Server) {
	f := newFakeAPI(token)
	return f, httptest.NewServer(f)
}

// serveSignIn is POST /api/v1/automation/token: an API key as the bearer token, or identity_id
// and oidc_token in the body, exchanged for a session token. Caller holds f.mu.
func (f *fakeAPI) serveSignIn(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IdentityID string `json:"identity_id"`
		OIDCToken  string `json:"oidc_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	byKey := f.apiKey != "" && key == f.apiKey
	byPipeline := f.identityID != "" && body.IdentityID == f.identityID && body.OIDCToken == f.pipelineToken
	if !byKey && !byPipeline {
		jsonOut(w, 401, map[string]any{"error": "sign-in refused: the key is not recognised"})
		return
	}
	f.signIns++
	if f.sessions == nil {
		f.sessions = map[string]bool{}
	}
	token := fmt.Sprintf("pat_session_%d", f.signIns)
	f.sessions[token] = true
	secs := f.sessionSecs
	if secs == 0 {
		secs = 600
	}
	jsonOut(w, 200, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": secs})
}
