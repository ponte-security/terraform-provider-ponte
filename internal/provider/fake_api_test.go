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

type fakeAPI struct {
	mu       sync.Mutex
	token    string
	n        int
	policies map[string]*fakePolicy // by policy id
	groups   map[string]*fakeGroup
	members  map[string]map[string]bool // group → agent set
	bindings map[string]map[string]bool // agent → policy id set
	calls    []string
}

func newFakeAPI(token string) *fakeAPI {
	return &fakeAPI{token: token, policies: map[string]*fakePolicy{}, groups: map[string]*fakeGroup{}, members: map[string]map[string]bool{}, bindings: map[string]map[string]bool{}}
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
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		jsonOut(w, 401, map[string]any{"error": "unauthorized"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	p := strings.TrimPrefix(r.URL.Path, "/v1")
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/policies" && r.Method == http.MethodPost:
		var body struct {
			PPL string `json:"ppl_source"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		var doc struct {
			Metadata struct {
				Name string `yaml:"name"`
			} `yaml:"metadata"`
			Spec struct {
				Description string `yaml:"description"`
			} `yaml:"spec"`
		}
		if err := yaml.Unmarshal([]byte(body.PPL), &doc); err != nil || doc.Metadata.Name == "" {
			jsonOut(w, 400, map[string]any{"error": "invalid policy"})
			return
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
		np := &fakePolicy{PolicyID: f.id("pol"), Name: doc.Metadata.Name, Version: version, Description: strings.TrimSpace(doc.Spec.Description), Status: "active", EnforcementMode: "enforce", PPL: body.PPL}
		f.policies[np.PolicyID] = np
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
	default:
		jsonOut(w, 404, map[string]any{"error": "no route " + r.Method + " " + r.URL.Path})
	}
}

func startFake(token string) (*fakeAPI, *httptest.Server) {
	f := newFakeAPI(token)
	return f, httptest.NewServer(f)
}
