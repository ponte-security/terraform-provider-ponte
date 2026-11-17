package provider

// The fake's MCP server registry, with the behaviours ponte_mcp_server depends on: one
// registration per endpoint, a registry update that replaces the whole record but carries the
// server-owned metadata when the request leaves it out, pinned tools that only exist after a
// sync, and a delete that takes the pins with it.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

type fakeMCPServer struct {
	ID       string
	Record   map[string]any    // the registry record, as the control plane returns it
	Pins     map[string]string // tool → declared risk tier ("" = undeclared)
	Replaced int               // registry updates received
	Nulls    []string          // members a registry update left out (the real store writes them as JSON null)
}

var fakeServerOwned = []string{"mcp_proxy_identity", "sync", "require_tool_review"}

var fakeRiskTiers = map[string]bool{"read": true, "write": true, "external_send": true, "destructive": true, "code_exec": true}

// pinTools is what a sync does: the server's tools become pinned, undeclared.
func (f *fakeAPI) pinTools(serverID string, tools ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.mcp[serverID]
	for _, t := range tools {
		s.Pins[t] = ""
	}
	s.Record["tools_exposed"] = tools
	s.Record["metadata"].(map[string]any)["sync"] = map[string]any{"status": "ok", "tool_count": len(tools)}
}

func (f *fakeAPI) mcpByName(name string) *fakeMCPServer {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.mcp {
		if s.Record["name"] == name {
			return s
		}
	}
	return nil
}

func (f *fakeAPI) serveMCP(w http.ResponseWriter, r *http.Request, parts []string) bool {
	if f.mcp == nil {
		f.mcp = map[string]*fakeMCPServer{}
	}
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }
	switch {
	case len(parts) == 1 && parts[0] == "mcp-servers" && r.Method == http.MethodPost:
		var in map[string]any
		_ = json.NewDecoder(r.Body).Decode(&in)
		name, endpoint := strings.TrimSpace(str(in, "name")), strings.TrimSpace(str(in, "endpoint_url"))
		if len(name) < 3 || !strings.HasPrefix(endpoint, "https://") {
			jsonOut(w, 400, map[string]any{"error": "invalid registration"})
			return true
		}
		for _, s := range f.mcp {
			if strings.EqualFold(strings.TrimRight(str(s.Record, "endpoint_url"), "/"), strings.TrimRight(endpoint, "/")) {
				jsonOut(w, 409, map[string]any{"error": "this endpoint is already registered as " + str(s.Record, "name")})
				return true
			}
		}
		id := f.id("res")
		rec := map[string]any{"resource_id": id, "org_id": "org_1", "name": name, "type": "mcp_server", "endpoint_url": endpoint,
			"auth_mechanisms": []any{}, "tools_exposed": []any{}, "data_classification": str(in, "data_classification"),
			"environment": str(in, "environment"), "status": "active", "owner": str(in, "owner"),
			"metadata": map[string]any{"mcp_proxy_identity": map[string]any{"agent_id": "agt_proxy"}}}
		f.mcp[id] = &fakeMCPServer{ID: id, Record: rec, Pins: map[string]string{}}
		jsonOut(w, 201, map[string]any{"resource_id": id, "name": name, "status": "active"})
	case len(parts) == 1 && parts[0] == "mcp-servers" && r.Method == http.MethodGet:
		list := []map[string]any{}
		for _, s := range f.mcp {
			review, _ := s.Record["metadata"].(map[string]any)["require_tool_review"].(bool)
			list = append(list, map[string]any{"resource_id": s.ID, "name": s.Record["name"], "endpoint_url": s.Record["endpoint_url"],
				"data_classification": s.Record["data_classification"], "environment": s.Record["environment"], "status": s.Record["status"],
				"owner": s.Record["owner"], "require_tool_review": review})
		}
		sort.Slice(list, func(i, j int) bool { return list[i]["name"].(string) < list[j]["name"].(string) })
		jsonOut(w, 200, map[string]any{"mcp_servers": list, "count": len(list)})
	case len(parts) == 2 && parts[0] == "mcp-servers" && r.Method == http.MethodDelete:
		if f.mcp[parts[1]] == nil {
			jsonOut(w, 404, map[string]any{"error": "mcp server not found"})
			return true
		}
		delete(f.mcp, parts[1])
		jsonOut(w, 200, map[string]any{"deleted": true})
	case len(parts) == 3 && parts[0] == "mcp-servers" && parts[2] == "review-mode" && r.Method == http.MethodPut:
		s := f.mcp[parts[1]]
		if s == nil {
			jsonOut(w, 404, map[string]any{"error": "mcp server not found"})
			return true
		}
		var in struct {
			RequireReview bool `json:"require_review"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		s.Record["metadata"].(map[string]any)["require_tool_review"] = in.RequireReview
		jsonOut(w, 200, map[string]any{"require_review": in.RequireReview})
	case len(parts) == 3 && parts[0] == "mcp-servers" && parts[2] == "tool-definitions" && r.Method == http.MethodGet:
		// Like the api, an unknown server is an empty list, not a 404.
		tools := []map[string]any{}
		if s := f.mcp[parts[1]]; s != nil {
			for t, tier := range s.Pins {
				tools = append(tools, map[string]any{"tool": t, "risk_tier": tier, "risk_tier_declared": tier != ""})
			}
		}
		jsonOut(w, 200, map[string]any{"resource_id": parts[1], "tools": tools})
	case len(parts) == 5 && parts[0] == "mcp-servers" && parts[2] == "tool-definitions" && parts[4] == "risk-tier" && r.Method == http.MethodPost:
		var in struct {
			RiskTier string `json:"risk_tier"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if !fakeRiskTiers[in.RiskTier] {
			jsonOut(w, 400, map[string]any{"error": "risk_tier must be one of read, write, external_send, destructive, code_exec"})
			return true
		}
		s := f.mcp[parts[1]]
		if s == nil {
			jsonOut(w, 404, map[string]any{"error": "tool not pinned for this server"})
			return true
		}
		if _, pinned := s.Pins[parts[3]]; !pinned {
			jsonOut(w, 404, map[string]any{"error": "tool not pinned for this server"})
			return true
		}
		s.Pins[parts[3]] = in.RiskTier
		jsonOut(w, 200, map[string]any{"tool": parts[3], "risk_tier": in.RiskTier})
	case len(parts) == 3 && parts[0] == "registry" && parts[1] == "resources" && r.Method == http.MethodGet:
		s := f.mcp[parts[2]]
		if s == nil {
			jsonOut(w, 404, map[string]any{"error": "resource not found"})
			return true
		}
		jsonOut(w, 200, s.Record)
	case len(parts) == 3 && parts[0] == "registry" && parts[1] == "resources" && r.Method == http.MethodPut:
		s := f.mcp[parts[2]]
		if s == nil {
			jsonOut(w, 404, map[string]any{"error": "resource not found"})
			return true
		}
		// The whole record is replaced; only the server-owned metadata survives an omission.
		var next map[string]any
		_ = json.NewDecoder(r.Body).Decode(&next)
		for _, k := range []string{"metadata", "auth_mechanisms", "sensitivity_labels"} {
			if next[k] == nil {
				s.Nulls = append(s.Nulls, k)
			}
		}
		meta, _ := next["metadata"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		cur := s.Record["metadata"].(map[string]any)
		for _, k := range fakeServerOwned {
			if _, supplied := meta[k]; !supplied {
				if v, ok := cur[k]; ok {
					meta[k] = v
				}
			}
		}
		next["metadata"] = meta
		next["resource_id"], next["org_id"] = s.ID, "org_1"
		if next["tools_exposed"] == nil {
			next["tools_exposed"] = []any{}
		}
		s.Record = next
		s.Replaced++
		jsonOut(w, 200, s.Record)
	default:
		return false
	}
	return true
}
