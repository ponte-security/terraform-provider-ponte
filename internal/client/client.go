// Package client is the thin HTTP client the provider uses against the Ponte control plane:
// an endpoint (…/api/control), an operator bearer token, JSON in and out, and one error type
// that carries the status so resources can tell "gone" from "failed".
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one Ponte control plane as one operator.
type Client struct {
	Endpoint    string
	Token       string
	UserAgent   string
	HTTP        *http.Client
	apiEndpoint string
}

// New builds a client. endpoint is the control plane base, e.g. https://app.ponte.ai/api/control.
func New(endpoint, token, userAgent string) *Client {
	return &Client{Endpoint: strings.TrimRight(strings.TrimSpace(endpoint), "/"), Token: strings.TrimSpace(token), UserAgent: userAgent,
		HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Error is a non-2xx answer.
type Error struct {
	Status int
	Method string
	Path   string
	Body   string
}

func (e *Error) Error() string {
	msg := e.Body
	var parsed struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(e.Body), &parsed) == nil {
		if parsed.Error != "" {
			msg = parsed.Error
		} else if parsed.Message != "" {
			msg = parsed.Message
		}
	}
	return fmt.Sprintf("%s %s: %d %s", e.Method, e.Path, e.Status, strings.TrimSpace(msg))
}

// IsNotFound reports whether err is a 404.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// Do sends a JSON request to the control plane and decodes a JSON answer into out (nil to discard).
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	return c.do(ctx, c.Endpoint, method, path, in, out)
}

func (c *Client) do(ctx context.Context, base, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &Error{Status: resp.StatusCode, Method: method, Path: path, Body: string(raw)}
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("%s %s: answer is not JSON: %w", method, path, err)
		}
	}
	return nil
}

// ── Policies ──

// Policy is the control plane's policy record (the fields the provider reads).
type Policy struct {
	PolicyID        string `json:"policy_id"`
	Name            string `json:"name"`
	Version         int    `json:"version"`
	Description     string `json:"description"`
	Status          string `json:"status"`
	EnforcementMode string `json:"enforcement_mode"`
	ReasoningMode   string `json:"reasoning_mode"`
}

// CreatePolicy saves a policy version from PPL YAML. A name that exists gets a new version
// with a NEW policy id; the previous version is archived and bindings follow the name.
func (c *Client) CreatePolicy(ctx context.Context, ppl string) (*Policy, error) {
	var p Policy
	if err := c.Do(ctx, http.MethodPost, "/v1/policies", map[string]any{"ppl_source": ppl}, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetPolicy reads one version by id.
func (c *Client) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	var p Policy
	if err := c.Do(ctx, http.MethodGet, "/v1/policies/"+id, nil, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ActivePolicyByName finds the active version of a name; nil when none.
func (c *Client) ActivePolicyByName(ctx context.Context, name string) (*Policy, error) {
	var out struct {
		Policies []Policy `json:"policies"`
		Data     []Policy `json:"data"`
	}
	if err := c.Do(ctx, http.MethodGet, "/v1/policies?status=active", nil, &out); err != nil {
		return nil, err
	}
	list := out.Policies
	if len(list) == 0 {
		list = out.Data
	}
	for i := range list {
		if list[i].Name == name && (list[i].Status == "" || list[i].Status == "active") {
			return &list[i], nil
		}
	}
	return nil, nil
}

// SetPolicyMode sets enforce | observe.
func (c *Client) SetPolicyMode(ctx context.Context, id, mode string) error {
	return c.Do(ctx, http.MethodPatch, "/v1/policies/"+id+"/mode", map[string]any{"mode": mode}, nil)
}

// DeletePolicy archives a version.
func (c *Client) DeletePolicy(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/policies/"+id, nil, nil)
}

// ── Agent groups ──

// Group is an agent group.
type Group struct {
	GroupID             string   `json:"group_id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	TrustLevel          string   `json:"trust_level"`
	Owner               string   `json:"owner"`
	Tags                []string `json:"tags"`
	MaxConcurrentAgents *int     `json:"max_concurrent_agents,omitempty"`
}

// GroupInput is what create and update take.
type GroupInput struct {
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	TrustLevel          string   `json:"trust_level"`
	Owner               string   `json:"owner"`
	Tags                []string `json:"tags"`
	MaxConcurrentAgents *int     `json:"max_concurrent_agents,omitempty"`
}

func (c *Client) CreateGroup(ctx context.Context, in GroupInput) (*Group, error) {
	var g Group
	if err := c.Do(ctx, http.MethodPost, "/v1/registry/groups", in, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func (c *Client) GetGroup(ctx context.Context, id string) (*Group, error) {
	var g Group
	if err := c.Do(ctx, http.MethodGet, "/v1/registry/groups/"+id, nil, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func (c *Client) UpdateGroup(ctx context.Context, id string, in GroupInput) (*Group, error) {
	var g Group
	if err := c.Do(ctx, http.MethodPut, "/v1/registry/groups/"+id, in, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/registry/groups/"+id, nil, nil)
}

// GroupMembers lists the agent ids in a group.
func (c *Client) GroupMembers(ctx context.Context, id string) ([]string, error) {
	var out struct {
		AgentIDs []string `json:"agent_ids"`
	}
	if err := c.Do(ctx, http.MethodGet, "/v1/registry/groups/"+id+"/members", nil, &out); err != nil {
		return nil, err
	}
	return out.AgentIDs, nil
}

func (c *Client) AddGroupMember(ctx context.Context, groupID, agentID string) error {
	return c.Do(ctx, http.MethodPost, "/v1/registry/groups/"+groupID+"/members", map[string]any{"agent_id": agentID}, nil)
}

func (c *Client) RemoveGroupMember(ctx context.Context, groupID, agentID string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/registry/groups/"+groupID+"/members/"+agentID, nil, nil)
}

// ── Policy bindings ──

// AgentPolicyBindings lists the policy ids bound to an agent.
func (c *Client) AgentPolicyBindings(ctx context.Context, agentID string) ([]string, error) {
	var out struct {
		PolicyIDs []string `json:"policy_ids"`
	}
	if err := c.Do(ctx, http.MethodGet, "/v1/agents/"+agentID+"/policy-bindings", nil, &out); err != nil {
		return nil, err
	}
	return out.PolicyIDs, nil
}

func (c *Client) BindPolicy(ctx context.Context, agentID, policyID string) error {
	return c.Do(ctx, http.MethodPost, "/v1/agents/"+agentID+"/policy-bindings", map[string]any{"policy_id": policyID}, nil)
}

func (c *Client) UnbindPolicy(ctx context.Context, agentID, policyID string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/agents/"+agentID+"/policy-bindings/"+policyID, nil, nil)
}

// ── The api side (…/api/v1): webhooks and budgets live on the api, not the control plane ──

// APIEndpoint is the api base (…/api). Derived from Endpoint when unset: the control plane is
// mounted at …/api/control, so the api is its parent.
func (c *Client) APIEndpoint() string {
	if c.apiEndpoint != "" {
		return c.apiEndpoint
	}
	return strings.TrimSuffix(c.Endpoint, "/control")
}

// SetAPIEndpoint overrides the api base.
func (c *Client) SetAPIEndpoint(s string) {
	c.apiEndpoint = strings.TrimRight(strings.TrimSpace(s), "/")
}

// DoAPI is Do against the api base. Resources run concurrently, so the base is passed, never
// swapped on the client.
func (c *Client) DoAPI(ctx context.Context, method, path string, in, out any) error {
	return c.do(ctx, c.APIEndpoint(), method, path, in, out)
}

// Webhook is an outbound webhook subscription. Headers come back redacted from the api.
type Webhook struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	URL          string            `json:"url"`
	EventTypes   []string          `json:"event_types"`
	Headers      map[string]string `json:"headers"`
	Enabled      bool              `json:"enabled"`
	Description  string            `json:"description"`
	Format       string            `json:"format"`
	FormatConfig json.RawMessage   `json:"format_config"`
	MinSeverity  string            `json:"min_severity"`
}

// WebhookInput is what create takes; update sends the same fields (all of them).
type WebhookInput struct {
	Name         string            `json:"name"`
	URL          string            `json:"url"`
	EventTypes   []string          `json:"event_types"`
	Headers      map[string]string `json:"headers"`
	Description  string            `json:"description"`
	Enabled      *bool             `json:"enabled,omitempty"`
	Format       string            `json:"format,omitempty"`
	FormatConfig json.RawMessage   `json:"format_config,omitempty"`
	MinSeverity  string            `json:"min_severity,omitempty"`
}

// CreateWebhook creates a subscription and returns it with the signing secret (shown once).
func (c *Client) CreateWebhook(ctx context.Context, in WebhookInput) (*Webhook, string, error) {
	var out struct {
		ID            string `json:"id"`
		SigningSecret string `json:"signing_secret"`
	}
	if err := c.DoAPI(ctx, http.MethodPost, "/v1/webhooks", in, &out); err != nil {
		return nil, "", err
	}
	w, err := c.GetWebhook(ctx, out.ID)
	if err != nil {
		return nil, "", err
	}
	return w, out.SigningSecret, nil
}

// GetWebhook reads one subscription (through the list; the api has no single-item read).
func (c *Client) GetWebhook(ctx context.Context, id string) (*Webhook, error) {
	var out struct {
		Subscriptions []Webhook `json:"subscriptions"`
	}
	if err := c.DoAPI(ctx, http.MethodGet, "/v1/webhooks", nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Subscriptions {
		if out.Subscriptions[i].ID == id {
			return &out.Subscriptions[i], nil
		}
	}
	return nil, &Error{Status: http.StatusNotFound, Method: http.MethodGet, Path: "/v1/webhooks/" + id, Body: "not found"}
}

// UpdateWebhook patches every field of a subscription.
func (c *Client) UpdateWebhook(ctx context.Context, id string, in WebhookInput) error {
	body := map[string]any{"name": in.Name, "url": in.URL, "event_types": in.EventTypes, "headers": in.Headers, "description": in.Description}
	if in.Enabled != nil {
		body["enabled"] = *in.Enabled
	}
	if in.Format != "" {
		body["format"] = in.Format
	}
	if len(in.FormatConfig) > 0 {
		body["format_config"] = in.FormatConfig
	}
	if in.MinSeverity != "" {
		body["min_severity"] = in.MinSeverity
	}
	return c.DoAPI(ctx, http.MethodPatch, "/v1/webhooks/"+id, body, nil)
}

func (c *Client) DeleteWebhook(ctx context.Context, id string) error {
	return c.DoAPI(ctx, http.MethodDelete, "/v1/webhooks/"+id, nil, nil)
}

// Budget is one spend budget on a scope.
type Budget struct {
	Scope         string   `json:"scope"`
	Ref           string   `json:"ref"`
	MonthlyUSD    *float64 `json:"monthly_usd"`
	MonthlyTokens *int64   `json:"monthly_tokens"`
}

// PutBudget sets (or, with both limits nil, clears) a budget.
func (c *Client) PutBudget(ctx context.Context, b Budget) error {
	return c.DoAPI(ctx, http.MethodPut, "/v1/spend/budgets", b, nil)
}

// GetBudget finds a budget by scope and ref; nil when none.
func (c *Client) GetBudget(ctx context.Context, scope, ref string) (*Budget, error) {
	var out struct {
		Budgets []Budget `json:"budgets"`
	}
	if err := c.DoAPI(ctx, http.MethodGet, "/v1/spend/budgets", nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Budgets {
		if out.Budgets[i].Scope == scope && out.Budgets[i].Ref == ref {
			return &out.Budgets[i], nil
		}
	}
	return nil, nil
}

// ── MCP servers (api side for register / list / delete / review mode; the control plane's
// registry for an edit in place) ──

// MCPServer is a registered MCP server (the fields the provider reads).
type MCPServer struct {
	ResourceID         string `json:"resource_id"`
	Name               string `json:"name"`
	EndpointURL        string `json:"endpoint_url"`
	DataClassification string `json:"data_classification"`
	Environment        string `json:"environment"`
	Owner              string `json:"owner"`
	Status             string `json:"status"`
	RequireToolReview  bool   `json:"require_tool_review"`
}

// MCPServerInput is what register and update take.
type MCPServerInput struct {
	Name               string `json:"name"`
	EndpointURL        string `json:"endpoint_url"`
	DataClassification string `json:"data_classification"`
	Environment        string `json:"environment"`
	Owner              string `json:"owner"`
}

// RegisterMCPServer registers a server and returns its id. The api refuses a second
// registration of the same endpoint (409).
func (c *Client) RegisterMCPServer(ctx context.Context, in MCPServerInput) (string, error) {
	var out struct {
		ResourceID string `json:"resource_id"`
	}
	if err := c.DoAPI(ctx, http.MethodPost, "/v1/mcp-servers", in, &out); err != nil {
		return "", err
	}
	return out.ResourceID, nil
}

// GetMCPServer reads one server (through the list; the api has no single-item read).
func (c *Client) GetMCPServer(ctx context.Context, id string) (*MCPServer, error) {
	var out struct {
		Servers []MCPServer `json:"mcp_servers"`
	}
	if err := c.DoAPI(ctx, http.MethodGet, "/v1/mcp-servers", nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Servers {
		if out.Servers[i].ResourceID == id {
			return &out.Servers[i], nil
		}
	}
	return nil, &Error{Status: http.StatusNotFound, Method: http.MethodGet, Path: "/v1/mcp-servers/" + id, Body: "not found"}
}

// mcpServerOwnedMetadata are the metadata members the control plane writes itself. They are
// left out of an update so the server carries its current values across (a sync may have
// written them since the read); sending a copy read a moment ago could put an old one back.
var mcpServerOwnedMetadata = []string{"mcp_proxy_identity", "sync", "require_tool_review"}

// UpdateMCPServer changes name, classification, environment and owner in place. The registry
// update replaces the whole record, so the record is read and sent back with only those four
// fields changed: pinned tools, the proxy identity and the sync state are untouched.
func (c *Client) UpdateMCPServer(ctx context.Context, id string, in MCPServerInput) error {
	var cur map[string]any
	if err := c.Do(ctx, http.MethodGet, "/v1/registry/resources/"+id, nil, &cur); err != nil {
		return err
	}
	if cur == nil {
		return &Error{Status: http.StatusNotFound, Method: http.MethodGet, Path: "/v1/registry/resources/" + id, Body: "not found"}
	}
	cur["name"] = in.Name
	cur["data_classification"] = in.DataClassification
	cur["environment"] = in.Environment
	cur["owner"] = in.Owner
	meta, _ := cur["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	for _, k := range mcpServerOwnedMetadata {
		delete(meta, k)
	}
	cur["metadata"] = meta
	// The read leaves out empty members; the update stores a missing one as JSON null, which
	// later writes to the record (the review mode, the sync state) cannot build on.
	for _, k := range []string{"auth_mechanisms", "sensitivity_labels", "tools_exposed"} {
		if cur[k] == nil {
			cur[k] = []any{}
		}
	}
	return c.Do(ctx, http.MethodPut, "/v1/registry/resources/"+id, cur, nil)
}

// SetMCPServerReviewMode sets whether a newly seen tool waits for approval before use.
func (c *Client) SetMCPServerReviewMode(ctx context.Context, id string, require bool) error {
	return c.DoAPI(ctx, http.MethodPut, "/v1/mcp-servers/"+id+"/review-mode", map[string]any{"require_review": require}, nil)
}

// DeleteMCPServer deregisters a server with its pinned tools, proxy config and sync credential.
func (c *Client) DeleteMCPServer(ctx context.Context, id string) error {
	return c.DoAPI(ctx, http.MethodDelete, "/v1/mcp-servers/"+id, nil, nil)
}

// ToolRiskTier reads a pinned tool's declared risk tier ("" when undeclared). A tool that is
// not pinned for the server is a 404.
func (c *Client) ToolRiskTier(ctx context.Context, serverID, tool string) (string, error) {
	var out struct {
		Tools []struct {
			Tool     string `json:"tool"`
			RiskTier string `json:"risk_tier"`
		} `json:"tools"`
	}
	path := "/v1/mcp-servers/" + serverID + "/tool-definitions"
	if err := c.DoAPI(ctx, http.MethodGet, path, nil, &out); err != nil {
		return "", err
	}
	for _, t := range out.Tools {
		if t.Tool == tool {
			return t.RiskTier, nil
		}
	}
	return "", &Error{Status: http.StatusNotFound, Method: http.MethodGet, Path: path + "/" + tool, Body: "tool not pinned for this server"}
}

// DeclareToolRiskTier declares what a pinned tool can do: read, write, external_send,
// destructive or code_exec.
func (c *Client) DeclareToolRiskTier(ctx context.Context, serverID, tool, tier string) error {
	return c.DoAPI(ctx, http.MethodPost, "/v1/mcp-servers/"+serverID+"/tool-definitions/"+url.PathEscape(tool)+"/risk-tier", map[string]any{"risk_tier": tier}, nil)
}

// ── Agents (read only: agents are registered and onboarded in Ponte, not in Terraform) ──

// Agent is a registered agent (the fields the provider reads).
type Agent struct {
	AgentID     string            `json:"agent_id"`
	DisplayName string            `json:"display_name"`
	Framework   string            `json:"framework"`
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	TrustTier   string            `json:"trust_tier"`
	Tools       []string          `json:"tool_manifest"`
}

// GetAgent reads one agent by id.
func (c *Client) GetAgent(ctx context.Context, id string) (*Agent, error) {
	var a Agent
	if err := c.Do(ctx, http.MethodGet, "/v1/agents/"+url.PathEscape(id), nil, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// agentPageSize is how many agents one list call asks for: the api's maximum. Asking for more
// does not get more, it gets the api's default of 50.
const agentPageSize = 100

// ListAgents returns the org's agents, optionally narrowed by a search term and a status. It
// walks every page, advancing by what each page actually returned and stopping at an empty
// one: a lookup that trusted its own page size would stop early if the api clamps it, miss an
// agent and say it does not exist.
func (c *Client) ListAgents(ctx context.Context, search, status string) ([]Agent, error) {
	var all []Agent
	for offset := 0; offset < 1000000; {
		q := url.Values{"limit": {fmt.Sprint(agentPageSize)}, "offset": {fmt.Sprint(offset)}}
		if search != "" {
			q.Set("q", search)
		}
		if status != "" {
			q.Set("status", status)
		}
		var out struct {
			Agents []Agent `json:"agents"`
		}
		if err := c.Do(ctx, http.MethodGet, "/v1/agents?"+q.Encode(), nil, &out); err != nil {
			return nil, err
		}
		if len(out.Agents) == 0 {
			break
		}
		all = append(all, out.Agents...)
		offset += len(out.Agents)
	}
	return all, nil
}
