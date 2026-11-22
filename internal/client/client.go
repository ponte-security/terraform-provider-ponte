// Package client is the thin HTTP client the provider uses against the Ponte control plane:
// an endpoint (…/api/control), an operator bearer token, JSON in and out, and one error type
// that carries the status so resources can tell "gone" from "failed".
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Client talks to one Ponte control plane as one operator.
type Client struct {
	Endpoint    string
	Token       string
	UserAgent   string
	HTTP        *http.Client
	apiEndpoint string
	// retryWait is the first pause between attempts; it doubles each time. Tests shorten it.
	retryWait time.Duration

	// signIn, when set, gets a session token for an automation identity (an API key or a
	// pipeline's own identity exchanged at the api). The client signs in before the first
	// request, again shortly before the session runs out, and once more if a request is
	// answered 401. Token is then the current session token.
	signIn   func(ctx context.Context) (token string, lifetime time.Duration, err error)
	mu       sync.Mutex
	tokenEnd time.Time
}

// New builds a client. endpoint is the control plane base, e.g. https://app.ponte.ai/api/control.
func New(endpoint, token, userAgent string) *Client {
	return &Client{Endpoint: strings.TrimRight(strings.TrimSpace(endpoint), "/"), Token: strings.TrimSpace(token), UserAgent: userAgent,
		HTTP: &http.Client{Timeout: 60 * time.Second}, retryWait: 500 * time.Millisecond}
}

// seg makes one id safe as a single path segment. Ids reach here from configuration and from
// `terraform import`, so a slash or a dot-dot in one must not select a different endpoint.
func seg(id string) string {
	switch id {
	case ".":
		return "%2E"
	case "..":
		return "%2E%2E"
	}
	return url.PathEscape(id)
}

// TokenExpiry reads the expiry out of the operator token without verifying it (the control
// plane verifies; this is only to say "expired" instead of a bare 401). ok is false when the
// token is not a JWT or carries no expiry.
func TokenExpiry(token string) (at time.Time, ok bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp float64 `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(claims.Exp), 0), true
}

// Error is a non-2xx answer.
type Error struct {
	Status int
	Method string
	Path   string
	Body   string
	// Hint says what to do about it, when the client can tell (an expired token).
	Hint string
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
	out := fmt.Sprintf("%s %s: %d %s", e.Method, e.Path, e.Status, strings.TrimSpace(msg))
	if e.Hint != "" {
		out += "\n\n" + e.Hint
	}
	return out
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

// maxAttempts is how many times one request is tried.
const maxAttempts = 4

// retryable says whether a failed attempt may be repeated. A GET, PUT or DELETE here is safe to
// send twice, so it is retried on a dropped connection and on a gateway's 502/503/504. A POST
// may have been carried out even though its answer was lost (a second one would register a
// second webhook), so it is repeated only when the server says it did nothing: 429.
func retryable(method string, status int, transport bool) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	if method == http.MethodPost || method == http.MethodPatch {
		return false
	}
	return transport || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func (c *Client) do(ctx context.Context, base, method, path string, in, out any) error {
	var payload []byte
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		payload = raw
	}
	wait := c.retryWait
	signedInAgain := false
	for attempt := 1; ; attempt++ {
		token, err := c.bearer(ctx, false)
		if err != nil {
			return err
		}
		status, raw, err := c.send(ctx, base, method, path, payload, in != nil, token)
		// A session that ended early (the identity's key was rotated, a session was ended):
		// sign in again and repeat, once.
		if err == nil && status == http.StatusUnauthorized && c.signIn != nil && !signedInAgain {
			signedInAgain = true
			if _, serr := c.bearer(ctx, true); serr != nil {
				return serr
			}
			continue
		}
		if err == nil && status >= 200 && status <= 299 {
			if out != nil && len(bytes.TrimSpace(raw)) > 0 {
				if err := json.Unmarshal(raw, out); err != nil {
					return fmt.Errorf("%s %s: answer is not JSON: %w", method, path, err)
				}
			}
			return nil
		}
		if attempt < maxAttempts && ctx.Err() == nil && retryable(method, status, err != nil) {
			select {
			case <-ctx.Done():
			case <-time.After(wait):
				wait *= 2
				continue
			}
		}
		if err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
		e := &Error{Status: status, Method: method, Path: path, Body: string(raw)}
		if status == http.StatusUnauthorized {
			e.Hint = c.unauthorizedHint()
		}
		return e
	}
}

// unauthorizedHint explains a 401. The usual cause is the operator token running out during a
// long apply: they last minutes.
func (c *Client) unauthorizedHint() string {
	if c.signIn != nil {
		return "The automation identity signed in, and its session was refused. Check that the identity is enabled and its key has not been revoked."
	}
	if at, ok := TokenExpiry(c.Token); ok && time.Now().After(at) {
		return "The operator token expired at " + at.UTC().Format(time.RFC3339) + ". Get a new one and run again; what was already applied is in the state."
	}
	return "Check that PONTE_OPERATOR_TOKEN is a signed-in operator's access token for this endpoint. An agent's token is refused."
}

// send makes one attempt and returns the status and the body.
func (c *Client) send(ctx context.Context, base, method, path string, payload []byte, hasBody bool, token string) (int, []byte, error) {
	var body io.Reader
	if hasBody {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, raw, nil
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
	// PPLSource is the policy as the control plane parsed it (JSON, not the YAML that was sent).
	PPLSource json.RawMessage `json:"ppl_source"`
}

// CreatePolicy saves a policy version from PPL YAML. A name that exists gets a new version
// with a NEW policy id; the previous version is archived and bindings follow the name. mode
// (enforce | observe) is stored with the version, so an observe policy never enforces first. A
// control plane that predates the field ignores it and answers with enforce; the caller checks.
func (c *Client) CreatePolicy(ctx context.Context, ppl, mode string) (*Policy, error) {
	var p Policy
	body := map[string]any{"ppl_source": ppl}
	if mode != "" {
		body["enforcement_mode"] = mode
	}
	if err := c.Do(ctx, http.MethodPost, "/v1/policies", body, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetPolicy reads one version by id.
func (c *Client) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	var p Policy
	if err := c.Do(ctx, http.MethodGet, "/v1/policies/"+seg(id), nil, &p); err != nil {
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
	return c.Do(ctx, http.MethodPatch, "/v1/policies/"+seg(id)+"/mode", map[string]any{"mode": mode}, nil)
}

// DeletePolicy archives a version.
func (c *Client) DeletePolicy(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/policies/"+seg(id), nil, nil)
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
	if err := c.Do(ctx, http.MethodGet, "/v1/registry/groups/"+seg(id), nil, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func (c *Client) UpdateGroup(ctx context.Context, id string, in GroupInput) (*Group, error) {
	var g Group
	if err := c.Do(ctx, http.MethodPut, "/v1/registry/groups/"+seg(id), in, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

func (c *Client) DeleteGroup(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/registry/groups/"+seg(id), nil, nil)
}

// GroupMembers lists the agent ids in a group.
func (c *Client) GroupMembers(ctx context.Context, id string) ([]string, error) {
	var out struct {
		AgentIDs []string `json:"agent_ids"`
	}
	if err := c.Do(ctx, http.MethodGet, "/v1/registry/groups/"+seg(id)+"/members", nil, &out); err != nil {
		return nil, err
	}
	return out.AgentIDs, nil
}

func (c *Client) AddGroupMember(ctx context.Context, groupID, agentID string) error {
	return c.Do(ctx, http.MethodPost, "/v1/registry/groups/"+seg(groupID)+"/members", map[string]any{"agent_id": agentID}, nil)
}

func (c *Client) RemoveGroupMember(ctx context.Context, groupID, agentID string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/registry/groups/"+seg(groupID)+"/members/"+seg(agentID), nil, nil)
}

// ── Policy bindings ──

// AgentPolicyBindings lists the policy ids bound to an agent.
func (c *Client) AgentPolicyBindings(ctx context.Context, agentID string) ([]string, error) {
	var out struct {
		PolicyIDs []string `json:"policy_ids"`
	}
	if err := c.Do(ctx, http.MethodGet, "/v1/agents/"+seg(agentID)+"/policy-bindings", nil, &out); err != nil {
		return nil, err
	}
	return out.PolicyIDs, nil
}

func (c *Client) BindPolicy(ctx context.Context, agentID, policyID string) error {
	return c.Do(ctx, http.MethodPost, "/v1/agents/"+seg(agentID)+"/policy-bindings", map[string]any{"policy_id": policyID}, nil)
}

func (c *Client) UnbindPolicy(ctx context.Context, agentID, policyID string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/agents/"+seg(agentID)+"/policy-bindings/"+seg(policyID), nil, nil)
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
	// Always sent: an empty object clears overrides that were removed from the configuration.
	body["format_config"] = json.RawMessage("{}")
	if len(in.FormatConfig) > 0 {
		body["format_config"] = in.FormatConfig
	}
	if in.MinSeverity != "" {
		body["min_severity"] = in.MinSeverity
	}
	return c.DoAPI(ctx, http.MethodPatch, "/v1/webhooks/"+seg(id), body, nil)
}

func (c *Client) DeleteWebhook(ctx context.Context, id string) error {
	return c.DoAPI(ctx, http.MethodDelete, "/v1/webhooks/"+seg(id), nil, nil)
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
	if err := c.Do(ctx, http.MethodGet, "/v1/registry/resources/"+seg(id), nil, &cur); err != nil {
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
	return c.Do(ctx, http.MethodPut, "/v1/registry/resources/"+seg(id), cur, nil)
}

// SetMCPServerReviewMode sets whether a newly seen tool waits for approval before use.
func (c *Client) SetMCPServerReviewMode(ctx context.Context, id string, require bool) error {
	return c.DoAPI(ctx, http.MethodPut, "/v1/mcp-servers/"+seg(id)+"/review-mode", map[string]any{"require_review": require}, nil)
}

// DeleteMCPServer deregisters a server with its pinned tools, proxy config and sync credential.
func (c *Client) DeleteMCPServer(ctx context.Context, id string) error {
	return c.DoAPI(ctx, http.MethodDelete, "/v1/mcp-servers/"+seg(id), nil, nil)
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
	path := "/v1/mcp-servers/" + seg(serverID) + "/tool-definitions"
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
	return c.DoAPI(ctx, http.MethodPost, "/v1/mcp-servers/"+seg(serverID)+"/tool-definitions/"+seg(tool)+"/risk-tier", map[string]any{"risk_tier": tier}, nil)
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
	if err := c.Do(ctx, http.MethodGet, "/v1/agents/"+seg(id), nil, &a); err != nil {
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

// ── SCIM targets: systems Ponte pushes its agents to over SCIM ──

// SCIMTarget is an outbound SCIM target. The bearer credential is write-only: Ponte stores it
// in its secret store and never returns it.
type SCIMTarget struct {
	TargetID  string `json:"target_id"`
	Name      string `json:"name"`
	BaseURL   string `json:"base_url"`
	Enabled   bool   `json:"enabled"`
	LastError string `json:"last_error"`
}

// CreateSCIMTarget records a target and stores its credential. A new target is enabled.
func (c *Client) CreateSCIMTarget(ctx context.Context, name, baseURL, bearerToken string) (*SCIMTarget, error) {
	var out struct {
		Target SCIMTarget `json:"target"`
	}
	in := map[string]any{"name": name, "base_url": baseURL, "bearer_token": bearerToken}
	if err := c.Do(ctx, http.MethodPost, "/v1/scim/targets", in, &out); err != nil {
		return nil, err
	}
	return &out.Target, nil
}

// GetSCIMTarget reads one target (through the list; there is no single-item read).
func (c *Client) GetSCIMTarget(ctx context.Context, id string) (*SCIMTarget, error) {
	var out struct {
		Targets []SCIMTarget `json:"targets"`
	}
	if err := c.Do(ctx, http.MethodGet, "/v1/scim/targets", nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Targets {
		if out.Targets[i].TargetID == id {
			return &out.Targets[i], nil
		}
	}
	return nil, &Error{Status: http.StatusNotFound, Method: http.MethodGet, Path: "/v1/scim/targets/" + id, Body: "not found"}
}

// SetSCIMTargetEnabled turns pushes to a target on or off. It is the only in-place change.
func (c *Client) SetSCIMTargetEnabled(ctx context.Context, id string, enabled bool) error {
	return c.Do(ctx, http.MethodPatch, "/v1/scim/targets/"+seg(id), map[string]any{"enabled": enabled}, nil)
}

// DeleteSCIMTarget removes a target and its stored credential.
func (c *Client) DeleteSCIMTarget(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/scim/targets/"+seg(id), nil, nil)
}

// ── Recertification review policies: how a campaign is reviewed ──

// RecertCondition is one auto-certify condition.
type RecertCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// RecertPolicySpec is how a campaign is reviewed. Members are sent in full on every save: the
// control plane replaces the whole spec.
type RecertPolicySpec struct {
	Reviewer      string            `json:"reviewer"`
	ReviewerRef   string            `json:"reviewer_ref"`
	FallbackGroup string            `json:"fallback_group"`
	SecondReview  string            `json:"second_review"`
	SecondGroup   string            `json:"second_group"`
	DueDays       int64             `json:"due_days"`
	RemindDays    int64             `json:"remind_days"`
	OnOverdue     string            `json:"on_overdue"`
	EscalateGroup string            `json:"escalate_group"`
	EscalateDays  int64             `json:"escalate_days"`
	OnDeny        string            `json:"on_deny"`
	AutoCertify   []RecertCondition `json:"auto_certify"`
}

// RecertPolicy is a stored review policy.
type RecertPolicy struct {
	PolicyID string           `json:"policy_id"`
	Name     string           `json:"name"`
	Spec     RecertPolicySpec `json:"spec"`
	UsedBy   int              `json:"used_by"`
}

// SaveRecertPolicy creates a review policy (id "") or replaces one.
func (c *Client) SaveRecertPolicy(ctx context.Context, id, name string, spec RecertPolicySpec) (*RecertPolicy, error) {
	var out struct {
		Policy RecertPolicy `json:"policy"`
	}
	if spec.AutoCertify == nil {
		spec.AutoCertify = []RecertCondition{}
	}
	method, path := http.MethodPost, "/v1/recert/policies"
	if id != "" {
		method, path = http.MethodPut, path+"/"+seg(id)
	}
	if err := c.Do(ctx, method, path, map[string]any{"name": name, "spec": spec}, &out); err != nil {
		return nil, err
	}
	return &out.Policy, nil
}

// GetRecertPolicy reads one review policy (through the list; there is no single-item read).
func (c *Client) GetRecertPolicy(ctx context.Context, id string) (*RecertPolicy, error) {
	var out struct {
		Policies []RecertPolicy `json:"policies"`
	}
	if err := c.Do(ctx, http.MethodGet, "/v1/recert/policies", nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Policies {
		if out.Policies[i].PolicyID == id {
			return &out.Policies[i], nil
		}
	}
	return nil, &Error{Status: http.StatusNotFound, Method: http.MethodGet, Path: "/v1/recert/policies/" + id, Body: "not found"}
}

// DeleteRecertPolicy deletes a review policy. One that a schedule or rule uses is refused (409).
func (c *Client) DeleteRecertPolicy(ctx context.Context, id string) error {
	return c.Do(ctx, http.MethodDelete, "/v1/recert/policies/"+seg(id), nil, nil)
}

// IsConflict reports whether err is a 409.
func IsConflict(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusConflict
}

// ── Signing in as an automation identity ──

// sessionMargin is how long before a session's end the client signs in again, so a request
// never starts with a token about to run out.
const sessionMargin = 60 * time.Second

// bearer returns the token to send. With a static operator token that is the token. With an
// automation identity it is the current session token, signing in first when there is none,
// when it is about to run out, or when fresh is true.
func (c *Client) bearer(ctx context.Context, fresh bool) (string, error) {
	if c.signIn == nil {
		return c.Token, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !fresh && c.Token != "" && time.Until(c.tokenEnd) > sessionMargin {
		return c.Token, nil
	}
	token, lifetime, err := c.signIn(ctx)
	if err != nil {
		return "", fmt.Errorf("signing in to Ponte: %w", err)
	}
	c.Token, c.tokenEnd = token, time.Now().Add(lifetime)
	return token, nil
}

// exchange calls the sign-in exchange with one credential and returns the session token.
func (c *Client) exchange(ctx context.Context, bearerKey string, body map[string]any) (string, time.Duration, error) {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	const path = "/v1/automation/token"
	status, raw, err := c.send(ctx, c.APIEndpoint(), http.MethodPost, path, payload, body != nil, bearerKey)
	if err != nil {
		return "", 0, err
	}
	if status != http.StatusOK {
		return "", 0, &Error{Status: status, Method: http.MethodPost, Path: path, Body: string(raw)}
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" {
		return "", 0, fmt.Errorf("POST %s: the answer carries no session token", path)
	}
	if out.ExpiresIn <= 0 {
		out.ExpiresIn = 300
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

// UseAPIKey makes the client sign in with an automation identity's API key.
func (c *Client) UseAPIKey(key string) {
	c.Token = ""
	c.signIn = func(ctx context.Context) (string, time.Duration, error) {
		return c.exchange(ctx, strings.TrimSpace(key), nil)
	}
}

// UsePipelineIdentity makes the client sign in as an automation identity with the pipeline's
// own OIDC token. pipelineToken is asked for a new token at every sign-in: a pipeline's token
// lasts minutes too.
func (c *Client) UsePipelineIdentity(identityID string, pipelineToken func(ctx context.Context) (string, error)) {
	c.Token = ""
	c.signIn = func(ctx context.Context) (string, time.Duration, error) {
		tok, err := pipelineToken(ctx)
		if err != nil {
			return "", 0, fmt.Errorf("reading the pipeline's identity token: %w", err)
		}
		return c.exchange(ctx, "", map[string]any{"identity_id": identityID, "oidc_token": strings.TrimSpace(tok)})
	}
}

// PipelineTokenSource says where a pipeline's OIDC token comes from. The first that is set is
// used: a literal token, a file holding one, or a request URL that returns one (GitHub
// Actions: ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN).
type PipelineTokenSource struct {
	Token        string
	File         string
	RequestURL   string
	RequestToken string
	Audience     string
}

// Configured reports whether any source is set.
func (p PipelineTokenSource) Configured() bool {
	return p.Token != "" || p.File != "" || (p.RequestURL != "" && p.RequestToken != "")
}

// Fetch returns the pipeline's token.
func (p PipelineTokenSource) Fetch(ctx context.Context, hc *http.Client) (string, error) {
	switch {
	case p.Token != "":
		return p.Token, nil
	case p.File != "":
		raw, err := os.ReadFile(p.File)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(string(raw)) == "" {
			return "", fmt.Errorf("%s is empty", p.File)
		}
		return strings.TrimSpace(string(raw)), nil
	case p.RequestURL != "" && p.RequestToken != "":
		u, err := url.Parse(p.RequestURL)
		if err != nil {
			return "", err
		}
		if p.Audience != "" {
			q := u.Query()
			q.Set("audience", p.Audience)
			u.RawQuery = q.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+p.RequestToken)
		req.Header.Set("Accept", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("the pipeline's token endpoint answered %d", resp.StatusCode)
		}
		var out struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(raw, &out); err != nil || out.Value == "" {
			return "", errors.New("the pipeline's token endpoint returned no token")
		}
		return out.Value, nil
	}
	return "", errors.New("no pipeline token is configured")
}
