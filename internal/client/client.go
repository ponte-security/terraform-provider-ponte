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
	"strings"
	"time"
)

// Client talks to one Ponte control plane as one operator.
type Client struct {
	Endpoint  string
	Token     string
	UserAgent string
	HTTP      *http.Client
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

// Do sends a JSON request and decodes a JSON answer into out (nil to discard).
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Endpoint+path, body)
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
