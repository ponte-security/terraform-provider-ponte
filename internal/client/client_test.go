package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a server that answers each request from a script of statuses and remembers what
// it was asked.
type recorder struct {
	mu       sync.Mutex
	statuses []int // one per request; the last repeats
	requests []string
	bodies   []string
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	body, _ := io.ReadAll(req.Body)
	r.requests = append(r.requests, req.Method+" "+req.URL.EscapedPath())
	r.bodies = append(r.bodies, string(body))
	status := http.StatusOK
	if n := len(r.requests) - 1; n < len(r.statuses) {
		status = r.statuses[n]
	} else if len(r.statuses) > 0 {
		status = r.statuses[len(r.statuses)-1]
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"policy_id":"pol_1","enforcement_mode":"observe","error":"nope"}`))
}

func newTestClient(t *testing.T, statuses ...int) (*Client, *recorder) {
	t.Helper()
	rec := &recorder{statuses: statuses}
	ts := httptest.NewServer(rec)
	t.Cleanup(ts.Close)
	c := New(ts.URL+"/api/control", "token", "test")
	c.retryWait = time.Millisecond
	return c, rec
}

func TestRetries(t *testing.T) {
	for _, c := range []struct {
		name     string
		method   string
		statuses []int
		wantSent int
		wantErr  bool
	}{
		{"a read is repeated past a gateway error", http.MethodGet, []int{503, 502, 200}, 3, false},
		{"a replace is repeated", http.MethodPut, []int{504, 200}, 2, false},
		{"a delete is repeated", http.MethodDelete, []int{503, 200}, 2, false},
		{"a create is not repeated: it may have happened", http.MethodPost, []int{503, 200}, 1, true},
		{"a create is repeated when the server says it did nothing", http.MethodPost, []int{429, 200}, 2, false},
		{"it gives up", http.MethodGet, []int{503}, maxAttempts, true},
		{"a refusal is not repeated", http.MethodGet, []int{403, 200}, 1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl, rec := newTestClient(t, c.statuses...)
			err := cl.Do(context.Background(), c.method, "/v1/x", map[string]any{"a": 1}, nil)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, want error %v", err, c.wantErr)
			}
			if len(rec.requests) != c.wantSent {
				t.Fatalf("sent %d requests, want %d", len(rec.requests), c.wantSent)
			}
			for i, b := range rec.bodies {
				if b != `{"a":1}` {
					t.Fatalf("attempt %d sent body %q", i+1, b)
				}
			}
		})
	}
}

func TestRetryStopsWhenCancelled(t *testing.T) {
	cl, rec := newTestClient(t, 503)
	cl.retryWait = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := cl.Do(ctx, http.MethodGet, "/v1/x", nil, nil); err == nil {
		t.Fatal("no error")
	}
	if len(rec.requests) != 1 {
		t.Fatalf("sent %d requests, want 1", len(rec.requests))
	}
}

func jwtExpiring(at time.Time) string {
	enc := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return enc(map[string]any{"alg": "none"}) + "." + enc(map[string]any{"exp": at.Unix()}) + ".sig"
}

func TestTokenExpiry(t *testing.T) {
	at := time.Unix(1900000000, 0)
	if got, ok := TokenExpiry(jwtExpiring(at)); !ok || !got.Equal(at) {
		t.Fatalf("TokenExpiry = %v, %v", got, ok)
	}
	for _, tok := range []string{"", "opaque-token", "a.b.c", "a.!!!.c"} {
		if _, ok := TokenExpiry(tok); ok {
			t.Fatalf("TokenExpiry(%q) reported an expiry", tok)
		}
	}
}

func TestUnauthorizedSaysWhy(t *testing.T) {
	cl, _ := newTestClient(t, 401)
	cl.Token = jwtExpiring(time.Now().Add(-time.Minute))
	err := cl.Do(context.Background(), http.MethodGet, "/v1/x", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "expired at") {
		t.Fatalf("an expired token: %v", err)
	}
	cl.Token = jwtExpiring(time.Now().Add(time.Hour))
	err = cl.Do(context.Background(), http.MethodGet, "/v1/x", nil, nil)
	if err == nil || strings.Contains(err.Error(), "expired at") || !strings.Contains(err.Error(), "operator") {
		t.Fatalf("a live token that is refused: %v", err)
	}
	if IsNotFound(err) {
		t.Fatal("a 401 read as not found")
	}
}

// An id is one path segment whatever it contains: it comes from configuration and from
// `terraform import`. Every call that puts an id in a path is listed here.
func TestIDsStayOneSegment(t *testing.T) {
	const evil = "../a/b?x=1"
	const want = "..%2Fa%2Fb%3Fx=1"
	ctx := context.Background()
	calls := map[string]func(c *Client) error{
		"GetPolicy":            func(c *Client) error { _, err := c.GetPolicy(ctx, evil); return err },
		"SetPolicyMode":        func(c *Client) error { return c.SetPolicyMode(ctx, evil, "observe") },
		"DeletePolicy":         func(c *Client) error { return c.DeletePolicy(ctx, evil) },
		"GetGroup":             func(c *Client) error { _, err := c.GetGroup(ctx, evil); return err },
		"UpdateGroup":          func(c *Client) error { _, err := c.UpdateGroup(ctx, evil, GroupInput{}); return err },
		"DeleteGroup":          func(c *Client) error { return c.DeleteGroup(ctx, evil) },
		"GroupMembers":         func(c *Client) error { _, err := c.GroupMembers(ctx, evil); return err },
		"AddGroupMember":       func(c *Client) error { return c.AddGroupMember(ctx, evil, "a") },
		"RemoveGroupMember":    func(c *Client) error { return c.RemoveGroupMember(ctx, evil, evil) },
		"AgentPolicyBindings":  func(c *Client) error { _, err := c.AgentPolicyBindings(ctx, evil); return err },
		"BindPolicy":           func(c *Client) error { return c.BindPolicy(ctx, evil, "p") },
		"UnbindPolicy":         func(c *Client) error { return c.UnbindPolicy(ctx, evil, evil) },
		"UpdateWebhook":        func(c *Client) error { return c.UpdateWebhook(ctx, evil, WebhookInput{}) },
		"DeleteWebhook":        func(c *Client) error { return c.DeleteWebhook(ctx, evil) },
		"SetMCPServerReview":   func(c *Client) error { return c.SetMCPServerReviewMode(ctx, evil, true) },
		"DeleteMCPServer":      func(c *Client) error { return c.DeleteMCPServer(ctx, evil) },
		"ToolRiskTier":         func(c *Client) error { _, err := c.ToolRiskTier(ctx, evil, "t"); return err },
		"DeclareToolRiskTier":  func(c *Client) error { return c.DeclareToolRiskTier(ctx, evil, evil, "read") },
		"GetAgent":             func(c *Client) error { _, err := c.GetAgent(ctx, evil); return err },
		"SetSCIMTargetEnabled": func(c *Client) error { return c.SetSCIMTargetEnabled(ctx, evil, true) },
		"DeleteSCIMTarget":     func(c *Client) error { return c.DeleteSCIMTarget(ctx, evil) },
		"SaveRecertPolicy":     func(c *Client) error { _, err := c.SaveRecertPolicy(ctx, evil, "n", RecertPolicySpec{}); return err },
		"DeleteRecertPolicy":   func(c *Client) error { return c.DeleteRecertPolicy(ctx, evil) },
	}
	for name, call := range calls {
		cl, rec := newTestClient(t, 200)
		_ = call(cl)
		if len(rec.requests) == 0 {
			t.Errorf("%s sent nothing", name)
			continue
		}
		got := rec.requests[0]
		if !strings.Contains(got, want) || strings.Contains(got, "/a/b") {
			t.Errorf("%s: path %q does not keep the id in one segment", name, got)
		}
	}
	if seg("..") == ".." || seg(".") == "." {
		t.Error("a dot segment is passed through")
	}
}

func TestCreatePolicySendsMode(t *testing.T) {
	cl, rec := newTestClient(t, 201)
	p, err := cl.CreatePolicy(context.Background(), "yaml", "observe")
	if err != nil || p.PolicyID != "pol_1" {
		t.Fatalf("CreatePolicy = %+v, %v", p, err)
	}
	var sent map[string]string
	_ = json.Unmarshal([]byte(rec.bodies[0]), &sent)
	if sent["enforcement_mode"] != "observe" || sent["ppl_source"] != "yaml" {
		t.Fatalf("sent %s", rec.bodies[0])
	}
}

func TestUpdateWebhookClearsFormatConfig(t *testing.T) {
	cl, rec := newTestClient(t, 200)
	cl.SetAPIEndpoint(strings.TrimSuffix(cl.Endpoint, "/control"))
	if err := cl.UpdateWebhook(context.Background(), "wh_1", WebhookInput{Name: "n"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.bodies[0], `"format_config":{}`) {
		t.Fatalf("an update with no overrides sent %s", rec.bodies[0])
	}
}

func TestErrorMessage(t *testing.T) {
	e := &Error{Status: 400, Method: "POST", Path: "/v1/x", Body: `{"error":"bad thing"}`}
	if got := e.Error(); got != "POST /v1/x: 400 bad thing" {
		t.Fatal(got)
	}
	if got := fmt.Sprint(&Error{Status: 500, Method: "GET", Path: "/p", Body: "plain"}); got != "GET /p: 500 plain" {
		t.Fatal(got)
	}
}

// signInServer is the api's sign-in exchange and one route behind it. A session token is good
// until ended; the route answers 401 for any other bearer token.
type signInServer struct {
	mu       sync.Mutex
	signIns  int
	requests int
	good     map[string]bool
	lifetime int
}

func (s *signInServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if strings.HasSuffix(r.URL.Path, "/v1/automation/token") {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if bearer != "pak_good" && !(body["identity_id"] == "auto_ci" && body["oidc_token"] == "pipeline-jwt") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"sign-in refused: the key is not recognised"}`))
			return
		}
		s.signIns++
		token := fmt.Sprintf("pat_%d", s.signIns)
		s.good[token] = true
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": token, "expires_in": s.lifetime})
		return
	}
	s.requests++
	if !s.good[bearer] {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"the automation session has expired or been ended; sign in again"}`))
		return
	}
	_, _ = w.Write([]byte(`{}`))
}

func newSignInClient(t *testing.T, lifetime int) (*Client, *signInServer) {
	t.Helper()
	s := &signInServer{good: map[string]bool{}, lifetime: lifetime}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	c := New(ts.URL+"/api/control", "", "test")
	c.retryWait = time.Millisecond
	return c, s
}

func TestSignInWithAPIKey(t *testing.T) {
	c, s := newSignInClient(t, 600)
	c.UseAPIKey("pak_good")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := c.Do(ctx, http.MethodGet, "/v1/x", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if s.signIns != 1 || s.requests != 3 {
		t.Fatalf("%d sign-ins for %d requests, want 1 for 3", s.signIns, s.requests)
	}

	// The session is ended on the server (a key rotated, an identity edited): the next request
	// signs in again and succeeds, without the caller seeing a 401.
	s.mu.Lock()
	s.good = map[string]bool{}
	s.mu.Unlock()
	if err := c.Do(ctx, http.MethodGet, "/v1/x", nil, nil); err != nil {
		t.Fatalf("after the session ended: %v", err)
	}
	if s.signIns != 2 {
		t.Fatalf("%d sign-ins after the session ended, want 2", s.signIns)
	}
}

func TestSessionIsRenewedBeforeItRunsOut(t *testing.T) {
	c, s := newSignInClient(t, 30) // shorter than the margin: every request signs in first
	c.UseAPIKey("pak_good")
	for i := 0; i < 3; i++ {
		if err := c.Do(context.Background(), http.MethodGet, "/v1/x", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if s.signIns != 3 {
		t.Fatalf("%d sign-ins, want one per request for a session about to run out", s.signIns)
	}
}

func TestSignInRefusedIsSaidPlainly(t *testing.T) {
	c, s := newSignInClient(t, 600)
	c.UseAPIKey("pak_wrong")
	err := c.Do(context.Background(), http.MethodGet, "/v1/x", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "signing in to Ponte") || !strings.Contains(err.Error(), "not recognised") {
		t.Fatalf("a key Ponte does not know: %v", err)
	}
	if s.requests != 0 {
		t.Fatalf("%d requests were sent without a session", s.requests)
	}
}

func TestSignInWithPipelineIdentity(t *testing.T) {
	c, s := newSignInClient(t, 600)
	asked := 0
	c.UsePipelineIdentity("auto_ci", func(context.Context) (string, error) {
		asked++
		return " pipeline-jwt\n", nil
	})
	if err := c.Do(context.Background(), http.MethodGet, "/v1/x", nil, nil); err != nil {
		t.Fatal(err)
	}
	if s.signIns != 1 || asked != 1 {
		t.Fatalf("%d sign-ins, pipeline token asked for %d times", s.signIns, asked)
	}
}

// GitHub Actions hands a job a URL and a bearer token to request its identity token with.
func TestPipelineTokenFromARequestURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer request-token" || r.URL.Query().Get("audience") != "https://app.ponte.ai" || r.URL.Query().Get("api-version") != "2.0" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"value":"the-jwt"}`))
	}))
	defer ts.Close()
	src := PipelineTokenSource{RequestURL: ts.URL + "/token?api-version=2.0", RequestToken: "request-token", Audience: "https://app.ponte.ai"}
	if got, err := src.Fetch(context.Background(), http.DefaultClient); err != nil || got != "the-jwt" {
		t.Fatalf("Fetch = %q, %v", got, err)
	}
	src.RequestToken = "wrong"
	if _, err := src.Fetch(context.Background(), http.DefaultClient); err == nil {
		t.Fatal("a refused request returned a token")
	}
	if (PipelineTokenSource{RequestURL: "x"}).Configured() || !(PipelineTokenSource{Token: "t"}).Configured() {
		t.Fatal("Configured is wrong")
	}
}
