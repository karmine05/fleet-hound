package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/karmine05/fleet-hound/internal/graphdb"
)

// scriptCallTimeout bounds one script API call. These are small JSON calls,
// unlike the multi-MB host pages the Extractor reads.
const scriptCallTimeout = 30 * time.Second

// ScriptClient is the write side of the Fleet API: it runs one-off scripts on
// hosts and reads their results. Calls are never retried: POST /scripts/run
// is not idempotent, and a retry could queue the same script twice.
type ScriptClient struct {
	fleetURL string
	apiToken string
	client   *http.Client
}

// NewScriptClient builds a client for fleetURL. verify=false skips TLS
// verification (INSECURE=true, dev only).
func NewScriptClient(fleetURL, apiToken string, verify bool) *ScriptClient {
	return &ScriptClient{
		fleetURL: strings.TrimRight(fleetURL, "/"),
		apiToken: apiToken,
		client:   newHTTPClient(verify),
	}
}

// APIError is a non-2xx Fleet reply. Message is Fleet's own reason text.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("fleet api: status %d: %s", e.Status, e.Message)
}

// apiErrorMessage pulls the most specific reason out of a Fleet error body:
// {"message": "...", "errors": [{"name": "base", "reason": "..."}]}.
func apiErrorMessage(body map[string]any) string {
	if errs, ok := body["errors"].([]any); ok {
		for _, e := range errs {
			if m, ok := e.(map[string]any); ok {
				if reason, _ := m["reason"].(string); reason != "" {
					return reason
				}
			}
		}
	}
	if msg, _ := body["message"].(string); msg != "" {
		return msg
	}
	return "no error detail returned"
}

// call sends one JSON request and decodes a JSON object reply.
func (c *ScriptClient) call(ctx context.Context, method, path string, payload any) (map[string]any, error) {
	var body *bytes.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode %s body: %w", path, err)
		}
		body = bytes.NewReader(raw)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.fleetURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("build %s request: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := do(ctx, c.client, req, scriptCallTimeout)
	if err != nil {
		return nil, fmt.Errorf("fleet %s %s: %w", method, path, err)
	}
	data, ok := resp.jsonObject()
	if resp.status < 200 || resp.status > 299 {
		if !ok {
			data = map[string]any{}
		}
		return nil, &APIError{Status: resp.status, Message: apiErrorMessage(data)}
	}
	if !ok {
		return nil, fmt.Errorf("fleet %s %s: reply was not a JSON object", method, path)
	}
	return data, nil
}

// Identity is the role of the API token's user (GET /me).
type Identity struct {
	GlobalRole string           // "" when the user only has team roles
	TeamRoles  map[int64]string // team id -> role
}

// scriptRoles may run a one-off script (Fleet policy.rego: host_script_result
// write with no script_id).
var scriptRoles = map[string]bool{"admin": true, "maintainer": true}

// CanRunOn reports whether the user may run a one-off script on a host in
// teamID (nil = no team, which needs a global role).
func (i *Identity) CanRunOn(teamID *int64) bool {
	if scriptRoles[i.GlobalRole] {
		return true
	}
	return teamID != nil && scriptRoles[i.TeamRoles[*teamID]]
}

// CanRunAnywhere reports whether any role of the user can run scripts.
func (i *Identity) CanRunAnywhere() bool {
	if scriptRoles[i.GlobalRole] {
		return true
	}
	for _, role := range i.TeamRoles {
		if scriptRoles[role] {
			return true
		}
	}
	return false
}

// RoleLabel is a short description for the UI ("global observer",
// "team roles only", ...).
func (i *Identity) RoleLabel() string {
	if i.GlobalRole != "" {
		return "global " + i.GlobalRole
	}
	if len(i.TeamRoles) > 0 {
		return "team roles only"
	}
	return "no role"
}

// Me replaces a trial run: it reads the token's roles so the UI can say up
// front whether scripts can be run.
func (c *ScriptClient) Me(ctx context.Context) (*Identity, error) {
	data, err := c.call(ctx, http.MethodGet, "/api/v1/fleet/me", nil)
	if err != nil {
		return nil, err
	}
	user, _ := data["user"].(map[string]any)
	id := &Identity{TeamRoles: map[int64]string{}}
	id.GlobalRole, _ = user["global_role"].(string)
	for _, t := range objects(user["teams"]) {
		tid, ok := graphdb.AsInt64(t["id"])
		role, _ := t["role"].(string)
		if ok && t["id"] != nil && role != "" {
			id.TeamRoles[tid] = role
		}
	}
	return id, nil
}

// HostState is the part of GET /hosts/{id} that decides whether a script can
// run now.
type HostState struct {
	Status         string // "online" / "offline" / ...
	ScriptsEnabled *bool  // nil = unknown (Fleet treats unknown as allowed)
}

// HostState reads one host's status and scripts_enabled flag.
func (c *ScriptClient) HostState(ctx context.Context, hostID int64) (*HostState, error) {
	q := url.Values{"exclude_software": {"true"}}
	data, err := c.call(ctx, http.MethodGet, fmt.Sprintf("/api/v1/fleet/hosts/%d?%s", hostID, q.Encode()), nil)
	if err != nil {
		return nil, err
	}
	host, _ := data["host"].(map[string]any)
	st := &HostState{}
	st.Status, _ = host["status"].(string)
	if enabled, ok := host["scripts_enabled"].(bool); ok {
		st.ScriptsEnabled = &enabled
	}
	return st, nil
}

// RunScript queues contents as a one-off script on hostID and returns Fleet's
// execution id. The script stays queued while the host is offline.
func (c *ScriptClient) RunScript(ctx context.Context, hostID int64, contents string) (string, error) {
	data, err := c.call(ctx, http.MethodPost, "/api/v1/fleet/scripts/run",
		map[string]any{"host_id": hostID, "script_contents": contents})
	if err != nil {
		return "", err
	}
	id, _ := data["execution_id"].(string)
	if id == "" {
		return "", fmt.Errorf("fleet scripts/run: reply had no execution_id")
	}
	return id, nil
}

// ScriptResult is GET /scripts/results/{execution_id}.
type ScriptResult struct {
	ExitCode *int64 // nil while the host has not reported back
	Output   string
	Message  string
}

// ScriptResult reads the result of one execution.
func (c *ScriptClient) ScriptResult(ctx context.Context, executionID string) (*ScriptResult, error) {
	data, err := c.call(ctx, http.MethodGet, "/api/v1/fleet/scripts/results/"+url.PathEscape(executionID), nil)
	if err != nil {
		return nil, err
	}
	res := &ScriptResult{}
	// AsInt64 maps nil to 0, and exit code 0 means success: test nil first.
	if data["exit_code"] != nil {
		if code, ok := graphdb.AsInt64(data["exit_code"]); ok {
			res.ExitCode = &code
		}
	}
	res.Output, _ = data["output"].(string)
	res.Message, _ = data["message"].(string)
	return res, nil
}
