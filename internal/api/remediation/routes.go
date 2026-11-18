// Package remediation serves the extension-removal routes: a preflight that
// says what can be removed and why not, the request that queues a Fleet
// script per host, and the run history.
package remediation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/karmine05/fleet-hound/internal/app"
	"github.com/karmine05/fleet-hound/internal/fleet"
	"github.com/karmine05/fleet-hound/internal/graphdb"
	"github.com/karmine05/fleet-hound/internal/httpx"
	"github.com/karmine05/fleet-hound/internal/remediate"
)

const (
	// maxHostsPerRequest bounds one removal request.
	maxHostsPerRequest = 50
	// maxHostStates bounds the per-host Fleet lookups of one preflight;
	// hosts past it are listed with status "unknown".
	maxHostStates = 100
	// fleetParallelism bounds in-flight Fleet calls of one request.
	fleetParallelism = 8
)

// extWhere scopes a query to browser-extension Software nodes (same guard as
// the inventory routes).
const extWhere = "(s.kind = 'browser_extension' OR s.extension_key STARTS WITH 'ext:')"

type routes struct{ d *app.Deps }

// Register mounts this package's routes on mux.
func Register(mux *http.ServeMux, d *app.Deps) {
	rt := &routes{d: d}
	mux.HandleFunc("GET /api/extensions/uninstall/preflight", rt.preflight)
	mux.HandleFunc("GET /api/extensions/uninstall/script", rt.script)
	mux.HandleFunc("GET /api/extensions/uninstall/jobs", rt.jobs)
	mux.HandleFunc("POST /api/extensions/uninstall", rt.uninstall)
}

func (rt *routes) log() *slog.Logger {
	if rt.d.Log != nil {
		return rt.d.Log
	}
	return slog.Default()
}

func (rt *routes) enabled() bool {
	return rt.d.Cfg != nil && rt.d.Cfg.ExtensionUninstallEnabled
}

// extHost is one host that has the extension, from the graph.
type extHost struct {
	FleetHostID int64
	Hostname    string
	Platform    string
	TeamID      *int64
	TeamName    string
	Version     string
}

// extension is the removal view of one extension key.
type extension struct {
	Key         string
	ID          string
	Store       string
	DisplayName string
	Builtin     bool
	Hosts       []extHost
}

// unsupported is why this extension cannot be removed, or "".
func (e *extension) unsupported() string {
	if e.Builtin {
		return "This extension ships with the browser and cannot be removed."
	}
	if err := remediate.Check(e.Store, e.ID); err != nil {
		msg := err.Error()
		return strings.ToUpper(msg[:1]) + msg[1:] + "."
	}
	return ""
}

// lookup reads an extension and the hosts it is installed on. nil = unknown key.
func (rt *routes) lookup(ctx context.Context, key string) (*extension, error) {
	rows, err := rt.d.DB.Query(ctx, `
        MATCH (s:Software)
        WHERE s.extension_key = $key AND `+extWhere+`
        OPTIONAL MATCH (s)-[r:INSTALLED_ON]->(h:Host)
        RETURN s.store AS store, s.extension_id AS extension_id,
               coalesce(s.display_name, s.name) AS display_name,
               coalesce(s.is_builtin, false) AS is_builtin,
               collect(DISTINCT {
                   fleet_host_id: h.fleet_host_id,
                   hostname: h.hostname,
                   platform: h.platform,
                   team_id: h.team_id,
                   team_name: h.team_name,
                   version: r.version
               }) AS hosts
    `, map[string]any{"key": key})
	if err != nil {
		return nil, fmt.Errorf("extension lookup: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	ext := &extension{Key: key}
	seen := map[int64]bool{}
	for _, row := range rows {
		// Several nodes can share a key; the first non-empty value wins.
		if ext.Store == "" {
			ext.Store = graphdb.AsString(row["store"])
		}
		if ext.ID == "" {
			ext.ID = graphdb.AsString(row["extension_id"])
		}
		if ext.DisplayName == "" {
			ext.DisplayName = graphdb.AsString(row["display_name"])
		}
		if b, _ := row["is_builtin"].(bool); b {
			ext.Builtin = true
		}
		hosts, _ := row["hosts"].([]any)
		for _, x := range hosts {
			m, ok := x.(map[string]any)
			if !ok || m["fleet_host_id"] == nil {
				continue
			}
			id, ok := graphdb.AsInt64(m["fleet_host_id"])
			if !ok || seen[id] {
				continue
			}
			seen[id] = true
			h := extHost{
				FleetHostID: id,
				Hostname:    graphdb.AsString(m["hostname"]),
				Platform:    graphdb.AsString(m["platform"]),
				TeamName:    graphdb.AsString(m["team_name"]),
				Version:     graphdb.AsString(m["version"]),
			}
			if m["team_id"] != nil {
				if tid, ok := graphdb.AsInt64(m["team_id"]); ok {
					h.TeamID = &tid
				}
			}
			ext.Hosts = append(ext.Hosts, h)
		}
	}
	sort.Slice(ext.Hosts, func(i, j int) bool { return ext.Hosts[i].Hostname < ext.Hosts[j].Hostname })
	return ext, nil
}

// keyParam reads ?key=, writing the 400 itself when it is missing.
func keyParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if key == "" {
		httpx.Error(w, http.StatusBadRequest, "key parameter required")
		return "", false
	}
	return key, true
}

// load is lookup plus the shared error replies.
func (rt *routes) load(w http.ResponseWriter, r *http.Request, key string) *extension {
	if rt.d.DB == nil || !rt.d.DB.Available(r.Context()) {
		httpx.Error(w, http.StatusInternalServerError, "Database connection failed")
		return nil
	}
	ext, err := rt.lookup(r.Context(), key)
	if err != nil {
		rt.log().Error("extension removal lookup failed", "err", err)
		httpx.ErrorMsg(w, http.StatusInternalServerError, "Extension query failed", httpx.DebugMsg(rt.d.Debug(), err))
		return nil
	}
	if ext == nil {
		httpx.Error(w, http.StatusNotFound, "Extension not found")
		return nil
	}
	return ext
}

// fleetBlocker explains a failed GET /me in operator terms.
func fleetBlocker(err error) string {
	var apiErr *fleet.APIError
	if errors.As(err, &apiErr) {
		if apiErr.Status == http.StatusUnauthorized {
			return "Fleet rejected the API token (FLEET_API_TOKEN)."
		}
		return fmt.Sprintf("Fleet answered with status %d: %s", apiErr.Status, apiErr.Message)
	}
	return "Fleet could not be reached."
}

// forEach runs fn for i in [0,n) with bounded concurrency.
func forEach(ctx context.Context, n int, fn func(i int)) {
	sem := make(chan struct{}, fleetParallelism)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

func (rt *routes) preflight(w http.ResponseWriter, r *http.Request) {
	key, ok := keyParam(w, r)
	if !ok {
		return
	}
	ext := rt.load(w, r, key)
	if ext == nil {
		return
	}
	ctx := r.Context()

	// blocker is the one reason nothing can be removed; "" = ready.
	var blocker, role string
	var me *fleet.Identity
	switch {
	case !rt.enabled():
		blocker = "Extension removal is turned off. Set EXTENSION_UNINSTALL_ENABLED=true to turn it on."
	case rt.d.Fleet == nil:
		blocker = "FLEET_URL and FLEET_API_TOKEN are not set, so no script can be sent."
	default:
		var err error
		if me, err = rt.d.Fleet.Me(ctx); err != nil {
			rt.log().Warn("fleet identity check failed", "err", err)
			blocker = fleetBlocker(err)
			me = nil
		} else {
			role = me.RoleLabel()
			if !me.CanRunAnywhere() {
				blocker = fmt.Sprintf("The Fleet API token's role (%s) cannot run scripts. It needs maintainer or admin.", role)
			}
		}
	}
	unsupported := ext.unsupported()
	if blocker == "" && unsupported != "" {
		blocker = unsupported
	}

	// Per-host Fleet state, only when a removal is possible at all.
	states := make([]*fleet.HostState, len(ext.Hosts))
	if blocker == "" {
		forEach(ctx, min(len(ext.Hosts), maxHostStates), func(i int) {
			st, err := rt.d.Fleet.HostState(ctx, ext.Hosts[i].FleetHostID)
			if err != nil {
				rt.log().Warn("fleet host state failed", "host", ext.Hosts[i].FleetHostID, "err", err)
				return
			}
			states[i] = st
		})
	}

	latest := remediate.Latest(rt.refreshJobs(ctx, key))
	hosts := make([]map[string]any, 0, len(ext.Hosts))
	for i, h := range ext.Hosts {
		osName, osOK := remediate.OSFor(h.Platform)
		row := map[string]any{
			"fleet_host_id":   h.FleetHostID,
			"hostname":        h.Hostname,
			"platform":        h.Platform,
			"os":              osName,
			"team_name":       h.TeamName,
			"version":         h.Version,
			"status":          "unknown",
			"scripts_enabled": nil,
			"can_block":       osOK && remediate.CanBlock(osName, ext.Store),
			"job":             nil,
		}
		if st := states[i]; st != nil {
			if st.Status != "" {
				row["status"] = st.Status
			}
			if st.ScriptsEnabled != nil {
				row["scripts_enabled"] = *st.ScriptsEnabled
			}
		}
		job, hasJob := latest[h.FleetHostID]
		if hasJob {
			row["job"] = job
		}
		reason := ""
		switch {
		case blocker != "":
			reason = blocker
		case !osOK:
			reason = "Fleet cannot run scripts on this platform."
		case !me.CanRunOn(h.TeamID):
			reason = "The Fleet API token has no maintainer or admin role on this host's team."
		case states[i] != nil && states[i].ScriptsEnabled != nil && !*states[i].ScriptsEnabled:
			reason = "Scripts are turned off on this host (fleetd needs --enable-scripts)."
		case hasJob && job.Pending():
			reason = "A removal is already queued for this host."
		}
		row["eligible"] = reason == ""
		row["reason"] = reason
		hosts = append(hosts, row)
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"enabled": rt.enabled(),
		"ready":   blocker == "",
		"reason":  blocker,
		"fleet": map[string]any{
			"configured": rt.d.Fleet != nil,
			"role":       role,
		},
		"extension": map[string]any{
			"extension_key": ext.Key,
			"extension_id":  ext.ID,
			"store":         ext.Store,
			"display_name":  ext.DisplayName,
			"supported":     unsupported == "",
		},
		"hosts":     hosts,
		"max_hosts": maxHostsPerRequest,
	})
}

// script returns the exact script a removal would send, for review.
func (rt *routes) script(w http.ResponseWriter, r *http.Request) {
	key, ok := keyParam(w, r)
	if !ok {
		return
	}
	ext := rt.load(w, r, key)
	if ext == nil {
		return
	}
	osName := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("os")))
	body, err := remediate.BuildScript(osName, ext.Store, ext.ID, httpx.ArgBool(r, "block"))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"os": osName, "script": body})
}

// applyResult folds a Fleet script result into job.
func applyResult(job *remediate.Job, res *fleet.ScriptResult) {
	if res.ExitCode == nil {
		return // host has not reported back yet
	}
	code := *res.ExitCode
	out := remediate.ParseOutput(res.Output)
	job.ExitCode = &code
	job.Output = remediate.TailOutput(res.Output)
	job.Removed = out.Removed
	job.BlockState = out.Block
	job.UpdatedAt = app.PyISO(time.Now())
	switch {
	case code == 0 && out.Result == "removed":
		job.Status = remediate.StatusRemoved
	case code == 0 && out.Result == "not_found":
		job.Status = remediate.StatusNotFound
		job.Detail = "The extension was not found on disk. It may already be gone, or it is an unpacked extension outside the browser profile."
	case code == -2:
		job.Status = remediate.StatusFailed
		job.Detail = "Scripts are turned off on this host."
	case code == -1:
		job.Status = remediate.StatusFailed
		job.Detail = "The script timed out or never started."
	default:
		job.Status = remediate.StatusFailed
		job.Detail = fmt.Sprintf("The script exited with code %d.", code)
		if res.Message != "" {
			job.Detail += " " + res.Message
		}
	}
}

// refreshJobs returns the jobs of key (oldest first) after asking Fleet for
// the result of each one that is still queued.
func (rt *routes) refreshJobs(ctx context.Context, key string) []remediate.Job {
	jobs := rt.d.UninstallJobs.ForKey(key)
	if rt.d.Fleet == nil {
		return jobs
	}
	var pending []int
	for i := range jobs {
		if jobs[i].Pending() && jobs[i].ExecutionID != "" {
			pending = append(pending, i)
		}
	}
	if len(pending) == 0 {
		return jobs
	}
	changed := make([]bool, len(pending))
	forEach(ctx, len(pending), func(n int) {
		job := &jobs[pending[n]]
		res, err := rt.d.Fleet.ScriptResult(ctx, job.ExecutionID)
		if err != nil {
			var apiErr *fleet.APIError
			if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
				job.Status = remediate.StatusFailed
				job.Detail = "Fleet no longer has this run (cancelled or expired)."
				job.UpdatedAt = app.PyISO(time.Now())
				changed[n] = true
				return
			}
			rt.log().Warn("fleet script result failed", "execution_id", job.ExecutionID, "err", err)
			return
		}
		before := job.Status
		applyResult(job, res)
		changed[n] = job.Status != before
	})
	var updated []remediate.Job
	for n, i := range pending {
		if changed[n] {
			updated = append(updated, jobs[i])
		}
	}
	if err := rt.d.UninstallJobs.Update(updated); err != nil {
		rt.log().Error("uninstall job save failed", "err", err)
	}
	return jobs
}

func (rt *routes) jobs(w http.ResponseWriter, r *http.Request) {
	key, ok := keyParam(w, r)
	if !ok {
		return
	}
	latest := remediate.Latest(rt.refreshJobs(r.Context(), key))
	out := make([]remediate.Job, 0, len(latest))
	pending := 0
	for _, j := range latest {
		if j.Pending() {
			pending++
		}
		out = append(out, j)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"jobs": out, "pending": pending})
}

// rejection explains a refused POST /scripts/run in operator terms.
func rejection(err error) string {
	var apiErr *fleet.APIError
	if !errors.As(err, &apiErr) {
		return "Fleet could not be reached."
	}
	switch apiErr.Status {
	case http.StatusUnauthorized:
		return "Fleet rejected the API token."
	case http.StatusForbidden:
		return "Fleet refused: the API token's role cannot run scripts on this host. " + apiErr.Message
	}
	return "Fleet refused: " + apiErr.Message
}

// hostIDs reads the host_ids array of the request body.
func hostIDs(v any) ([]int64, bool) {
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	seen := map[int64]bool{}
	out := make([]int64, 0, len(list))
	for _, x := range list {
		id, isInt := x.(int64)
		if !isInt || id <= 0 {
			return nil, false
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, true
}

func (rt *routes) uninstall(w http.ResponseWriter, r *http.Request) {
	if !rt.enabled() {
		httpx.Error(w, http.StatusForbidden, "Extension removal is turned off")
		return
	}
	if rt.d.Fleet == nil {
		httpx.Error(w, http.StatusServiceUnavailable, "Fleet API is not configured")
		return
	}
	body, _ := httpx.DecodeJSONBody(r, 0).(map[string]any)
	if body == nil {
		httpx.Error(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	key, _ := body["extension_key"].(string)
	key = strings.TrimSpace(key)
	ids, idsOK := hostIDs(body["host_ids"])
	block, _ := body["block_reinstall"].(bool)
	switch {
	case key == "":
		httpx.Error(w, http.StatusBadRequest, "extension_key required")
		return
	case !idsOK || len(ids) == 0:
		httpx.Error(w, http.StatusBadRequest, "host_ids must be a non-empty list of Fleet host ids")
		return
	case len(ids) > maxHostsPerRequest:
		httpx.Error(w, http.StatusBadRequest, fmt.Sprintf("At most %d hosts per request", maxHostsPerRequest))
		return
	}
	ext := rt.load(w, r, key)
	if ext == nil {
		return
	}
	if reason := ext.unsupported(); reason != "" {
		httpx.Error(w, http.StatusUnprocessableEntity, reason)
		return
	}
	ctx := r.Context()

	// Only hosts the graph says have this extension can be targeted.
	installed := make(map[int64]extHost, len(ext.Hosts))
	for _, h := range ext.Hosts {
		installed[h.FleetHostID] = h
	}
	pending := map[int64]bool{}
	for id, j := range remediate.Latest(rt.d.UninstallJobs.ForKey(key)) {
		pending[id] = j.Pending()
	}

	now := app.PyISO(time.Now())
	jobs := make([]remediate.Job, len(ids))
	scripts := make([]string, len(ids))
	// duplicate marks hosts skipped because a run is already queued; they are
	// reported but not stored, so the queued run stays the host's latest job.
	duplicate := make([]bool, len(ids))
	for i, id := range ids {
		h, ok := installed[id]
		if !ok {
			httpx.Error(w, http.StatusBadRequest, fmt.Sprintf("Host %d does not have this extension", id))
			return
		}
		job := remediate.Job{
			ExtensionKey: ext.Key, ExtensionID: ext.ID, Store: ext.Store, DisplayName: ext.DisplayName,
			FleetHostID: id, Hostname: h.Hostname, RequestedAt: now, UpdatedAt: now,
			Status: remediate.StatusRejected,
		}
		osName, osOK := remediate.OSFor(h.Platform)
		job.OS = osName
		switch {
		case !osOK:
			job.Detail = "Fleet cannot run scripts on this platform."
		case pending[id]:
			job.Detail = "A removal is already queued for this host."
			duplicate[i] = true
		default:
			job.Block = block && remediate.CanBlock(osName, ext.Store)
			script, err := remediate.BuildScript(osName, ext.Store, ext.ID, job.Block)
			if err != nil {
				job.Detail = err.Error()
			} else {
				scripts[i] = script
			}
		}
		jobs[i] = job
	}

	forEach(ctx, len(jobs), func(i int) {
		if scripts[i] == "" {
			return
		}
		execID, err := rt.d.Fleet.RunScript(ctx, jobs[i].FleetHostID, scripts[i])
		if err != nil {
			rt.log().Warn("fleet script run refused", "host", jobs[i].FleetHostID, "err", err)
			jobs[i].Detail = rejection(err)
			return
		}
		jobs[i].ExecutionID = execID
		jobs[i].Status = remediate.StatusQueued
	})

	queued := 0
	queuedHosts := make([]string, 0, len(jobs))
	stored := make([]remediate.Job, 0, len(jobs))
	for i, j := range jobs {
		if j.Status == remediate.StatusQueued {
			queued++
			queuedHosts = append(queuedHosts, fmt.Sprintf("%s(%d)", j.Hostname, j.FleetHostID))
		}
		if !duplicate[i] {
			stored = append(stored, j)
		}
	}
	if err := rt.d.UninstallJobs.Append(stored...); err != nil {
		// The scripts are already queued in Fleet; say so instead of failing.
		rt.log().Error("uninstall job save failed", "err", err)
	}
	rt.d.Audit("extension_uninstall", fmt.Sprintf(
		"key=%s id=%s store=%s block=%t requested=%d queued=%d rejected=%d hosts=%s",
		ext.Key, ext.ID, ext.Store, block, len(jobs), queued, len(jobs)-queued, strings.Join(queuedHosts, ",")))

	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
		"jobs": jobs, "queued": queued, "rejected": len(jobs) - queued,
	})
}
