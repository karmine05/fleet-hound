package remediate

import (
	"fmt"
	"sync"

	"github.com/karmine05/fleet-hound/internal/workerutil"
)

// Job statuses.
const (
	StatusQueued   = "queued"    // Fleet accepted the script; the host has not reported back
	StatusRemoved  = "removed"   // script ran and deleted the extension
	StatusNotFound = "not_found" // script ran and found nothing to delete
	StatusFailed   = "failed"    // script ran and failed, timed out or was refused by the host
	StatusRejected = "rejected"  // Fleet refused to queue the script
)

// maxJobs bounds the history file.
const maxJobs = 1000

// maxOutputRunes is how much script output a job keeps (the tail).
const maxOutputRunes = 4000

// Job is one removal run on one host.
type Job struct {
	ExtensionKey string `json:"extension_key"`
	ExtensionID  string `json:"extension_id"`
	Store        string `json:"store"`
	DisplayName  string `json:"display_name"`
	FleetHostID  int64  `json:"fleet_host_id"`
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Block        bool   `json:"block_reinstall"`
	ExecutionID  string `json:"execution_id,omitempty"`
	Status       string `json:"status"`
	ExitCode     *int64 `json:"exit_code"`
	Removed      int    `json:"removed_paths"`
	BlockState   string `json:"block_state,omitempty"`
	Detail       string `json:"detail,omitempty"`
	Output       string `json:"output,omitempty"`
	RequestedAt  string `json:"requested_at"`
	UpdatedAt    string `json:"updated_at"`
}

// Pending reports whether the job still waits for the host.
func (j Job) Pending() bool { return j.Status == StatusQueued }

// TailOutput keeps the last maxOutputRunes of script output.
func TailOutput(s string) string {
	r := []rune(s)
	if len(r) <= maxOutputRunes {
		return s
	}
	return string(r[len(r)-maxOutputRunes:])
}

// Store is the job history file (JSON array, newest last). The server is one
// process, so a mutex is enough to serialise read-modify-write.
type Store struct {
	path string
	mu   sync.Mutex
}

// NewStore returns the store kept at path.
func NewStore(path string) *Store { return &Store{path: path} }

func (s *Store) load() []Job {
	var jobs []Job
	workerutil.ReadJSON(s.path, &jobs)
	return jobs
}

func (s *Store) save(jobs []Job) error {
	if len(jobs) > maxJobs {
		jobs = jobs[len(jobs)-maxJobs:]
	}
	if err := workerutil.AtomicWriteJSON(s.path, jobs, ".uninstall."); err != nil {
		return fmt.Errorf("save uninstall jobs: %w", err)
	}
	return nil
}

// ForKey returns the jobs of one extension, oldest first.
func (s *Store) ForKey(key string) []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Job
	for _, j := range s.load() {
		if j.ExtensionKey == key {
			out = append(out, j)
		}
	}
	return out
}

// Append adds jobs to the history.
func (s *Store) Append(jobs ...Job) error {
	if len(jobs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(append(s.load(), jobs...))
}

// Update replaces stored jobs that share an execution id with one of updated.
func (s *Store) Update(updated []Job) error {
	if len(updated) == 0 {
		return nil
	}
	byExec := make(map[string]Job, len(updated))
	for _, j := range updated {
		byExec[j.ExecutionID] = j
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	jobs := s.load()
	for i := range jobs {
		if u, ok := byExec[jobs[i].ExecutionID]; ok && jobs[i].ExecutionID != "" {
			jobs[i] = u
		}
	}
	return s.save(jobs)
}

// Latest keeps the newest job per host from jobs (oldest first input).
func Latest(jobs []Job) map[int64]Job {
	out := make(map[int64]Job, len(jobs))
	for _, j := range jobs {
		out[j.FleetHostID] = j
	}
	return out
}
