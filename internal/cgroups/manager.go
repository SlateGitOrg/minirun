package cgroups

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/archit2501/minirun/internal/spec"
)

// DefaultRoot is where the cgroup v2 hierarchy is mounted on modern
// distributions.
const DefaultRoot = "/sys/fs/cgroup"

// ErrNotFound is returned when the container's cgroup does not exist.
var ErrNotFound = errors.New("cgroup does not exist")

// Manager owns one container cgroup at Root/Rel.
type Manager struct {
	fs   FS
	root string
	rel  string
}

// New returns a manager for the cgroup rel (relative to root, validated
// with spec.CheckCgroupsPath).
func New(fsys FS, root, rel string) (*Manager, error) {
	if err := spec.CheckCgroupsPath(rel); err != nil {
		return nil, fmt.Errorf("cgroup path: %w", err)
	}
	return &Manager{fs: fsys, root: filepath.Clean(root), rel: strings.Trim(rel, "/")}, nil
}

// Path is the absolute path of the cgroup directory.
func (m *Manager) Path() string { return filepath.Join(m.root, m.rel) }

func (m *Manager) file(name string) string { return filepath.Join(m.Path(), name) }

// Create makes the cgroup and every missing ancestor, enabling the given
// controllers in each ancestor's cgroup.subtree_control so they are
// available in the leaf. It fails if the leaf already exists, so two
// containers never share a cgroup by accident.
func (m *Manager) Create(controllers []string) error {
	parts := strings.Split(m.rel, "/")
	dir := m.root
	for i, part := range parts {
		if len(controllers) > 0 {
			if err := m.delegate(dir, controllers); err != nil {
				return err
			}
		}
		dir = filepath.Join(dir, part)
		err := m.fs.Mkdir(dir)
		switch {
		case err == nil:
		case errors.Is(err, fs.ErrExist) && i < len(parts)-1:
		case errors.Is(err, fs.ErrExist):
			return fmt.Errorf("create cgroup %s: already exists (a container with this cgroup path is running or was not deleted)", dir)
		default:
			return explain("create cgroup", dir, err)
		}
	}
	return nil
}

// delegate enables controllers in dir/cgroup.subtree_control, skipping any
// that are already enabled.
func (m *Manager) delegate(dir string, controllers []string) error {
	avail, err := m.readList(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return err
	}
	enabled, err := m.readList(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		return err
	}
	var want []string
	for _, c := range controllers {
		if !slices.Contains(avail, c) {
			return fmt.Errorf("cgroup controller %q is not available in %s (available: %s)", c, dir, strings.Join(avail, " "))
		}
		if !slices.Contains(enabled, c) {
			want = append(want, "+"+c)
		}
	}
	if len(want) == 0 {
		return nil
	}
	path := filepath.Join(dir, "cgroup.subtree_control")
	if err := m.fs.WriteFile(path, []byte(strings.Join(want, " "))); err != nil {
		return explain("enable controllers in", path, err)
	}
	return nil
}

func (m *Manager) readList(path string) ([]string, error) {
	data, err := m.fs.ReadFile(path)
	if err != nil {
		return nil, explain("read", path, err)
	}
	return strings.Fields(string(data)), nil
}

// Apply writes the settings into the cgroup's interface files, in order.
//
// One write is allowed to find its file missing: memory.swap.max "0" on a
// kernel built without swap accounting, where there is no swap to limit.
func (m *Manager) Apply(settings []Setting) error {
	for _, s := range settings {
		err := m.fs.WriteFile(m.file(s.File), []byte(s.Value))
		if err == nil || (s.File == "memory.swap.max" && s.Value == "0" && errors.Is(err, fs.ErrNotExist)) {
			continue
		}
		return explain("write "+strconv.Quote(s.Value)+" to", m.file(s.File), err)
	}
	return nil
}

// AddProc moves a process (all of its threads) into the cgroup.
func (m *Manager) AddProc(pid int) error {
	if err := m.fs.WriteFile(m.file("cgroup.procs"), []byte(strconv.Itoa(pid))); err != nil {
		return explain("add process "+strconv.Itoa(pid)+" to", m.Path(), err)
	}
	return nil
}

// Exists reports whether the cgroup directory exists.
func (m *Manager) Exists() bool {
	_, err := m.fs.ReadFile(m.file("cgroup.procs"))
	return err == nil
}

// Procs returns the PIDs (as seen from the caller's PID namespace) of the
// processes in the cgroup.
func (m *Manager) Procs() ([]int, error) {
	data, err := m.fs.ReadFile(m.file("cgroup.procs"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, explain("read", m.file("cgroup.procs"), err)
	}
	var pids []int
	for _, f := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", m.file("cgroup.procs"), err)
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// ErrKillUnsupported means the kernel predates cgroup.kill (Linux 5.14).
var ErrKillUnsupported = errors.New("cgroup.kill is not supported by this kernel")

// Kill sends SIGKILL to every process in the cgroup via cgroup.kill.
func (m *Manager) Kill() error {
	err := m.fs.WriteFile(m.file("cgroup.kill"), []byte("1"))
	if errors.Is(err, fs.ErrNotExist) {
		if !m.Exists() {
			return ErrNotFound
		}
		return ErrKillUnsupported
	}
	if err != nil {
		return explain("write to", m.file("cgroup.kill"), err)
	}
	return nil
}

// Destroy removes the cgroup directory. It fails with EBUSY while
// processes remain. A missing cgroup is not an error.
func (m *Manager) Destroy() error {
	err := m.fs.Rmdir(m.Path())
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return explain("remove cgroup", m.Path(), err)
}

// Stats is a snapshot of the cgroup's counters. Fields whose controller is
// not enabled are left zero.
type Stats struct {
	MemoryCurrent uint64 `json:"memoryCurrent"`
	MemoryPeak    uint64 `json:"memoryPeak,omitempty"`
	MemoryMax     string `json:"memoryMax,omitempty"`
	OOMEvents     uint64 `json:"oomEvents"`
	OOMKills      uint64 `json:"oomKills"`
	PidsCurrent   uint64 `json:"pidsCurrent"`
	PidsMax       string `json:"pidsMax,omitempty"`
	PidsLimitHits uint64 `json:"pidsLimitHits"`
	CPUUsageUsec  uint64 `json:"cpuUsageUsec"`
	CPUThrottled  uint64 `json:"cpuThrottledUsec"`
}

// Stats reads the counters of the memory, pids and cpu controllers.
func (m *Manager) Stats() (Stats, error) {
	if !m.Exists() {
		return Stats{}, ErrNotFound
	}
	var s Stats
	var errs []error
	readUint := func(name string, dst *uint64) {
		data, err := m.fs.ReadFile(m.file(name))
		if err != nil {
			return // controller not enabled
		}
		v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse %s: %w", name, err))
			return
		}
		*dst = v
	}
	readString := func(name string, dst *string) {
		if data, err := m.fs.ReadFile(m.file(name)); err == nil {
			*dst = strings.TrimSpace(string(data))
		}
	}
	readKeyed := func(name string, fields map[string]*uint64) {
		data, err := m.fs.ReadFile(m.file(name))
		if err != nil {
			return
		}
		kv, err := ParseFlatKeyed(string(data))
		if err != nil {
			errs = append(errs, fmt.Errorf("parse %s: %w", name, err))
			return
		}
		for k, dst := range fields {
			*dst = kv[k]
		}
	}
	readUint("memory.current", &s.MemoryCurrent)
	readUint("memory.peak", &s.MemoryPeak)
	readString("memory.max", &s.MemoryMax)
	readKeyed("memory.events", map[string]*uint64{"oom": &s.OOMEvents, "oom_kill": &s.OOMKills})
	readUint("pids.current", &s.PidsCurrent)
	readString("pids.max", &s.PidsMax)
	readKeyed("pids.events", map[string]*uint64{"max": &s.PidsLimitHits})
	readKeyed("cpu.stat", map[string]*uint64{"usage_usec": &s.CPUUsageUsec, "throttled_usec": &s.CPUThrottled})
	return s, errors.Join(errs...)
}

// ParseFlatKeyed parses a cgroup "flat keyed" file ("key value" per line).
func ParseFlatKeyed(text string) (map[string]uint64, error) {
	out := map[string]uint64{}
	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed line %q", line)
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %q: %w", line, err)
		}
		out[fields[0]] = v
	}
	return out, nil
}
