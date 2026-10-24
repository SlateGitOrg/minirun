// Package fakecg is an on-disk fake of the cgroup v2 filesystem, rooted in an
// ordinary directory. It reproduces the kernel behaviour the cgroups manager
// depends on:
//
//   - mkdir populates cgroup.* core files plus the interface files of every
//     controller the parent delegates via cgroup.subtree_control;
//   - interface files are never created by writes (ENOENT), and read-only
//     files reject writes (EACCES);
//   - cgroup.subtree_control only accepts controllers listed in
//     cgroup.controllers and refuses to enable controllers in a non-root
//     cgroup that has processes (EBUSY, the "no internal processes" rule);
//   - limit files validate their values (EINVAL), as the kernel does;
//   - rmdir fails with EBUSY while the cgroup has processes or children;
//   - writing "1" to cgroup.kill empties cgroup.procs.
//
// Every successful write is recorded so callers can show exactly what a
// container launch would do to a real hierarchy.
package fakecg

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// Write is one recorded write.
type Write struct {
	Path string
	Data string
}

// FS is the fake filesystem. Paths passed to its methods are absolute paths
// under Root, as with the real hierarchy.
type FS struct {
	Root string

	mu     sync.Mutex
	writes []Write
}

// AllControllers are the controllers the fake root offers.
var AllControllers = []string{"cpuset", "cpu", "io", "memory", "pids"}

var controllerFiles = map[string]map[string]string{
	"cpu": {
		"cpu.max": "max 100000\n", "cpu.weight": "100\n",
		"cpu.stat": "usage_usec 0\nuser_usec 0\nsystem_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n",
	},
	"cpuset": {"cpuset.cpus": "\n", "cpuset.mems": "\n", "cpuset.cpus.effective": "0-7\n", "cpuset.mems.effective": "0\n"},
	"io":     {"io.max": "", "io.weight": "default 100\n", "io.stat": ""},
	"memory": {
		"memory.max": "max\n", "memory.high": "max\n", "memory.low": "0\n", "memory.min": "0\n",
		"memory.swap.max": "max\n", "memory.current": "0\n", "memory.peak": "0\n",
		"memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
		"memory.stat":   "anon 0\nfile 0\n",
	},
	"pids": {"pids.max": "max\n", "pids.current": "0\n", "pids.events": "max 0\n"},
}

var readOnly = map[string]bool{
	"cgroup.controllers": true, "cgroup.events": true, "cpu.stat": true,
	"cpuset.cpus.effective": true, "cpuset.mems.effective": true, "io.stat": true,
	"memory.current": true, "memory.peak": true, "memory.events": true, "memory.stat": true,
	"pids.current": true, "pids.events": true,
}

// New creates a fake hierarchy root inside dir offering AllControllers.
func New(dir string) (*FS, error) {
	f := &FS{Root: filepath.Clean(dir)}
	core := map[string]string{
		"cgroup.controllers":     strings.Join(AllControllers, " ") + "\n",
		"cgroup.subtree_control": "\n",
		"cgroup.procs":           "",
	}
	if err := os.MkdirAll(f.Root, 0o755); err != nil {
		return nil, err
	}
	for name, content := range core {
		if err := os.WriteFile(filepath.Join(f.Root, name), []byte(content), 0o644); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (f *FS) check(path string) error {
	rel, err := filepath.Rel(f.Root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return fmt.Errorf("fakecg: %s: %w %s", path, ErrOutside, f.Root)
	}
	return nil
}

func pathErr(op, path string, err error) error {
	return &fs.PathError{Op: op, Path: path, Err: err}
}

// Mkdir creates a cgroup and its interface files.
func (f *FS) Mkdir(path string) error {
	if err := f.check(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	delegated, err := os.ReadFile(filepath.Join(parent, "cgroup.subtree_control"))
	if err != nil {
		return pathErr("mkdir", path, syscall.ENOENT)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		return err
	}
	enabled := strings.Fields(string(delegated))
	files := map[string]string{
		"cgroup.controllers":     strings.Join(enabled, " ") + "\n",
		"cgroup.subtree_control": "\n",
		"cgroup.procs":           "",
		"cgroup.events":          "populated 0\nfrozen 0\n",
		"cgroup.kill":            "",
		"cgroup.type":            "domain\n",
	}
	for _, c := range enabled {
		for name, content := range controllerFiles[c] {
			files[name] = content
		}
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(path, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Rmdir removes an empty cgroup.
func (f *FS) Rmdir(path string) error {
	if err := f.check(path); err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			return pathErr("rmdir", path, syscall.EBUSY)
		}
	}
	procs, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(procs)) != "" {
		return pathErr("rmdir", path, syscall.EBUSY)
	}
	return os.RemoveAll(path)
}

// ReadFile reads an interface file.
func (f *FS) ReadFile(path string) ([]byte, error) {
	if err := f.check(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// WriteFile writes an interface file with kernel-like validation.
func (f *FS) WriteFile(path string, data []byte) error {
	if err := f.check(path); err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return pathErr("open", path, syscall.ENOENT)
	}
	name := filepath.Base(path)
	if readOnly[name] {
		return pathErr("write", path, syscall.EACCES)
	}
	value := strings.TrimSpace(string(data))
	content, err := f.apply(path, name, value)
	if err != nil {
		return pathErr("write", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	f.mu.Lock()
	f.writes = append(f.writes, Write{Path: path, Data: string(data)})
	f.mu.Unlock()
	return nil
}

// apply validates a write and returns the file's new content.
func (f *FS) apply(path, name, value string) (string, error) {
	dir := filepath.Dir(path)
	switch name {
	case "cgroup.subtree_control":
		return f.subtreeControl(dir, value)
	case "cgroup.procs":
		if _, err := strconv.Atoi(value); err != nil {
			return "", syscall.EINVAL
		}
		old, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return string(old) + value + "\n", nil
	case "cgroup.kill":
		if value != "1" {
			return "", syscall.EINVAL
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), nil, 0o644); err != nil {
			return "", err
		}
		return "", nil
	case "memory.max", "memory.high", "memory.low", "memory.min", "memory.swap.max", "pids.max":
		if value != "max" {
			if _, err := strconv.ParseUint(value, 10, 64); err != nil {
				return "", syscall.EINVAL
			}
		}
	case "cpu.max":
		if !validCPUMax(value) {
			return "", syscall.EINVAL
		}
	case "cpu.weight":
		w, err := strconv.ParseUint(value, 10, 64)
		if err != nil || w < 1 || w > 10000 {
			return "", syscall.EINVAL
		}
	}
	return value + "\n", nil
}

func validCPUMax(v string) bool {
	fields := strings.Fields(v)
	if len(fields) == 0 || len(fields) > 2 {
		return false
	}
	if fields[0] != "max" {
		q, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || q < 1000 {
			return false
		}
	}
	if len(fields) == 2 {
		p, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || p < 1000 || p > 1000000 {
			return false
		}
	}
	return true
}

func (f *FS) subtreeControl(dir, value string) (string, error) {
	avail, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return "", err
	}
	current, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		return "", err
	}
	procs, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return "", err
	}
	enabled := strings.Fields(string(current))
	for _, tok := range strings.Fields(value) {
		if len(tok) < 2 || (tok[0] != '+' && tok[0] != '-') {
			return "", syscall.EINVAL
		}
		c := tok[1:]
		if !slices.Contains(strings.Fields(string(avail)), c) {
			return "", syscall.ENOENT
		}
		if tok[0] == '+' {
			if dir != f.Root && strings.TrimSpace(string(procs)) != "" {
				return "", syscall.EBUSY
			}
			if !slices.Contains(enabled, c) {
				enabled = append(enabled, c)
			}
		} else {
			enabled = slices.DeleteFunc(enabled, func(e string) bool { return e == c })
		}
	}
	// The kernel lists controllers in a fixed order.
	var ordered []string
	for _, c := range AllControllers {
		if slices.Contains(enabled, c) {
			ordered = append(ordered, c)
		}
	}
	return strings.Join(ordered, " ") + "\n", nil
}

// Writes returns the successful writes so far, in order.
func (f *FS) Writes() []Write {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.writes)
}

// SetCounter overwrites a (possibly read-only) file to simulate the kernel
// updating a counter, e.g. memory.events after an OOM kill.
func (f *FS) SetCounter(path, content string) error {
	if err := f.check(path); err != nil {
		return err
	}
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// AddProc simulates a process joining a cgroup.
func (f *FS) AddProc(dir string, pid int) error {
	return f.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)))
}

// ErrOutside reports a path outside the fake root.
var ErrOutside = errors.New("path is outside the fake cgroup root")
