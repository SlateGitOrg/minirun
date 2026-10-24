// Package state persists container state under a state directory (default
// /run/minirun), one subdirectory per container, and derives a container's
// live status from /proc.
//
// Layout of <root>/<id>/:
//
//	state.json   OCI state plus minirun bookkeeping (atomic replace)
//	plan.json    the launch plan, reused by `exec`
//	lock         flock(2) target serialising lifecycle operations
//	upper/ work/ overlayfs upper and work directories
//	rootfs/      mount point the container's root is assembled on
//	console.log  stdout/stderr of detached containers
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// DefaultRoot is the default state directory.
const DefaultRoot = "/run/minirun"

// Status is the OCI lifecycle status.
type Status string

// Lifecycle states from the OCI runtime specification.
const (
	Creating Status = "creating"
	Created  Status = "created"
	Running  Status = "running"
	Stopped  Status = "stopped"
)

// State is the persisted state of one container. The first block of fields
// is the OCI state object; the rest is minirun's own bookkeeping.
type State struct {
	OCIVersion  string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      Status            `json:"status"`
	Pid         int               `json:"pid,omitempty"`
	Bundle      string            `json:"bundle"`
	Annotations map[string]string `json:"annotations,omitempty"`

	Created      time.Time `json:"created"`
	PidStartTime uint64    `json:"pidStartTime,omitempty"`
	CgroupRoot   string    `json:"cgroupRoot"`
	CgroupPath   string    `json:"cgroupPath"`
	Detached     bool      `json:"detached,omitempty"`
	ExitCode     *int      `json:"exitCode,omitempty"`
	OOMKilled    bool      `json:"oomKilled,omitempty"`
}

// Errors returned by Store.
var (
	ErrNotFound = errors.New("container does not exist")
	ErrExists   = errors.New("container already exists")
)

var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// ValidateID checks a container ID. IDs become directory and cgroup names,
// so they are restricted to a safe alphabet with no path separators.
func ValidateID(id string) error {
	if !idRE.MatchString(id) {
		return fmt.Errorf("invalid container id %q: use 1-64 characters from [A-Za-z0-9_.-], starting with a letter or digit", id)
	}
	return nil
}

// Store manages the state directory.
type Store struct {
	Root string
}

// Dir returns the state directory of a container.
func (s *Store) Dir(id string) string { return filepath.Join(s.Root, id) }

// Create reserves the directory for a new container. It fails with
// ErrExists if the ID is taken.
func (s *Store) Create(id string) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Root, 0o711); err != nil {
		return fmt.Errorf("create state root: %w", err)
	}
	if err := os.Mkdir(s.Dir(id), 0o711); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w", id, ErrExists)
		}
		return fmt.Errorf("create state dir: %w", err)
	}
	return nil
}

// Save atomically replaces state.json.
func (s *Store) Save(st *State) error {
	return s.WriteJSON(st.ID, "state.json", st)
}

// Load reads a container's state.
func (s *Store) Load(id string) (*State, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	var st State
	if err := s.ReadJSON(id, "state.json", &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// WriteJSON atomically writes v as <id>/<name> (write to a temp file, fsync,
// rename), so readers never observe a partial file.
func (s *Store) WriteJSON(id, name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	dir := s.Dir(id)
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", id, ErrNotFound)
		}
		return fmt.Errorf("write %s: %w", name, err)
	}
	_, werr := tmp.Write(append(data, '\n'))
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// ReadJSON decodes <id>/<name> into v.
func (s *Store) ReadJSON(id, name string, v any) error {
	data, err := os.ReadFile(filepath.Join(s.Dir(id), name))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s: %w", id, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("decode %s of %s: %w", name, id, err)
	}
	return nil
}

// List returns the state of every container, sorted by ID. Directories
// without a readable state.json (a container still being created, or
// debris) are skipped.
func (s *Store) List() ([]*State, error) {
	entries, err := os.ReadDir(s.Root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list state root: %w", err)
	}
	var out []*State
	for _, e := range entries {
		if !e.IsDir() || ValidateID(e.Name()) != nil {
			continue
		}
		st, err := s.Load(e.Name())
		if err != nil {
			continue
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ErrMountPoint is returned by Remove when the state directory contains a
// mount point. Deleting through it could destroy data on another filesystem
// (for example a bind mount that leaked out of the container through shared
// mount propagation), so removal stops instead.
var ErrMountPoint = errors.New("state directory contains a mount point")

// Remove deletes a container's state directory and everything in it
// (including the overlay upper layer). Like `rm --one-file-system` it never
// descends into a directory on a different device.
func (s *Store) Remove(id string) error {
	if err := ValidateID(id); err != nil {
		return err
	}
	dir := s.Dir(id)
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove state of %s: %w", id, err)
	}
	if err := checkOneFilesystem(dir, deviceOf(info)); err != nil {
		return fmt.Errorf("remove state of %s: %w", id, err)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove state of %s: %w", id, err)
	}
	return nil
}

// checkOneFilesystem walks dir without following symlinks and fails if any
// directory lives on a device other than dev.
func checkOneFilesystem(dir string, dev uint64) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if deviceOf(info) != dev {
			return fmt.Errorf("%w: %s (unmount it first)", ErrMountPoint, path)
		}
		return nil
	})
}
