// Package cgroups manages cgroup v2 hierarchies for containers: creating a
// cgroup, enabling controllers along its ancestry, translating OCI resource
// limits into interface-file writes, reading statistics and tearing down.
//
// All filesystem access goes through the FS interface. OSFS talks to the
// real cgroup2 mount; the fakecg package provides a temp-directory fake that
// reproduces the kernel's rules (interface files appearing on mkdir,
// controller delegation, the no-internal-processes rule, value validation)
// so the manager is tested on any OS.
package cgroups

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// FS is the subset of filesystem operations the manager needs.
type FS interface {
	// Mkdir creates one cgroup directory. It returns an error wrapping
	// fs.ErrExist if the directory exists.
	Mkdir(path string) error
	// Rmdir removes an empty cgroup directory.
	Rmdir(path string) error
	// ReadFile returns the contents of an interface file.
	ReadFile(path string) ([]byte, error)
	// WriteFile writes data to an existing interface file. Like the kernel
	// it never creates files.
	WriteFile(path string, data []byte) error
}

// OSFS is the real cgroup2 filesystem.
type OSFS struct{}

// Mkdir implements FS.
func (OSFS) Mkdir(path string) error { return os.Mkdir(path, 0o755) }

// Rmdir implements FS. Cgroup directories contain only kernel-provided
// interface files, which rmdir(2) handles.
func (OSFS) Rmdir(path string) error { return syscall.Rmdir(path) }

// ReadFile implements FS.
func (OSFS) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// WriteFile implements FS.
func (OSFS) WriteFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	return errors.Join(werr, cerr)
}

// explain adds remediation hints to the errors the kernel uses for the most
// common cgroup misconfigurations.
func explain(op, path string, err error) error {
	switch {
	case errors.Is(err, syscall.EBUSY) && strings.HasPrefix(op, "remove"):
		return fmt.Errorf("%s %s: %w (processes or child cgroups remain)", op, path, err)
	case errors.Is(err, syscall.EBUSY):
		return fmt.Errorf("%s %s: %w (cgroup v2 forbids enabling controllers in a cgroup that has processes; move them to a leaf cgroup first)", op, path, err)
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%s %s: %w (is the controller enabled in the parent's cgroup.subtree_control?)", op, path, err)
	case errors.Is(err, syscall.EINVAL):
		return fmt.Errorf("%s %s: %w (value rejected by the kernel)", op, path, err)
	default:
		return fmt.Errorf("%s %s: %w", op, path, err)
	}
}
