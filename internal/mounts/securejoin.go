package mounts

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxSymlinks bounds symlink expansion, like the kernel's ELOOP limit.
const maxSymlinks = 255

// ErrTooManyLinks is returned when resolution exceeds maxSymlinks.
var ErrTooManyLinks = errors.New("too many levels of symbolic links")

// SecureJoin resolves unsafePath as if root were "/", following symlinks but
// never leaving root: absolute link targets restart at root and ".." stops
// at root. The result is a host path inside root that is not itself a
// symlink. Every component is checked with lstat, including those after a
// component that does not exist yet (a later ".." can lead back into
// existing directories); missing components are kept as they are, so the
// result can be used to create a mount point.
//
// The caller must still be aware of the usual time-of-check/time-of-use
// window: a process that can modify the tree concurrently can swap a
// directory for a symlink after resolution. minirun resolves mount targets
// before the container's process runs, while only minirun can write the
// rootfs.
func SecureJoin(root, unsafePath string) (string, error) {
	root = filepath.Clean(root)
	var resolved []string // components below root: non-symlinks, existing or missing
	pending := splitPath(unsafePath)
	links := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(resolved) > 0 {
				resolved = resolved[:len(resolved)-1]
			}
			continue
		}
		candidate := filepath.Join(root, filepath.Join(resolved...), part)
		info, err := os.Lstat(candidate)
		if errors.Is(err, fs.ErrNotExist) {
			// Nothing on disk to follow here. Later components are still
			// resolved one by one: a later ".." can climb back out of the
			// missing part into existing directories, where the next name
			// may be a symlink that must be followed, not appended.
			resolved = append(resolved, part)
			continue
		}
		if err != nil {
			return "", fmt.Errorf("resolve %s in %s: %w", unsafePath, root, err)
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			resolved = append(resolved, part)
			continue
		}
		links++
		if links > maxSymlinks {
			return "", fmt.Errorf("resolve %s in %s: %w", unsafePath, root, ErrTooManyLinks)
		}
		target, err := os.Readlink(candidate)
		if err != nil {
			return "", fmt.Errorf("resolve %s in %s: %w", unsafePath, root, err)
		}
		if filepath.IsAbs(target) {
			resolved = resolved[:0]
		}
		pending = append(splitPath(target), pending...)
	}
	result := filepath.Join(root, filepath.Join(resolved...))
	// Every component was checked above; this re-check keeps the promise
	// that the result is never itself a symlink even if that loop is
	// changed later.
	if info, err := os.Lstat(result); err == nil && info.Mode()&fs.ModeSymlink != 0 {
		return "", fmt.Errorf("resolve %s in %s: result %s is a symlink", unsafePath, root, result)
	}
	return result, nil
}

func splitPath(p string) []string {
	return strings.Split(filepath.ToSlash(p), "/")
}
