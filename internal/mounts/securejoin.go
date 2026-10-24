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
// at root. The result is a host path inside root. Components that do not
// exist yet are appended lexically, so the result can be used to create a
// mount point.
//
// The caller must still be aware of the usual time-of-check/time-of-use
// window: a process that can modify the tree concurrently can swap a
// directory for a symlink after resolution. minirun resolves mount targets
// before the container's process runs, while only minirun can write the
// rootfs.
func SecureJoin(root, unsafePath string) (string, error) {
	root = filepath.Clean(root)
	var resolved []string // components below root, all existing non-symlinks
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
			// Nothing on disk to follow: keep the rest lexically.
			resolved = append(resolved, part)
			for _, rest := range pending {
				switch rest {
				case "", ".":
				case "..":
					if len(resolved) > 0 {
						resolved = resolved[:len(resolved)-1]
					}
				default:
					resolved = append(resolved, rest)
				}
			}
			pending = nil
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
	return filepath.Join(root, filepath.Join(resolved...)), nil
}

func splitPath(p string) []string {
	return strings.Split(filepath.ToSlash(p), "/")
}
