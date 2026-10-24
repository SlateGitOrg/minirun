package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// defaultPath is used when the process environment has no PATH, matching
// what execvp(3) falls back to.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// LookPath resolves the command name the way execvp does, but against the
// PATH in the container's environment and relative to root (the container
// root as seen by the caller). Names containing a slash are used as given.
// It returns the path inside the container.
func LookPath(root, file string, env []string) (string, error) {
	if strings.Contains(file, "/") {
		return file, nil
	}
	pathEnv := defaultPath
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			pathEnv = v
		}
	}
	for dir := range strings.SplitSeq(pathEnv, ":") {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, file)
		info, err := os.Stat(filepath.Join(root, candidate))
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("executable %q not found in PATH %s", file, pathEnv)
}
