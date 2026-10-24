//go:build !linux

package seccomp

import "errors"

// Install is only implemented on Linux.
func Install(*Program) error {
	return errors.New("seccomp: loading filters requires Linux")
}
