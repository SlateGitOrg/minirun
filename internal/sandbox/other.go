//go:build !linux

package sandbox

import "errors"

var errNotLinux = errors.New("containers can only be started on Linux")

// RunInit is only implemented on Linux.
func RunInit() error { return errNotLinux }

// RunExec is only implemented on Linux.
func RunExec() error { return errNotLinux }
