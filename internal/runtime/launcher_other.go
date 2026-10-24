//go:build !linux

package runtime

import (
	"context"
	"errors"

	"github.com/archit2501/minirun/internal/launch"
)

type unsupportedLauncher struct{}

// NewLauncher returns the platform launcher, which on this OS refuses to
// start containers.
func NewLauncher() Launcher { return unsupportedLauncher{} }

func (unsupportedLauncher) Check() error { return ErrUnsupported }

func (unsupportedLauncher) StartInit(context.Context, *launch.Plan, Stdio) (Child, error) {
	return nil, ErrUnsupported
}

func (unsupportedLauncher) StartExec(context.Context, *launch.Plan, int, launch.Process, Stdio) (Child, error) {
	return nil, ErrUnsupported
}

// SignalFunc returns the platform function that delivers signals. Container
// processes only exist on Linux, so there is nothing to signal here.
func SignalFunc() func(pid, sig int) error {
	return func(int, int) error { return errors.New("signals are delivered to containers only on Linux") }
}
