package state

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Lock takes an exclusive flock(2) on the container's lock file, blocking
// until it is available, and returns the function that releases it. Every
// operation that changes a container's state holds the lock, so concurrent
// `kill`, `delete` and a foreground `run` updating its exit status cannot
// interleave writes.
func (s *Store) Lock(id string) (func(), error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.Dir(id), "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("open lock: %w", err)
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", id, err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
