//go:build linux

package caps

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// KernelLast returns the highest capability number the running kernel
// supports (/proc/sys/kernel/cap_last_cap), capped at Last.
func KernelLast() (int, error) {
	data, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, fmt.Errorf("read cap_last_cap: %w", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse cap_last_cap: %w", err)
	}
	return min(n, Last), nil
}

// DropBounding removes every capability not in keep from the calling
// thread's bounding set. It needs CAP_SETPCAP, so it must run before
// SetSets drops it.
func DropBounding(keep Set, last int) error {
	for c := 0; c <= last; c++ {
		if keep.Has(c) {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
			return fmt.Errorf("drop %s from bounding set: %w", Name(c), err)
		}
	}
	return nil
}

// SetSets installs the effective, permitted and inheritable sets with
// capset(2) and then the ambient set, for the calling thread only.
func SetSets(s Sets, last int) error {
	eff, prm, inh := s.Effective.Upto(last), s.Permitted.Upto(last), s.Inheritable.Upto(last)
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: uint32(eff), Permitted: uint32(prm), Inheritable: uint32(inh)},
		{Effective: uint32(eff >> 32), Permitted: uint32(prm >> 32), Inheritable: uint32(inh >> 32)},
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient capabilities: %w", err)
	}
	for c := 0; c <= last; c++ {
		if !s.Ambient.Has(c) {
			continue
		}
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(c), 0, 0); err != nil {
			return fmt.Errorf("raise ambient %s: %w", Name(c), err)
		}
	}
	return nil
}
