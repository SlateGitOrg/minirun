//go:build linux

package sandbox

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/archit2501/minirun/internal/caps"
	"github.com/archit2501/minirun/internal/launch"
	"github.com/archit2501/minirun/internal/seccomp"
)

// The identity syscalls below are issued with RawSyscall on purpose. Go's
// syscall.Setuid and friends broadcast the change to every thread of the
// process (AllThreadsSyscall); minirun wants the opposite: only the locked
// thread that is about to execve changes identity, which keeps the
// sequence identical to a single-threaded C runtime and leaves the Go
// runtime's other threads untouched until execve discards them.

func setgroups(gids []uint32) error {
	var p unsafe.Pointer
	if len(gids) > 0 {
		p = unsafe.Pointer(&gids[0]) //nolint:gosec // G103: setgroups(2) takes a gid_t array; gids outlives the call
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_SETGROUPS, uintptr(len(gids)), uintptr(p), 0); errno != 0 {
		return fmt.Errorf("setgroups: %w", errno)
	}
	return nil
}

func setresgid(gid uint32) error {
	if _, _, errno := unix.RawSyscall(unix.SYS_SETRESGID, uintptr(gid), uintptr(gid), uintptr(gid)); errno != 0 {
		return fmt.Errorf("setresgid(%d): %w", gid, errno)
	}
	return nil
}

func setresuid(uid uint32) error {
	if _, _, errno := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(uid), uintptr(uid), uintptr(uid)); errno != 0 {
		return fmt.Errorf("setresuid(%d): %w", uid, errno)
	}
	return nil
}

func prctl(option, arg uintptr, what string) error {
	if _, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, option, arg, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(%s): %w", what, errno)
	}
	return nil
}

// dropPrivileges turns the calling (locked) thread into the configured
// process identity. Order matters:
//
//  1. without no_new_privs, the seccomp filter must be loaded while the
//     thread still has CAP_SYS_ADMIN, so it goes first;
//  2. the bounding set is trimmed while CAP_SETPCAP is still effective;
//  3. PR_SET_KEEPCAPS keeps the permitted set across the uid change;
//  4. groups, gid, then uid (setgroups needs CAP_SETGID, setresuid last);
//  5. capset installs effective/permitted/inheritable, then ambient;
//  6. with no_new_privs, set it and load the filter last, so the filter
//     governs nothing but the final execve and the program itself.
//
// last is the kernel's highest capability number, read by the caller before
// it changed root (the container may not mount /proc).
func dropPrivileges(p launch.Process, filter *launch.Seccomp, userNS bool, last int) error {
	var prog *seccomp.Program
	if filter != nil {
		var err error
		if prog, err = filter.Program(); err != nil {
			return err
		}
	}
	if prog != nil && !p.NoNewPrivs {
		if err := seccomp.Install(prog); err != nil {
			return err
		}
	}
	if err := caps.DropBounding(p.Caps.Bounding, last); err != nil {
		return err
	}
	if err := prctl(unix.PR_SET_KEEPCAPS, 1, "PR_SET_KEEPCAPS"); err != nil {
		return err
	}
	// In a user namespace minirun writes "deny" to setgroups (required for
	// an unprivileged-style gid_map), so supplementary groups cannot be set;
	// launch.Build rejects additionalGids in that case.
	if !userNS {
		if err := setgroups(p.AdditionalGids); err != nil {
			return err
		}
	}
	if err := setresgid(p.GID); err != nil {
		return err
	}
	if err := setresuid(p.UID); err != nil {
		return err
	}
	if err := prctl(unix.PR_SET_KEEPCAPS, 0, "PR_SET_KEEPCAPS"); err != nil {
		return err
	}
	if err := caps.SetSets(p.Caps, last); err != nil {
		return err
	}
	if p.NoNewPrivs {
		if err := prctl(unix.PR_SET_NO_NEW_PRIVS, 1, "PR_SET_NO_NEW_PRIVS"); err != nil {
			return err
		}
		if prog != nil {
			if err := seccomp.Install(prog); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyRlimits sets the process's resource limits.
func applyRlimits(limits []launch.Rlimit) error {
	for _, rl := range limits {
		lim := unix.Rlimit{Cur: rl.Soft, Max: rl.Hard}
		if err := unix.Prlimit(0, rl.Resource, &lim, nil); err != nil {
			return fmt.Errorf("setrlimit %s: %w", rl.Name, err)
		}
	}
	return nil
}
