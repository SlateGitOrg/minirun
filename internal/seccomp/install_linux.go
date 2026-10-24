//go:build linux

package seccomp

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccompSetModeFilter is SECCOMP_SET_MODE_FILTER from linux/seccomp.h.
const seccompSetModeFilter = 1

// Install loads p into the kernel for the calling OS thread with
// seccomp(SECCOMP_SET_MODE_FILTER). Unless p.Flags contains
// SECCOMP_FILTER_FLAG_TSYNC the filter applies to the calling thread only,
// so callers must hold runtime.LockOSThread and exec from the same thread.
// The caller must either have set no_new_privs or hold CAP_SYS_ADMIN.
func Install(p *Program) error {
	native, err := NativeArch()
	if err != nil {
		return err
	}
	if p.Arch != native {
		return fmt.Errorf("seccomp: program compiled for %s cannot be loaded on %s", p.Arch.Name, native.Name)
	}
	if err := Validate(p.Instructions); err != nil {
		return err
	}
	filter := make([]unix.SockFilter, len(p.Instructions))
	for i, ins := range p.Instructions {
		filter[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, seccompSetModeFilter, uintptr(p.Flags), uintptr(unsafe.Pointer(&prog))) //nolint:gosec // G103: seccomp(2) takes a sock_fprog pointer; kept alive below
	runtime.KeepAlive(filter)
	if errno != 0 {
		return fmt.Errorf("seccomp: load filter: %w", errno)
	}
	return nil
}
