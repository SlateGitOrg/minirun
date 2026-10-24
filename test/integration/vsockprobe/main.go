//go:build linux

// Command vsockprobe is a helper for the integration suite: it calls
// socket(AF_VSOCK) directly, once with the plain family and once with bit 32
// of the argument set. The kernel truncates the family to an int, so both
// calls ask for the same socket; a seccomp filter that compared all 64 bits
// would deny only the first.
package main

import (
	"fmt"
	"syscall"
)

const afVsock = 40

func try(family uint64) string {
	fd, _, errno := syscall.RawSyscall(syscall.SYS_SOCKET, uintptr(family), syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if errno != 0 {
		return errno.Error()
	}
	_ = syscall.Close(int(fd))
	return "created"
}

func main() {
	fmt.Printf("plain=%s\nhi=%s\n", try(afVsock), try(1<<32|afVsock))
}
