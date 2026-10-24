package seccomp

import (
	"strings"

	"github.com/archit2501/minirun/internal/spec"
)

// defaultAllowed is the allow-list of the default profile. It is modelled on
// the allow-list of Docker's default profile for containers without
// CAP_SYS_ADMIN: ordinary process, file, memory, IPC, signal, time and socket
// calls are allowed; calls that administer the kernel or the host (mount,
// unshare/setns, module loading, kexec, bpf, perf, keyrings, ptrace, clock
// setting, swap, reboot, ...) fall through to the default EPERM. Only
// x86-64 and arm64 names are listed (Docker's list also carries 32-bit-only
// calls such as stat64); the legacy x86-64 calls arm64 lacks (open, stat,
// fork, ...) are skipped when compiling for arm64.
const defaultAllowed = `
accept accept4 access adjtimex alarm arch_prctl bind brk cachestat capget capset chdir chmod
chown chroot clock_adjtime clock_getres clock_gettime clock_nanosleep close close_range connect
copy_file_range creat dup dup2 dup3 epoll_create epoll_create1 epoll_ctl epoll_ctl_old
epoll_pwait epoll_pwait2 epoll_wait epoll_wait_old eventfd eventfd2 execve execveat exit
exit_group faccessat faccessat2 fadvise64 fallocate fanotify_mark fchdir fchmod fchmodat
fchmodat2 fchown fchownat fcntl fdatasync fgetxattr flistxattr flock fork fremovexattr fsetxattr
fstat fstatfs fsync ftruncate futex futex_requeue futex_wait futex_waitv futex_wake futimesat
get_robust_list get_thread_area getcpu getcwd getdents getdents64 getegid geteuid getgid
getgroups getitimer getpeername getpgid getpgrp getpid getppid getpriority getrandom getresgid
getresuid getrlimit getrusage getsid getsockname getsockopt gettid gettimeofday getuid getxattr
inotify_add_watch inotify_init inotify_init1 inotify_rm_watch io_cancel io_destroy io_getevents
io_pgetevents io_setup io_submit ioctl ioprio_get ioprio_set kill landlock_add_rule
landlock_create_ruleset landlock_restrict_self lchown lgetxattr link linkat listen listxattr
llistxattr lremovexattr lseek lsetxattr lstat madvise map_shadow_stack membarrier memfd_create
memfd_secret mincore mkdir mkdirat mknod mknodat mlock mlock2 mlockall mmap mprotect
mq_getsetattr mq_notify mq_open mq_timedreceive mq_timedsend mq_unlink mremap msgctl msgget
msgrcv msgsnd msync munlock munlockall munmap name_to_handle_at nanosleep newfstatat open openat
openat2 pause pidfd_open pidfd_send_signal pipe pipe2 pkey_alloc pkey_free pkey_mprotect poll
ppoll prctl pread64 preadv preadv2 prlimit64 process_mrelease pselect6 pwrite64 pwritev pwritev2
read readahead readlink readlinkat readv recvfrom recvmmsg recvmsg remap_file_pages removexattr
rename renameat renameat2 restart_syscall rmdir rseq rt_sigaction rt_sigpending rt_sigprocmask
rt_sigqueueinfo rt_sigreturn rt_sigsuspend rt_sigtimedwait rt_tgsigqueueinfo
sched_get_priority_max sched_get_priority_min sched_getaffinity sched_getattr sched_getparam
sched_getscheduler sched_rr_get_interval sched_setaffinity sched_setattr sched_setparam
sched_setscheduler sched_yield seccomp select semctl semget semop semtimedop sendfile sendmmsg
sendmsg sendto set_robust_list set_thread_area set_tid_address setfsgid setfsuid setgid
setgroups setitimer setpgid setpriority setregid setresgid setresuid setreuid setrlimit setsid
setsockopt setuid setxattr shmat shmctl shmdt shmget shutdown sigaltstack signalfd signalfd4
socketpair splice stat statfs statx symlink symlinkat sync sync_file_range syncfs sysinfo tee
tgkill time timer_create timer_delete timer_getoverrun timer_gettime timer_settime
timerfd_create timerfd_gettime timerfd_settime times tkill truncate umask uname unlink unlinkat
utime utimensat utimes vfork vmsplice wait4 waitid write writev
`

// Constants used by the conditional rules of the default profile.
const (
	afVsock = 40 // AF_VSOCK: host<->guest sockets, denied as Docker does
	enosys  = 38 // ENOSYS: makes libc fall back from clone3 to clone

	// cloneNamespaceFlags is CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|
	// CLONE_NEWIPC|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET (0x7e020000):
	// clone(2) is allowed only when none of them is set, so a container
	// cannot create namespaces (in particular unprivileged user namespaces).
	cloneNamespaceFlags = 0x7e020000
)

// DefaultProfile returns minirun's default seccomp profile in OCI form.
func DefaultProfile() *spec.Seccomp {
	eperm := uint(1)
	nosys := uint(enosys)
	s := &spec.Seccomp{
		DefaultAction:   "SCMP_ACT_ERRNO",
		DefaultErrnoRet: &eperm,
		Architectures:   []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"},
		Syscalls: []spec.Syscall{
			{Names: strings.Fields(defaultAllowed), Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"socket"}, Action: "SCMP_ACT_ALLOW", Args: []spec.Arg{{Index: 0, Value: afVsock, Op: "SCMP_CMP_NE"}}},
			{Names: []string{"clone"}, Action: "SCMP_ACT_ALLOW", Args: []spec.Arg{{Index: 0, Value: cloneNamespaceFlags, ValueTwo: 0, Op: "SCMP_CMP_MASKED_EQ"}}},
			// clone3 passes its flags in memory, which seccomp cannot inspect.
			{Names: []string{"clone3"}, Action: "SCMP_ACT_ERRNO", ErrnoRet: &nosys},
		},
	}
	// personality(2): only the execution domains libc and tools use.
	for _, v := range []uint64{0x0, 0x0008, 0x20000, 0x20008, 0xffffffff} {
		s.Syscalls = append(s.Syscalls, spec.Syscall{
			Names: []string{"personality"}, Action: "SCMP_ACT_ALLOW",
			Args: []spec.Arg{{Index: 0, Value: v, Op: "SCMP_CMP_EQ"}},
		})
	}
	return s
}
