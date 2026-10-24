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
// setting, swap, reboot, ...) fall through to the default EPERM. Names that
// do not exist on an architecture are skipped at compile time.
const defaultAllowed = `
accept accept4 access adjtimex alarm arch_prctl bind brk cachestat capget capset chdir chmod
chown chown32 chroot clock_adjtime clock_adjtime64 clock_getres clock_getres_time64 clock_gettime
clock_gettime64 clock_nanosleep clock_nanosleep_time64 close close_range connect copy_file_range
creat dup dup2 dup3 epoll_create epoll_create1 epoll_ctl epoll_ctl_old epoll_pwait epoll_pwait2
epoll_wait epoll_wait_old eventfd eventfd2 execve execveat exit exit_group faccessat faccessat2
fadvise64 fadvise64_64 fallocate fanotify_mark fchdir fchmod fchmodat fchmodat2 fchown fchown32
fchownat fcntl fcntl64 fdatasync fgetxattr flistxattr flock fork fremovexattr fsetxattr fstat
fstat64 fstatat64 fstatfs fstatfs64 fsync ftruncate ftruncate64 futex futex_requeue futex_time64
futex_wait futex_waitv futex_wake futimesat get_robust_list get_thread_area getcpu getcwd getdents
getdents64 getegid getegid32 geteuid geteuid32 getgid getgid32 getgroups getgroups32 getitimer
getpeername getpgid getpgrp getpid getppid getpriority getrandom getresgid getresgid32 getresuid
getresuid32 getrlimit getrusage getsid getsockname getsockopt gettid gettimeofday getuid getuid32
getxattr inotify_add_watch inotify_init inotify_init1 inotify_rm_watch io_cancel io_destroy
io_getevents io_pgetevents io_pgetevents_time64 io_setup io_submit ioctl ioprio_get ioprio_set ipc
kill landlock_add_rule landlock_create_ruleset landlock_restrict_self lchown lchown32 lgetxattr
link linkat listen listxattr llistxattr _llseek lremovexattr lseek lsetxattr lstat lstat64
madvise map_shadow_stack membarrier memfd_create memfd_secret mincore mkdir mkdirat mknod mknodat
mlock mlock2 mlockall mmap mmap2 mprotect mq_getsetattr mq_notify mq_open mq_timedreceive
mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 mq_unlink mremap msgctl msgget msgrcv
msgsnd msync munlock munlockall munmap name_to_handle_at nanosleep newfstatat _newselect open
openat openat2 pause pidfd_open pidfd_send_signal pipe pipe2 pkey_alloc pkey_free pkey_mprotect
poll ppoll ppoll_time64 prctl pread64 preadv preadv2 prlimit64 process_mrelease pselect6
pselect6_time64 pwrite64 pwritev pwritev2 read readahead readlink readlinkat readv recv recvfrom
recvmmsg recvmmsg_time64 recvmsg remap_file_pages removexattr rename renameat renameat2
restart_syscall rmdir rseq rt_sigaction rt_sigpending rt_sigprocmask rt_sigqueueinfo
rt_sigreturn rt_sigsuspend rt_sigtimedwait rt_sigtimedwait_time64 rt_tgsigqueueinfo
sched_get_priority_max sched_get_priority_min sched_getaffinity sched_getattr sched_getparam
sched_getscheduler sched_rr_get_interval sched_rr_get_interval_time64 sched_setaffinity
sched_setattr sched_setparam sched_setscheduler sched_yield seccomp select semctl semget semop
semtimedop semtimedop_time64 send sendfile sendfile64 sendmmsg sendmsg sendto set_robust_list
set_thread_area set_tid_address setfsgid setfsgid32 setfsuid setfsuid32 setgid setgid32 setgroups
setgroups32 setitimer setpgid setpriority setregid setregid32 setresgid setresgid32 setresuid
setresuid32 setreuid setreuid32 setrlimit setsid setsockopt setuid setuid32 setxattr shmat shmctl
shmdt shmget shutdown sigaltstack signalfd signalfd4 sigprocmask sigreturn socketcall socketpair
splice stat stat64 statfs statfs64 statx symlink symlinkat sync sync_file_range sync_file_range2
syncfs sysinfo tee tgkill time timer_create timer_delete timer_getoverrun timer_gettime
timer_gettime64 timer_settime timer_settime64 timerfd_create timerfd_gettime timerfd_gettime64
timerfd_settime timerfd_settime64 times tkill truncate truncate64 ugetrlimit umask uname unlink
unlinkat utime utimensat utimensat_time64 utimes vfork vmsplice wait4 waitid waitpid write writev
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
