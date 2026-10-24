package spec

// DefaultCapabilities is the capability set granted to a container process
// unless the config says otherwise. It is the same 14-capability set Docker
// uses by default, which drops everything that administers the host
// (CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_NET_ADMIN, ...).
var DefaultCapabilities = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FSETID",
	"CAP_FOWNER",
	"CAP_MKNOD",
	"CAP_NET_RAW",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETFCAP",
	"CAP_SETPCAP",
	"CAP_NET_BIND_SERVICE",
	"CAP_SYS_CHROOT",
	"CAP_KILL",
	"CAP_AUDIT_WRITE",
}

// DefaultMaskedPaths hide kernel interfaces that leak host information or
// allow host-wide side effects. Files are covered with /dev/null, directories
// with an empty read-only tmpfs.
var DefaultMaskedPaths = []string{
	"/proc/acpi",
	"/proc/asound",
	"/proc/kcore",
	"/proc/keys",
	"/proc/latency_stats",
	"/proc/timer_list",
	"/proc/timer_stats",
	"/proc/sched_debug",
	"/proc/scsi",
	"/sys/firmware",
}

// DefaultReadonlyPaths are bind-remounted read-only inside the container.
var DefaultReadonlyPaths = []string{
	"/proc/bus",
	"/proc/fs",
	"/proc/irq",
	"/proc/sys",
	"/proc/sysrq-trigger",
}

// DefaultOptions parameterise Default.
type DefaultOptions struct {
	Args     []string
	Rootfs   string
	Hostname string
	ReadOnly bool
	// UserNS adds a user namespace mapping container IDs 0..65535 to host IDs
	// starting at HostIDBase.
	UserNS     bool
	HostIDBase uint32
	// HostNetwork keeps the container in the host network namespace. By
	// default a fresh network namespace with only loopback is created.
	HostNetwork bool
	MemoryLimit int64 // bytes; 0 means no limit
	PidsLimit   int64 // 0 means no limit
	CPUQuota    int64 // microseconds per CPUPeriod; 0 means no limit
	CPUPeriod   uint64
	Seccomp     *Seccomp
}

// Default returns a runnable config for the given options. It mirrors the
// shape of `runc spec`, so it doubles as documentation of what a complete
// minirun config looks like.
func Default(o DefaultOptions) *Spec {
	args := o.Args
	if len(args) == 0 {
		args = []string{"sh"}
	}
	rootfs := o.Rootfs
	if rootfs == "" {
		rootfs = "rootfs"
	}
	hostname := o.Hostname
	if hostname == "" {
		hostname = "minirun"
	}
	caps := append([]string(nil), DefaultCapabilities...)
	s := &Spec{
		OCIVersion: Version,
		Process: &Process{
			User: User{UID: 0, GID: 0},
			Args: args,
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"TERM=xterm",
				"HOME=/root",
			},
			Cwd: "/",
			Capabilities: &Capabilities{
				Bounding:  caps,
				Effective: caps,
				Permitted: caps,
			},
			Rlimits:         []Rlimit{{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024}},
			NoNewPrivileges: true,
		},
		Root:     &Root{Path: rootfs, Readonly: o.ReadOnly},
		Hostname: hostname,
		Mounts:   defaultMounts(o.UserNS, o.HostNetwork),
		Linux: &Linux{
			Namespaces: []Namespace{
				{Type: PIDNamespace},
				{Type: IPCNamespace},
				{Type: UTSNamespace},
				{Type: MountNamespace},
			},
			MaskedPaths:   append([]string(nil), DefaultMaskedPaths...),
			ReadonlyPaths: append([]string(nil), DefaultReadonlyPaths...),
			Seccomp:       o.Seccomp,
		},
	}
	if !o.HostNetwork {
		s.Linux.Namespaces = append(s.Linux.Namespaces, Namespace{Type: NetworkNamespace})
	}
	if o.UserNS {
		s.Linux.Namespaces = append(s.Linux.Namespaces, Namespace{Type: UserNamespace})
		s.Linux.UIDMappings = []IDMapping{{ContainerID: 0, HostID: o.HostIDBase, Size: 65536}}
		s.Linux.GIDMappings = []IDMapping{{ContainerID: 0, HostID: o.HostIDBase, Size: 65536}}
	}
	if r := defaultResources(o); r != nil {
		s.Linux.Resources = r
	}
	return s
}

func defaultResources(o DefaultOptions) *Resources {
	var r Resources
	set := false
	if o.MemoryLimit > 0 {
		limit := o.MemoryLimit
		swap := o.MemoryLimit // memory+swap == memory: no swap
		r.Memory = &Memory{Limit: &limit, Swap: &swap}
		set = true
	}
	if o.PidsLimit > 0 {
		r.Pids = &Pids{Limit: o.PidsLimit}
		set = true
	}
	if o.CPUQuota > 0 {
		quota := o.CPUQuota
		period := o.CPUPeriod
		if period == 0 {
			period = 100000
		}
		r.CPU = &CPU{Quota: &quota, Period: &period}
		set = true
	}
	if !set {
		return nil
	}
	return &r
}

func defaultMounts(userNS, hostNetwork bool) []Mount {
	mounts := []Mount{
		{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
		{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
		{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
	}
	// sysfs can only be mounted by the owner of the network namespace; a
	// user-namespaced container on the host network gets a read-only bind of
	// the host's /sys instead, as runc does for rootless containers.
	if userNS && hostNetwork {
		mounts = append(mounts, Mount{Destination: "/sys", Source: "/sys", Options: []string{"rbind", "nosuid", "noexec", "nodev", "ro"}})
	} else {
		mounts = append(mounts, Mount{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}})
	}
	return mounts
}
