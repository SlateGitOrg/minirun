// Package spec models the subset of the OCI runtime-spec config.json that
// minirun understands, and provides loading, validation and default
// generation for it.
//
// Field names and JSON keys follow the upstream specification
// (https://github.com/opencontainers/runtime-spec, config.md and
// config-linux.md) so a bundle produced by minirun is readable by other
// runtimes and a bundle produced by `runc spec` loads here, with unsupported
// keys reported as warnings rather than silently dropped.
package spec

// Version is the OCI runtime-spec version minirun writes and targets.
const Version = "1.2.0"

// Spec is the root of config.json.
type Spec struct {
	OCIVersion  string            `json:"ociVersion"`
	Process     *Process          `json:"process,omitempty"`
	Root        *Root             `json:"root,omitempty"`
	Hostname    string            `json:"hostname,omitempty"`
	Domainname  string            `json:"domainname,omitempty"`
	Mounts      []Mount           `json:"mounts,omitempty"`
	Linux       *Linux            `json:"linux,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Process describes the container's init process.
type Process struct {
	Terminal        bool          `json:"terminal,omitempty"`
	User            User          `json:"user"`
	Args            []string      `json:"args"`
	Env             []string      `json:"env,omitempty"`
	Cwd             string        `json:"cwd"`
	Capabilities    *Capabilities `json:"capabilities,omitempty"`
	Rlimits         []Rlimit      `json:"rlimits,omitempty"`
	NoNewPrivileges bool          `json:"noNewPrivileges,omitempty"`
}

// User is the identity the process runs as, in the container's user
// namespace if it has one.
type User struct {
	UID            uint32   `json:"uid"`
	GID            uint32   `json:"gid"`
	Umask          *uint32  `json:"umask,omitempty"`
	AdditionalGids []uint32 `json:"additionalGids,omitempty"`
}

// Capabilities lists capability names (e.g. "CAP_CHOWN") per set.
type Capabilities struct {
	Bounding    []string `json:"bounding,omitempty"`
	Effective   []string `json:"effective,omitempty"`
	Inheritable []string `json:"inheritable,omitempty"`
	Permitted   []string `json:"permitted,omitempty"`
	Ambient     []string `json:"ambient,omitempty"`
}

// Rlimit is a POSIX resource limit applied with setrlimit(2).
type Rlimit struct {
	Type string `json:"type"`
	Hard uint64 `json:"hard"`
	Soft uint64 `json:"soft"`
}

// Root is the container's root filesystem.
type Root struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly,omitempty"`
}

// Mount is an additional mount inside the container.
type Mount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type,omitempty"`
	Source      string   `json:"source,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// Linux holds the Linux-specific configuration.
type Linux struct {
	Namespaces        []Namespace `json:"namespaces,omitempty"`
	UIDMappings       []IDMapping `json:"uidMappings,omitempty"`
	GIDMappings       []IDMapping `json:"gidMappings,omitempty"`
	Resources         *Resources  `json:"resources,omitempty"`
	CgroupsPath       string      `json:"cgroupsPath,omitempty"`
	Seccomp           *Seccomp    `json:"seccomp,omitempty"`
	MaskedPaths       []string    `json:"maskedPaths,omitempty"`
	ReadonlyPaths     []string    `json:"readonlyPaths,omitempty"`
	RootfsPropagation string      `json:"rootfsPropagation,omitempty"`
}

// NamespaceType is one of the namespace kinds in config-linux.md.
type NamespaceType string

// Namespace kinds minirun can create.
const (
	PIDNamespace     NamespaceType = "pid"
	NetworkNamespace NamespaceType = "network"
	MountNamespace   NamespaceType = "mount"
	IPCNamespace     NamespaceType = "ipc"
	UTSNamespace     NamespaceType = "uts"
	UserNamespace    NamespaceType = "user"
	CgroupNamespace  NamespaceType = "cgroup"
	TimeNamespace    NamespaceType = "time"
)

// Namespace requests a new namespace (Path empty) or joining one (Path set;
// unsupported by minirun).
type Namespace struct {
	Type NamespaceType `json:"type"`
	Path string        `json:"path,omitempty"`
}

// IDMapping maps a contiguous range of container IDs to host IDs.
type IDMapping struct {
	ContainerID uint32 `json:"containerID"`
	HostID      uint32 `json:"hostID"`
	Size        uint32 `json:"size"`
}

// Resources are cgroup limits. Field semantics follow config-linux.md
// (which is phrased in cgroup v1 terms); the cgroups package converts them
// to cgroup v2 interface files.
type Resources struct {
	Memory  *Memory           `json:"memory,omitempty"`
	CPU     *CPU              `json:"cpu,omitempty"`
	Pids    *Pids             `json:"pids,omitempty"`
	Unified map[string]string `json:"unified,omitempty"`
}

// Memory limits, in bytes. Swap is memory+swap, as in the OCI spec; -1 means
// unlimited.
type Memory struct {
	Limit       *int64 `json:"limit,omitempty"`
	Reservation *int64 `json:"reservation,omitempty"`
	Swap        *int64 `json:"swap,omitempty"`
}

// CPU limits. Shares uses the cgroup v1 2..262144 scale.
type CPU struct {
	Shares *uint64 `json:"shares,omitempty"`
	Quota  *int64  `json:"quota,omitempty"`
	Period *uint64 `json:"period,omitempty"`
	Cpus   string  `json:"cpus,omitempty"`
	Mems   string  `json:"mems,omitempty"`
}

// Pids limits the number of tasks (processes and threads). Limit <= 0 means
// unlimited.
type Pids struct {
	Limit int64 `json:"limit"`
}

// Seccomp is the linux.seccomp object.
type Seccomp struct {
	DefaultAction   string    `json:"defaultAction"`
	DefaultErrnoRet *uint     `json:"defaultErrnoRet,omitempty"`
	Architectures   []string  `json:"architectures,omitempty"`
	Flags           []string  `json:"flags,omitempty"`
	Syscalls        []Syscall `json:"syscalls,omitempty"`
}

// Syscall is one rule of a seccomp profile.
type Syscall struct {
	Names    []string `json:"names"`
	Action   string   `json:"action"`
	ErrnoRet *uint    `json:"errnoRet,omitempty"`
	Args     []Arg    `json:"args,omitempty"`
}

// Arg is a condition on one 64-bit syscall argument.
type Arg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo,omitempty"`
	Op       string `json:"op"`
}

// HasNamespace reports whether the spec requests a namespace of type t.
func (s *Spec) HasNamespace(t NamespaceType) bool {
	if s.Linux == nil {
		return false
	}
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == t {
			return true
		}
	}
	return false
}
