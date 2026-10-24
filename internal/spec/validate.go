package spec

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// rlimitResources maps OCI rlimit type names to Linux resource numbers
// (include/uapi/asm-generic/resource.h). They are the same on amd64 and
// arm64.
var rlimitResources = map[string]int{
	"RLIMIT_CPU":        0,
	"RLIMIT_FSIZE":      1,
	"RLIMIT_DATA":       2,
	"RLIMIT_STACK":      3,
	"RLIMIT_CORE":       4,
	"RLIMIT_RSS":        5,
	"RLIMIT_NPROC":      6,
	"RLIMIT_NOFILE":     7,
	"RLIMIT_MEMLOCK":    8,
	"RLIMIT_AS":         9,
	"RLIMIT_LOCKS":      10,
	"RLIMIT_SIGPENDING": 11,
	"RLIMIT_MSGQUEUE":   12,
	"RLIMIT_NICE":       13,
	"RLIMIT_RTPRIO":     14,
	"RLIMIT_RTTIME":     15,
}

// RlimitResource returns the Linux resource number for an OCI rlimit type.
func RlimitResource(name string) (int, bool) {
	r, ok := rlimitResources[name]
	return r, ok
}

// supportedNamespaces are the namespace kinds minirun can create.
var supportedNamespaces = map[NamespaceType]bool{
	PIDNamespace:     true,
	NetworkNamespace: true,
	MountNamespace:   true,
	IPCNamespace:     true,
	UTSNamespace:     true,
	UserNamespace:    true,
	CgroupNamespace:  true,
}

var hostnameRE = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// Validate checks the structural rules of the subset minirun runs. It
// reports every problem it finds, joined into one error, so a user can fix a
// config in one pass. Semantic checks that need other packages (capability
// names, seccomp syscalls, cgroup values) happen when a launch plan is built.
func Validate(s *Spec) error {
	v := &validator{}
	v.check(s)
	return errors.Join(v.errs...)
}

type validator struct {
	errs []error
}

func (v *validator) addf(format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf(format, args...))
}

func (v *validator) check(s *Spec) {
	if s == nil {
		v.addf("config is empty")
		return
	}
	if !strings.HasPrefix(s.OCIVersion, "1.") {
		v.addf("ociVersion %q: only 1.x configs are supported", s.OCIVersion)
	}
	v.checkRoot(s.Root)
	v.checkProcess(s.Process)
	v.checkMounts(s.Mounts)
	if s.Linux == nil {
		v.addf("linux: section is required")
		return
	}
	v.checkLinux(s)
	if s.Hostname != "" {
		if !s.HasNamespace(UTSNamespace) {
			v.addf("hostname: setting a hostname requires a uts namespace")
		}
		if !hostnameRE.MatchString(s.Hostname) || len(s.Hostname) > 64 {
			v.addf("hostname %q: not a valid RFC 1123 host name of at most 64 bytes", s.Hostname)
		}
	}
	if s.Domainname != "" && !s.HasNamespace(UTSNamespace) {
		v.addf("domainname: setting a domain name requires a uts namespace")
	}
}

func (v *validator) checkRoot(r *Root) {
	if r == nil || r.Path == "" {
		v.addf("root.path: is required")
	}
}

func (v *validator) checkProcess(p *Process) {
	if p == nil {
		v.addf("process: is required")
		return
	}
	if p.Terminal {
		v.addf("process.terminal: pseudo-terminals are not supported; set it to false")
	}
	if len(p.Args) == 0 || p.Args[0] == "" {
		v.addf("process.args: at least one non-empty argument is required")
	}
	if !path.IsAbs(p.Cwd) {
		v.addf("process.cwd %q: must be an absolute path", p.Cwd)
	}
	for i, e := range p.Env {
		if k, _, ok := strings.Cut(e, "="); !ok || k == "" {
			v.addf("process.env[%d] %q: must have the form KEY=value", i, e)
		}
	}
	if p.User.Umask != nil && *p.User.Umask > 0o777 {
		v.addf("process.user.umask %#o: must be at most 0777", *p.User.Umask)
	}
	seen := map[string]bool{}
	for i, rl := range p.Rlimits {
		if _, ok := rlimitResources[rl.Type]; !ok {
			v.addf("process.rlimits[%d].type %q: unknown resource", i, rl.Type)
		}
		if rl.Soft > rl.Hard {
			v.addf("process.rlimits[%d] %s: soft limit %d exceeds hard limit %d", i, rl.Type, rl.Soft, rl.Hard)
		}
		if seen[rl.Type] {
			v.addf("process.rlimits[%d] %s: duplicate entry", i, rl.Type)
		}
		seen[rl.Type] = true
	}
}

func (v *validator) checkMounts(mounts []Mount) {
	for i, m := range mounts {
		if !path.IsAbs(m.Destination) {
			v.addf("mounts[%d].destination %q: must be an absolute path", i, m.Destination)
		}
		if path.Clean(m.Destination) == "/" {
			v.addf("mounts[%d].destination: mounting over / is not allowed; use root.path", i)
		}
		if m.Type == "" && !hasBindOption(m.Options) {
			v.addf("mounts[%d] %s: type is required unless options contain bind or rbind", i, m.Destination)
		}
	}
}

func hasBindOption(opts []string) bool {
	for _, o := range opts {
		if o == "bind" || o == "rbind" {
			return true
		}
	}
	return false
}

func (v *validator) checkLinux(s *Spec) {
	l := s.Linux
	seen := map[NamespaceType]bool{}
	for i, ns := range l.Namespaces {
		if !supportedNamespaces[ns.Type] {
			v.addf("linux.namespaces[%d].type %q: unsupported namespace type", i, ns.Type)
		}
		if ns.Path != "" {
			v.addf("linux.namespaces[%d] %s: joining an existing namespace by path is not supported", i, ns.Type)
		}
		if seen[ns.Type] {
			v.addf("linux.namespaces[%d] %s: duplicate namespace", i, ns.Type)
		}
		seen[ns.Type] = true
	}
	if !seen[MountNamespace] {
		v.addf("linux.namespaces: a mount namespace is required (minirun pivots into the rootfs)")
	}
	hasUser := seen[UserNamespace]
	if hasUser && (len(l.UIDMappings) == 0 || len(l.GIDMappings) == 0) {
		v.addf("linux: a user namespace requires both uidMappings and gidMappings")
	}
	if !hasUser && (len(l.UIDMappings) > 0 || len(l.GIDMappings) > 0) {
		v.addf("linux: uidMappings/gidMappings require a user namespace")
	}
	v.checkMappings("uidMappings", l.UIDMappings)
	v.checkMappings("gidMappings", l.GIDMappings)
	if s.Process != nil && hasUser {
		if !mapped(l.UIDMappings, s.Process.User.UID) {
			v.addf("process.user.uid %d: not covered by linux.uidMappings", s.Process.User.UID)
		}
		if !mapped(l.GIDMappings, s.Process.User.GID) {
			v.addf("process.user.gid %d: not covered by linux.gidMappings", s.Process.User.GID)
		}
	}
	if l.CgroupsPath != "" {
		if err := CheckCgroupsPath(l.CgroupsPath); err != nil {
			v.addf("linux.cgroupsPath: %v", err)
		}
	}
	for i, p := range l.MaskedPaths {
		if !path.IsAbs(p) {
			v.addf("linux.maskedPaths[%d] %q: must be an absolute path", i, p)
		}
	}
	for i, p := range l.ReadonlyPaths {
		if !path.IsAbs(p) {
			v.addf("linux.readonlyPaths[%d] %q: must be an absolute path", i, p)
		}
	}
	switch l.RootfsPropagation {
	case "", "private", "rprivate", "slave", "rslave", "shared", "rshared", "unbindable", "runbindable":
	default:
		v.addf("linux.rootfsPropagation %q: unknown propagation mode", l.RootfsPropagation)
	}
}

func (v *validator) checkMappings(field string, maps []IDMapping) {
	type span struct{ lo, hi uint64 }
	var container, host []span
	for i, m := range maps {
		if m.Size == 0 {
			v.addf("linux.%s[%d]: size must be positive", field, i)
			continue
		}
		container = append(container, span{uint64(m.ContainerID), uint64(m.ContainerID) + uint64(m.Size)})
		host = append(host, span{uint64(m.HostID), uint64(m.HostID) + uint64(m.Size)})
	}
	if len(maps) > 340 {
		v.addf("linux.%s: at most 340 ranges are allowed by the kernel", field)
	}
	for _, spans := range [][]span{container, host} {
		sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
		for i := 1; i < len(spans); i++ {
			if spans[i].lo < spans[i-1].hi {
				v.addf("linux.%s: ranges overlap", field)
				break
			}
		}
	}
}

func mapped(maps []IDMapping, id uint32) bool {
	for _, m := range maps {
		if uint64(id) >= uint64(m.ContainerID) && uint64(id) < uint64(m.ContainerID)+uint64(m.Size) {
			return true
		}
	}
	return false
}

// MapToHost translates a container ID to a host ID using maps. It returns
// false if the ID is not mapped.
func MapToHost(maps []IDMapping, id uint32) (uint32, bool) {
	for _, m := range maps {
		if uint64(id) >= uint64(m.ContainerID) && uint64(id) < uint64(m.ContainerID)+uint64(m.Size) {
			return m.HostID + (id - m.ContainerID), true
		}
	}
	return 0, false
}

// CheckCgroupsPath validates a cgroup path relative to the cgroup v2 mount.
// Absolute paths are accepted and interpreted relative to the mount, as runc
// does; ".." components are rejected so a config cannot escape the
// hierarchy it was given.
func CheckCgroupsPath(p string) error {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return errors.New("must name a cgroup below the root")
	}
	for seg := range strings.SplitSeq(trimmed, "/") {
		switch seg {
		case "", ".", "..":
			return fmt.Errorf("%q: empty, '.' and '..' components are not allowed", p)
		}
	}
	return nil
}
