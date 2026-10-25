// Package launch turns a loaded bundle into a Plan: a fully validated,
// serialisable description of everything the container's init process must
// do (namespaces, ID maps, mounts, cgroup writes, capabilities, rlimits, the
// compiled seccomp program, the process to exec). Building a plan is where
// all semantic validation happens; executing it (package sandbox) makes no
// decisions of its own.
//
// Plans are pure data, so `minirun plan` can show exactly what a launch
// would do on any OS, and the parent passes the plan to the child as JSON.
package launch

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/SlateGitOrg/minirun/internal/caps"
	"github.com/SlateGitOrg/minirun/internal/cgroups"
	"github.com/SlateGitOrg/minirun/internal/mounts"
	"github.com/SlateGitOrg/minirun/internal/seccomp"
	"github.com/SlateGitOrg/minirun/internal/spec"
)

// Linux clone(2) namespace flags.
const (
	CloneNewNS     uint64 = 0x00020000
	CloneNewCgroup uint64 = 0x02000000
	CloneNewUTS    uint64 = 0x04000000
	CloneNewIPC    uint64 = 0x08000000
	CloneNewUser   uint64 = 0x10000000
	CloneNewPID    uint64 = 0x20000000
	CloneNewNet    uint64 = 0x40000000
)

var nsFlags = map[spec.NamespaceType]uint64{
	spec.MountNamespace:   CloneNewNS,
	spec.CgroupNamespace:  CloneNewCgroup,
	spec.UTSNamespace:     CloneNewUTS,
	spec.IPCNamespace:     CloneNewIPC,
	spec.UserNamespace:    CloneNewUser,
	spec.PIDNamespace:     CloneNewPID,
	spec.NetworkNamespace: CloneNewNet,
}

// procNSNames maps namespace types to their /proc/<pid>/ns entry, in the
// order `exec` joins them.
var procNSNames = []struct {
	Type spec.NamespaceType
	Name string
}{
	{spec.IPCNamespace, "ipc"},
	{spec.UTSNamespace, "uts"},
	{spec.NetworkNamespace, "net"},
	{spec.PIDNamespace, "pid"},
	{spec.CgroupNamespace, "cgroup"},
	{spec.MountNamespace, "mnt"},
}

// Devices bind-mounted from the host into the container's /dev when it is
// a fresh tmpfs. Bind mounts work inside user namespaces, where mknod does
// not.
var Devices = []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty"}

// DevSymlinks are created in the container's /dev.
var DevSymlinks = [][2]string{
	{"/proc/self/fd", "/dev/fd"},
	{"/proc/self/fd/0", "/dev/stdin"},
	{"/proc/self/fd/1", "/dev/stdout"},
	{"/proc/self/fd/2", "/dev/stderr"},
	{"pts/ptmx", "/dev/ptmx"},
}

// Rlimit is a resolved resource limit.
type Rlimit struct {
	Name     string `json:"name"`
	Resource int    `json:"resource"`
	Soft     uint64 `json:"soft"`
	Hard     uint64 `json:"hard"`
}

// Process is what the init (or exec) process becomes.
type Process struct {
	Args           []string  `json:"args"`
	Env            []string  `json:"env"`
	Cwd            string    `json:"cwd"`
	UID            uint32    `json:"uid"`
	GID            uint32    `json:"gid"`
	AdditionalGids []uint32  `json:"additionalGids,omitempty"`
	Umask          *uint32   `json:"umask,omitempty"`
	Rlimits        []Rlimit  `json:"rlimits,omitempty"`
	NoNewPrivs     bool      `json:"noNewPrivileges"`
	Caps           caps.Sets `json:"capabilities"`
}

// Seccomp is a compiled filter plus what is needed to explain it.
type Seccomp struct {
	Arch          string                `json:"arch"`
	DefaultAction string                `json:"defaultAction"`
	Rules         int                   `json:"rules"`
	Flags         uint                  `json:"flags"`
	Ranges        int                   `json:"ranges"`
	Skipped       []string              `json:"skipped,omitempty"`
	Instructions  []seccomp.Instruction `json:"instructions"`
	profile       *seccomp.Profile      // kept for local evaluation, not serialised
	arch          *seccomp.Arch         // likewise
}

// Program returns the filter as a seccomp.Program for installation.
func (s *Seccomp) Program() (*seccomp.Program, error) {
	a, err := seccomp.LookupArch(s.Arch)
	if err != nil {
		return nil, err
	}
	return &seccomp.Program{Arch: a, Instructions: s.Instructions, Flags: s.Flags}, nil
}

// Evaluate reports the verdict for a syscall using the reference evaluator
// (only available on plans built in this process).
func (s *Seccomp) Evaluate(d seccomp.Data) (seccomp.Action, bool) {
	if s.profile == nil || s.arch == nil {
		return 0, false
	}
	return seccomp.Evaluate(s.profile, s.arch, d), true
}

// ArchInfo returns the architecture the filter was compiled for, if this
// plan was built in-process.
func (s *Seccomp) ArchInfo() *seccomp.Arch { return s.arch }

// Cgroup describes the container's cgroup.
type Cgroup struct {
	Root        string            `json:"root"`
	Path        string            `json:"path"`
	Controllers []string          `json:"controllers"`
	Settings    []cgroups.Setting `json:"settings"`
}

// Plan is the complete launch description.
type Plan struct {
	ID       string `json:"id"`
	Bundle   string `json:"bundle"`
	StateDir string `json:"stateDir"`

	// Root filesystem: Lower (the bundle rootfs) is overlaid with Upper and
	// Work (in the state dir) on Target, which becomes "/" via pivot_root.
	Lower        string `json:"lower"`
	Upper        string `json:"upper"`
	Work         string `json:"work"`
	Target       string `json:"target"`
	OverlayData  string `json:"overlayData"`
	ReadonlyRoot bool   `json:"readonlyRoot"`
	Propagation  uint64 `json:"propagation"`

	// CloneFlags are passed to clone(2). They never include
	// CLONE_NEWCGROUP: see CgroupNS.
	CloneFlags uint64 `json:"cloneFlags"`
	// CgroupNS requests a cgroup namespace. Init creates it with
	// unshare(2) only after the parent has moved it into the container's
	// cgroup, so the namespace is rooted at that cgroup rather than at
	// minirun's own.
	CgroupNS    bool             `json:"cgroupNamespace,omitempty"`
	Namespaces  []string         `json:"namespaces"`
	UIDMappings []spec.IDMapping `json:"uidMappings,omitempty"`
	GIDMappings []spec.IDMapping `json:"gidMappings,omitempty"`
	Hostname    string           `json:"hostname,omitempty"`
	Domainname  string           `json:"domainname,omitempty"`
	// Loopback is true when a new network namespace is created; init then
	// brings up lo.
	Loopback bool `json:"loopback"`

	Mounts        []mounts.Op `json:"mounts"`
	BindDevices   bool        `json:"bindDevices"`
	MaskedPaths   []string    `json:"maskedPaths,omitempty"`
	ReadonlyPaths []string    `json:"readonlyPaths,omitempty"`

	Process Process  `json:"process"`
	Seccomp *Seccomp `json:"seccomp,omitempty"`
	Cgroup  Cgroup   `json:"cgroup"`

	Annotations map[string]string `json:"annotations,omitempty"`
	// Warnings are non-fatal findings (ignored config keys, syscalls unknown
	// to the architecture).
	Warnings []string `json:"warnings,omitempty"`
}

// Options parameterise Build.
type Options struct {
	ID         string
	StateDir   string        // the container's state directory
	CgroupRoot string        // cgroup v2 mount, normally /sys/fs/cgroup
	Arch       *seccomp.Arch // architecture to compile seccomp for; nil = native
}

// Build validates a bundle and produces its launch plan. All problems found
// are reported together.
func Build(b *spec.Bundle, o Options) (*Plan, error) {
	s := b.Spec
	if err := spec.Validate(s); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	p := &Plan{
		ID:           o.ID,
		Bundle:       b.Dir,
		StateDir:     o.StateDir,
		Lower:        b.RootfsPath(),
		Upper:        filepath.Join(o.StateDir, "upper"),
		Work:         filepath.Join(o.StateDir, "work"),
		Target:       filepath.Join(o.StateDir, "rootfs"),
		ReadonlyRoot: s.Root.Readonly,
		Hostname:     s.Hostname,
		Domainname:   s.Domainname,
		Annotations:  s.Annotations,
	}
	for _, k := range b.Unsupported {
		p.Warnings = append(p.Warnings, "ignored unsupported config key "+k)
	}
	var errs []error
	add := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	data, err := mounts.OverlayData([]string{p.Lower}, p.Upper, p.Work)
	add(err)
	p.OverlayData = data
	p.Propagation, err = mounts.PropagationFlags(s.Linux.RootfsPropagation)
	add(err)

	for _, ns := range s.Linux.Namespaces {
		if ns.Type == spec.CgroupNamespace {
			p.CgroupNS = true
		} else {
			p.CloneFlags |= nsFlags[ns.Type]
		}
		p.Namespaces = append(p.Namespaces, string(ns.Type))
	}
	sort.Strings(p.Namespaces)
	p.UIDMappings = s.Linux.UIDMappings
	p.GIDMappings = s.Linux.GIDMappings
	p.Loopback = p.CloneFlags&CloneNewNet != 0

	p.Mounts, err = mounts.FromSpec(s.Mounts)
	add(err)
	for _, m := range p.Mounts {
		if m.Destination == "/dev" && m.FSType == "tmpfs" {
			p.BindDevices = true
		}
	}
	p.MaskedPaths = s.Linux.MaskedPaths
	p.ReadonlyPaths = s.Linux.ReadonlyPaths

	proc, err := buildProcess(s.Process)
	add(err)
	p.Process = proc
	if p.CloneFlags&CloneNewUser != 0 && len(proc.AdditionalGids) > 0 {
		add(errors.New("process.user.additionalGids: supplementary groups cannot be set in a user namespace (setgroups is denied)"))
	}

	if s.Linux.Seccomp != nil {
		sc, warn, err := buildSeccomp(s.Linux.Seccomp, o.Arch)
		add(err)
		p.Seccomp = sc
		p.Warnings = append(p.Warnings, warn...)
	} else {
		p.Warnings = append(p.Warnings, "no linux.seccomp profile: every syscall is allowed")
	}

	cg, err := buildCgroup(s, o)
	add(err)
	p.Cgroup = cg

	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return p, nil
}

func buildProcess(sp *spec.Process) (Process, error) {
	p := Process{
		Args:           sp.Args,
		Env:            sp.Env,
		Cwd:            sp.Cwd,
		UID:            sp.User.UID,
		GID:            sp.User.GID,
		AdditionalGids: sp.User.AdditionalGids,
		Umask:          sp.User.Umask,
		NoNewPrivs:     sp.NoNewPrivileges,
	}
	for _, rl := range sp.Rlimits {
		res, _ := spec.RlimitResource(rl.Type) // validated by spec.Validate
		p.Rlimits = append(p.Rlimits, Rlimit{Name: rl.Type, Resource: res, Soft: rl.Soft, Hard: rl.Hard})
	}
	sets, err := caps.FromSpec(sp.Capabilities)
	if err != nil {
		return p, err
	}
	p.Caps = sets
	return p, nil
}

func buildSeccomp(s *spec.Seccomp, arch *seccomp.Arch) (*Seccomp, []string, error) {
	if arch == nil {
		native, err := seccomp.NativeArch()
		if err != nil {
			return nil, nil, fmt.Errorf("linux.seccomp: %w", err)
		}
		arch = native
	}
	prof, err := seccomp.FromSpec(s)
	if err != nil {
		return nil, nil, fmt.Errorf("linux.seccomp: %w", err)
	}
	prog, err := seccomp.Compile(prof, arch)
	if err != nil {
		return nil, nil, fmt.Errorf("linux.seccomp: %w", err)
	}
	var warn []string
	if len(prog.Skipped) > 0 {
		warn = append(warn, fmt.Sprintf("seccomp: %d syscall names do not exist on %s and were skipped: %s",
			len(prog.Skipped), arch.Name, strings.Join(prog.Skipped, " ")))
	}
	return &Seccomp{
		Arch:          arch.Name,
		DefaultAction: prof.DefaultAction.String(),
		Rules:         len(prof.Rules),
		Flags:         prog.Flags,
		Ranges:        prog.Ranges,
		Skipped:       prog.Skipped,
		Instructions:  prog.Instructions,
		profile:       prof,
		arch:          arch,
	}, warn, nil
}

// DefaultCgroupParent is where containers' cgroups go when the config does
// not set linux.cgroupsPath.
const DefaultCgroupParent = "minirun"

func buildCgroup(s *spec.Spec, o Options) (Cgroup, error) {
	rel := s.Linux.CgroupsPath
	if rel == "" {
		rel = path.Join(DefaultCgroupParent, o.ID)
	}
	settings, err := cgroups.Settings(s.Linux.Resources)
	if err != nil {
		return Cgroup{}, err
	}
	return Cgroup{
		Root:        o.CgroupRoot,
		Path:        strings.Trim(rel, "/"),
		Controllers: cgroups.Controllers(settings),
		Settings:    settings,
	}, nil
}

// ProcNamespaces returns the /proc/<pid>/ns entries a process must join to
// enter the container (excluding the user namespace, see exec), in join
// order.
func (p *Plan) ProcNamespaces() []string {
	var out []string
	for _, ns := range procNSNames {
		if p.CloneFlags&nsFlags[ns.Type] != 0 || (ns.Type == spec.CgroupNamespace && p.CgroupNS) {
			out = append(out, ns.Name)
		}
	}
	return out
}

// HasUserNS reports whether the container has its own user namespace.
func (p *Plan) HasUserNS() bool { return p.CloneFlags&CloneNewUser != 0 }
