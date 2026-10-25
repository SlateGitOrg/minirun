// Package mounts turns OCI mount entries into mount(2) operations and
// resolves paths inside a container root without letting symlinks escape it.
// Everything here is pure computation; the sandbox package performs the
// mounts on Linux.
package mounts

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/SlateGitOrg/minirun/internal/spec"
)

// mount(2) flags (include/uapi/linux/mount.h). Defined here rather than
// taken from x/sys/unix so plans can be built and tested on any OS.
const (
	MSRdonly      uint64 = 1
	MSNosuid      uint64 = 2
	MSNodev       uint64 = 4
	MSNoexec      uint64 = 8
	MSSynchronous uint64 = 16
	MSRemount     uint64 = 32
	MSMandlock    uint64 = 64
	MSDirsync     uint64 = 128
	MSNosymfollow uint64 = 256
	MSNoatime     uint64 = 1024
	MSNodiratime  uint64 = 2048
	MSBind        uint64 = 4096
	MSRec         uint64 = 16384
	MSUnbindable  uint64 = 1 << 17
	MSPrivate     uint64 = 1 << 18
	MSSlave       uint64 = 1 << 19
	MSShared      uint64 = 1 << 20
	MSRelatime    uint64 = 1 << 21
	MSStrictatime uint64 = 1 << 24
	MSLazytime    uint64 = 1 << 25
)

type flagOp struct {
	clear bool
	flag  uint64
}

// flagOptions are the options that map to mount flags; the rest are passed
// to the filesystem as data.
var flagOptions = map[string]flagOp{
	"defaults":      {false, 0},
	"ro":            {false, MSRdonly},
	"rw":            {true, MSRdonly},
	"suid":          {true, MSNosuid},
	"nosuid":        {false, MSNosuid},
	"dev":           {true, MSNodev},
	"nodev":         {false, MSNodev},
	"exec":          {true, MSNoexec},
	"noexec":        {false, MSNoexec},
	"sync":          {false, MSSynchronous},
	"async":         {true, MSSynchronous},
	"dirsync":       {false, MSDirsync},
	"remount":       {false, MSRemount},
	"mand":          {false, MSMandlock},
	"nomand":        {true, MSMandlock},
	"atime":         {true, MSNoatime},
	"noatime":       {false, MSNoatime},
	"diratime":      {true, MSNodiratime},
	"nodiratime":    {false, MSNodiratime},
	"bind":          {false, MSBind},
	"rbind":         {false, MSBind | MSRec},
	"relatime":      {false, MSRelatime},
	"norelatime":    {true, MSRelatime},
	"strictatime":   {false, MSStrictatime},
	"nostrictatime": {true, MSStrictatime},
	"lazytime":      {false, MSLazytime},
	"nolazytime":    {true, MSLazytime},
	"symfollow":     {true, MSNosymfollow},
	"nosymfollow":   {false, MSNosymfollow},
}

// propagationOptions map to a separate mount(2) call that changes the
// propagation type of an existing mount.
var propagationOptions = map[string]uint64{
	"private":     MSPrivate,
	"rprivate":    MSPrivate | MSRec,
	"shared":      MSShared,
	"rshared":     MSShared | MSRec,
	"slave":       MSSlave,
	"rslave":      MSSlave | MSRec,
	"unbindable":  MSUnbindable,
	"runbindable": MSUnbindable | MSRec,
}

// PropagationFlags returns the flags for a rootfsPropagation value; the
// empty string means "rprivate".
func PropagationFlags(mode string) (uint64, error) {
	if mode == "" {
		mode = "rprivate"
	}
	f, ok := propagationOptions[mode]
	if !ok {
		return 0, fmt.Errorf("unknown propagation mode %q", mode)
	}
	return f, nil
}

// Op is one fully resolved mount.
type Op struct {
	// Destination is the absolute path inside the container.
	Destination string `json:"destination"`
	Source      string `json:"source"`
	FSType      string `json:"fstype,omitempty"`
	// Flags are passed to the initial mount(2) call.
	Flags uint64 `json:"flags"`
	// Data is the comma-separated filesystem-specific option string.
	Data string `json:"data,omitempty"`
	// Propagation flags, each applied with its own mount(2) call.
	Propagation []uint64 `json:"propagation,omitempty"`
	// RemountFlags is non-zero for bind mounts whose flags (ro, nosuid, ...)
	// need a second MS_BIND|MS_REMOUNT call, since the kernel ignores them
	// on the initial bind.
	RemountFlags uint64 `json:"remountFlags,omitempty"`
}

// IsBind reports whether the op is a bind mount.
func (o Op) IsBind() bool { return o.Flags&MSBind != 0 }

// ParseOptions splits OCI mount options into mount flags, propagation flags
// and filesystem data.
func ParseOptions(opts []string) (flags uint64, propagation []uint64, data string) {
	var dataOpts []string
	for _, o := range opts {
		if f, ok := flagOptions[o]; ok {
			if f.clear {
				flags &^= f.flag
			} else {
				flags |= f.flag
			}
			continue
		}
		if p, ok := propagationOptions[o]; ok {
			propagation = append(propagation, p)
			continue
		}
		dataOpts = append(dataOpts, o)
	}
	return flags, propagation, strings.Join(dataOpts, ",")
}

// remountable are the flags a bind remount can change.
const remountable = MSRdonly | MSNosuid | MSNodev | MSNoexec | MSNoatime | MSNodiratime | MSRelatime | MSStrictatime | MSNosymfollow

// supportedTypes are filesystem types minirun knows how to mount inside a
// container. Others are rejected rather than handed to the kernel blindly.
var supportedTypes = map[string]bool{
	"proc": true, "sysfs": true, "tmpfs": true, "devpts": true, "mqueue": true,
	"cgroup2": true, "bind": true, "none": true, "": true,
}

// FromSpec converts the config's mounts into ordered operations. Mounts are
// performed in config order, as the OCI spec requires (later mounts may
// stack on earlier ones).
func FromSpec(ms []spec.Mount) ([]Op, error) {
	ops := make([]Op, 0, len(ms))
	for i, m := range ms {
		flags, prop, data := ParseOptions(m.Options)
		typ := m.Type
		if typ == "bind" || typ == "none" {
			typ = ""
			flags |= MSBind
		}
		if !supportedTypes[typ] {
			return nil, fmt.Errorf("mounts[%d] %s: filesystem type %q is not supported", i, m.Destination, m.Type)
		}
		if flags&MSRemount != 0 {
			return nil, fmt.Errorf("mounts[%d] %s: the remount option is not allowed in config mounts", i, m.Destination)
		}
		op := Op{
			Destination: path.Clean(m.Destination),
			Source:      m.Source,
			FSType:      typ,
			Flags:       flags,
			Data:        data,
			Propagation: prop,
		}
		if op.IsBind() {
			if !path.IsAbs(m.Source) {
				return nil, fmt.Errorf("mounts[%d] %s: bind mount source %q must be an absolute host path", i, m.Destination, m.Source)
			}
			if data != "" {
				return nil, fmt.Errorf("mounts[%d] %s: bind mounts take no filesystem options (got %q)", i, m.Destination, data)
			}
			if extra := flags & remountable; extra != 0 {
				op.RemountFlags = MSBind | MSRemount | extra
				op.Flags = flags &^ remountable
			}
		} else if typ == "" {
			return nil, fmt.Errorf("mounts[%d] %s: type is required", i, m.Destination)
		}
		ops = append(ops, op)
	}
	return ops, nil
}

// OverlayData builds the option string for an overlay mount. Paths are
// rejected rather than escaped if they contain characters overlayfs treats
// as separators (',' between options, ':' between lower layers) or '\\'.
func OverlayData(lower []string, upper, work string) (string, error) {
	if len(lower) == 0 {
		return "", fmt.Errorf("overlay: at least one lower directory is required")
	}
	all := append(append([]string(nil), lower...), upper, work)
	for _, p := range all {
		if p == "" || !path.IsAbs(p) {
			return "", fmt.Errorf("overlay: %q must be an absolute path", p)
		}
		if strings.ContainsAny(p, ",:\\") {
			return "", fmt.Errorf("overlay: path %q contains ',', ':' or '\\', which overlayfs cannot take", p)
		}
	}
	return fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", strings.Join(lower, ":"), upper, work), nil
}

// FlagNames renders mount flags for logs and plans, e.g. "MS_BIND|MS_REC".
func FlagNames(f uint64) string {
	names := map[uint64]string{
		MSRdonly: "MS_RDONLY", MSNosuid: "MS_NOSUID", MSNodev: "MS_NODEV", MSNoexec: "MS_NOEXEC",
		MSSynchronous: "MS_SYNCHRONOUS", MSRemount: "MS_REMOUNT", MSMandlock: "MS_MANDLOCK",
		MSDirsync: "MS_DIRSYNC", MSNosymfollow: "MS_NOSYMFOLLOW", MSNoatime: "MS_NOATIME",
		MSNodiratime: "MS_NODIRATIME", MSBind: "MS_BIND", MSRec: "MS_REC", MSUnbindable: "MS_UNBINDABLE",
		MSPrivate: "MS_PRIVATE", MSSlave: "MS_SLAVE", MSShared: "MS_SHARED", MSRelatime: "MS_RELATIME",
		MSStrictatime: "MS_STRICTATIME", MSLazytime: "MS_LAZYTIME",
	}
	var parts []string
	var bits []uint64
	for b := range names {
		bits = append(bits, b)
	}
	sort.Slice(bits, func(i, j int) bool { return bits[i] < bits[j] })
	rest := f
	for _, b := range bits {
		if f&b != 0 {
			parts = append(parts, names[b])
			rest &^= b
		}
	}
	if rest != 0 {
		parts = append(parts, fmt.Sprintf("%#x", rest))
	}
	if len(parts) == 0 {
		return "0"
	}
	return strings.Join(parts, "|")
}
