package launch

import (
	"fmt"
	"io"
	"strings"

	"github.com/archit2501/minirun/internal/mounts"
)

// Describe writes a human-readable account of the plan, in the order the
// runtime executes it.
func (p *Plan) Describe(w io.Writer) error {
	ew := &errWriter{w: w}
	ew.printf("container %s (bundle %s)\n", p.ID, p.Bundle)
	ew.printf("\n[1] namespaces  clone flags %#x: %s\n", p.CloneFlags, strings.Join(p.Namespaces, ", "))
	for _, m := range p.UIDMappings {
		ew.printf("    uid_map  %d %d %d\n", m.ContainerID, m.HostID, m.Size)
	}
	for _, m := range p.GIDMappings {
		ew.printf("    gid_map  %d %d %d  (setgroups denied)\n", m.ContainerID, m.HostID, m.Size)
	}

	ew.printf("\n[2] cgroup %s/%s\n", p.Cgroup.Root, p.Cgroup.Path)
	if p.CgroupNS {
		ew.printf("    init joins it early, then unshares a cgroup namespace rooted there\n")
	}
	if len(p.Cgroup.Controllers) > 0 {
		ew.printf("    delegate +%s along the path\n", strings.Join(p.Cgroup.Controllers, " +"))
	}
	for _, s := range p.Cgroup.Settings {
		ew.printf("    write %-16s = %s\n", s.File, s.Value)
	}
	if len(p.Cgroup.Settings) == 0 {
		ew.printf("    (no resource limits)\n")
	}

	ew.printf("\n[3] root filesystem\n")
	ew.printf("    mount propagation of / -> %s\n", mounts.FlagNames(p.Propagation))
	ew.printf("    mount overlay on %s\n      %s\n", p.Target, p.OverlayData)
	for _, m := range p.Mounts {
		src := m.Source
		if src == "" {
			src = m.FSType
		}
		line := fmt.Sprintf("    mount %-12s on %-12s type %-7s %s", src, m.Destination, orBind(m.FSType), mounts.FlagNames(m.Flags))
		if m.Data != "" {
			line += " [" + m.Data + "]"
		}
		ew.printf("%s\n", line)
		if m.RemountFlags != 0 {
			ew.printf("      remount %s\n", mounts.FlagNames(m.RemountFlags))
		}
	}
	if p.BindDevices {
		ew.printf("    bind devices %s\n", strings.Join(Devices, " "))
	}
	ew.printf("    pivot_root into %s, detach old root\n", p.Target)
	if len(p.MaskedPaths) > 0 {
		ew.printf("    mask %s\n", strings.Join(p.MaskedPaths, " "))
	}
	if len(p.ReadonlyPaths) > 0 {
		ew.printf("    read-only %s\n", strings.Join(p.ReadonlyPaths, " "))
	}
	if p.ReadonlyRoot {
		ew.printf("    remount / read-only\n")
	}

	ew.printf("\n[4] identity\n")
	if p.Hostname != "" {
		ew.printf("    hostname %s\n", p.Hostname)
	}
	if p.Loopback {
		ew.printf("    bring up lo in the new network namespace\n")
	}
	for _, rl := range p.Process.Rlimits {
		ew.printf("    setrlimit %s soft=%d hard=%d\n", rl.Name, rl.Soft, rl.Hard)
	}

	c := p.Process.Caps
	ew.printf("\n[5] privileges  uid=%d gid=%d no_new_privs=%v\n", p.Process.UID, p.Process.GID, p.Process.NoNewPrivs)
	ew.printf("    bounding    %s  (%d caps)\n", c.Bounding.Hex(), len(c.Bounding.Names()))
	ew.printf("    effective   %s\n", c.Effective.Hex())
	ew.printf("    permitted   %s\n", c.Permitted.Hex())
	ew.printf("    inheritable %s\n", c.Inheritable.Hex())
	ew.printf("    ambient     %s\n", c.Ambient.Hex())
	if sc := p.Seccomp; sc != nil {
		ew.printf("    seccomp %s: %d rules -> %d BPF instructions over %d syscall ranges, default %s\n",
			sc.Arch, sc.Rules, len(sc.Instructions), sc.Ranges, sc.DefaultAction)
	}

	ew.printf("\n[6] exec %s (cwd %s)\n", strings.Join(p.Process.Args, " "), p.Process.Cwd)
	for _, w := range p.Warnings {
		ew.printf("\nwarning: %s\n", w)
	}
	return ew.err
}

func orBind(t string) string {
	if t == "" {
		return "bind"
	}
	return t
}

type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}
