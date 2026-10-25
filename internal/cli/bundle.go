package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/SlateGitOrg/minirun/internal/cgroups"
	"github.com/SlateGitOrg/minirun/internal/cgroups/fakecg"
	"github.com/SlateGitOrg/minirun/internal/launch"
	"github.com/SlateGitOrg/minirun/internal/seccomp"
	"github.com/SlateGitOrg/minirun/internal/spec"
)

func specVersion() string { return spec.Version }

// ParseSize parses a byte count with an optional binary suffix: 512, 64k,
// 32M, 1G (case-insensitive, optional trailing "b"/"ib").
func ParseSize(s string) (int64, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.TrimSuffix(strings.TrimSuffix(t, "b"), "i")
	mult := int64(1)
	if n := len(t); n > 0 {
		switch t[n-1] {
		case 'k':
			mult, t = 1<<10, t[:n-1]
		case 'm':
			mult, t = 1<<20, t[:n-1]
		case 'g':
			mult, t = 1<<30, t[:n-1]
		}
	}
	v, err := strconv.ParseInt(t, 10, 64)
	if err != nil || v <= 0 || v > (1<<62)/mult {
		return 0, fmt.Errorf("invalid size %q (examples: 512, 64k, 32M, 1G)", s)
	}
	return v * mult, nil
}

// ParseCPUs converts a CPU count like "0.5" to a CFS quota for a 100ms
// period.
func ParseCPUs(s string) (int64, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0.01 || f > 1024 {
		return 0, fmt.Errorf("invalid CPU count %q (0.01 to 1024)", s)
	}
	return int64(f * 100000), nil
}

func cmdSpec(a *App, _ context.Context, _ Globals, _ *slog.Logger, args []string) error {
	fs := a.newFlags("spec", "[flags] [-- command args...]")
	out := fs.String("o", "config.json", "output file (\"-\" for stdout)")
	rootfs := fs.String("rootfs", "rootfs", "root filesystem path, relative to the bundle")
	hostname := fs.String("hostname", "minirun", "container hostname")
	userns := fs.Bool("userns", false, "add a user namespace mapping container 0-65535 to host --host-id...")
	hostID := fs.Uint("host-id", 100000, "first host uid/gid of the user namespace mapping")
	hostNet := fs.Bool("host-network", false, "share the host network namespace")
	cgroupNS := fs.Bool("cgroupns", false, "add a cgroup namespace rooted at the container's cgroup")
	readonly := fs.Bool("readonly", false, "make the root filesystem read-only")
	memory := fs.String("memory", "", "memory limit, e.g. 64M (swap disabled)")
	pids := fs.Int64("pids", 0, "maximum number of tasks")
	cpus := fs.String("cpus", "", "CPU limit as a number of CPUs, e.g. 0.5")
	noSeccomp := fs.Bool("no-seccomp", false, "omit the default seccomp profile")
	var deny multiFlag
	fs.Var(&deny, "deny-syscall", "make NAME[:ERRNO] fail with ERRNO (default EPERM) in the default profile (repeatable)")
	force := fs.Bool("force", false, "overwrite an existing output file")
	cmdArgs, err := parse(fs, args, 0)
	if err != nil {
		return err
	}
	if *hostID > 1<<32-65536 {
		return usagef("--host-id %d leaves no room for a 65536-id mapping", *hostID)
	}
	o := spec.DefaultOptions{
		Args: cmdArgs, Rootfs: *rootfs, Hostname: *hostname, ReadOnly: *readonly,
		UserNS: *userns, HostIDBase: uint32(*hostID), HostNetwork: *hostNet, CgroupNS: *cgroupNS, PidsLimit: *pids,
	}
	if *memory != "" {
		if o.MemoryLimit, err = ParseSize(*memory); err != nil {
			return usageError{err.Error()}
		}
	}
	if *cpus != "" {
		if o.CPUQuota, err = ParseCPUs(*cpus); err != nil {
			return usageError{err.Error()}
		}
	}
	if !*noSeccomp {
		o.Seccomp = seccomp.DefaultProfile()
		for _, d := range deny {
			if err := denySyscall(o.Seccomp, d); err != nil {
				return usageError{err.Error()}
			}
		}
	} else if len(deny) > 0 {
		return usagef("--deny-syscall needs the default seccomp profile")
	}
	s := spec.Default(o)
	if err := spec.Validate(s); err != nil {
		return err
	}
	data, err := spec.Marshal(s)
	if err != nil {
		return err
	}
	if *out == "-" {
		_, err = a.Stdout.Write(data)
		return err
	}
	mode := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		mode = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(*out, mode, 0o644)
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	_, werr := f.Write(data)
	if err := errors.Join(werr, f.Close()); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	_, err = fmt.Fprintf(a.Stdout, "wrote %s\n", *out)
	return err
}

// denySyscall removes NAME from every rule of p and appends an ERRNO rule
// for it, so the result has no conflicting unconditional rules.
func denySyscall(p *spec.Seccomp, expr string) error {
	name, errnoStr, hasErrno := strings.Cut(expr, ":")
	errno := uint64(1)
	if hasErrno {
		var err error
		if errno, err = strconv.ParseUint(errnoStr, 10, 12); err != nil || errno == 0 {
			return fmt.Errorf("--deny-syscall %q: errno must be 1..4095", expr)
		}
	}
	if name == "" {
		return fmt.Errorf("--deny-syscall %q: syscall name required", expr)
	}
	kept := p.Syscalls[:0]
	for _, r := range p.Syscalls {
		r.Names = slices.DeleteFunc(slices.Clone(r.Names), func(n string) bool { return n == name })
		if len(r.Names) > 0 {
			kept = append(kept, r)
		}
	}
	e := uint(errno)
	kept = append(kept, spec.Syscall{Names: []string{name}, Action: "SCMP_ACT_ERRNO", ErrnoRet: &e})
	p.Syscalls = kept
	return nil
}

func cmdValidate(a *App, _ context.Context, g Globals, _ *slog.Logger, args []string) error {
	fs := a.newFlags("validate", "[--bundle DIR]")
	bundle := fs.String("bundle", ".", "bundle directory")
	if rest, err := parse(fs, args, 0); err != nil {
		return err
	} else if len(rest) > 0 {
		return usagef("unexpected arguments %v", rest)
	}
	b, err := spec.LoadBundle(*bundle)
	if err != nil {
		return err
	}
	plan, err := launch.Build(b, launch.Options{ID: "validate", StateDir: filepath.Join(g.Root, "validate"), CgroupRoot: g.CgroupRoot})
	if err != nil {
		return err
	}
	for _, w := range plan.Warnings {
		if _, err := fmt.Fprintf(a.Stdout, "warning: %s\n", w); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(a.Stdout, "%s: valid (%d mounts, %d namespaces, %d cgroup settings)\n",
		filepath.Join(b.Dir, spec.ConfigName), len(plan.Mounts), len(plan.Namespaces), len(plan.Cgroup.Settings))
	return err
}

// archFlag adds --arch to a flag set.
func archFlag(fs *flag.FlagSet) *string {
	return fs.String("arch", "", "architecture to compile seccomp for (x86_64 or aarch64; default: this machine's)")
}

func resolveArch(name string) (*seccomp.Arch, error) {
	if name == "" {
		return seccomp.NativeArch()
	}
	return seccomp.LookupArch(name)
}

func cmdPlan(a *App, _ context.Context, g Globals, _ *slog.Logger, args []string) error {
	fs := a.newFlags("plan", "[--bundle DIR] [--id ID] [--json] [--simulate-cgroups DIR]")
	bundle := fs.String("bundle", ".", "bundle directory")
	id := fs.String("id", "demo", "container id to plan for")
	asJSON := fs.Bool("json", false, "print the plan as JSON (the document init receives)")
	simulate := fs.String("simulate-cgroups", "", "apply the cgroup steps to a fake cgroupfs created in this directory and list the writes")
	archName := archFlag(fs)
	if rest, err := parse(fs, args, 0); err != nil {
		return err
	} else if len(rest) > 0 {
		return usagef("unexpected arguments %v", rest)
	}
	arch, err := resolveArch(*archName)
	if err != nil {
		return err
	}
	b, err := spec.LoadBundle(*bundle)
	if err != nil {
		return err
	}
	plan, err := launch.Build(b, launch.Options{ID: *id, StateDir: filepath.Join(g.Root, *id), CgroupRoot: g.CgroupRoot, Arch: arch})
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(plan)
	}
	if err := plan.Describe(a.Stdout); err != nil {
		return err
	}
	if *simulate != "" {
		return simulateCgroups(a, plan, *simulate)
	}
	return nil
}

// simulateCgroups runs the real cgroup manager against a fake cgroupfs and
// prints the resulting writes.
func simulateCgroups(a *App, plan *launch.Plan, dir string) error {
	fake, err := fakecg.New(dir)
	if err != nil {
		return err
	}
	m, err := cgroups.New(fake, fake.Root, plan.Cgroup.Path)
	if err != nil {
		return err
	}
	if err := m.Create(plan.Cgroup.Controllers); err != nil {
		return err
	}
	if err := m.Apply(plan.Cgroup.Settings); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(a.Stdout, "\nsimulated cgroupfs writes (fake hierarchy at %s):\n", fake.Root); err != nil {
		return err
	}
	for _, w := range fake.Writes() {
		rel, _ := filepath.Rel(fake.Root, w.Path)
		if _, err := fmt.Fprintf(a.Stdout, "  echo %q > /sys/fs/cgroup/%s\n", w.Data, rel); err != nil {
			return err
		}
	}
	return nil
}

func cmdSeccomp(a *App, _ context.Context, _ Globals, _ *slog.Logger, args []string) error {
	fs := a.newFlags("seccomp", "[--bundle DIR | --default] [--arch A] [--disasm] [--check name[:arg0,arg1,...]]...")
	bundle := fs.String("bundle", ".", "bundle directory")
	useDefault := fs.Bool("default", false, "use minirun's default profile instead of a bundle")
	disasm := fs.Bool("disasm", false, "print the BPF program")
	cost := fs.Bool("cost", false, "measure instructions executed per syscall (vs a linear jeq chain)")
	raw := fs.String("o", "", "write the raw sock_filter array to this file")
	archName := archFlag(fs)
	var checks multiFlag
	fs.Var(&checks, "check", "syscall to evaluate, optionally with arguments (repeatable)")
	if rest, err := parse(fs, args, 0); err != nil {
		return err
	} else if len(rest) > 0 {
		return usagef("unexpected arguments %v", rest)
	}
	arch, err := resolveArch(*archName)
	if err != nil {
		return err
	}
	profileSpec := seccomp.DefaultProfile()
	if !*useDefault {
		b, err := spec.LoadBundle(*bundle)
		if err != nil {
			return err
		}
		if b.Spec.Linux == nil || b.Spec.Linux.Seccomp == nil {
			return errors.New("the bundle has no linux.seccomp profile")
		}
		profileSpec = b.Spec.Linux.Seccomp
	}
	prof, err := seccomp.FromSpec(profileSpec)
	if err != nil {
		return err
	}
	prog, err := seccomp.Compile(prof, arch)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(a.Stdout, "%s: %d rules, %d syscall names (%d unknown on this arch), %d ranges -> %d instructions (%d bytes), default %s\n",
		arch.Name, len(prof.Rules), len(prof.SyscallNames()), len(prog.Skipped), prog.Ranges,
		len(prog.Instructions), len(prog.Bytes()), prof.DefaultAction); err != nil {
		return err
	}
	if *raw != "" {
		if err := os.WriteFile(*raw, prog.Bytes(), 0o644); err != nil {
			return fmt.Errorf("write program: %w", err)
		}
	}
	if *disasm {
		if err := seccomp.Disassemble(a.Stdout, prog); err != nil {
			return err
		}
	}
	if *cost {
		c, err := seccomp.MeasureCost(prof, prog)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(a.Stdout, "cost over %d syscalls: range tree avg %.1f / max %d instructions; linear jeq chain avg %.1f / max %d\n",
			c.Calls, c.Avg, c.Max, c.LinearAvg, c.LinearMax); err != nil {
			return err
		}
	}
	for _, c := range checks {
		if err := checkSyscall(a, prof, prog, arch, c); err != nil {
			return err
		}
	}
	return nil
}

// checkSyscall evaluates "name[:a0,a1,...]" with both the compiled program
// (in the BPF interpreter) and the reference evaluator.
func checkSyscall(a *App, prof *seccomp.Profile, prog *seccomp.Program, arch *seccomp.Arch, expr string) error {
	name, argList, _ := strings.Cut(expr, ":")
	nr, ok := arch.Syscall(name)
	if !ok {
		return fmt.Errorf("--check %s: no such syscall on %s", name, arch.Name)
	}
	d := seccomp.Data{Nr: nr, Arch: arch.AuditArch}
	if argList != "" {
		parts := strings.Split(argList, ",")
		if len(parts) > 6 {
			return fmt.Errorf("--check %s: at most 6 arguments", expr)
		}
		for i, p := range parts {
			v, err := strconv.ParseUint(p, 0, 64)
			if err != nil {
				return fmt.Errorf("--check %s: argument %d: %w", expr, i, err)
			}
			d.Args[i] = v
		}
	}
	vm, err := seccomp.Run(prog.Instructions, d)
	if err != nil {
		return err
	}
	ref := seccomp.Evaluate(prof, arch, d)
	agree := "agrees with reference"
	if seccomp.Action(vm) != ref {
		agree = "DISAGREES with reference " + ref.String()
	}
	_, err = fmt.Fprintf(a.Stdout, "  %-28s nr=%-4d -> %-24s (%s)\n", expr, nr, seccomp.Action(vm), agree)
	if err == nil && seccomp.Action(vm) != ref {
		err = fmt.Errorf("compiled filter disagrees with the reference evaluator for %s", expr)
	}
	return err
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
