package launch

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archit2501/minirun/internal/seccomp"
	"github.com/archit2501/minirun/internal/spec"
)

var update = os.Getenv("UPDATE_GOLDEN") == "1"

func bundle(s *spec.Spec) *spec.Bundle {
	return &spec.Bundle{Dir: "/bundles/demo", Spec: s}
}

func defaultSpec() *spec.Spec {
	return spec.Default(spec.DefaultOptions{
		Args: []string{"/bin/sh", "-c", "echo hello"}, Hostname: "demo",
		MemoryLimit: 32 << 20, PidsLimit: 16, CPUQuota: 50000, Seccomp: seccomp.DefaultProfile(),
	})
}

func opts() Options {
	return Options{ID: "demo", StateDir: "/run/minirun/demo", CgroupRoot: "/sys/fs/cgroup", Arch: seccomp.ArchX86_64}
}

func TestBuildDefault(t *testing.T) {
	p, err := Build(bundle(defaultSpec()), opts())
	if err != nil {
		t.Fatal(err)
	}
	want := CloneNewPID | CloneNewIPC | CloneNewUTS | CloneNewNS | CloneNewNet
	if p.CloneFlags != want {
		t.Errorf("CloneFlags = %#x, want %#x", p.CloneFlags, want)
	}
	if strings.Join(p.Namespaces, ",") != "ipc,mount,network,pid,uts" {
		t.Errorf("Namespaces = %v", p.Namespaces)
	}
	if !p.Loopback || !p.BindDevices || p.HasUserNS() {
		t.Errorf("flags: loopback=%v bindDevices=%v userns=%v", p.Loopback, p.BindDevices, p.HasUserNS())
	}
	if p.Lower != "/bundles/demo/rootfs" || p.Upper != "/run/minirun/demo/upper" || p.Target != "/run/minirun/demo/rootfs" {
		t.Errorf("paths: %s %s %s", p.Lower, p.Upper, p.Target)
	}
	if p.Cgroup.Path != "minirun/demo" || strings.Join(p.Cgroup.Controllers, ",") != "cpu,memory,pids" {
		t.Errorf("cgroup: %+v", p.Cgroup)
	}
	if p.Process.Caps.Effective.Hex() != "00000000a80425fb" || !p.Process.NoNewPrivs {
		t.Errorf("process: %+v", p.Process)
	}
	if p.Seccomp == nil || p.Seccomp.Arch != "SCMP_ARCH_X86_64" || len(p.Seccomp.Instructions) == 0 {
		t.Fatalf("seccomp: %+v", p.Seccomp)
	}
	if got := strings.Join(p.ProcNamespaces(), ","); got != "ipc,uts,net,pid,mnt" {
		t.Errorf("ProcNamespaces = %s", got)
	}
	if len(p.Process.Rlimits) != 1 || p.Process.Rlimits[0].Resource != 7 {
		t.Errorf("rlimits: %+v", p.Process.Rlimits)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("x86_64 warnings = %v", p.Warnings)
	}
	// The arm64 build skips the legacy x86-64-only names and says so.
	o := opts()
	o.Arch = seccomp.ArchAArch64
	arm, err := Build(bundle(defaultSpec()), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(arm.Warnings) != 1 || !strings.Contains(arm.Warnings[0], "do not exist on SCMP_ARCH_AARCH64 and were skipped: access alarm arch_prctl") {
		t.Errorf("arm64 warnings = %v", arm.Warnings)
	}
}

func TestSeccompProgramAndEvaluate(t *testing.T) {
	p, err := Build(bundle(defaultSpec()), opts())
	if err != nil {
		t.Fatal(err)
	}
	prog, err := p.Seccomp.Program()
	if err != nil || prog.Arch != seccomp.ArchX86_64 {
		t.Fatalf("Program: %v %v", prog, err)
	}
	nr, _ := seccomp.ArchX86_64.Syscall("mount")
	act, ok := p.Seccomp.Evaluate(seccomp.Data{Nr: nr, Arch: seccomp.ArchX86_64.AuditArch})
	if !ok || act != seccomp.Action(seccomp.RetErrno|1) {
		t.Errorf("Evaluate(mount) = %v %v", act, ok)
	}
	if p.Seccomp.ArchInfo() != seccomp.ArchX86_64 {
		t.Error("ArchInfo")
	}
	// After a JSON round trip (what init receives) the program survives but
	// the in-process evaluator is gone.
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back Plan
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	prog2, err := back.Seccomp.Program()
	if err != nil || len(prog2.Instructions) != len(prog.Instructions) {
		t.Fatalf("round trip: %v", err)
	}
	if _, ok := back.Seccomp.Evaluate(seccomp.Data{}); ok {
		t.Error("decoded plan should not evaluate")
	}
	back.Seccomp.Arch = "SCMP_ARCH_PPC"
	if _, err := back.Seccomp.Program(); err == nil {
		t.Error("unknown arch accepted")
	}
}

func TestBuildUserNSAndNoSeccomp(t *testing.T) {
	s := spec.Default(spec.DefaultOptions{UserNS: true, HostIDBase: 100000, HostNetwork: true})
	s.Linux.CgroupsPath = "/custom/path/"
	p, err := Build(bundle(s), Options{ID: "u", StateDir: "/s/u", CgroupRoot: "/cg"})
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasUserNS() || p.Loopback || p.Seccomp != nil {
		t.Errorf("userns=%v loopback=%v seccomp=%v", p.HasUserNS(), p.Loopback, p.Seccomp)
	}
	if p.Cgroup.Path != "custom/path" || len(p.Cgroup.Settings) != 0 {
		t.Errorf("cgroup = %+v", p.Cgroup)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "every syscall is allowed") {
		t.Errorf("warnings = %v", p.Warnings)
	}
}

func TestBuildCgroupNamespaceIsDeferred(t *testing.T) {
	s := spec.Default(spec.DefaultOptions{CgroupNS: true})
	p, err := Build(bundle(s), opts())
	if err != nil {
		t.Fatal(err)
	}
	if !p.CgroupNS || p.CloneFlags&CloneNewCgroup != 0 {
		t.Errorf("CgroupNS=%v cloneFlags=%#x", p.CgroupNS, p.CloneFlags)
	}
	if got := strings.Join(p.ProcNamespaces(), ","); got != "ipc,uts,net,pid,cgroup,mnt" {
		t.Errorf("ProcNamespaces = %s", got)
	}
	var buf bytes.Buffer
	if err := p.Describe(&buf); err != nil || !strings.Contains(buf.String(), "unshares a cgroup namespace") {
		t.Errorf("describe: %v", err)
	}
}

func TestBuildAggregatesErrors(t *testing.T) {
	s := defaultSpec()
	s.Process.Capabilities.Effective = append(s.Process.Capabilities.Effective, "CAP_SYS_ADMIN")
	s.Linux.Seccomp.DefaultAction = "SCMP_ACT_WHATEVER"
	s.Mounts = append(s.Mounts, spec.Mount{Destination: "/data", Type: "ext4", Source: "/dev/sdb"})
	bad := int64(-7)
	s.Linux.Resources.Memory.Limit = &bad
	s.Linux.Namespaces = append(s.Linux.Namespaces, spec.Namespace{Type: spec.UserNamespace})
	s.Linux.UIDMappings = []spec.IDMapping{{ContainerID: 0, HostID: 1000, Size: 10}}
	s.Linux.GIDMappings = s.Linux.UIDMappings
	s.Process.User.AdditionalGids = []uint32{5}
	s.Root.Path = "/root,with,commas"
	_, err := Build(bundle(s), opts())
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{"effective has capabilities", "defaultAction", "ext4", "memory.limit", "additionalGids", "overlay"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	s = defaultSpec()
	s.OCIVersion = "0.9"
	if _, err := Build(bundle(s), opts()); err == nil || !strings.Contains(err.Error(), "ociVersion") {
		t.Errorf("structural error not reported: %v", err)
	}
	s = defaultSpec()
	s.Linux.RootfsPropagation = "rslave"
	p, err := Build(bundle(s), opts())
	if err != nil || p.Propagation == 0 {
		t.Errorf("propagation: %v", err)
	}
}

func TestBuildUnsupportedKeysBecomeWarnings(t *testing.T) {
	b := bundle(defaultSpec())
	b.Unsupported = []string{"linux.sysctl"}
	p, err := Build(b, opts())
	if err != nil {
		t.Fatal(err)
	}
	if p.Warnings[0] != "ignored unsupported config key linux.sysctl" {
		t.Errorf("warnings = %v", p.Warnings)
	}
}

func TestBuildNativeArch(t *testing.T) {
	o := opts()
	o.Arch = nil
	p, err := Build(bundle(defaultSpec()), o)
	native, nerr := seccomp.NativeArch()
	if nerr != nil {
		if err == nil {
			t.Fatal("expected error on an architecture without a syscall table")
		}
		return
	}
	if err != nil || p.Seccomp.Arch != native.Name {
		t.Fatalf("native build: %v", err)
	}
}

func TestDescribeGolden(t *testing.T) {
	s := defaultSpec()
	s.Mounts = append(s.Mounts, spec.Mount{Destination: "/data", Source: "/srv/data", Options: []string{"rbind", "ro"}})
	s.Linux.Namespaces = append(s.Linux.Namespaces, spec.Namespace{Type: spec.UserNamespace})
	s.Linux.UIDMappings = []spec.IDMapping{{ContainerID: 0, HostID: 100000, Size: 65536}}
	s.Linux.GIDMappings = s.Linux.UIDMappings
	s.Root.Readonly = true
	p, err := Build(bundle(s), opts())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := p.Describe(&buf); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "describe.golden")
	if update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != string(want) {
		t.Errorf("Describe changed (UPDATE_GOLDEN=1 to accept):\n%s", buf.String())
	}
	// A plan without limits or hostname still describes cleanly.
	bare := spec.Default(spec.DefaultOptions{})
	bare.Hostname = ""
	p2, err := Build(bundle(bare), opts())
	if err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := p2.Describe(&buf); err != nil || !strings.Contains(buf.String(), "(no resource limits)") {
		t.Errorf("bare describe: %v\n%s", err, buf.String())
	}
	if err := p2.Describe(failWriter{}); err == nil {
		t.Error("write error not reported")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }
