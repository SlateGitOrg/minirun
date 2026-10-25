package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/SlateGitOrg/minirun/internal/cgroups/fakecg"
	"github.com/SlateGitOrg/minirun/internal/launch"
	"github.com/SlateGitOrg/minirun/internal/runtime"
	"github.com/SlateGitOrg/minirun/internal/spec"
	"github.com/SlateGitOrg/minirun/internal/state"
)

// stubLauncher "runs" containers instantly: the init exits with exitCode.
type stubLauncher struct {
	proc     string
	cgroup   string
	pid      int
	exitCode int
	execArgs [][]string
}

type stubChild struct {
	s     *stubLauncher
	pid   int
	procs string // the cgroup.procs file of the container
}

func (c *stubChild) Pid() int     { return c.pid }
func (c *stubChild) Start() error { return nil }
func (c *stubChild) Abort()       {}
func (c *stubChild) Wait() (int, error) {
	// Like the kernel, drop the reaped process from its cgroup.
	data, _ := os.ReadFile(c.procs)
	var keep []string
	for _, f := range strings.Fields(string(data)) {
		if f != strconv.Itoa(c.pid) {
			keep = append(keep, f+"\n")
		}
	}
	_ = os.WriteFile(c.procs, []byte(strings.Join(keep, "")), 0o644)
	return c.s.exitCode, nil
}

func (s *stubLauncher) spawn() int {
	s.pid++
	dir := filepath.Join(s.proc, strconv.Itoa(s.pid))
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(filepath.Join(dir, "stat"), []byte(strconv.Itoa(s.pid)+" (x) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 77 0 0"), 0o644)
	return s.pid
}

func (s *stubLauncher) Check() error { return nil }

func (s *stubLauncher) child(plan *launch.Plan) *stubChild {
	return &stubChild{s: s, pid: s.spawn(), procs: filepath.Join(s.cgroup, plan.Cgroup.Path, "cgroup.procs")}
}

func (s *stubLauncher) StartInit(_ context.Context, plan *launch.Plan, _ runtime.Stdio, _ func(int) error) (runtime.Child, error) {
	return s.child(plan), nil
}

func (s *stubLauncher) StartExec(_ context.Context, plan *launch.Plan, _ int, p launch.Process, _ runtime.Stdio) (runtime.Child, error) {
	s.execArgs = append(s.execArgs, p.Args)
	return s.child(plan), nil
}

type env struct {
	app      *App
	out, err *bytes.Buffer
	dir      string
	launcher *stubLauncher
	signals  []int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	cg, err := fakecg.New(filepath.Join(dir, "cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{out: &bytes.Buffer{}, err: &bytes.Buffer{}, dir: dir}
	e.launcher = &stubLauncher{proc: filepath.Join(dir, "proc"), cgroup: cg.Root, pid: 4000}
	e.app = &App{
		Stdin:  strings.NewReader(""),
		Stdout: e.out,
		Stderr: e.err,
		NewRuntime: func(g Globals, log *slog.Logger) *runtime.Runtime {
			return &runtime.Runtime{
				Store:      &state.Store{Root: g.Root},
				CgroupFS:   cg,
				CgroupRoot: cg.Root,
				Proc:       state.ProcFS{Root: e.launcher.proc},
				Launcher:   e.launcher,
				Signal: func(_, sig int) error {
					e.signals = append(e.signals, sig)
					return nil
				},
				Log: log,
			}
		},
		ForwardSignals: func() (<-chan int, func()) { return make(chan int), func() {} },
	}
	return e
}

func (e *env) run(args ...string) int {
	e.out.Reset()
	e.err.Reset()
	full := append([]string{"--root", filepath.Join(e.dir, "run"), "--cgroup-root", filepath.Join(e.dir, "cgroup")}, args...)
	return e.app.Run(context.Background(), full)
}

func (e *env) bundle(t *testing.T, flags ...string) string {
	t.Helper()
	b := filepath.Join(e.dir, "bundle-"+strconv.Itoa(len(flags))+"-"+strings.Join(flags, ""))
	b = strings.NewReplacer("/", "_", " ", "_").Replace(b[len(e.dir):])
	b = filepath.Join(e.dir, b)
	if err := os.MkdirAll(b, 0o755); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"spec", "-o", filepath.Join(b, "config.json")}, flags...)
	if code := e.run(args...); code != 0 {
		t.Fatalf("spec failed: %s", e.err.String())
	}
	return b
}

func TestSpecValidatePlan(t *testing.T) {
	e := newEnv(t)
	b := e.bundle(t, "--memory", "32M", "--pids", "16", "--cpus", "0.5", "--hostname", "demo", "--", "/bin/echo", "hi")
	if code := e.run("validate", "--bundle", b); code != 0 || !strings.Contains(e.out.String(), "valid (6 mounts, 5 namespaces, 4 cgroup settings)") {
		t.Fatalf("validate: %d %s %s", code, e.out, e.err)
	}
	if code := e.run("plan", "--bundle", b, "--arch", "x86_64", "--simulate-cgroups", filepath.Join(e.dir, "sim")); code != 0 {
		t.Fatalf("plan: %s", e.err)
	}
	for _, want := range []string{"[1] namespaces", "write memory.max       = 33554432", "exec /bin/echo hi", `echo "+cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control`, `echo "50000 100000" > /sys/fs/cgroup/minirun/demo/cpu.max`} {
		if !strings.Contains(e.out.String(), want) {
			t.Errorf("plan output lacks %q:\n%s", want, e.out)
		}
	}
	if code := e.run("plan", "--bundle", b, "--json", "--arch", "aarch64", "--id", "j"); code != 0 {
		t.Fatalf("plan --json: %s", e.err)
	}
	var p launch.Plan
	if err := json.Unmarshal(e.out.Bytes(), &p); err != nil || p.ID != "j" || p.Seccomp.Arch != "SCMP_ARCH_AARCH64" {
		t.Errorf("plan json: %v %+v", err, p.ID)
	}
	// Refuses to overwrite without --force.
	if code := e.run("spec", "-o", filepath.Join(b, "config.json")); code != 1 {
		t.Errorf("overwrite without --force: %d", code)
	}
	if code := e.run("spec", "-o", filepath.Join(b, "config.json"), "--force", "--userns", "--readonly", "--no-seccomp"); code != 0 {
		t.Errorf("--force: %s", e.err)
	}
	if code := e.run("spec", "-o", "-"); code != 0 || !strings.Contains(e.out.String(), `"ociVersion": "1.2.0"`) {
		t.Errorf("spec to stdout: %d", code)
	}
}

func TestSpecUsageErrors(t *testing.T) {
	e := newEnv(t)
	for _, args := range [][]string{
		{"spec", "-o", "-", "--memory", "lots"},
		{"spec", "-o", "-", "--cpus", "0"},
		{"spec", "-o", "-", "--host-id", "4294967295"},
		{"spec", "-o", "-", "--no-seccomp", "--deny-syscall", "mkdir"},
		{"spec", "-o", "-", "--deny-syscall", "mkdir:0"},
		{"spec", "-o", "-", "--deny-syscall", ":5"},
		{"spec", "--bogus"},
	} {
		if code := e.run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2 (%s)", args, code, e.err)
		}
	}
	if code := e.run("spec", "-o", filepath.Join(e.dir, "missing", "config.json")); code != 1 {
		t.Errorf("unwritable output: %d", code)
	}
}

func TestDenySyscall(t *testing.T) {
	e := newEnv(t)
	b := e.bundle(t, "--deny-syscall", "mkdirat:38", "--deny-syscall", "unlinkat")
	if code := e.run("seccomp", "--bundle", b, "--arch", "aarch64", "--check", "mkdirat", "--check", "unlinkat", "--check", "openat"); code != 0 {
		t.Fatalf("seccomp: %s", e.err)
	}
	out := e.out.String()
	for _, want := range []string{"mkdirat", "SCMP_ACT_ERRNO(38)", "SCMP_ACT_ERRNO(1)", "SCMP_ACT_ALLOW", "agrees with reference"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestSeccompCommand(t *testing.T) {
	e := newEnv(t)
	raw := filepath.Join(e.dir, "filter.bpf")
	if code := e.run("seccomp", "--default", "--arch", "x86_64", "--disasm", "--cost", "-o", raw, "--check", "clone:0x10000011", "--check", "socket:40", "--check", "personality:0"); code != 0 {
		t.Fatalf("seccomp: %s", e.err)
	}
	out := e.out.String()
	for _, want := range []string{"SCMP_ARCH_X86_64:", "0000: ld   [4]", "clone:0x10000011", "SCMP_ACT_ERRNO(1)", "cost over 385 syscalls"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if info, err := os.Stat(raw); err != nil || info.Size()%8 != 0 || info.Size() == 0 {
		t.Errorf("raw program: %v", err)
	}
	cases := [][]string{
		{"seccomp", "--default", "--check", "nosuchcall"},
		{"seccomp", "--default", "--check", "read:x"},
		{"seccomp", "--default", "--check", "read:1,2,3,4,5,6,7"},
		{"seccomp", "--default", "--arch", "sparc"},
		{"seccomp", "--bundle", e.dir},
	}
	for _, args := range cases {
		if code := e.run(args...); code != 1 {
			t.Errorf("%v: exit %d (%s)", args, code, e.err)
		}
	}
	b := e.bundle(t, "--no-seccomp")
	if code := e.run("seccomp", "--bundle", b); code != 1 || !strings.Contains(e.err.String(), "no linux.seccomp") {
		t.Errorf("no profile: %d %s", code, e.err)
	}
}

func TestValidateReportsWarningsAndErrors(t *testing.T) {
	e := newEnv(t)
	b := filepath.Join(e.dir, "runc")
	if err := os.MkdirAll(b, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../spec/testdata/runc-style.json")
	if err != nil {
		t.Fatal(err)
	}
	// runc-style ambient capabilities are not inheritable: minirun rejects them.
	if err := os.WriteFile(filepath.Join(b, "config.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := e.run("validate", "--bundle", b); code != 1 || !strings.Contains(e.err.String(), "ambient") {
		t.Errorf("runc config: %d %s", code, e.err)
	}
	s, _, err := spec.Parse(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	s.Process.Capabilities.Ambient = nil
	fixed, _ := spec.Marshal(s)
	// Re-add an unsupported key so the warning path is exercised.
	fixed = bytes.Replace(fixed, []byte(`"ociVersion"`), []byte(`"vm": {}, "ociVersion"`), 1)
	if err := os.WriteFile(filepath.Join(b, "config.json"), fixed, 0o644); err != nil {
		t.Fatal(err)
	}
	if code := e.run("validate", "--bundle", b); code != 0 || !strings.Contains(e.out.String(), "warning: ignored unsupported config key vm") {
		t.Errorf("warnings: %d %s %s", code, e.out, e.err)
	}
	if code := e.run("validate", "--bundle", b, "extra"); code != 2 {
		t.Errorf("extra arg: %d", code)
	}
	if code := e.run("validate", "--bundle", filepath.Join(e.dir, "none")); code != 1 {
		t.Errorf("missing bundle: %d", code)
	}
}

func TestLifecycleCommands(t *testing.T) {
	e := newEnv(t)
	b := e.bundle(t)
	if code := e.run("run", "--bundle", b, "-d", "c1"); code != 0 || strings.TrimSpace(e.out.String()) != "c1" {
		t.Fatalf("run -d: %d %s %s", code, e.out, e.err)
	}
	if code := e.run("ps"); code != 0 || !strings.Contains(e.out.String(), "c1") || !strings.Contains(e.out.String(), "running") {
		t.Errorf("ps: %s", e.out)
	}
	if code := e.run("ps", "--json"); code != 0 || !strings.Contains(e.out.String(), `"status": "running"`) {
		t.Errorf("ps --json: %s", e.out)
	}
	if code := e.run("ps", "c1"); code != 0 || strings.TrimSpace(e.out.String()) != "4001" {
		t.Errorf("ps c1: %q", e.out)
	}
	if code := e.run("ps", "--json", "c1"); code != 0 || !strings.Contains(e.out.String(), "4001") {
		t.Errorf("ps --json c1: %q", e.out)
	}
	if code := e.run("state", "c1"); code != 0 || !strings.Contains(e.out.String(), `"pid": 4001`) {
		t.Errorf("state: %s", e.out)
	}
	if code := e.run("stats", "c1"); code != 0 || !strings.Contains(e.out.String(), "memoryCurrent") {
		t.Errorf("stats: %s", e.out)
	}
	if code := e.run("exec", "--env", "A=1", "--user", "1000", "c1", "sh", "-c", "echo hi"); code != 0 {
		t.Errorf("exec: %s", e.err)
	}
	if got := strings.Join(e.launcher.execArgs[0], " "); got != "sh -c echo hi" {
		t.Errorf("exec args = %q", got)
	}
	if code := e.run("exec", "c1", "--", "ls", "-l"); code != 0 || strings.Join(e.launcher.execArgs[1], " ") != "ls -l" {
		t.Errorf("exec with --: %v", e.launcher.execArgs)
	}
	if code := e.run("kill", "c1", "USR1"); code != 0 {
		t.Errorf("kill: %s", e.err)
	}
	if code := e.run("kill", "--all", "c1"); code != 0 {
		t.Errorf("kill --all: %s", e.err)
	}
	if len(e.signals) != 2 || e.signals[0] != 10 || e.signals[1] != 15 {
		t.Errorf("signals = %v", e.signals)
	}
	if code := e.run("delete", "c1"); code != 1 || !strings.Contains(e.err.String(), "running") {
		t.Errorf("delete running: %d %s", code, e.err)
	}
	// Simulate the container exiting, then delete it.
	_ = os.RemoveAll(filepath.Join(e.launcher.proc, "4001"))
	_ = os.WriteFile(filepath.Join(e.dir, "cgroup", "minirun", "c1", "cgroup.procs"), nil, 0o644)
	if code := e.run("delete", "c1"); code != 0 {
		t.Errorf("delete: %s", e.err)
	}
	if code := e.run("state", "c1"); code != 1 {
		t.Errorf("state after delete: %d", code)
	}
}

func TestForegroundExitCodes(t *testing.T) {
	e := newEnv(t)
	b := e.bundle(t)
	e.launcher.exitCode = 3
	if code := e.run("run", "--bundle", b, "--rm", "fg"); code != 3 {
		t.Errorf("exit code = %d (%s)", code, e.err)
	}
	e.launcher.exitCode = 0
	if code := e.run("run", "--bundle", b, "--rm", "fg2"); code != 0 {
		t.Errorf("exit code = %d (%s)", code, e.err)
	}
	if code := e.run("ps"); code != 0 || strings.Count(e.out.String(), "\n") != 1 {
		t.Errorf("ps after --rm: %q", e.out)
	}
	if code := e.run("run", "--bundle", b, "keep"); code != 0 {
		t.Fatal(e.err)
	}
	if code := e.run("ps"); code != 0 || !strings.Contains(e.out.String(), "stopped") || !strings.Contains(e.out.String(), "0") {
		t.Errorf("ps stopped: %q", e.out)
	}
	if code := e.run("exec", "keep", "true"); code != 1 || !strings.Contains(e.err.String(), "not running") {
		t.Errorf("exec stopped: %d %s", code, e.err)
	}
}

func TestUsageErrors(t *testing.T) {
	e := newEnv(t)
	cases := [][]string{
		{},
		{"frobnicate"},
		{"run"},
		{"run", "-d", "--rm", "x"},
		{"exec", "c1"},
		{"exec", "--env", "NOEQ", "c1", "true"},
		{"exec", "--user", "bob", "c1", "true"},
		{"exec", "--user", "1:bob", "c1", "true"},
		{"ps", "a", "b"},
		{"state"},
		{"stats", "a", "b"},
		{"kill"},
		{"kill", "c1", "SIGWHAT"},
		{"delete"},
		{"version", "x"},
		{"plan", "extra"},
		{"seccomp", "extra"},
		{"--log-level", "loud", "version"},
		{"--log-format", "xml", "version"},
		{"--no-such-global"},
	}
	for _, args := range cases {
		if code := e.run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2 (stderr %s)", args, code, e.err)
		}
	}
	if code := e.run("version"); code != 0 || !strings.HasPrefix(e.out.String(), "minirun ") {
		t.Errorf("version: %d %s", code, e.out)
	}
	if code := e.run("--help"); code != 0 {
		t.Errorf("--help: %d", code)
	}
	if code := e.run("run", "--help"); code != 0 {
		t.Errorf("run --help: %d", code)
	}
	if code := e.run("--log-format", "json", "--log-level", "debug", "plan", "--bundle", e.dir); code != 1 {
		t.Errorf("plan on missing config: %d", code)
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		args      []string
		stopAfter int
		want      string
		all       bool
	}{
		{[]string{"c1", "--all"}, 0, "c1", true},
		{[]string{"--all", "c1", "TERM"}, 0, "c1 TERM", true},
		{[]string{"c1", "--", "--all"}, 0, "c1 --all", false},
		{[]string{"--", "-x"}, 0, "-x", false},
		{[]string{"c1", "sh", "-c", "x"}, 1, "c1 sh -c x", false},
		{[]string{"--all", "c1", "--", "sh"}, 1, "c1 sh", true},
	}
	for _, c := range cases {
		fs := (&App{Stderr: &bytes.Buffer{}}).newFlags("t", "")
		all := fs.Bool("all", false, "")
		got, err := parse(fs, c.args, c.stopAfter)
		if err != nil || strings.Join(got, " ") != c.want || *all != c.all {
			t.Errorf("parse(%v) = %v %v all=%v", c.args, got, err, *all)
		}
	}
}

func TestParseSizeAndCPUs(t *testing.T) {
	sizes := map[string]int64{"512": 512, "64k": 64 << 10, "32M": 32 << 20, "1G": 1 << 30, "16MiB": 16 << 20, "2mb": 2 << 20}
	for in, want := range sizes {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0", "-1", "abc", "99999999999G"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
	if q, err := ParseCPUs("1.5"); err != nil || q != 150000 {
		t.Errorf("ParseCPUs = %d %v", q, err)
	}
	if _, err := ParseCPUs("x"); err == nil {
		t.Error("ParseCPUs accepted x")
	}
}

func TestDefaultsWireRealComponents(t *testing.T) {
	a := New()
	if a.Stdout != os.Stdout || a.NewRuntime == nil || a.ForwardSignals == nil {
		t.Fatal("New() not wired")
	}
	rt := a.NewRuntime(Globals{Root: t.TempDir(), CgroupRoot: "/sys/fs/cgroup", ProcRoot: "/proc"}, slog.Default())
	if rt.Store == nil || rt.Launcher == nil || rt.Signal == nil {
		t.Error("runtime not wired")
	}
	ch, stop := a.ForwardSignals()
	if ch == nil {
		t.Error("nil channel")
	}
	stop()
}
