package runtime_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/archit2501/minirun/internal/cgroups/fakecg"
	"github.com/archit2501/minirun/internal/launch"
	"github.com/archit2501/minirun/internal/runtime"
	"github.com/archit2501/minirun/internal/spec"
	"github.com/archit2501/minirun/internal/state"
)

// fakeLauncher stands in for the Linux launcher: it "starts" processes by
// writing /proc/<pid>/stat entries into a fake procfs and records calls.
type fakeLauncher struct {
	mu        sync.Mutex
	procRoot  string
	cg        *fakecg.FS
	nextPid   int
	exitCode  int
	oom       bool
	startErr  error
	execErr   error
	initErr   error
	execs     []launch.Process
	waitBlock chan struct{}
}

type fakeChild struct {
	l        *fakeLauncher
	pid      int
	cgroup   string
	startErr error
	aborted  bool
}

func (c *fakeChild) Pid() int     { return c.pid }
func (c *fakeChild) Start() error { return c.startErr }
func (c *fakeChild) Abort()       { c.aborted = true; c.gone() }
func (c *fakeChild) Wait() (int, error) {
	if c.l.waitBlock != nil {
		<-c.l.waitBlock
	}
	if c.l.oom && c.cgroup != "" {
		_ = c.l.cg.SetCounter(filepath.Join(c.l.cg.Root, c.cgroup, "memory.events"), "oom 1\noom_kill 1\n")
	}
	c.gone()
	return c.l.exitCode, nil
}

// gone removes the process from the fake procfs and from its cgroup, as the
// kernel does once a process has been reaped.
func (c *fakeChild) gone() {
	c.l.exit(c.pid)
	if c.cgroup == "" {
		return
	}
	procs := filepath.Join(c.l.cg.Root, c.cgroup, "cgroup.procs")
	data, err := os.ReadFile(procs)
	if err != nil {
		return
	}
	var keep []string
	for _, f := range strings.Fields(string(data)) {
		if f != strconv.Itoa(c.pid) {
			keep = append(keep, f+"\n")
		}
	}
	_ = c.l.cg.SetCounter(procs, strings.Join(keep, ""))
}

func (l *fakeLauncher) Check() error { return nil }

func (l *fakeLauncher) spawn() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextPid++
	pid := l.nextPid
	dir := filepath.Join(l.procRoot, strconv.Itoa(pid))
	_ = os.MkdirAll(dir, 0o755)
	stat := strconv.Itoa(pid) + " (minirun-init) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 " + strconv.Itoa(1000+pid) + " 0 0"
	_ = os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644)
	return pid
}

func (l *fakeLauncher) exit(pid int) {
	_ = os.RemoveAll(filepath.Join(l.procRoot, strconv.Itoa(pid)))
}

func (l *fakeLauncher) StartInit(_ context.Context, plan *launch.Plan, stdio runtime.Stdio, join func(int) error) (runtime.Child, error) {
	if l.initErr != nil {
		return nil, l.initErr
	}
	pid := l.spawn()
	if plan.CgroupNS {
		if err := join(pid); err != nil {
			return nil, err
		}
	}
	if stdio.Out != nil {
		_, _ = stdio.Out.Write([]byte("init output\n"))
	}
	return &fakeChild{l: l, pid: pid, cgroup: plan.Cgroup.Path, startErr: l.startErr}, nil
}

func (l *fakeLauncher) StartExec(_ context.Context, plan *launch.Plan, _ int, proc launch.Process, _ runtime.Stdio) (runtime.Child, error) {
	if l.execErr != nil {
		return nil, l.execErr
	}
	l.mu.Lock()
	l.execs = append(l.execs, proc)
	l.mu.Unlock()
	return &fakeChild{l: l, pid: l.spawn(), cgroup: plan.Cgroup.Path, startErr: l.startErr}, nil
}

type harness struct {
	rt      *runtime.Runtime
	l       *fakeLauncher
	cg      *fakecg.FS
	bundle  string
	signals [][2]int
	chowns  []string
	mu      sync.Mutex
}

func newHarness(t *testing.T, o spec.DefaultOptions) *harness {
	t.Helper()
	dir := t.TempDir()
	cg, err := fakecg.New(filepath.Join(dir, "cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle")
	writeBundle(t, bundle, spec.Default(o))
	h := &harness{cg: cg, bundle: bundle}
	h.l = &fakeLauncher{procRoot: filepath.Join(dir, "proc"), cg: cg, nextPid: 100}
	h.rt = &runtime.Runtime{
		Store:      &state.Store{Root: filepath.Join(dir, "run")},
		CgroupFS:   cg,
		CgroupRoot: cg.Root,
		Proc:       state.ProcFS{Root: h.l.procRoot},
		Launcher:   h.l,
		Signal: func(pid, sig int) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.signals = append(h.signals, [2]int{pid, sig})
			return nil
		},
		Chown: func(path string, uid, gid int) error {
			h.chowns = append(h.chowns, filepath.Base(path)+":"+strconv.Itoa(uid)+":"+strconv.Itoa(gid))
			return nil
		},
		Now:   func() time.Time { return time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC) },
		Sleep: func(time.Duration) {},
	}
	return h
}

func writeBundle(t *testing.T, dir string, s *spec.Spec) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := spec.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, spec.ConfigName), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) cgFile(t *testing.T, id, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.cg.Root, "minirun", id, name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func TestForegroundRunRecordsExit(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{MemoryLimit: 16 << 20, PidsLimit: 8})
	h.l.exitCode = 137
	h.l.oom = true
	var out bytes.Buffer
	code, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "c1", Bundle: h.bundle, Stdio: runtime.Stdio{Out: &out}})
	if err != nil || code != 137 {
		t.Fatalf("Run = %d, %v", code, err)
	}
	if out.String() != "init output\n" {
		t.Errorf("stdout = %q", out.String())
	}
	st, err := h.rt.State("c1")
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != state.Stopped || *st.ExitCode != 137 || !st.OOMKilled || st.Pid != 101 || st.PidStartTime != 1101 {
		t.Errorf("state = %+v", st)
	}
	if got := h.cgFile(t, "c1", "memory.max"); got != "16777216" {
		t.Errorf("memory.max = %s", got)
	}
	if got := h.cgFile(t, "c1", "pids.max"); got != "8" {
		t.Errorf("pids.max = %s", got)
	}
	for _, d := range []string{"upper", "work", "rootfs", "plan.json", "state.json"} {
		if _, err := os.Stat(filepath.Join(h.rt.Store.Dir("c1"), d)); err != nil {
			t.Errorf("%s: %v", d, err)
		}
	}
	// The init pid joined the cgroup before it was started.
	var procsWrite bool
	for _, w := range h.cg.Writes() {
		if strings.HasSuffix(w.Path, "c1/cgroup.procs") && w.Data == "101" {
			procsWrite = true
		}
	}
	if !procsWrite {
		t.Error("init pid was never written to cgroup.procs")
	}
	if err := h.rt.Delete("c1", false); err != nil {
		t.Fatalf("Delete stopped container: %v", err)
	}
	if _, err := h.rt.State("c1"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("state after delete: %v", err)
	}
}

func TestCgroupNamespaceJoinsEarly(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{CgroupNS: true})
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "cns", Bundle: h.bundle}); err != nil {
		t.Fatal(err)
	}
	joins := 0
	for _, w := range h.cg.Writes() {
		if strings.HasSuffix(w.Path, "cns/cgroup.procs") {
			joins++
		}
	}
	if joins != 2 {
		t.Errorf("cgroup.procs written %d times, want 2 (early join for the namespace, then before exec)", joins)
	}
}

func TestRunRemove(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{PidsLimit: 4})
	code, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "tmp", Bundle: h.bundle, Remove: true})
	if err != nil || code != 0 {
		t.Fatalf("Run = %d, %v", code, err)
	}
	if list, _ := h.rt.List(); len(list) != 0 {
		t.Errorf("container not removed: %v", list)
	}
	if _, err := os.Stat(filepath.Join(h.cg.Root, "minirun", "tmp")); !os.IsNotExist(err) {
		t.Errorf("cgroup not removed: %v", err)
	}
}

func TestDetachedLifecycle(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{})
	code, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "web", Bundle: h.bundle, Detach: true})
	if err != nil || code != 0 {
		t.Fatalf("Run = %d, %v", code, err)
	}
	console, err := os.ReadFile(filepath.Join(h.rt.Store.Dir("web"), "console.log"))
	if err != nil || string(console) != "init output\n" {
		t.Errorf("console.log = %q, %v", console, err)
	}
	list, err := h.rt.List()
	if err != nil || len(list) != 1 || list[0].Status != state.Running || !list[0].Detached {
		t.Fatalf("List = %+v, %v", list, err)
	}
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "web", Bundle: h.bundle, Detach: true}); !errors.Is(err, state.ErrExists) {
		t.Errorf("duplicate run: %v", err)
	}
	pids, err := h.rt.Processes("web")
	if err != nil || !slices.Equal(pids, []int{101}) {
		t.Errorf("Processes = %v, %v", pids, err)
	}
	if _, err := h.rt.Stats("web"); err != nil {
		t.Errorf("Stats: %v", err)
	}

	// exec
	code, err = h.rt.Exec(context.Background(), runtime.ExecOptions{
		ID: "web", Args: []string{"env"}, Env: []string{"TERM=dumb", "EXTRA=1"}, Cwd: "/tmp", User: &[2]uint32{1000, 1001},
	})
	if err != nil || code != 0 {
		t.Fatalf("Exec = %d, %v", code, err)
	}
	p := h.l.execs[0]
	if p.Cwd != "/tmp" || p.UID != 1000 || p.GID != 1001 || p.Args[0] != "env" {
		t.Errorf("exec process = %+v", p)
	}
	if !slices.Contains(p.Env, "TERM=dumb") || !slices.Contains(p.Env, "EXTRA=1") || slices.Contains(p.Env, "TERM=xterm") {
		t.Errorf("exec env = %v", p.Env)
	}
	if p.Caps.Effective.Hex() != "00000000a80425fb" {
		t.Errorf("exec caps = %s", p.Caps.Effective.Hex())
	}
	if _, err := h.rt.Exec(context.Background(), runtime.ExecOptions{ID: "web"}); err == nil {
		t.Error("exec without a command accepted")
	}

	// kill
	if err := h.rt.Kill("web", 15, false); err != nil {
		t.Fatal(err)
	}
	if err := h.cg.AddProc(filepath.Join(h.cg.Root, "minirun", "web"), 555); err != nil {
		t.Fatal(err)
	}
	if err := h.rt.Kill("web", 10, true); err != nil {
		t.Fatal(err)
	}
	want := [][2]int{{101, 15}, {101, 10}, {555, 10}}
	if !slices.Equal(h.signals, want) {
		t.Errorf("signals = %v, want %v", h.signals, want)
	}

	// delete
	if err := h.rt.Delete("web", false); !errors.Is(err, runtime.ErrRunning) {
		t.Errorf("delete running: %v", err)
	}
	if err := h.rt.Delete("web", true); err != nil {
		t.Fatalf("force delete: %v", err)
	}
	if _, err := os.Stat(h.rt.Store.Dir("web")); !os.IsNotExist(err) {
		t.Errorf("state dir remains: %v", err)
	}
}

func TestStoppedContainerRefusesKillAndExec(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{})
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "done", Bundle: h.bundle}); err != nil {
		t.Fatal(err)
	}
	if err := h.rt.Kill("done", 9, false); !errors.Is(err, runtime.ErrNotRunning) {
		t.Errorf("kill: %v", err)
	}
	if _, err := h.rt.Exec(context.Background(), runtime.ExecOptions{ID: "done", Args: []string{"true"}}); !errors.Is(err, runtime.ErrNotRunning) {
		t.Errorf("exec: %v", err)
	}
	if err := h.rt.Kill("ghost", 9, false); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("kill missing: %v", err)
	}
	if err := h.rt.Delete("ghost", false); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("delete missing: %v", err)
	}
	if _, err := h.rt.Stats("ghost"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("stats missing: %v", err)
	}
	if _, err := h.rt.Processes("ghost"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("processes missing: %v", err)
	}
}

func TestExecIntoUserNamespaceRefused(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{UserNS: true, HostIDBase: 200000})
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "u", Bundle: h.bundle, Detach: true}); err != nil {
		t.Fatal(err)
	}
	if len(h.chowns) != 3 || h.chowns[0] != "upper:200000:200000" {
		t.Errorf("chowns = %v", h.chowns)
	}
	if _, err := h.rt.Exec(context.Background(), runtime.ExecOptions{ID: "u", Args: []string{"true"}}); !errors.Is(err, runtime.ErrExecUserNS) {
		t.Errorf("exec: %v", err)
	}
}

func TestFailedStartCleansUp(t *testing.T) {
	cases := map[string]func(l *fakeLauncher){
		"init error":  func(l *fakeLauncher) { l.initErr = errors.New("clone failed") },
		"start error": func(l *fakeLauncher) { l.startErr = errors.New("exec failed") },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, spec.DefaultOptions{PidsLimit: 3})
			setup(h.l)
			if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "bad", Bundle: h.bundle}); err == nil {
				t.Fatal("expected error")
			}
			if _, err := os.Stat(h.rt.Store.Dir("bad")); !os.IsNotExist(err) {
				t.Errorf("state dir left behind: %v", err)
			}
			if _, err := os.Stat(filepath.Join(h.cg.Root, "minirun", "bad")); !os.IsNotExist(err) {
				t.Errorf("cgroup left behind: %v", err)
			}
		})
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{})
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "../x", Bundle: h.bundle}); err == nil {
		t.Error("bad id accepted")
	}
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "x", Bundle: t.TempDir()}); err == nil {
		t.Error("missing config accepted")
	}
	bad := spec.Default(spec.DefaultOptions{})
	bad.Process.Cwd = "relative"
	dir := t.TempDir()
	writeBundle(t, dir, bad)
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "x", Bundle: dir}); err == nil || !strings.Contains(err.Error(), "process.cwd") {
		t.Errorf("invalid config: %v", err)
	}
	// A cgroup that cannot be created fails the run and leaves no state.
	limited := spec.Default(spec.DefaultOptions{})
	limited.Linux.Resources = &spec.Resources{Unified: map[string]string{"rdma.max": "mlx4_0 hca_handle=2"}}
	dir = t.TempDir()
	writeBundle(t, dir, limited)
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "rdma", Bundle: dir}); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Errorf("unavailable controller: %v", err)
	}
	if _, err := os.Stat(h.rt.Store.Dir("rdma")); !os.IsNotExist(err) {
		t.Errorf("state left behind: %v", err)
	}
	// A cgroup that already exists belongs to someone else: the run fails
	// and must leave it alone.
	if err := h.cg.Mkdir(filepath.Join(h.cg.Root, "minirun")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(h.cg.Root, "minirun", "taken")
	if err := h.cg.Mkdir(other); err != nil {
		t.Fatal(err)
	}
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "taken", Bundle: h.bundle}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("existing cgroup: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("pre-existing cgroup was removed: %v", err)
	}
}

func TestSignalForwarding(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{})
	h.l.waitBlock = make(chan struct{})
	fwd := make(chan int)
	done := make(chan error)
	go func() {
		_, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "fg", Bundle: h.bundle, Forward: fwd})
		done <- err
	}()
	fwd <- 2
	fwd <- 15
	// The unbuffered sends above complete only once the forwarder has
	// received them; let Wait return now.
	close(h.l.waitBlock)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for len(h.signals) < 2 {
		h.mu.Unlock()
		time.Sleep(time.Millisecond)
		h.mu.Lock()
	}
	if !slices.Equal(h.signals, [][2]int{{101, 2}, {101, 15}}) {
		t.Errorf("forwarded = %v", h.signals)
	}
}

func TestDeleteFallsBackWithoutCgroupKill(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{})
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "old", Bundle: h.bundle, Detach: true}); err != nil {
		t.Fatal(err)
	}
	cgDir := filepath.Join(h.cg.Root, "minirun", "old")
	if err := os.Remove(filepath.Join(cgDir, "cgroup.kill")); err != nil {
		t.Fatal(err)
	}
	// Processes never leave: delete must give up with a clear error.
	err := h.rt.Delete("old", true)
	if err == nil || !strings.Contains(err.Error(), "still busy") {
		t.Fatalf("Delete = %v", err)
	}
	if !slices.Contains(h.signals, [2]int{101, 9}) {
		t.Errorf("signals = %v", h.signals)
	}
	// Once the process is gone the delete succeeds.
	_ = h.cg.SetCounter(filepath.Join(cgDir, "cgroup.procs"), "")
	h.l.exit(101)
	if err := h.rt.Delete("old", false); err != nil {
		t.Fatalf("Delete after exit: %v", err)
	}
}

func TestDeleteWhenCgroupVanished(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{})
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "v", Bundle: h.bundle, Detach: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(h.cg.Root, "minirun", "v")); err != nil {
		t.Fatal(err)
	}
	if err := h.rt.Delete("v", true); err != nil {
		t.Fatalf("Delete = %v", err)
	}
	if !slices.Contains(h.signals, [2]int{101, 9}) {
		t.Errorf("init not killed directly: %v", h.signals)
	}
}

func TestExecLaunchFailures(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{})
	if _, err := h.rt.Run(context.Background(), runtime.RunOptions{ID: "e", Bundle: h.bundle, Detach: true}); err != nil {
		t.Fatal(err)
	}
	h.l.execErr = errors.New("setns failed")
	if _, err := h.rt.Exec(context.Background(), runtime.ExecOptions{ID: "e", Args: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "setns") {
		t.Errorf("exec error: %v", err)
	}
	h.l.execErr = nil
	h.l.startErr = errors.New("exec format error")
	if _, err := h.rt.Exec(context.Background(), runtime.ExecOptions{ID: "e", Args: []string{"true"}}); err == nil || !strings.Contains(err.Error(), "exec format") {
		t.Errorf("start error: %v", err)
	}
}

func TestPlan(t *testing.T) {
	h := newHarness(t, spec.DefaultOptions{})
	p, err := h.rt.Plan("p1", h.bundle)
	if err != nil {
		t.Fatal(err)
	}
	if p.StateDir != h.rt.Store.Dir("p1") || p.Cgroup.Root != h.cg.Root {
		t.Errorf("plan paths: %s %s", p.StateDir, p.Cgroup.Root)
	}
}

func TestMergeEnv(t *testing.T) {
	got := runtime.MergeEnv([]string{"A=1", "B=2"}, []string{"B=3", "C=4", "A=5"})
	if !slices.Equal(got, []string{"A=5", "B=3", "C=4"}) {
		t.Errorf("MergeEnv = %v", got)
	}
}

func TestUnsupportedLauncher(t *testing.T) {
	l := runtime.NewLauncher()
	if l == nil {
		t.Fatal("nil launcher")
	}
	if runtime.SignalFunc() == nil {
		t.Fatal("nil signal func")
	}
}
