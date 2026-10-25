package cgroups_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/SlateGitOrg/minirun/internal/cgroups"
	"github.com/SlateGitOrg/minirun/internal/cgroups/fakecg"
	"github.com/SlateGitOrg/minirun/internal/spec"
)

func i64(v int64) *int64   { return &v }
func u64(v uint64) *uint64 { return &v }
func newFake(t *testing.T) *fakecg.FS {
	t.Helper()
	f, err := fakecg.New(filepath.Join(t.TempDir(), "cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func TestSettingsConversion(t *testing.T) {
	r := &spec.Resources{
		Memory: &spec.Memory{Limit: i64(64 << 20), Reservation: i64(32 << 20), Swap: i64(96 << 20)},
		CPU:    &spec.CPU{Shares: u64(1024), Quota: i64(50000), Period: u64(100000), Cpus: "0-1,3", Mems: "0"},
		Pids:   &spec.Pids{Limit: 32},
		Unified: map[string]string{
			"memory.high": "50331648",
			"pids.max":    "40", // overrides the converted value
		},
	}
	got, err := cgroups.Settings(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []cgroups.Setting{
		{File: "cpu.max", Value: "50000 100000"},
		{File: "cpu.weight", Value: "39"},
		{File: "cpuset.cpus", Value: "0-1,3"},
		{File: "cpuset.mems", Value: "0"},
		{File: "memory.high", Value: "50331648"},
		{File: "memory.low", Value: "33554432"},
		{File: "memory.max", Value: "67108864"},
		{File: "memory.swap.max", Value: "33554432"},
		{File: "pids.max", Value: "40"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Settings =\n%v\nwant\n%v", got, want)
	}
	if c := cgroups.Controllers(got); !reflect.DeepEqual(c, []string{"cpu", "cpuset", "memory", "pids"}) {
		t.Errorf("Controllers = %v", c)
	}
}

func TestSettingsEdgeValues(t *testing.T) {
	cases := []struct {
		r    *spec.Resources
		want []cgroups.Setting
	}{
		{nil, nil},
		{&spec.Resources{Memory: &spec.Memory{Limit: i64(-1), Swap: i64(-1), Reservation: i64(-1)}},
			[]cgroups.Setting{{File: "memory.low", Value: "max"}, {File: "memory.max", Value: "max"}, {File: "memory.swap.max", Value: "max"}}},
		{&spec.Resources{Memory: &spec.Memory{Reservation: i64(0)}}, []cgroups.Setting{{File: "memory.low", Value: "0"}}},
		{&spec.Resources{CPU: &spec.CPU{Period: u64(50000)}}, []cgroups.Setting{{File: "cpu.max", Value: "max 50000"}}},
		{&spec.Resources{CPU: &spec.CPU{Quota: i64(-1)}}, []cgroups.Setting{{File: "cpu.max", Value: "max 100000"}}},
		{&spec.Resources{Pids: &spec.Pids{Limit: 0}}, []cgroups.Setting{{File: "pids.max", Value: "max"}}},
		{&spec.Resources{Memory: &spec.Memory{}}, []cgroups.Setting{}},
	}
	for i, c := range cases {
		got, err := cgroups.Settings(c.r)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("case %d: %v, want %v", i, got, c.want)
		}
	}
}

func TestSettingsErrors(t *testing.T) {
	cases := map[string]*spec.Resources{
		"zero limit":       {Memory: &spec.Memory{Limit: i64(0)}},
		"bad reservation":  {Memory: &spec.Memory{Reservation: i64(-5)}},
		"swap no limit":    {Memory: &spec.Memory{Swap: i64(100)}},
		"swap below limit": {Memory: &spec.Memory{Limit: i64(100), Swap: i64(50)}},
		"shares range":     {CPU: &spec.CPU{Shares: u64(1)}},
		"period range":     {CPU: &spec.CPU{Period: u64(10)}},
		"tiny quota":       {CPU: &spec.CPU{Quota: i64(10)}},
		"cpus syntax":      {CPU: &spec.CPU{Cpus: "0-a"}},
		"mems syntax":      {CPU: &spec.CPU{Mems: "x"}},
		"unified path":     {Unified: map[string]string{"../memory.max": "1"}},
		"unified dotdot":   {Unified: map[string]string{"memory..max": "1"}},
		"unified core":     {Unified: map[string]string{"cgroup.procs": "1"}},
		"unified newline":  {Unified: map[string]string{"memory.max": "1\n2"}},
	}
	for name, r := range cases {
		if _, err := cgroups.Settings(r); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestSharesToWeight(t *testing.T) {
	for shares, want := range map[uint64]uint64{0: 0, 2: 1, 1024: 39, 262144: 10000} {
		if got := cgroups.SharesToWeight(shares); got != want {
			t.Errorf("SharesToWeight(%d) = %d, want %d", shares, got, want)
		}
	}
}

func TestCreateApplyStatsDestroy(t *testing.T) {
	f := newFake(t)
	m, err := cgroups.New(f, f.Root, "minirun/c1")
	if err != nil {
		t.Fatal(err)
	}
	settings, err := cgroups.Settings(&spec.Resources{
		Memory: &spec.Memory{Limit: i64(32 << 20), Swap: i64(32 << 20)},
		Pids:   &spec.Pids{Limit: 8},
		CPU:    &spec.CPU{Quota: i64(25000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Create(cgroups.Controllers(settings)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Apply(settings); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := read(t, filepath.Join(f.Root, "cgroup.subtree_control")); got != "cpu memory pids" {
		t.Errorf("root subtree_control = %q", got)
	}
	if got := read(t, filepath.Join(f.Root, "minirun", "cgroup.subtree_control")); got != "cpu memory pids" {
		t.Errorf("minirun subtree_control = %q", got)
	}
	for file, want := range map[string]string{"memory.max": "33554432", "memory.swap.max": "0", "pids.max": "8", "cpu.max": "25000 100000"} {
		if got := read(t, filepath.Join(m.Path(), file)); got != want {
			t.Errorf("%s = %q, want %q", file, got, want)
		}
	}
	writes := f.Writes()
	if len(writes) != 6 {
		t.Errorf("writes = %v", writes)
	}

	// A second container under the same parent reuses the delegation.
	m2, _ := cgroups.New(f, f.Root, "minirun/c2")
	if err := m2.Create([]string{"memory"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(nil); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("re-create: %v", err)
	}

	if err := f.AddProc(m.Path(), 4242); err != nil {
		t.Fatal(err)
	}
	if err := f.SetCounter(filepath.Join(m.Path(), "memory.events"), "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\noom_group_kill 0\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.SetCounter(filepath.Join(m.Path(), "pids.events"), "max 2\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.SetCounter(filepath.Join(m.Path(), "memory.current"), "1048576\n"); err != nil {
		t.Fatal(err)
	}
	st, err := m.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.OOMKills != 1 || st.OOMEvents != 1 || st.PidsLimitHits != 2 || st.MemoryCurrent != 1<<20 || st.MemoryMax != "33554432" || st.PidsMax != "8" {
		t.Errorf("Stats = %+v", st)
	}
	pids, err := m.Procs()
	if err != nil || !reflect.DeepEqual(pids, []int{4242}) {
		t.Errorf("Procs = %v %v", pids, err)
	}
	if err := m.Destroy(); !errors.Is(err, syscall.EBUSY) {
		t.Errorf("Destroy with procs: %v", err)
	}
	if err := m.Kill(); err != nil {
		t.Fatal(err)
	}
	if pids, _ := m.Procs(); len(pids) != 0 {
		t.Errorf("procs after kill = %v", pids)
	}
	if err := m.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if m.Exists() {
		t.Error("cgroup still exists")
	}
	if err := m.Destroy(); err != nil {
		t.Errorf("Destroy of missing cgroup: %v", err)
	}
	if _, err := m.Procs(); !errors.Is(err, cgroups.ErrNotFound) {
		t.Errorf("Procs after destroy: %v", err)
	}
	if _, err := m.Stats(); !errors.Is(err, cgroups.ErrNotFound) {
		t.Errorf("Stats after destroy: %v", err)
	}
	if err := m.Kill(); !errors.Is(err, cgroups.ErrNotFound) {
		t.Errorf("Kill after destroy: %v", err)
	}
}

func TestCreateErrors(t *testing.T) {
	f := newFake(t)
	if _, err := cgroups.New(f, f.Root, "../x"); err == nil {
		t.Error("expected path error")
	}
	m, _ := cgroups.New(f, f.Root, "a/b")
	if err := m.Create([]string{"rdma"}); err == nil || !strings.Contains(err.Error(), "not available") {
		t.Errorf("unavailable controller: %v", err)
	}
	// No internal processes: a populated intermediate cgroup cannot delegate.
	busy, _ := cgroups.New(f, f.Root, "busy")
	if err := busy.Create([]string{"pids"}); err != nil {
		t.Fatal(err)
	}
	if err := f.AddProc(busy.Path(), 1); err != nil {
		t.Fatal(err)
	}
	child, _ := cgroups.New(f, f.Root, "busy/child")
	err := child.Create([]string{"pids"})
	if !errors.Is(err, syscall.EBUSY) || !strings.Contains(err.Error(), "leaf cgroup") {
		t.Errorf("internal process rule: %v", err)
	}
	// Writing a limit for a controller that was not delegated fails like the
	// kernel does (the file does not exist).
	plain, _ := cgroups.New(f, f.Root, "plain")
	if err := plain.Create(nil); err != nil {
		t.Fatal(err)
	}
	err = plain.Apply([]cgroups.Setting{{File: "hugetlb.2MB.max", Value: "1"}})
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "subtree_control") {
		t.Errorf("missing controller: %v", err)
	}
	// Values are validated.
	mem, _ := cgroups.New(f, f.Root, "mem")
	if err := mem.Create([]string{"memory", "cpu"}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []cgroups.Setting{{File: "memory.max", Value: "lots"}, {File: "cpu.max", Value: "1 1"}, {File: "cpu.weight", Value: "0"}} {
		if err := mem.Apply([]cgroups.Setting{s}); !errors.Is(err, syscall.EINVAL) || !strings.Contains(err.Error(), "rejected") {
			t.Errorf("%v: %v", s, err)
		}
	}
	if err := mem.Apply([]cgroups.Setting{{File: "memory.current", Value: "1"}}); !errors.Is(err, syscall.EACCES) {
		t.Errorf("read-only write: %v", err)
	}
	// Missing parent.
	broken, _ := cgroups.New(f, filepath.Join(f.Root, "nope"), "x")
	if err := broken.Create(nil); err == nil {
		t.Error("expected error for missing root")
	}
	if err := broken.Create([]string{"pids"}); err == nil {
		t.Error("expected error reading controllers of missing root")
	}
}

func TestStatsParseErrors(t *testing.T) {
	f := newFake(t)
	m, _ := cgroups.New(f, f.Root, "s")
	if err := m.Create([]string{"memory", "pids", "cpu"}); err != nil {
		t.Fatal(err)
	}
	_ = f.SetCounter(filepath.Join(m.Path(), "memory.current"), "abc\n")
	_ = f.SetCounter(filepath.Join(m.Path(), "pids.events"), "max\n")
	if _, err := m.Stats(); err == nil {
		t.Error("expected parse errors")
	}
}

func TestParseFlatKeyed(t *testing.T) {
	kv, err := cgroups.ParseFlatKeyed("a 1\n\nb 2\n")
	if err != nil || kv["a"] != 1 || kv["b"] != 2 {
		t.Fatalf("%v %v", kv, err)
	}
	for _, bad := range []string{"a\n", "a b\n", "a 1 2\n"} {
		if _, err := cgroups.ParseFlatKeyed(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestProcsParseError(t *testing.T) {
	f := newFake(t)
	m, _ := cgroups.New(f, f.Root, "p")
	if err := m.Create(nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.Path(), "cgroup.procs"), []byte("12\nxx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Procs(); err == nil {
		t.Error("expected parse error")
	}
}

func TestKillUnsupported(t *testing.T) {
	f := newFake(t)
	m, _ := cgroups.New(f, f.Root, "old")
	if err := m.Create(nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(m.Path(), "cgroup.kill")); err != nil {
		t.Fatal(err)
	}
	if err := m.Kill(); !errors.Is(err, cgroups.ErrKillUnsupported) {
		t.Errorf("err = %v", err)
	}
}

func TestOSFSAgainstTempDir(t *testing.T) {
	dir := t.TempDir()
	var fsys cgroups.OSFS
	p := filepath.Join(dir, "c")
	if err := fsys.Mkdir(p); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile(filepath.Join(p, "missing"), []byte("1")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("OSFS must not create files: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fsys.WriteFile(filepath.Join(p, "f"), []byte("v")); err != nil {
		t.Fatal(err)
	}
	if data, err := fsys.ReadFile(filepath.Join(p, "f")); err != nil || string(data) != "v" {
		t.Errorf("ReadFile = %q %v", data, err)
	}
	if err := os.Remove(filepath.Join(p, "f")); err != nil {
		t.Fatal(err)
	}
	if err := fsys.Rmdir(p); err != nil {
		t.Fatal(err)
	}
}
