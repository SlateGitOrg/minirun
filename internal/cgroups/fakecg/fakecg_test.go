package fakecg

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestKernelRules(t *testing.T) {
	f, err := New(filepath.Join(t.TempDir(), "cg"))
	if err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(f.Root, "cgroup.subtree_control")
	if err := f.WriteFile(sub, []byte("+memory +pids")); err != nil {
		t.Fatal(err)
	}
	if err := f.WriteFile(sub, []byte("-pids")); err != nil {
		t.Fatal(err)
	}
	if data, _ := f.ReadFile(sub); strings.TrimSpace(string(data)) != "memory" {
		t.Errorf("subtree_control = %q", data)
	}
	for _, bad := range []string{"memory", "+", "+rdma"} {
		if err := f.WriteFile(sub, []byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	child := filepath.Join(f.Root, "a")
	if err := f.Mkdir(child); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(child, "memory.max")); err != nil {
		t.Errorf("memory files not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(child, "pids.max")); err == nil {
		t.Error("pids files created without delegation")
	}
	if err := f.Mkdir(filepath.Join(child, "b")); err != nil {
		t.Fatal(err)
	}
	if err := f.Rmdir(child); !errors.Is(err, syscall.EBUSY) {
		t.Errorf("rmdir with child: %v", err)
	}
	if err := f.Mkdir(filepath.Join(f.Root, "x", "y")); err == nil {
		t.Error("mkdir under missing parent succeeded")
	}
	if err := f.Mkdir(child); !errors.Is(err, os.ErrExist) {
		t.Errorf("mkdir existing: %v", err)
	}
	procs := filepath.Join(child, "cgroup.procs")
	if err := f.WriteFile(procs, []byte("abc")); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("bad pid: %v", err)
	}
	if err := f.WriteFile(filepath.Join(child, "cgroup.kill"), []byte("2")); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("bad kill: %v", err)
	}
	for _, v := range []string{"max", "max 100000", "2000 5000"} {
		if !validCPUMax(v) {
			t.Errorf("%q rejected", v)
		}
	}
	for _, v := range []string{"", "a b c", "x", "2000 1", "2000 x"} {
		if validCPUMax(v) {
			t.Errorf("%q accepted", v)
		}
	}
	outside := filepath.Join(t.TempDir(), "elsewhere")
	for name, err := range map[string]error{
		"mkdir": f.Mkdir(outside),
		"rmdir": f.Rmdir(outside),
		"write": f.WriteFile(outside, nil),
		"set":   f.SetCounter(outside, ""),
	} {
		if !errors.Is(err, ErrOutside) {
			t.Errorf("%s outside root: %v", name, err)
		}
	}
	if _, err := f.ReadFile(outside); !errors.Is(err, ErrOutside) {
		t.Errorf("read outside root: %v", err)
	}
	if err := f.SetCounter(filepath.Join(child, "nope"), "1"); err == nil {
		t.Error("SetCounter on missing file succeeded")
	}
	if err := f.Rmdir(filepath.Join(f.Root, "missing")); err == nil {
		t.Error("rmdir missing succeeded")
	}
}
