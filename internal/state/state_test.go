package state

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestValidateID(t *testing.T) {
	for _, ok := range []string{"a", "web-1", "x.y_z", strings.Repeat("a", 64)} {
		if err := ValidateID(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", ".hidden", "-x", "a/b", "..", "a b", strings.Repeat("a", 65)} {
		if err := ValidateID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestStoreLifecycle(t *testing.T) {
	s := &Store{Root: filepath.Join(t.TempDir(), "run")}
	if list, err := s.List(); err != nil || len(list) != 0 {
		t.Fatalf("List on missing root = %v %v", list, err)
	}
	if err := s.Create("bad/id"); err == nil {
		t.Fatal("invalid id accepted")
	}
	for _, id := range []string{"b", "a"} {
		if err := s.Create(id); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Create("a"); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	code := 3
	st := &State{OCIVersion: "1.2.0", ID: "a", Status: Running, Pid: 42, Bundle: "/b", Created: time.Unix(0, 0).UTC(), ExitCode: &code}
	if err := s.Save(st); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load("a")
	if err != nil || got.Pid != 42 || *got.ExitCode != 3 {
		t.Fatalf("Load = %+v %v", got, err)
	}
	// "b" has no state.json yet (still creating) and is skipped; so is junk.
	if err := os.WriteFile(filepath.Join(s.Root, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(s.Root, ".junk"), 0o700); err != nil {
		t.Fatal(err)
	}
	list, err := s.List()
	if err != nil || len(list) != 1 || list[0].ID != "a" {
		t.Fatalf("List = %v %v", list, err)
	}
	if _, err := s.Load("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Load missing: %v", err)
	}
	if _, err := s.Load("../x"); err == nil {
		t.Error("Load accepted bad id")
	}
	if err := s.WriteJSON("nope", "plan.json", 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("WriteJSON missing: %v", err)
	}
	if err := s.WriteJSON("a", "bad.json", func() {}); err == nil {
		t.Error("unencodable value accepted")
	}
	if err := os.WriteFile(filepath.Join(s.Dir("b"), "state.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("b"); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("corrupt state: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(s.Dir("a"), "upper", "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("a"); err != nil {
		t.Errorf("Remove missing: %v", err)
	}
	if err := s.Remove("a/.."); err == nil {
		t.Error("Remove accepted bad id")
	}
}

func TestCheckOneFilesystem(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "x", "y"), 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	dev := deviceOf(info)
	if err := checkOneFilesystem(dir, dev); err != nil {
		t.Errorf("same device: %v", err)
	}
	if err := checkOneFilesystem(dir, dev+1); !errors.Is(err, ErrMountPoint) {
		t.Errorf("different device: %v", err)
	}
	if err := checkOneFilesystem(filepath.Join(dir, "missing"), dev); err == nil {
		t.Error("missing dir accepted")
	}
}

func TestLockSerialises(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	if err := s.Create("c"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lock("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("lock missing: %v", err)
	}
	if _, err := s.Lock("../c"); err == nil {
		t.Error("lock accepted bad id")
	}
	var mu sync.Mutex
	inside := 0
	maxInside := 0
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := s.Lock("c")
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inside++
			maxInside = max(maxInside, inside)
			mu.Unlock()
			time.Sleep(2 * time.Millisecond)
			mu.Lock()
			inside--
			mu.Unlock()
			unlock()
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Errorf("lock admitted %d holders at once", maxInside)
	}
}

const sampleStat = "1234 (my (weird) cmd) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000000 200 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0"

func TestParseStat(t *testing.T) {
	info, err := ParseStat(sampleStat)
	if err != nil || info.State != 'S' || info.StartTime != 98765 {
		t.Fatalf("ParseStat = %+v %v", info, err)
	}
	for _, bad := range []string{"no paren", "1 (x) S 1 2", "1 (x) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 notanumber"} {
		if _, err := ParseStat(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func writeProc(t *testing.T, root string, pid int, state string, start uint64) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	line := strconv.Itoa(pid) + " (sh) " + state + " 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 " + strconv.FormatUint(start, 10) + " 0 0"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRefresh(t *testing.T) {
	root := t.TempDir()
	p := ProcFS{Root: root}
	writeProc(t, root, 10, "S", 500)
	writeProc(t, root, 11, "Z", 600)
	if err := os.MkdirAll(filepath.Join(root, "12"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "12", "stat"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		st   State
		want Status
	}{
		{State{Status: Running, Pid: 10, PidStartTime: 500}, Running},
		{State{Status: Created, Pid: 10}, Created},
		{State{Status: Running, Pid: 10, PidStartTime: 499}, Stopped},
		{State{Status: Running, Pid: 11, PidStartTime: 600}, Stopped},
		{State{Status: Running, Pid: 99}, Stopped},
		{State{Status: Running, Pid: 0}, Stopped},
		{State{Status: Running, Pid: 12}, Running},
		{State{Status: Stopped, Pid: 10}, Stopped},
		{State{Status: Creating}, Creating},
	}
	for i, c := range cases {
		if got := Refresh(&c.st, p); got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}
