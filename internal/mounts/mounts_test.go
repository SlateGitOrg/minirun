package mounts

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/archit2501/minirun/internal/spec"
)

func TestParseOptions(t *testing.T) {
	flags, prop, data := ParseOptions([]string{"nosuid", "noexec", "ro", "rw", "rbind", "rslave", "private", "mode=755", "size=64k"})
	if flags != MSNosuid|MSNoexec|MSBind|MSRec {
		t.Errorf("flags = %s", FlagNames(flags))
	}
	if !reflect.DeepEqual(prop, []uint64{MSSlave | MSRec, MSPrivate}) {
		t.Errorf("propagation = %v", prop)
	}
	if data != "mode=755,size=64k" {
		t.Errorf("data = %q", data)
	}
}

func TestFromSpecDefaults(t *testing.T) {
	ops, err := FromSpec(spec.Default(spec.DefaultOptions{}).Mounts)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != 6 {
		t.Fatalf("ops = %d", len(ops))
	}
	pts := ops[2]
	if pts.Destination != "/dev/pts" || pts.FSType != "devpts" || pts.Data != "newinstance,ptmxmode=0666,mode=0620" || pts.Flags != MSNosuid|MSNoexec {
		t.Errorf("devpts op = %+v", pts)
	}
	sys := ops[5]
	if sys.FSType != "sysfs" || sys.Flags&MSRdonly == 0 {
		t.Errorf("sysfs op = %+v", sys)
	}
}

func TestFromSpecBindRemount(t *testing.T) {
	ops, err := FromSpec([]spec.Mount{
		{Destination: "/data/", Source: "/srv/data", Options: []string{"rbind", "ro", "nosuid", "rprivate"}},
		{Destination: "/x", Type: "bind", Source: "/x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := ops[0]
	if b.Destination != "/data" || b.Flags != MSBind|MSRec || b.RemountFlags != MSBind|MSRemount|MSRdonly|MSNosuid || !b.IsBind() {
		t.Errorf("bind op = %+v (%s / %s)", b, FlagNames(b.Flags), FlagNames(b.RemountFlags))
	}
	if !reflect.DeepEqual(b.Propagation, []uint64{MSPrivate | MSRec}) {
		t.Errorf("propagation = %v", b.Propagation)
	}
	if ops[1].Flags != MSBind || ops[1].RemountFlags != 0 {
		t.Errorf("type=bind op = %+v", ops[1])
	}
}

func TestFromSpecErrors(t *testing.T) {
	cases := map[string]spec.Mount{
		"type":         {Destination: "/x", Type: "ext4", Source: "/dev/sda1"},
		"remount":      {Destination: "/x", Type: "tmpfs", Options: []string{"remount"}},
		"relative src": {Destination: "/x", Source: "rel", Options: []string{"bind"}},
		"bind data":    {Destination: "/x", Source: "/y", Options: []string{"bind", "size=1"}},
		"no type":      {Destination: "/x", Source: "/y"},
	}
	for name, m := range cases {
		if _, err := FromSpec([]spec.Mount{m}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestPropagationFlags(t *testing.T) {
	if f, err := PropagationFlags(""); err != nil || f != MSPrivate|MSRec {
		t.Errorf("default = %v %v", f, err)
	}
	if f, err := PropagationFlags("rslave"); err != nil || f != MSSlave|MSRec {
		t.Errorf("rslave = %v %v", f, err)
	}
	if _, err := PropagationFlags("sideways"); err == nil {
		t.Error("unknown mode accepted")
	}
}

func TestOverlayData(t *testing.T) {
	got, err := OverlayData([]string{"/b/rootfs"}, "/s/upper", "/s/work")
	if err != nil || got != "lowerdir=/b/rootfs,upperdir=/s/upper,workdir=/s/work" {
		t.Fatalf("%q %v", got, err)
	}
	got, err = OverlayData([]string{"/l1", "/l2"}, "/u", "/w")
	if err != nil || !strings.HasPrefix(got, "lowerdir=/l1:/l2,") {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range [][]string{{}, {"rel"}, {"/a,b"}, {"/a:b"}, {`/a\b`}} {
		if _, err := OverlayData(bad, "/u", "/w"); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestFlagNames(t *testing.T) {
	if got := FlagNames(MSBind | MSRec | 1<<40); got != "MS_BIND|MS_REC|0x10000000000" {
		t.Errorf("FlagNames = %s", got)
	}
	if FlagNames(0) != "0" {
		t.Error("zero")
	}
}

func TestSecureJoin(t *testing.T) {
	root := t.TempDir()
	mk := func(p string) {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, name string) {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	mk("usr/lib")
	mk("etc")
	link("/usr/lib", "lib")         // absolute, stays inside
	link("../../../../etc", "up")   // tries to climb out
	link("/", "slash")              // root
	link("lib/../../../tmp", "mix") // relative chain
	link("loop2", "loop1")
	link("loop1", "loop2")
	// A ".." after a missing component cancels it, so the next name is an
	// existing entry that must be resolved (here a symlink to an absolute
	// path that tries to climb out of root), not appended as text.
	link("missing/../evil", "proc")
	link("/../../../../../escape-target", "evil")
	cases := map[string]string{
		"/":                    root,
		"/etc/passwd":          filepath.Join(root, "etc/passwd"),
		"/lib/x":               filepath.Join(root, "usr/lib/x"),
		"/up/shadow":           filepath.Join(root, "etc/shadow"),
		"../../etc":            filepath.Join(root, "etc"),
		"/slash/slash/etc":     filepath.Join(root, "etc"),
		"/mix":                 filepath.Join(root, "tmp"),
		"/new/dir/../file":     filepath.Join(root, "new/file"),
		"/new/../../../escape": filepath.Join(root, "escape"),
		"/new/./a/./b":         filepath.Join(root, "new/a/b"),
		"/etc/./../usr//lib/.": filepath.Join(root, "usr/lib"),
		"/proc":                filepath.Join(root, "escape-target"),
		"/proc/self/fd":        filepath.Join(root, "escape-target/self/fd"),
		"/nope/../lib/x":       filepath.Join(root, "usr/lib/x"),
		"/nope/a/../../up/x":   filepath.Join(root, "etc/x"),
		"/nope/../evil":        filepath.Join(root, "escape-target"),
	}
	for in, want := range cases {
		got, err := SecureJoin(root, in)
		if err != nil || got != want {
			t.Errorf("SecureJoin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := SecureJoin(root, "/loop1/x"); !errors.Is(err, ErrTooManyLinks) {
		t.Errorf("loop: %v", err)
	}
	// Whatever the input, the result must stay inside root and must not be
	// a symlink (callers mkdir, create and mount on it as root).
	for in := range cases {
		got, err := SecureJoin(root, in)
		if err != nil {
			continue
		}
		if rel, err := filepath.Rel(root, got); err != nil || strings.HasPrefix(rel, "..") {
			t.Errorf("SecureJoin(%q) = %q escapes root", in, got)
		}
		if info, err := os.Lstat(got); err == nil && info.Mode()&os.ModeSymlink != 0 {
			t.Errorf("SecureJoin(%q) = %q is a symlink", in, got)
		}
	}
}
