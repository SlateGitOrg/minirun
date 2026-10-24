package spec

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseRuncStyleConfigReportsUnsupportedKeys(t *testing.T) {
	f, err := os.Open("testdata/runc-style.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	s, unknown, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{
		"linux.resources.devices",
		"linux.sysctl",
		"process.apparmorProfile",
		"process.oomScoreAdj",
	}
	if !reflect.DeepEqual(unknown, want) {
		t.Fatalf("unsupported keys = %v, want %v", unknown, want)
	}
	if got := *s.Linux.Resources.Memory.Limit; got != 64<<20 {
		t.Errorf("memory limit = %d", got)
	}
	if s.Linux.Resources.Unified["memory.high"] != "50331648" {
		t.Errorf("unified map not decoded: %v", s.Linux.Resources.Unified)
	}
	if err := Validate(s); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestParseErrorsCarryPosition(t *testing.T) {
	cases := map[string]string{
		"syntax":   "{\n  \"ociVersion\": \"1.2.0\",\n  \"process\": {,}\n}",
		"type":     "{\n  \"ociVersion\": 12\n}",
		"trailing": `{"ociVersion":"1.2.0"} {}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := Parse(strings.NewReader(doc))
			if err == nil {
				t.Fatal("expected error")
			}
			if name != "trailing" && !strings.Contains(err.Error(), "line ") {
				t.Errorf("error lacks position: %v", err)
			}
		})
	}
}

func TestParseRejectsHugeConfig(t *testing.T) {
	big := strings.Repeat(" ", maxConfigSize+10)
	if _, _, err := Parse(strings.NewReader(big)); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadBundleResolvesRootfs(t *testing.T) {
	dir := t.TempDir()
	data, err := Marshal(Default(DefaultOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := b.RootfsPath(), filepath.Join(dir, "rootfs"); got != want {
		t.Errorf("RootfsPath = %q, want %q", got, want)
	}
	if len(b.Unsupported) != 0 {
		t.Errorf("default config has unsupported keys: %v", b.Unsupported)
	}
	b.Spec.Root.Path = "/abs/rootfs/"
	if got := b.RootfsPath(); got != "/abs/rootfs" {
		t.Errorf("absolute RootfsPath = %q", got)
	}
	b.Spec.Root = nil
	if got := b.RootfsPath(); got != "" {
		t.Errorf("nil root RootfsPath = %q", got)
	}
}

func TestLoadBundleErrors(t *testing.T) {
	if _, err := LoadBundle(t.TempDir()); err == nil {
		t.Fatal("expected error for missing config.json")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ConfigName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(dir); err == nil || !strings.Contains(err.Error(), ConfigName) {
		t.Fatalf("err = %v", err)
	}
}

func TestDefaultConfigsValidate(t *testing.T) {
	opts := []DefaultOptions{
		{},
		{Args: []string{"/bin/echo", "hi"}, Hostname: "box", ReadOnly: true},
		{UserNS: true, HostIDBase: 100000, MemoryLimit: 32 << 20, PidsLimit: 16, CPUQuota: 50000},
		{UserNS: true, HostNetwork: true},
	}
	for i, o := range opts {
		s := Default(o)
		if err := Validate(s); err != nil {
			t.Errorf("Default(%d) invalid: %v", i, err)
		}
		data, err := Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		round, unknown, err := Parse(strings.NewReader(string(data)))
		if err != nil || len(unknown) != 0 {
			t.Fatalf("round trip %d: %v %v", i, err, unknown)
		}
		if !reflect.DeepEqual(round, s) {
			t.Errorf("round trip %d changed the spec", i)
		}
	}
	s := Default(DefaultOptions{UserNS: true, HostNetwork: true})
	if s.HasNamespace(NetworkNamespace) {
		t.Error("HostNetwork should not create a network namespace")
	}
	last := s.Mounts[len(s.Mounts)-1]
	if last.Destination != "/sys" || last.Type != "" {
		t.Errorf("userns+host network should bind /sys, got %+v", last)
	}
	r := Default(DefaultOptions{MemoryLimit: 1 << 20, CPUQuota: 1}).Linux.Resources
	if *r.CPU.Period != 100000 || *r.Memory.Swap != 1<<20 {
		t.Errorf("unexpected resources %+v %+v", r.CPU, r.Memory)
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	umask := uint32(0o1777)
	s := &Spec{
		OCIVersion: "2.0.0",
		Process: &Process{
			Terminal: true,
			Args:     []string{""},
			Cwd:      "relative",
			Env:      []string{"NOEQUALS", "=x"},
			User:     User{UID: 5000, GID: 5000, Umask: &umask},
			Rlimits: []Rlimit{
				{Type: "RLIMIT_BOGUS"},
				{Type: "RLIMIT_NOFILE", Soft: 10, Hard: 5},
				{Type: "RLIMIT_NOFILE", Soft: 1, Hard: 5},
			},
		},
		Hostname:   "bad_host!",
		Domainname: "example.org",
		Mounts: []Mount{
			{Destination: "rel", Type: "tmpfs"},
			{Destination: "/", Type: "tmpfs"},
			{Destination: "/x"},
		},
		Linux: &Linux{
			Namespaces: []Namespace{
				{Type: "pid"}, {Type: "pid"}, {Type: "time"},
				{Type: "net", Path: "/proc/1/ns/net"}, {Type: "user"},
			},
			UIDMappings:       []IDMapping{{ContainerID: 0, HostID: 1000, Size: 10}, {ContainerID: 5, HostID: 2000, Size: 10}, {Size: 0}},
			CgroupsPath:       "../escape",
			MaskedPaths:       []string{"proc/kcore"},
			ReadonlyPaths:     []string{"proc/sys"},
			RootfsPropagation: "sideways",
		},
	}
	err := Validate(s)
	if err == nil {
		t.Fatal("expected errors")
	}
	msg := err.Error()
	for _, want := range []string{
		"ociVersion", "root.path", "process.terminal", "process.args", "process.cwd",
		"process.env[0]", "process.env[1]", "umask", "RLIMIT_BOGUS", "soft limit", "duplicate entry",
		"mounts[0]", "mounting over /", "type is required", "duplicate namespace",
		"unsupported namespace type", "joining an existing namespace", "mount namespace is required",
		"requires both uidMappings", "ranges overlap", "size must be positive",
		"not covered by linux.uidMappings", "not covered by linux.gidMappings", "cgroupsPath",
		"maskedPaths[0]", "readonlyPaths[0]", "rootfsPropagation", "hostname \"bad_host!\"",
		"hostname: setting a hostname requires", "domainname",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
}

func TestValidateMisc(t *testing.T) {
	if err := Validate(nil); err == nil {
		t.Error("nil spec should fail")
	}
	s := Default(DefaultOptions{})
	s.Linux = nil
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "linux: section") {
		t.Errorf("err = %v", err)
	}
	s = Default(DefaultOptions{})
	s.Process = nil
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "process: is required") {
		t.Errorf("err = %v", err)
	}
	s = Default(DefaultOptions{})
	s.Linux.UIDMappings = []IDMapping{{Size: 1}}
	if err := Validate(s); err == nil || !strings.Contains(err.Error(), "require a user namespace") {
		t.Errorf("err = %v", err)
	}
	s = Default(DefaultOptions{})
	s.Mounts = append(s.Mounts, Mount{Destination: "/data", Source: "/srv", Options: []string{"rbind"}})
	if err := Validate(s); err != nil {
		t.Errorf("bind mount without type should be valid: %v", err)
	}
}

func TestMapToHost(t *testing.T) {
	maps := []IDMapping{{ContainerID: 0, HostID: 100000, Size: 1000}, {ContainerID: 5000, HostID: 7, Size: 1}}
	cases := []struct {
		in   uint32
		want uint32
		ok   bool
	}{
		{0, 100000, true}, {999, 100999, true}, {1000, 0, false}, {5000, 7, true}, {5001, 0, false},
	}
	for _, c := range cases {
		got, ok := MapToHost(maps, c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("MapToHost(%d) = %d,%v want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestCheckCgroupsPath(t *testing.T) {
	for _, ok := range []string{"minirun/a", "/minirun/a", "a"} {
		if err := CheckCgroupsPath(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/", "a/../b", "a//b", "./a", "a/.."} {
		if err := CheckCgroupsPath(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func TestRlimitResource(t *testing.T) {
	if r, ok := RlimitResource("RLIMIT_NOFILE"); !ok || r != 7 {
		t.Errorf("NOFILE = %d %v", r, ok)
	}
	if _, ok := RlimitResource("NOFILE"); ok {
		t.Error("short name should not resolve")
	}
}
