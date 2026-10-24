package sandbox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusProtocol(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMessage(&buf, Message{Type: "ready", Pid: 42}); err != nil {
		t.Fatal(err)
	}
	if err := WriteMessage(&buf, Message{Type: "error", Message: "pivot_root: invalid argument"}); err != nil {
		t.Fatal(err)
	}
	r := NewStatusReader(&buf)
	m, err := r.Next()
	if err != nil || m.Type != "ready" || m.Pid != 42 {
		t.Fatalf("first = %+v %v", m, err)
	}
	_, err = r.Next()
	if err == nil || !strings.Contains(err.Error(), "container setup failed: pivot_root") {
		t.Fatalf("second = %v", err)
	}
	if _, err := r.Next(); !errors.Is(err, ErrExecSucceeded) {
		t.Fatalf("EOF = %v", err)
	}
	if _, err := NewStatusReader(strings.NewReader("not json\n")).Next(); err == nil {
		t.Error("garbage accepted")
	}
	// A final line without a newline is still decoded.
	m, err = NewStatusReader(strings.NewReader(`{"type":"ready"}`)).Next()
	if err != nil || m.Type != "ready" {
		t.Errorf("unterminated line = %+v %v", m, err)
	}
	if _, err := NewStatusReader(errReader{}).Next(); err == nil || !strings.Contains(err.Error(), "read child status") {
		t.Errorf("read error = %v", err)
	}
	if err := WriteMessage(errWriter{}, Message{Type: "ready"}); err == nil {
		t.Error("write error swallowed")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, os.ErrClosed }

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestLookPath(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"bin", "usr/bin", "opt/tools"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(root, p), []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("bin/sh", 0o755)
	write("usr/bin/notexec", 0o644)
	write("opt/tools/tool", 0o755)
	if err := os.Mkdir(filepath.Join(root, "usr/bin/dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		file string
		env  []string
		want string
		ok   bool
	}{
		{"sh", nil, "/bin/sh", true},
		{"/abs/path", nil, "/abs/path", true},
		{"./rel", nil, "./rel", true},
		{"tool", []string{"PATH=/opt/tools"}, "/opt/tools/tool", true},
		{"tool", nil, "", false},
		{"notexec", nil, "", false},
		{"dir", nil, "", false},
		{"sh", []string{"PATH=:/bin"}, "/bin/sh", true},
	}
	for _, c := range cases {
		got, err := LookPath(root, c.file, c.env)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("LookPath(%q, %v) = %q, %v", c.file, c.env, got, err)
		}
	}
}

func TestStubsOffLinux(t *testing.T) {
	// On Linux these would try to read fd 3; only check the stubs elsewhere.
	if isLinux {
		t.Skip("real implementation on Linux")
	}
	if err := RunInit(); err == nil {
		t.Error("RunInit should fail off Linux")
	}
	if err := RunExec(); err == nil {
		t.Error("RunExec should fail off Linux")
	}
}
