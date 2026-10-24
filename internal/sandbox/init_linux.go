//go:build linux

package sandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/archit2501/minirun/internal/caps"
	"github.com/archit2501/minirun/internal/launch"
)

// child bundles the protocol file descriptors of a sandbox child.
type child struct {
	plan   *os.File
	start  *os.File
	status *os.File
}

func openChild() *child {
	return &child{
		plan:   os.NewFile(PlanFD, "plan"),
		start:  os.NewFile(StartFD, "start"),
		status: os.NewFile(StatusFD, "status"),
	}
}

// fail reports err to the parent. The caller exits non-zero afterwards.
func (c *child) fail(err error) error {
	_ = WriteMessage(c.status, Message{Type: "error", Message: err.Error()})
	return err
}

// handshake tells the parent the child is ready and waits for the go-ahead.
func (c *child) handshake() error {
	if err := WriteMessage(c.status, Message{Type: "ready", Pid: os.Getpid()}); err != nil {
		return fmt.Errorf("report ready: %w", err)
	}
	var b [1]byte
	if _, err := io.ReadFull(c.start, b[:]); err != nil {
		return fmt.Errorf("wait for start: %w", err)
	}
	return nil
}

// execProcess performs the final privilege drop and replaces the process
// image. On success it does not return.
func (c *child) execProcess(p launch.Process, filter *launch.Seccomp, userNS bool, lastCap int) error {
	if err := unix.Chdir(p.Cwd); err != nil {
		return fmt.Errorf("chdir %s: %w", p.Cwd, err)
	}
	if p.Umask != nil {
		unix.Umask(int(*p.Umask))
	}
	path, err := LookPath("/", p.Args[0], p.Env)
	if err != nil {
		return err
	}
	// Close every inherited descriptor above stdio on exec, including the
	// status pipe: its EOF tells the parent execve succeeded.
	if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return fmt.Errorf("close_range: %w", err)
	}
	if err := dropPrivileges(p, filter, userNS, lastCap); err != nil {
		return err
	}
	if err := unix.Exec(path, p.Args, p.Env); err != nil {
		return fmt.Errorf("exec %s: %w", path, err)
	}
	return errors.New("exec returned")
}

func readPlan(f *os.File, v any) error {
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(io.LimitReader(f, 16<<20))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode plan: %w", err)
	}
	return nil
}

// RunInit is the body of `minirun __init`. The process was cloned into the
// container's namespaces by the parent; it must be called on the main
// goroutine with the OS thread locked. It only returns on error.
func RunInit() error {
	c := openChild()
	var p launch.Plan
	if err := readPlan(c.plan, &p); err != nil {
		return c.fail(err)
	}
	if err := initContainer(&p, c); err != nil {
		return c.fail(err)
	}
	return nil
}

func initContainer(p *launch.Plan, c *child) error {
	lastCap, err := caps.KernelLast()
	if err != nil {
		return err
	}
	if err := setupRootfs(p); err != nil {
		return err
	}
	if p.Hostname != "" {
		if err := unix.Sethostname([]byte(p.Hostname)); err != nil {
			return fmt.Errorf("sethostname: %w", err)
		}
	}
	if p.Domainname != "" {
		if err := unix.Setdomainname([]byte(p.Domainname)); err != nil {
			return fmt.Errorf("setdomainname: %w", err)
		}
	}
	if p.Loopback {
		if err := bringUpLoopback(); err != nil {
			return err
		}
	}
	if err := applyRlimits(p.Process.Rlimits); err != nil {
		return err
	}
	if err := c.handshake(); err != nil {
		return err
	}
	return c.execProcess(p.Process, p.Seccomp, p.HasUserNS(), lastCap)
}

// RunExec is the body of `minirun __exec`. The parent forked it from a
// thread that had already joined the container's IPC, UTS, network, PID and
// cgroup namespaces; the helper joins the mount namespace itself, which
// requires an unshared filesystem context. Must be called with the OS
// thread locked. It only returns on error.
func RunExec() error {
	c := openChild()
	var p ExecPlan
	if err := readPlan(c.plan, &p); err != nil {
		return c.fail(err)
	}
	if err := enterContainer(&p, c); err != nil {
		return c.fail(err)
	}
	return nil
}

func enterContainer(p *ExecPlan, c *child) error {
	lastCap, err := caps.KernelLast()
	if err != nil {
		return err
	}
	// setns(CLONE_NEWNS) refuses callers that share fs_struct with other
	// threads, which every Go thread does; give this thread its own first.
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("unshare(CLONE_FS): %w", err)
	}
	mnt := os.NewFile(MntNSFD, "mntns")
	if err := unix.Setns(int(mnt.Fd()), unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("setns(mnt): %w", err)
	}
	_ = mnt.Close()
	if err := applyRlimits(p.Process.Rlimits); err != nil {
		return err
	}
	if err := c.handshake(); err != nil {
		return err
	}
	return c.execProcess(p.Process, p.Seccomp, false, lastCap)
}
