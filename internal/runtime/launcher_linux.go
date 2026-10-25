//go:build linux

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/SlateGitOrg/minirun/internal/launch"
	"github.com/SlateGitOrg/minirun/internal/sandbox"
	"github.com/SlateGitOrg/minirun/internal/spec"
)

// LinuxLauncher starts container processes by re-executing the minirun
// binary as `__init` or `__exec`.
//
// The binary is not re-executed from its path on disk but from a sealed
// in-memory copy (memfd). Between the re-exec and the final execve, the
// helper process is visible inside the container's PID namespace, and a
// process in the container could open /proc/<pid>/exe; with the on-disk
// binary that is the CVE-2019-5736 attack (overwrite the host's runtime
// binary). A sealed memfd cannot be written, so the attack has nothing to
// write to.
type LinuxLauncher struct {
	once   sync.Once
	binary *os.File
	err    error
}

// sealedSelf returns a write-sealed memfd holding a copy of the running
// executable, created once per launcher.
func (l *LinuxLauncher) sealedSelf() (*os.File, error) {
	l.once.Do(func() { l.binary, l.err = copyToSealedMemfd("/proc/self/exe") })
	return l.binary, l.err
}

func copyToSealedMemfd(path string) (*os.File, error) {
	src, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = src.Close() }()
	fd, err := unix.MemfdCreate("minirun", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	mem := os.NewFile(uintptr(fd), "memfd:minirun")
	if _, err := io.Copy(mem, src); err != nil {
		_ = mem.Close()
		return nil, fmt.Errorf("copy binary to memfd: %w", err)
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		_ = mem.Close()
		return nil, fmt.Errorf("seal memfd: %w", err)
	}
	return mem, nil
}

// command builds the re-exec command for a helper whose protocol files
// occupy fds 3..3+nfiles-1; the sealed binary is passed as the next fd and
// executed through /proc/self/fd, so the child never runs the on-disk file.
func (l *LinuxLauncher) command(ctx context.Context, sub string, nfiles int) (*exec.Cmd, *os.File, error) {
	bin, err := l.sealedSelf()
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/"+strconv.Itoa(3+nfiles), sub)
	cmd.Args[0] = "minirun-" + strings.TrimPrefix(sub, "__")
	cmd.Env = []string{}
	return cmd, bin, nil
}

// NewLauncher returns the platform launcher.
func NewLauncher() Launcher { return &LinuxLauncher{} }

// Check implements Launcher. minirun creates namespaces, mounts and cgroups
// directly and so needs root; other prerequisites (cgroup v2, overlayfs)
// fail later with explanatory errors.
func (l *LinuxLauncher) Check() error {
	if os.Geteuid() != 0 {
		return errors.New("minirun must run as root (rootless mode is not implemented)")
	}
	return nil
}

type pipes struct {
	planR, planW     *os.File
	startR, startW   *os.File
	statusR, statusW *os.File
}

func newPipes() (*pipes, error) {
	var p pipes
	var err error
	if p.planR, p.planW, err = os.Pipe(); err != nil {
		return nil, err
	}
	if p.startR, p.startW, err = os.Pipe(); err != nil {
		p.closeAll()
		return nil, err
	}
	if p.statusR, p.statusW, err = os.Pipe(); err != nil {
		p.closeAll()
		return nil, err
	}
	return &p, nil
}

func (p *pipes) closeAll() {
	for _, f := range []*os.File{p.planR, p.planW, p.startR, p.startW, p.statusR, p.statusW} {
		if f != nil {
			_ = f.Close()
		}
	}
}

// closeChildEnds closes the descriptors only the child should hold.
func (p *pipes) closeChildEnds() {
	_ = p.planR.Close()
	_ = p.startR.Close()
	_ = p.statusW.Close()
}

type linuxChild struct {
	cmd        *exec.Cmd
	start      *os.File
	status     *sandbox.StatusReader
	statusFile *os.File
}

func (c *linuxChild) Pid() int { return c.cmd.Process.Pid }

func (c *linuxChild) Start() error {
	_, err := c.start.Write([]byte{1})
	_ = c.start.Close()
	if err != nil {
		return fmt.Errorf("release child: %w", err)
	}
	_, err = c.status.Next()
	_ = c.statusFile.Close()
	if errors.Is(err, sandbox.ErrExecSucceeded) {
		return nil
	}
	if err == nil {
		return errors.New("child sent an unexpected second status message")
	}
	return err
}

func (c *linuxChild) Wait() (int, error) {
	err := c.cmd.Wait()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	}
	return -1, err
}

func (c *linuxChild) Abort() {
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
	_ = c.start.Close()
	_ = c.statusFile.Close()
}

// startChild launches the helper, sends it the plan and waits for "ready",
// answering "join-cgroup" requests on the way with join.
func startChild(cmd *exec.Cmd, p *pipes, plan any, join func(int) error, extra ...*os.File) (*linuxChild, error) {
	cmd.ExtraFiles = append([]*os.File{p.planR, p.startR, p.statusW}, extra...)
	if err := cmd.Start(); err != nil {
		p.closeAll()
		return nil, fmt.Errorf("start %s: %w", cmd.Args[0], err)
	}
	p.closeChildEnds()
	child := &linuxChild{cmd: cmd, start: p.startW, status: sandbox.NewStatusReader(p.statusR), statusFile: p.statusR}
	enc := json.NewEncoder(p.planW)
	werr := enc.Encode(plan)
	_ = p.planW.Close()
	if werr != nil {
		child.Abort()
		return nil, fmt.Errorf("send plan: %w", werr)
	}
	msg, err := child.status.Next()
	for err == nil && msg.Type == sandbox.MsgJoinCgroup && join != nil {
		if err = join(child.Pid()); err != nil {
			break
		}
		if _, err = child.start.Write([]byte{1}); err != nil {
			break
		}
		msg, err = child.status.Next()
	}
	if err == nil && msg.Type != sandbox.MsgReady {
		err = fmt.Errorf("unexpected child message %q", msg.Type)
	}
	if errors.Is(err, sandbox.ErrExecSucceeded) {
		err = errors.New("child exited during setup without reporting an error")
	}
	if err != nil {
		child.Abort()
		return nil, err
	}
	return child, nil
}

func idMaps(maps []spec.IDMapping) []syscall.SysProcIDMap {
	out := make([]syscall.SysProcIDMap, 0, len(maps))
	for _, m := range maps {
		out = append(out, syscall.SysProcIDMap{ContainerID: int(m.ContainerID), HostID: int(m.HostID), Size: int(m.Size)})
	}
	return out
}

// StartInit implements Launcher.
// The context is not tied to the process: a container must outlive the CLI
// invocation that created it.
func (l *LinuxLauncher) StartInit(_ context.Context, plan *launch.Plan, stdio Stdio, join func(int) error) (Child, error) {
	cmd, bin, err := l.command(context.Background(), "__init", 3)
	if err != nil {
		return nil, err
	}
	p, err := newPipes()
	if err != nil {
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdio.In, stdio.Out, stdio.Err
	attr := &syscall.SysProcAttr{
		Cloneflags: uintptr(plan.CloneFlags),
		Setsid:     true,
	}
	if plan.HasUserNS() {
		attr.UidMappings = idMaps(plan.UIDMappings)
		attr.GidMappings = idMaps(plan.GIDMappings)
		attr.GidMappingsEnableSetgroups = false
		// Become root of the new user namespace, so file access inside it
		// uses a mapped identity.
		attr.Credential = &syscall.Credential{Uid: 0, Gid: 0, NoSetGroups: true}
	}
	cmd.SysProcAttr = attr
	return startChild(cmd, p, plan, join, bin)
}

// StartExec implements Launcher. The namespaces other than mount are joined
// on a dedicated, locked OS thread which then forks the helper: a forked
// child inherits the forking thread's namespaces, and the PID namespace
// only applies to children. The thread is never unlocked, so the Go runtime
// destroys it instead of reusing a thread in foreign namespaces.
func (l *LinuxLauncher) StartExec(ctx context.Context, plan *launch.Plan, initPid int, proc launch.Process, stdio Stdio) (Child, error) {
	type result struct {
		child Child
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		goruntime.LockOSThread()
		c, err := l.startExecLocked(ctx, plan, initPid, proc, stdio)
		ch <- result{c, err}
	}()
	r := <-ch
	return r.child, r.err
}

func (l *LinuxLauncher) startExecLocked(ctx context.Context, plan *launch.Plan, initPid int, proc launch.Process, stdio Stdio) (Child, error) {
	nsDir := filepath.Join("/proc", strconv.Itoa(initPid), "ns")
	mnt, err := os.Open(filepath.Join(nsDir, "mnt"))
	if err != nil {
		return nil, fmt.Errorf("open mount namespace: %w", err)
	}
	defer func() { _ = mnt.Close() }()
	for _, name := range plan.ProcNamespaces() {
		if name == "mnt" {
			continue
		}
		if err := joinNamespace(filepath.Join(nsDir, name)); err != nil {
			return nil, err
		}
	}
	cmd, bin, err := l.command(ctx, "__exec", 4)
	if err != nil {
		return nil, err
	}
	p, err := newPipes()
	if err != nil {
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdio.In, stdio.Out, stdio.Err
	return startChild(cmd, p, sandbox.ExecPlan{Process: proc, Seccomp: plan.Seccomp}, nil, mnt, bin)
}

func joinNamespace(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if err := unix.Setns(int(f.Fd()), 0); err != nil {
		return fmt.Errorf("setns %s: %w", path, err)
	}
	return nil
}

func killPid(pid, sig int) error {
	if err := unix.Kill(pid, unix.Signal(sig)); err != nil {
		return fmt.Errorf("kill(%d, %d): %w", pid, sig, err)
	}
	return nil
}

// SignalFunc returns the platform function that delivers signals.
func SignalFunc() func(pid, sig int) error { return killPid }
