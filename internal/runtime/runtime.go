// Package runtime implements the container lifecycle (run, exec, kill,
// delete, list, state, stats, ps) on top of the state store, the cgroup
// manager and a Launcher that starts processes. The lifecycle logic is
// OS-independent and tested with a fake launcher and a fake cgroupfs; the
// Linux launcher lives in launcher_linux.go.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/SlateGitOrg/minirun/internal/cgroups"
	"github.com/SlateGitOrg/minirun/internal/launch"
	"github.com/SlateGitOrg/minirun/internal/spec"
	"github.com/SlateGitOrg/minirun/internal/state"
)

// Stdio is the standard streams of a container process.
type Stdio struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// Child is a process started by a Launcher that has completed its setup and
// is blocked before execve.
type Child interface {
	Pid() int
	// Start releases the child and returns once it has exec'd the target
	// program (or failed to).
	Start() error
	// Wait blocks until the process exits and returns its exit code
	// (128+signal for a signal death).
	Wait() (int, error)
	// Abort kills and reaps a child that will not be started.
	Abort()
}

// Launcher starts container processes.
type Launcher interface {
	// Check reports whether this launcher can start containers here, so a
	// run can fail before it touches state or cgroups.
	Check() error
	// StartInit creates the container's init process in new namespaces.
	// join is called with the child's pid if the child asks to be moved
	// into its cgroup during setup (needed before it creates a cgroup
	// namespace).
	StartInit(ctx context.Context, plan *launch.Plan, stdio Stdio, join func(pid int) error) (Child, error)
	// StartExec starts an additional process inside the running container
	// whose init has the given pid.
	StartExec(ctx context.Context, plan *launch.Plan, initPid int, proc launch.Process, stdio Stdio) (Child, error)
}

// ErrUnsupported is returned by the launcher on platforms that cannot run
// containers.
var ErrUnsupported = errors.New("running containers requires Linux")

// Lifecycle errors.
var (
	ErrNotRunning = errors.New("container is not running")
	ErrRunning    = errors.New("container is running; stop it first or use --force")
	ErrExecUserNS = errors.New("exec into a container with a user namespace is not supported: Go cannot setns(CLONE_NEWUSER) from a multithreaded process (see docs/THREAT_MODEL.md)")
)

// Runtime ties the pieces together.
type Runtime struct {
	Store      *state.Store
	CgroupFS   cgroups.FS
	CgroupRoot string
	Proc       state.Inspector
	Launcher   Launcher
	// Signal sends a Linux signal number to a host pid.
	Signal func(pid, sig int) error
	// Chown changes ownership of directories handed to a user-namespaced
	// container (overlay upper/work dirs). Defaults to os.Lchown.
	Chown func(path string, uid, gid int) error
	Log   *slog.Logger
	Now   func() time.Time
	// Sleep is used while waiting for processes to die in Delete.
	Sleep func(time.Duration)
}

func (r *Runtime) logger() *slog.Logger {
	if r.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return r.Log
}

func (r *Runtime) now() time.Time {
	if r.Now == nil {
		return time.Now()
	}
	return r.Now()
}

func (r *Runtime) cgroup(path string) (*cgroups.Manager, error) {
	return cgroups.New(r.CgroupFS, r.CgroupRoot, path)
}

// Plan loads a bundle and builds its launch plan without side effects.
func (r *Runtime) Plan(id, bundleDir string) (*launch.Plan, error) {
	if err := state.ValidateID(id); err != nil {
		return nil, err
	}
	b, err := spec.LoadBundle(bundleDir)
	if err != nil {
		return nil, err
	}
	return launch.Build(b, launch.Options{ID: id, StateDir: r.Store.Dir(id), CgroupRoot: r.CgroupRoot})
}

// RunOptions parameterise Run.
type RunOptions struct {
	ID     string
	Bundle string
	Detach bool
	// Remove deletes the container after a foreground run exits.
	Remove bool
	Stdio  Stdio
	// Forward carries signals (Linux numbers) to deliver to the container's
	// init while a foreground run waits.
	Forward <-chan int
}

// Run creates and starts a container. In the foreground it waits for the
// container to exit and returns its exit code; with Detach it returns once
// the container's process has exec'd.
func (r *Runtime) Run(ctx context.Context, o RunOptions) (int, error) {
	plan, err := r.Plan(o.ID, o.Bundle)
	if err != nil {
		return -1, err
	}
	if err := r.Launcher.Check(); err != nil {
		return -1, err
	}
	if err := r.Store.Create(o.ID); err != nil {
		return -1, err
	}
	child, err := r.create(ctx, plan, o)
	if err != nil {
		if rmErr := r.Store.Remove(plan.ID); rmErr != nil {
			r.logger().Warn("cleanup: remove state", "id", plan.ID, "err", rmErr)
		}
		return -1, err
	}
	if o.Detach {
		return 0, nil
	}
	return r.waitForeground(o, plan, child)
}

// create performs everything up to a running process, holding the
// container lock. If it fails after creating the cgroup it removes it again;
// a cgroup that already existed (another container's) is never touched.
func (r *Runtime) create(ctx context.Context, plan *launch.Plan, o RunOptions) (child Child, err error) {
	log := r.logger().With("id", plan.ID)
	unlock, err := r.Store.Lock(plan.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := r.prepareDirs(plan); err != nil {
		return nil, err
	}
	if err := r.Store.WriteJSON(plan.ID, "plan.json", plan); err != nil {
		return nil, err
	}
	st := &state.State{
		OCIVersion:  spec.Version,
		ID:          plan.ID,
		Status:      state.Creating,
		Bundle:      plan.Bundle,
		Annotations: plan.Annotations,
		Created:     r.now().UTC(),
		CgroupRoot:  plan.Cgroup.Root,
		CgroupPath:  plan.Cgroup.Path,
		Detached:    o.Detach,
	}
	if err := r.Store.Save(st); err != nil {
		return nil, err
	}
	cg, err := r.cgroup(plan.Cgroup.Path)
	if err != nil {
		return nil, err
	}
	if err := cg.Create(plan.Cgroup.Controllers); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			if derr := cg.Destroy(); derr != nil {
				log.Warn("cleanup: remove cgroup", "err", derr)
			}
		}
	}()
	if err := cg.Apply(plan.Cgroup.Settings); err != nil {
		return nil, err
	}
	log.Debug("cgroup ready", "path", cg.Path(), "settings", len(plan.Cgroup.Settings))

	stdio := o.Stdio
	if o.Detach {
		console, err := os.OpenFile(r.Store.Dir(plan.ID)+"/console.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open console log: %w", err)
		}
		defer func() { _ = console.Close() }()
		stdio = Stdio{Out: console, Err: console}
	}
	child, err = r.Launcher.StartInit(ctx, plan, stdio, cg.AddProc)
	if err != nil {
		return nil, err
	}
	pid := child.Pid()
	info, err := r.Proc.Info(pid)
	if err != nil {
		child.Abort()
		return nil, fmt.Errorf("inspect init process %d: %w", pid, err)
	}
	st.Pid, st.PidStartTime, st.Status = pid, info.StartTime, state.Created
	if err := r.Store.Save(st); err != nil {
		child.Abort()
		return nil, err
	}
	// Join the cgroup only now, immediately before exec: the init process
	// is a Go program whose runtime threads would otherwise count against a
	// tight pids.max. Migration is never refused by the pids controller.
	if err := cg.AddProc(pid); err != nil {
		child.Abort()
		return nil, err
	}
	if err := child.Start(); err != nil {
		child.Abort()
		return nil, err
	}
	st.Status = state.Running
	if err := r.Store.Save(st); err != nil {
		return nil, err
	}
	log.Info("container started", "pid", pid, "detached", o.Detach)
	return child, nil
}

func (r *Runtime) prepareDirs(plan *launch.Plan) error {
	for _, dir := range []string{plan.Upper, plan.Work, plan.Target} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if !plan.HasUserNS() {
		return nil
	}
	// The overlay is mounted by the container's root, which is an
	// unprivileged host uid; it needs to own the writable layers.
	uid, okU := spec.MapToHost(plan.UIDMappings, 0)
	gid, okG := spec.MapToHost(plan.GIDMappings, 0)
	if !okU || !okG {
		return errors.New("user namespace maps no container root (uid/gid 0); cannot prepare the overlay")
	}
	chown := r.Chown
	if chown == nil {
		chown = os.Lchown
	}
	for _, dir := range []string{plan.Upper, plan.Work, plan.Target} {
		if err := chown(dir, int(uid), int(gid)); err != nil {
			return fmt.Errorf("chown %s: %w", dir, err)
		}
	}
	return nil
}

func (r *Runtime) waitForeground(o RunOptions, plan *launch.Plan, child Child) (int, error) {
	done := make(chan struct{})
	defer close(done)
	if o.Forward != nil {
		go func() {
			for {
				select {
				case sig := <-o.Forward:
					if err := r.Signal(child.Pid(), sig); err != nil {
						r.logger().Warn("forward signal", "sig", sig, "err", err)
					}
				case <-done:
					return
				}
			}
		}()
	}
	code, waitErr := child.Wait()
	if err := r.recordExit(plan, code); err != nil {
		return code, errors.Join(waitErr, err)
	}
	if o.Remove {
		if err := r.Delete(o.ID, false); err != nil {
			return code, errors.Join(waitErr, err)
		}
	}
	return code, waitErr
}

func (r *Runtime) recordExit(plan *launch.Plan, code int) error {
	unlock, err := r.Store.Lock(plan.ID)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := r.Store.Load(plan.ID)
	if err != nil {
		return err
	}
	st.Status = state.Stopped
	st.ExitCode = &code
	if cg, err := r.cgroup(plan.Cgroup.Path); err == nil {
		if stats, err := cg.Stats(); err == nil && stats.OOMKills > 0 {
			st.OOMKilled = true
		}
	}
	r.logger().Info("container exited", "id", plan.ID, "code", code, "oomKilled", st.OOMKilled)
	return r.Store.Save(st)
}

// load reads a container's state and refreshes its live status.
func (r *Runtime) load(id string) (*state.State, error) {
	st, err := r.Store.Load(id)
	if err != nil {
		return nil, err
	}
	st.Status = state.Refresh(st, r.Proc)
	return st, nil
}

// State returns a container's state with its live status.
func (r *Runtime) State(id string) (*state.State, error) { return r.load(id) }

// List returns every container with its live status.
func (r *Runtime) List() ([]*state.State, error) {
	list, err := r.Store.List()
	if err != nil {
		return nil, err
	}
	for _, st := range list {
		st.Status = state.Refresh(st, r.Proc)
	}
	return list, nil
}
