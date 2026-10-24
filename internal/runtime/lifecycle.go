package runtime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/archit2501/minirun/internal/cgroups"
	"github.com/archit2501/minirun/internal/launch"
	"github.com/archit2501/minirun/internal/signals"
	"github.com/archit2501/minirun/internal/state"
)

// ExecOptions parameterise Exec.
type ExecOptions struct {
	ID   string
	Args []string
	// Env entries (KEY=value) override the container's environment.
	Env []string
	// Cwd overrides the container's working directory when set.
	Cwd string
	// User overrides the uid:gid when non-nil.
	User  *[2]uint32
	Stdio Stdio
}

// Exec runs an additional process inside a running container, in its
// namespaces and cgroup and under the same capabilities, rlimits and seccomp
// filter as the container's init, and returns its exit code.
func (r *Runtime) Exec(ctx context.Context, o ExecOptions) (int, error) {
	if len(o.Args) == 0 {
		return -1, errors.New("exec: a command is required")
	}
	st, err := r.load(o.ID)
	if err != nil {
		return -1, err
	}
	if st.Status != state.Running {
		return -1, fmt.Errorf("%s: %w (status %s)", o.ID, ErrNotRunning, st.Status)
	}
	var plan launch.Plan
	if err := r.Store.ReadJSON(o.ID, "plan.json", &plan); err != nil {
		return -1, err
	}
	if plan.HasUserNS() {
		return -1, ErrExecUserNS
	}
	proc := plan.Process
	proc.Args = o.Args
	proc.Env = MergeEnv(plan.Process.Env, o.Env)
	if o.Cwd != "" {
		proc.Cwd = o.Cwd
	}
	if o.User != nil {
		proc.UID, proc.GID = o.User[0], o.User[1]
		proc.AdditionalGids = nil
	}
	cg, err := r.cgroup(st.CgroupPath)
	if err != nil {
		return -1, err
	}
	child, err := r.Launcher.StartExec(ctx, &plan, st.Pid, proc, o.Stdio)
	if err != nil {
		return -1, err
	}
	if err := cg.AddProc(child.Pid()); err != nil {
		child.Abort()
		return -1, err
	}
	if err := child.Start(); err != nil {
		child.Abort()
		return -1, err
	}
	r.logger().Info("exec started", "id", o.ID, "pid", child.Pid(), "args", strings.Join(o.Args, " "))
	return child.Wait()
}

// MergeEnv returns base with entries from extra replacing same-named keys
// and new keys appended in order.
func MergeEnv(base, extra []string) []string {
	out := slices.Clone(base)
	for _, e := range extra {
		key, _, _ := strings.Cut(e, "=")
		replaced := false
		for i, b := range out {
			if k, _, _ := strings.Cut(b, "="); k == key {
				out[i] = e
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, e)
		}
	}
	return out
}

// Kill sends a signal to the container's init process, or with all to
// every process in its cgroup.
func (r *Runtime) Kill(id string, sig int, all bool) error {
	unlock, err := r.Store.Lock(id)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := r.load(id)
	if err != nil {
		return err
	}
	if st.Status != state.Running && st.Status != state.Created {
		return fmt.Errorf("%s: %w (status %s)", id, ErrNotRunning, st.Status)
	}
	r.logger().Info("signalling container", "id", id, "signal", signals.Name(sig), "all", all)
	if !all {
		return r.Signal(st.Pid, sig)
	}
	cg, err := r.cgroup(st.CgroupPath)
	if err != nil {
		return err
	}
	pids, err := cg.Procs()
	if err != nil {
		return err
	}
	var errs []error
	for _, pid := range pids {
		if err := r.Signal(pid, sig); err != nil {
			errs = append(errs, fmt.Errorf("signal %d: %w", pid, err))
		}
	}
	return errors.Join(errs...)
}

// sigkill is SIGKILL on Linux.
const sigkill = 9

// deleteTimeout bounds how long Delete waits for killed processes to leave
// the cgroup.
const deleteTimeout = 5 * time.Second

// Delete removes a stopped container's cgroup and state. With force, a
// running container is killed first.
func (r *Runtime) Delete(id string, force bool) error {
	unlock, err := r.Store.Lock(id)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := r.load(id)
	if err != nil {
		return err
	}
	cg, err := r.cgroup(st.CgroupPath)
	if err != nil {
		return err
	}
	if st.Status == state.Running || st.Status == state.Created {
		if !force {
			return fmt.Errorf("%s: %w", id, ErrRunning)
		}
		if err := r.killAll(cg, st.Pid); err != nil {
			return err
		}
	}
	if err := r.destroyCgroup(cg); err != nil {
		return err
	}
	if err := r.Store.Remove(id); err != nil {
		return err
	}
	r.logger().Info("container deleted", "id", id)
	return nil
}

// killAll SIGKILLs every process of the container, preferring cgroup.kill
// (atomic, Linux 5.14+) and falling back to signalling each listed pid.
func (r *Runtime) killAll(cg *cgroups.Manager, initPid int) error {
	err := cg.Kill()
	switch {
	case err == nil:
	case errors.Is(err, cgroups.ErrKillUnsupported):
		pids, perr := cg.Procs()
		if perr != nil {
			return perr
		}
		for _, pid := range pids {
			_ = r.Signal(pid, sigkill)
		}
	case errors.Is(err, cgroups.ErrNotFound):
		// No cgroup left; the init process is all there is.
		return r.Signal(initPid, sigkill)
	default:
		return err
	}
	return nil
}

// destroyCgroup removes the cgroup, retrying while killed processes are
// still exiting.
func (r *Runtime) destroyCgroup(cg *cgroups.Manager) error {
	sleep := r.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	const step = 50 * time.Millisecond
	var err error
	for waited := time.Duration(0); waited <= deleteTimeout; waited += step {
		if err = cg.Destroy(); err == nil {
			return nil
		}
		sleep(step)
	}
	return fmt.Errorf("cgroup still busy after %v: %w", deleteTimeout, err)
}

// Stats returns the container's cgroup counters.
func (r *Runtime) Stats(id string) (cgroups.Stats, error) {
	st, err := r.Store.Load(id)
	if err != nil {
		return cgroups.Stats{}, err
	}
	cg, err := r.cgroup(st.CgroupPath)
	if err != nil {
		return cgroups.Stats{}, err
	}
	return cg.Stats()
}

// Processes lists the host pids in the container's cgroup.
func (r *Runtime) Processes(id string) ([]int, error) {
	st, err := r.Store.Load(id)
	if err != nil {
		return nil, err
	}
	cg, err := r.cgroup(st.CgroupPath)
	if err != nil {
		return nil, err
	}
	return cg.Procs()
}
