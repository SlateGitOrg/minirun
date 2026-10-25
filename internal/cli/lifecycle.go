package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/SlateGitOrg/minirun/internal/runtime"
	"github.com/SlateGitOrg/minirun/internal/signals"
)

// forwardSignals relays the signals a terminal user sends to the foreground
// minirun process to the container, using Linux signal numbers.
func forwardSignals() (<-chan int, func()) {
	in := make(chan os.Signal, 8)
	out := make(chan int, 8)
	signal.Notify(in, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-in:
				// Forwarding only happens on Linux, where syscall.Signal
				// values are the Linux numbers the runtime expects.
				if sig, ok := s.(syscall.Signal); ok {
					out <- int(sig)
				}
			case <-done:
				return
			}
		}
	}()
	return out, func() {
		signal.Stop(in)
		close(done)
	}
}

func oneID(args []string, cmd string) (string, error) {
	if len(args) != 1 {
		return "", usagef("%s takes exactly one container id", cmd)
	}
	return args[0], nil
}

func cmdRun(a *App, ctx context.Context, g Globals, log *slog.Logger, args []string) error {
	fs := a.newFlags("run", "[--bundle DIR] [-d] [--rm] ID")
	bundle := fs.String("bundle", ".", "bundle directory")
	detach := fs.Bool("d", false, "detach: return once the container is running (output goes to <state>/<id>/console.log)")
	remove := fs.Bool("rm", false, "delete the container after it exits (foreground only)")
	rest, err := parse(fs, args, 0)
	if err != nil {
		return err
	}
	id, err := oneID(rest, "run")
	if err != nil {
		return err
	}
	if *detach && *remove {
		return usagef("--rm cannot be combined with -d")
	}
	rt := a.NewRuntime(g, log)
	o := runtime.RunOptions{ID: id, Bundle: *bundle, Detach: *detach, Remove: *remove,
		Stdio: runtime.Stdio{In: a.Stdin, Out: a.Stdout, Err: a.Stderr}}
	if !*detach && a.ForwardSignals != nil {
		ch, stop := a.ForwardSignals()
		defer stop()
		o.Forward = ch
	}
	code, err := rt.Run(ctx, o)
	if err != nil {
		return err
	}
	if *detach {
		_, err := fmt.Fprintln(a.Stdout, id)
		return err
	}
	if code != 0 {
		return exitError{code}
	}
	return nil
}

func cmdExec(a *App, ctx context.Context, g Globals, log *slog.Logger, args []string) error {
	fs := a.newFlags("exec", "[--env K=V]... [--cwd DIR] [--user UID[:GID]] ID [--] COMMAND [ARG...]")
	var env multiFlag
	fs.Var(&env, "env", "set an environment variable (repeatable)")
	cwd := fs.String("cwd", "", "working directory inside the container")
	user := fs.String("user", "", "run as UID[:GID] (container ids)")
	rest, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if len(rest) < 2 {
		return usagef("exec needs a container id and a command")
	}
	for _, e := range env {
		if k, _, ok := strings.Cut(e, "="); !ok || k == "" {
			return usagef("--env %q: expected KEY=value", e)
		}
	}
	o := runtime.ExecOptions{ID: rest[0], Args: rest[1:], Env: env, Cwd: *cwd,
		Stdio: runtime.Stdio{In: a.Stdin, Out: a.Stdout, Err: a.Stderr}}
	if *user != "" {
		ids, err := parseUser(*user)
		if err != nil {
			return usageError{err.Error()}
		}
		o.User = &ids
	}
	code, err := a.NewRuntime(g, log).Exec(ctx, o)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitError{code}
	}
	return nil
}

func parseUser(s string) ([2]uint32, error) {
	us, gs, hasGID := strings.Cut(s, ":")
	uid, err := strconv.ParseUint(us, 10, 32)
	if err != nil {
		return [2]uint32{}, fmt.Errorf("--user %q: uid must be a number", s)
	}
	gid := uid
	if hasGID {
		if gid, err = strconv.ParseUint(gs, 10, 32); err != nil {
			return [2]uint32{}, fmt.Errorf("--user %q: gid must be a number", s)
		}
	}
	return [2]uint32{uint32(uid), uint32(gid)}, nil
}

func cmdPs(a *App, _ context.Context, g Globals, log *slog.Logger, args []string) error {
	fs := a.newFlags("ps", "[--json] [ID]")
	asJSON := fs.Bool("json", false, "print JSON")
	rest, err := parse(fs, args, 0)
	if err != nil {
		return err
	}
	rt := a.NewRuntime(g, log)
	if len(rest) > 1 {
		return usagef("ps takes at most one container id")
	}
	if len(rest) == 1 {
		pids, err := rt.Processes(rest[0])
		if err != nil {
			return err
		}
		if *asJSON {
			return writeJSON(a, pids)
		}
		for _, pid := range pids {
			if _, err := fmt.Fprintln(a.Stdout, pid); err != nil {
				return err
			}
		}
		return nil
	}
	list, err := rt.List()
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a, list)
	}
	// tabwriter buffers everything; write errors surface from Flush.
	tw := tabwriter.NewWriter(a.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tPID\tSTATUS\tEXIT\tCREATED\tBUNDLE")
	for _, st := range list {
		exit := "-"
		if st.ExitCode != nil {
			exit = strconv.Itoa(*st.ExitCode)
			if st.OOMKilled {
				exit += " (oom)"
			}
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", st.ID, st.Pid, st.Status, exit, st.Created.Format(time.RFC3339), st.Bundle)
	}
	return tw.Flush()
}

func writeJSON(a *App, v any) error {
	enc := json.NewEncoder(a.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func cmdState(a *App, _ context.Context, g Globals, log *slog.Logger, args []string) error {
	fs := a.newFlags("state", "ID")
	rest, err := parse(fs, args, 0)
	if err != nil {
		return err
	}
	id, err := oneID(rest, "state")
	if err != nil {
		return err
	}
	st, err := a.NewRuntime(g, log).State(id)
	if err != nil {
		return err
	}
	return writeJSON(a, st)
}

func cmdStats(a *App, _ context.Context, g Globals, log *slog.Logger, args []string) error {
	fs := a.newFlags("stats", "ID")
	rest, err := parse(fs, args, 0)
	if err != nil {
		return err
	}
	id, err := oneID(rest, "stats")
	if err != nil {
		return err
	}
	stats, err := a.NewRuntime(g, log).Stats(id)
	if err != nil {
		return err
	}
	return writeJSON(a, stats)
}

func cmdKill(a *App, _ context.Context, g Globals, log *slog.Logger, args []string) error {
	fs := a.newFlags("kill", "[--all] ID [SIGNAL]")
	all := fs.Bool("all", false, "signal every process in the container's cgroup")
	rest, err := parse(fs, args, 0)
	if err != nil {
		return err
	}
	if len(rest) < 1 || len(rest) > 2 {
		return usagef("kill takes a container id and an optional signal")
	}
	sig := 15
	if len(rest) == 2 {
		if sig, err = signals.Parse(rest[1]); err != nil {
			return usageError{err.Error()}
		}
	}
	return a.NewRuntime(g, log).Kill(rest[0], sig, *all)
}

func cmdDelete(a *App, _ context.Context, g Globals, log *slog.Logger, args []string) error {
	fs := a.newFlags("delete", "[-f] ID")
	force := fs.Bool("f", false, "kill the container first if it is running")
	rest, err := parse(fs, args, 0)
	if err != nil {
		return err
	}
	id, err := oneID(rest, "delete")
	if err != nil {
		return err
	}
	return a.NewRuntime(g, log).Delete(id, *force)
}
