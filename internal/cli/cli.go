// Package cli implements the minirun command line. Commands are plain
// functions over an App value whose I/O and runtime construction are
// injectable, so the whole CLI is exercised in-process by tests.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/archit2501/minirun/internal/cgroups"
	"github.com/archit2501/minirun/internal/runtime"
	"github.com/archit2501/minirun/internal/state"
)

// Version is the minirun version, overridable at link time.
var Version = "0.1.0"

// Globals are the options accepted before the command name.
type Globals struct {
	Root       string
	CgroupRoot string
	ProcRoot   string
	LogLevel   string
	LogFormat  string
}

// App is one CLI invocation's environment.
type App struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// NewRuntime builds the runtime for the given globals. Tests replace it
	// to inject fakes.
	NewRuntime func(g Globals, log *slog.Logger) *runtime.Runtime
	// ForwardSignals starts relaying terminal signals during a foreground
	// run and returns the channel plus a stop function.
	ForwardSignals func() (<-chan int, func())
}

// New returns an App wired to the real process environment.
func New() *App {
	return &App{
		Stdin:          os.Stdin,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		NewRuntime:     defaultRuntime,
		ForwardSignals: forwardSignals,
	}
}

func defaultRuntime(g Globals, log *slog.Logger) *runtime.Runtime {
	return &runtime.Runtime{
		Store:      &state.Store{Root: g.Root},
		CgroupFS:   cgroups.OSFS{},
		CgroupRoot: g.CgroupRoot,
		Proc:       state.ProcFS{Root: g.ProcRoot},
		Launcher:   runtime.NewLauncher(),
		Signal:     runtime.SignalFunc(),
		Log:        log,
	}
}

type command struct {
	name    string
	summary string
	run     func(a *App, ctx context.Context, g Globals, log *slog.Logger, args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"spec", "write a default config.json for a bundle", cmdSpec},
		{"validate", "check a bundle's config and list ignored keys", cmdValidate},
		{"plan", "show every step a launch would take, without running anything", cmdPlan},
		{"seccomp", "compile, disassemble and test a bundle's seccomp profile", cmdSeccomp},
		{"run", "create and start a container", cmdRun},
		{"exec", "run a command in a running container", cmdExec},
		{"ps", "list containers, or the processes of one container", cmdPs},
		{"state", "print a container's state as JSON", cmdState},
		{"stats", "print a container's cgroup counters as JSON", cmdStats},
		{"kill", "send a signal to a container", cmdKill},
		{"delete", "remove a stopped container", cmdDelete},
		{"version", "print the version", cmdVersion},
	}
}

// exitError carries a specific exit status (a container's exit code).
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// usageError marks errors caused by bad command-line usage (exit 2).
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return usageError{fmt.Sprintf(format, args...)} }

// Run executes the command line and returns the process exit status.
func (a *App) Run(ctx context.Context, args []string) int {
	g := Globals{Root: state.DefaultRoot, CgroupRoot: cgroups.DefaultRoot, ProcRoot: "/proc", LogLevel: "warn", LogFormat: "text"}
	fs := flag.NewFlagSet("minirun", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	fs.StringVar(&g.Root, "root", g.Root, "state directory")
	fs.StringVar(&g.CgroupRoot, "cgroup-root", g.CgroupRoot, "cgroup v2 mount point")
	fs.StringVar(&g.ProcRoot, "proc-root", g.ProcRoot, "procfs mount used to inspect processes")
	fs.StringVar(&g.LogLevel, "log-level", g.LogLevel, "debug, info, warn or error")
	fs.StringVar(&g.LogFormat, "log-format", g.LogFormat, "text or json")
	fs.Usage = func() { a.usage(fs) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		a.usage(fs)
		return 2
	}
	log, err := newLogger(a.Stderr, g.LogLevel, g.LogFormat)
	if err != nil {
		a.errorf("minirun: %v\n", err)
		return 2
	}
	for _, c := range commands {
		if c.name != rest[0] {
			continue
		}
		err := c.run(a, ctx, g, log, rest[1:])
		return a.report(c.name, err)
	}
	a.errorf("minirun: unknown command %q\n", rest[0])
	a.usage(fs)
	return 2
}

func (a *App) report(name string, err error) int {
	var ee exitError
	var ue usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.code
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &ue):
		a.errorf("minirun %s: %v\n", name, err)
		return 2
	default:
		a.errorf("minirun %s: %v\n", name, err)
		return 1
	}
}

// errorf writes a diagnostic to stderr. A failure to write a diagnostic has
// nowhere to be reported, so it is ignored.
func (a *App) errorf(format string, args ...any) {
	_, _ = fmt.Fprintf(a.Stderr, format, args...)
}

func (a *App) usage(fs *flag.FlagSet) {
	a.errorf("usage: minirun [global flags] <command> [flags] [args]\n\ncommands:\n")
	names := make([]string, 0, len(commands))
	byName := map[string]string{}
	for _, c := range commands {
		names = append(names, c.name)
		byName[c.name] = c.summary
	}
	sort.Strings(names)
	for _, n := range names {
		a.errorf("  %-9s %s\n", n, byName[n])
	}
	a.errorf("\nglobal flags:\n")
	fs.PrintDefaults()
}

func newLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid --log-level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lv}
	switch strings.ToLower(format) {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid --log-format %q (text or json)", format)
	}
}

// newFlags creates a subcommand flag set that reports errors through the
// App's stderr.
func (a *App) newFlags(name, args string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	fs.Usage = func() {
		a.errorf("usage: minirun %s %s\n", name, args)
		fs.PrintDefaults()
	}
	return fs
}

// parse parses flags, allowing them to appear between positional arguments
// (`minirun kill c1 --all`), and returns the positional arguments. "--"
// ends flag parsing. Once stopAfter positional arguments have been seen
// (if stopAfter > 0), everything that follows is returned verbatim, so
// `minirun exec c1 sh -c 'echo hi'` passes "-c" to sh.
func parse(fs *flag.FlagSet, args []string, stopAfter int) ([]string, error) {
	var positional []string
	for {
		dashdash := slices.Index(args, "--")
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageError{err.Error()}
		}
		rest := fs.Args()
		if consumed := len(args) - len(rest); dashdash >= 0 && dashdash < consumed {
			return append(positional, rest...), nil // flag consumed "--"
		}
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
		if stopAfter > 0 && len(positional) == stopAfter {
			if len(args) > 0 && args[0] == "--" {
				args = args[1:]
			}
			return append(positional, args...), nil
		}
	}
}

func cmdVersion(a *App, _ context.Context, _ Globals, _ *slog.Logger, args []string) error {
	if len(args) != 0 {
		return usagef("version takes no arguments")
	}
	_, err := fmt.Fprintf(a.Stdout, "minirun %s (OCI runtime-spec subset %s)\n", Version, specVersion())
	return err
}
