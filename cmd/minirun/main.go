// Command minirun is a minimal OCI-style container runtime for Linux.
package main

import (
	"context"
	"fmt"
	"os"
	goruntime "runtime"

	"github.com/archit2501/minirun/internal/cli"
	"github.com/archit2501/minirun/internal/sandbox"
)

// The container init and exec helper are this same binary re-executed with
// a hidden first argument. They must run on a single, locked OS thread from
// the very start: namespace, credential, capability and seccomp changes are
// per-thread, and the final execve must come from that thread.
func init() {
	if len(os.Args) > 1 && (os.Args[1] == "__init" || os.Args[1] == "__exec") {
		goruntime.GOMAXPROCS(1)
		goruntime.LockOSThread()
	}
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "__init":
			_ = sandbox.RunInit() // already reported to the parent
			os.Exit(1)
		case "__exec":
			_ = sandbox.RunExec()
			os.Exit(1)
		}
	}
	code := cli.New().Run(context.Background(), os.Args[1:])
	if code < 0 || code > 255 {
		fmt.Fprintf(os.Stderr, "minirun: exit code %d out of range\n", code)
		code = 1
	}
	os.Exit(code)
}
