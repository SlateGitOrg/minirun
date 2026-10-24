// Package signals parses signal names and numbers using the Linux numbering
// (which differs from macOS and the BSDs), so the CLI behaves the same on
// every host it is built for.
package signals

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Linux signal numbers for x86-64 and arm64 (asm-generic/signal.h).
var linux = map[string]int{
	"HUP": 1, "INT": 2, "QUIT": 3, "ILL": 4, "TRAP": 5, "ABRT": 6, "IOT": 6, "BUS": 7,
	"FPE": 8, "KILL": 9, "USR1": 10, "SEGV": 11, "USR2": 12, "PIPE": 13, "ALRM": 14,
	"TERM": 15, "STKFLT": 16, "CHLD": 17, "CONT": 18, "STOP": 19, "TSTP": 20,
	"TTIN": 21, "TTOU": 22, "URG": 23, "XCPU": 24, "XFSZ": 25, "VTALRM": 26,
	"PROF": 27, "WINCH": 28, "IO": 29, "POLL": 29, "PWR": 30, "SYS": 31,
}

// Real-time signal range on Linux (glibc reserves 32 and 33 internally, but
// the kernel accepts them; minirun follows the kernel).
const (
	rtMin = 32
	rtMax = 64
)

// Parse converts "TERM", "SIGTERM", "sigterm", "15", "RTMIN+2" or
// "SIGRTMAX-1" to a Linux signal number.
func Parse(s string) (int, error) {
	if n, err := strconv.Atoi(s); err == nil {
		if n < 1 || n > rtMax {
			return 0, fmt.Errorf("signal %d out of range 1..%d", n, rtMax)
		}
		return n, nil
	}
	name := strings.TrimPrefix(strings.ToUpper(s), "SIG")
	if n, ok := linux[name]; ok {
		return n, nil
	}
	if n, ok := parseRealtime(name); ok {
		return n, nil
	}
	return 0, fmt.Errorf("unknown signal %q", s)
}

func parseRealtime(name string) (int, bool) {
	base, rest, sign := 0, "", 1
	switch {
	case strings.HasPrefix(name, "RTMIN"):
		base, rest = rtMin, strings.TrimPrefix(name, "RTMIN")
	case strings.HasPrefix(name, "RTMAX"):
		base, rest, sign = rtMax, strings.TrimPrefix(name, "RTMAX"), -1
	default:
		return 0, false
	}
	if rest == "" {
		return base, true
	}
	want := "+"
	if sign < 0 {
		want = "-"
	}
	if !strings.HasPrefix(rest, want) {
		return 0, false
	}
	off, err := strconv.Atoi(rest[1:])
	if err != nil || off < 0 || off > rtMax-rtMin {
		return 0, false
	}
	return base + sign*off, true
}

// Name returns the conventional name of a Linux signal number.
func Name(n int) string {
	var names []string
	for k, v := range linux {
		if v == n {
			names = append(names, k)
		}
	}
	if len(names) > 0 {
		sort.Strings(names)
		return "SIG" + names[0]
	}
	if n >= rtMin && n <= rtMax {
		return fmt.Sprintf("SIGRTMIN+%d", n-rtMin)
	}
	return fmt.Sprintf("SIG%d", n)
}
