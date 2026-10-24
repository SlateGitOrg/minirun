// Package caps converts between Linux capability names and bitmasks and
// applies the five capability sets (bounding, effective, permitted,
// inheritable, ambient) to a thread.
package caps

import (
	"bufio"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strconv"
	"strings"

	"github.com/archit2501/minirun/internal/spec"
)

// names lists capabilities by number (include/uapi/linux/capability.h).
var names = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_DAC_READ_SEARCH",
	"CAP_FOWNER",
	"CAP_FSETID",
	"CAP_KILL",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE",
	"CAP_NET_BROADCAST",
	"CAP_NET_ADMIN",
	"CAP_NET_RAW",
	"CAP_IPC_LOCK",
	"CAP_IPC_OWNER",
	"CAP_SYS_MODULE",
	"CAP_SYS_RAWIO",
	"CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE",
	"CAP_SYS_PACCT",
	"CAP_SYS_ADMIN",
	"CAP_SYS_BOOT",
	"CAP_SYS_NICE",
	"CAP_SYS_RESOURCE",
	"CAP_SYS_TIME",
	"CAP_SYS_TTY_CONFIG",
	"CAP_MKNOD",
	"CAP_LEASE",
	"CAP_AUDIT_WRITE",
	"CAP_AUDIT_CONTROL",
	"CAP_SETFCAP",
	"CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN",
	"CAP_SYSLOG",
	"CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND",
	"CAP_AUDIT_READ",
	"CAP_PERFMON",
	"CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

// Last is the highest capability number minirun knows.
var Last = len(names) - 1

var byName = func() map[string]int {
	m := make(map[string]int, len(names))
	for i, n := range names {
		m[n] = i
	}
	return m
}()

// Set is a capability bitmask; bit n is capability n.
type Set uint64

// Lookup returns the number of a capability. The "CAP_" prefix and case are
// optional, so "net_raw" and "CAP_NET_RAW" are equivalent.
func Lookup(name string) (int, bool) {
	n := strings.ToUpper(name)
	if !strings.HasPrefix(n, "CAP_") {
		n = "CAP_" + n
	}
	c, ok := byName[n]
	return c, ok
}

// Name returns the canonical name of capability c.
func Name(c int) string {
	if c >= 0 && c < len(names) {
		return names[c]
	}
	return "CAP_" + strconv.Itoa(c)
}

// Parse converts capability names to a Set, rejecting unknown names.
func Parse(list []string) (Set, error) {
	var s Set
	var unknown []string
	for _, n := range list {
		c, ok := Lookup(n)
		if !ok {
			unknown = append(unknown, n)
			continue
		}
		s |= 1 << uint(c)
	}
	if len(unknown) > 0 {
		return 0, fmt.Errorf("unknown capabilities: %s", strings.Join(unknown, ", "))
	}
	return s, nil
}

// Has reports whether capability c is in s.
func (s Set) Has(c int) bool { return c >= 0 && c < 64 && s&(1<<uint(c)) != 0 }

// Names returns the capability names in s, in numeric order.
func (s Set) Names() []string {
	out := make([]string, 0, bits.OnesCount64(uint64(s)))
	for c := range 64 {
		if s.Has(c) {
			out = append(out, Name(c))
		}
	}
	return out
}

// Hex formats s the way /proc/<pid>/status prints capability masks.
func (s Set) Hex() string { return fmt.Sprintf("%016x", uint64(s)) }

// Upto returns s restricted to capabilities 0..last.
func (s Set) Upto(last int) Set {
	if last >= 63 {
		return s
	}
	return s & (1<<uint(last+1) - 1)
}

// Sets holds the five per-thread capability sets.
type Sets struct {
	Bounding    Set `json:"bounding"`
	Effective   Set `json:"effective"`
	Permitted   Set `json:"permitted"`
	Inheritable Set `json:"inheritable"`
	Ambient     Set `json:"ambient"`
}

// FromSpec converts process.capabilities to Sets. A nil value means "no
// capabilities at all". It checks the invariants capset(2) and
// PR_CAP_AMBIENT_RAISE would otherwise reject with a bare EPERM (effective is
// a subset of permitted; ambient is a subset of permitted and inheritable),
// plus one policy rule: permitted must lie inside the bounding set, so a
// config cannot keep a capability it has also asked to drop.
func FromSpec(c *spec.Capabilities) (Sets, error) {
	if c == nil {
		return Sets{}, nil
	}
	var s Sets
	var errs []error
	for _, f := range []struct {
		field string
		in    []string
		out   *Set
	}{
		{"bounding", c.Bounding, &s.Bounding},
		{"effective", c.Effective, &s.Effective},
		{"permitted", c.Permitted, &s.Permitted},
		{"inheritable", c.Inheritable, &s.Inheritable},
		{"ambient", c.Ambient, &s.Ambient},
	} {
		v, err := Parse(f.in)
		if err != nil {
			errs = append(errs, fmt.Errorf("process.capabilities.%s: %w", f.field, err))
		}
		*f.out = v
	}
	if err := errors.Join(errs...); err != nil {
		return Sets{}, err
	}
	if extra := s.Effective &^ s.Permitted; extra != 0 {
		errs = append(errs, fmt.Errorf("process.capabilities: effective has capabilities not in permitted: %s", strings.Join(extra.Names(), ", ")))
	}
	if extra := s.Ambient &^ (s.Permitted & s.Inheritable); extra != 0 {
		errs = append(errs, fmt.Errorf("process.capabilities: ambient capabilities must also be permitted and inheritable: %s", strings.Join(extra.Names(), ", ")))
	}
	if extra := s.Permitted &^ s.Bounding; extra != 0 {
		errs = append(errs, fmt.Errorf("process.capabilities: permitted has capabilities outside the bounding set: %s", strings.Join(extra.Names(), ", ")))
	}
	return s, errors.Join(errs...)
}

// Status is the capability section of /proc/<pid>/status.
type Status struct {
	Inheritable, Permitted, Effective, Bounding, Ambient Set
}

// ParseStatus extracts the Cap* lines from the text of /proc/<pid>/status.
func ParseStatus(text string) (Status, error) {
	var st Status
	fields := map[string]*Set{
		"CapInh": &st.Inheritable,
		"CapPrm": &st.Permitted,
		"CapEff": &st.Effective,
		"CapBnd": &st.Bounding,
		"CapAmb": &st.Ambient,
	}
	found := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		dst, want := fields[key]
		if !ok || !want {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(val), 16, 64)
		if err != nil {
			return Status{}, fmt.Errorf("parse %s: %w", key, err)
		}
		*dst = Set(v)
		found[key] = true
	}
	if len(found) != len(fields) {
		var missing []string
		for k := range fields {
			if !found[k] {
				missing = append(missing, k)
			}
		}
		sort.Strings(missing)
		return Status{}, fmt.Errorf("status is missing %s", strings.Join(missing, ", "))
	}
	return st, nil
}
