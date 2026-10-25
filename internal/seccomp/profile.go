package seccomp

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/SlateGitOrg/minirun/internal/spec"
)

// SECCOMP_RET_* values from include/uapi/linux/seccomp.h.
const (
	RetKillProcess uint32 = 0x80000000
	RetKillThread  uint32 = 0x00000000
	RetTrap        uint32 = 0x00030000
	RetErrno       uint32 = 0x00050000
	RetTrace       uint32 = 0x7ff00000
	RetLog         uint32 = 0x7ffc0000
	RetAllow       uint32 = 0x7fff0000

	retDataMask   uint32 = 0x0000ffff
	retActionMask uint32 = 0xffff0000
)

// defaultErrno is EPERM, the errno libseccomp and runc use when an ERRNO
// action does not specify one.
const defaultErrno = 1

// maxErrno bounds errnoRet: the kernel only interprets 1..4095 as an errno.
const maxErrno = 4095

// Action is a seccomp verdict, stored as the 32-bit value a filter returns.
type Action uint32

// ParseAction converts an OCI action name and optional errnoRet into an
// Action.
func ParseAction(name string, errnoRet *uint) (Action, error) {
	data := uint32(0)
	if errnoRet != nil {
		if *errnoRet > maxErrno {
			return 0, fmt.Errorf("errnoRet %d out of range 0..%d", *errnoRet, maxErrno)
		}
		data = uint32(*errnoRet)
	}
	switch name {
	case "SCMP_ACT_ALLOW":
		return Action(RetAllow), nil
	case "SCMP_ACT_LOG":
		return Action(RetLog), nil
	case "SCMP_ACT_KILL", "SCMP_ACT_KILL_THREAD":
		return Action(RetKillThread), nil
	case "SCMP_ACT_KILL_PROCESS":
		return Action(RetKillProcess), nil
	case "SCMP_ACT_TRAP":
		return Action(RetTrap), nil
	case "SCMP_ACT_ERRNO":
		if errnoRet == nil {
			data = defaultErrno
		}
		return Action(RetErrno | data), nil
	case "SCMP_ACT_TRACE":
		return Action(RetTrace | data), nil
	case "SCMP_ACT_NOTIFY":
		return 0, errors.New("SCMP_ACT_NOTIFY requires a seccomp agent, which minirun does not implement")
	case "":
		return 0, errors.New("action is required")
	default:
		return 0, fmt.Errorf("unknown action %q", name)
	}
}

// String renders the action in OCI form, e.g. "SCMP_ACT_ERRNO(1)".
func (a Action) String() string {
	v := uint32(a)
	data := v & retDataMask
	switch v & retActionMask {
	case RetKillProcess:
		return "SCMP_ACT_KILL_PROCESS"
	case RetKillThread:
		return "SCMP_ACT_KILL_THREAD"
	case RetTrap:
		return "SCMP_ACT_TRAP"
	case RetErrno:
		return fmt.Sprintf("SCMP_ACT_ERRNO(%d)", data)
	case RetTrace:
		return fmt.Sprintf("SCMP_ACT_TRACE(%d)", data)
	case RetLog:
		return "SCMP_ACT_LOG"
	case RetAllow:
		return "SCMP_ACT_ALLOW"
	default:
		return fmt.Sprintf("SECCOMP_RET(%#08x)", v)
	}
}

// Op is a comparison operator for a syscall argument condition.
type Op int

// Comparison operators, in OCI naming.
const (
	OpEqual Op = iota
	OpNotEqual
	OpLessThan
	OpLessEqual
	OpGreaterThan
	OpGreaterEqual
	OpMaskedEqual
)

var opNames = map[string]Op{
	"SCMP_CMP_EQ":        OpEqual,
	"SCMP_CMP_NE":        OpNotEqual,
	"SCMP_CMP_LT":        OpLessThan,
	"SCMP_CMP_LE":        OpLessEqual,
	"SCMP_CMP_GT":        OpGreaterThan,
	"SCMP_CMP_GE":        OpGreaterEqual,
	"SCMP_CMP_MASKED_EQ": OpMaskedEqual,
}

func (o Op) String() string {
	for name, op := range opNames {
		if op == o {
			return name
		}
	}
	return fmt.Sprintf("Op(%d)", int(o))
}

// Cond is a condition on one syscall argument. Comparisons are unsigned and
// 64-bit, as in libseccomp. For OpMaskedEqual the test is
// (arg & Value) == ValueTwo.
type Cond struct {
	Index    int
	Op       Op
	Value    uint64
	ValueTwo uint64
}

// Matches evaluates the condition against an argument value.
func (c Cond) Matches(arg uint64) bool {
	switch c.Op {
	case OpEqual:
		return arg == c.Value
	case OpNotEqual:
		return arg != c.Value
	case OpLessThan:
		return arg < c.Value
	case OpLessEqual:
		return arg <= c.Value
	case OpGreaterThan:
		return arg > c.Value
	case OpGreaterEqual:
		return arg >= c.Value
	case OpMaskedEqual:
		return arg&c.Value == c.ValueTwo
	default:
		return false
	}
}

// Rule applies Action to calls of Syscall whose arguments satisfy every
// condition in Conds (an empty list always matches).
type Rule struct {
	Syscall string
	Action  Action
	Conds   []Cond
}

// Profile is a validated, normalised seccomp profile.
//
// Semantics, for a call to syscall S with arguments A:
//  1. the conditional rules for S are tried in profile order and the first
//     whose conditions all hold decides the action;
//  2. otherwise the unconditional rule for S (at most one), if any;
//  3. otherwise DefaultAction.
//
// A call from an architecture outside the compiled one is killed
// (SCMP_ACT_KILL_PROCESS) before any rule is consulted.
type Profile struct {
	DefaultAction Action
	// Architectures lists the libseccomp names from the profile. It is
	// informational: a program is always compiled for one Arch.
	Architectures []string
	// Flags is the bitmask passed to seccomp(SECCOMP_SET_MODE_FILTER).
	Flags uint
	Rules []Rule
}

// Filter flags accepted in linux.seccomp.flags.
var flagValues = map[string]uint{
	"SECCOMP_FILTER_FLAG_TSYNC":      1,
	"SECCOMP_FILTER_FLAG_LOG":        2,
	"SECCOMP_FILTER_FLAG_SPEC_ALLOW": 4,
}

// FromSpec validates an OCI seccomp object and converts it to a Profile.
func FromSpec(s *spec.Seccomp) (*Profile, error) {
	if s == nil {
		return nil, errors.New("seccomp: profile is nil")
	}
	var errs []error
	def, err := ParseAction(s.DefaultAction, s.DefaultErrnoRet)
	if err != nil {
		errs = append(errs, fmt.Errorf("defaultAction: %w", err))
	}
	p := &Profile{DefaultAction: def}
	for _, a := range s.Architectures {
		if _, ok := archByName[a]; !ok && !knownForeignArches[a] {
			errs = append(errs, fmt.Errorf("architectures: unknown architecture %q", a))
		}
		p.Architectures = append(p.Architectures, a)
	}
	for _, f := range s.Flags {
		v, ok := flagValues[f]
		if !ok {
			errs = append(errs, fmt.Errorf("flags: unsupported flag %q", f))
			continue
		}
		p.Flags |= v
	}
	unconditional := map[string]Action{}
	for i, sc := range s.Syscalls {
		act, err := ParseAction(sc.Action, sc.ErrnoRet)
		if err != nil {
			errs = append(errs, fmt.Errorf("syscalls[%d]: %w", i, err))
			continue
		}
		if len(sc.Names) == 0 {
			errs = append(errs, fmt.Errorf("syscalls[%d]: names must not be empty", i))
			continue
		}
		conds, err := parseConds(sc.Args)
		if err != nil {
			errs = append(errs, fmt.Errorf("syscalls[%d]: %w", i, err))
			continue
		}
		for _, name := range sc.Names {
			if name == "" || strings.ContainsAny(name, " \t") {
				errs = append(errs, fmt.Errorf("syscalls[%d]: invalid syscall name %q", i, name))
				continue
			}
			if len(conds) == 0 {
				if prev, dup := unconditional[name]; dup && prev != act {
					errs = append(errs, fmt.Errorf("syscalls[%d]: %s already has unconditional action %v, cannot also be %v", i, name, prev, act))
					continue
				} else if dup {
					continue
				}
				unconditional[name] = act
			}
			p.Rules = append(p.Rules, Rule{Syscall: name, Action: act, Conds: conds})
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("seccomp: %w", err)
	}
	return p, nil
}

func parseConds(args []spec.Arg) ([]Cond, error) {
	conds := make([]Cond, 0, len(args))
	for j, a := range args {
		if a.Index > 5 {
			return nil, fmt.Errorf("args[%d]: index %d out of range 0..5", j, a.Index)
		}
		op, ok := opNames[a.Op]
		if !ok {
			return nil, fmt.Errorf("args[%d]: unknown operator %q", j, a.Op)
		}
		conds = append(conds, Cond{Index: int(a.Index), Op: op, Value: a.Value, ValueTwo: a.ValueTwo})
	}
	return conds, nil
}

// syscallRules groups a profile's rules per syscall name: conditional rules
// in profile order, then the unconditional one if present.
type syscallRules struct {
	conditional   []Rule
	unconditional *Action
}

func (p *Profile) bySyscall() map[string]*syscallRules {
	out := map[string]*syscallRules{}
	for _, r := range p.Rules {
		sr := out[r.Syscall]
		if sr == nil {
			sr = &syscallRules{}
			out[r.Syscall] = sr
		}
		if len(r.Conds) == 0 {
			act := r.Action
			sr.unconditional = &act
		} else {
			sr.conditional = append(sr.conditional, r)
		}
	}
	return out
}

// SyscallNames returns the distinct syscall names the profile mentions,
// sorted.
func (p *Profile) SyscallNames() []string {
	seen := map[string]bool{}
	var names []string
	for _, r := range p.Rules {
		if !seen[r.Syscall] {
			seen[r.Syscall] = true
			names = append(names, r.Syscall)
		}
	}
	sort.Strings(names)
	return names
}
