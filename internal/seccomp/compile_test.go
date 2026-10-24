package seccomp

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archit2501/minirun/internal/spec"
)

var update = os.Getenv("UPDATE_GOLDEN") == "1"

func mustProfile(t testing.TB, s *spec.Seccomp) *Profile {
	t.Helper()
	p, err := FromSpec(s)
	if err != nil {
		t.Fatalf("FromSpec: %v", err)
	}
	return p
}

func mustCompile(t testing.TB, p *Profile, a *Arch) *Program {
	t.Helper()
	prog, err := Compile(p, a)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if err := Validate(prog.Instructions); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return prog
}

func call(t testing.TB, a *Arch, name string, args ...uint64) Data {
	t.Helper()
	nr, ok := a.Syscall(name)
	if !ok {
		t.Fatalf("%s has no syscall %s", a.Name, name)
	}
	d := Data{Nr: nr, Arch: a.AuditArch}
	copy(d.Args[:], args)
	return d
}

func runVM(t testing.TB, prog *Program, d Data) Action {
	t.Helper()
	v, err := Run(prog.Instructions, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return Action(v)
}

func TestDefaultProfileVerdicts(t *testing.T) {
	p := mustProfile(t, DefaultProfile())
	eperm := Action(RetErrno | 1)
	allow := Action(RetAllow)
	for _, a := range []*Arch{ArchX86_64, ArchAArch64} {
		t.Run(a.Name, func(t *testing.T) {
			prog := mustCompile(t, p, a)
			cases := []struct {
				name string
				d    Data
				want Action
			}{
				{"read", call(t, a, "read"), allow},
				{"execve", call(t, a, "execve"), allow},
				{"mkdirat", call(t, a, "mkdirat"), allow},
				{"mount", call(t, a, "mount"), eperm},
				{"unshare", call(t, a, "unshare"), eperm},
				{"setns", call(t, a, "setns"), eperm},
				{"bpf", call(t, a, "bpf"), eperm},
				{"init_module", call(t, a, "init_module"), eperm},
				{"clone plain", call(t, a, "clone", 0x11), allow},
				{"clone thread", call(t, a, "clone", 0x3d0f00), allow},
				{"clone newuser", call(t, a, "clone", 0x10000000|0x11), eperm},
				{"clone newns high bits", call(t, a, "clone", 1<<40|0x11), allow},
				{"clone3", call(t, a, "clone3"), Action(RetErrno | enosys)},
				{"socket inet", call(t, a, "socket", 2), allow},
				{"socket vsock", call(t, a, "socket", afVsock), eperm},
				{"socket vsock hi", call(t, a, "socket", 1<<32|afVsock), allow},
				{"personality 0", call(t, a, "personality", 0), allow},
				{"personality query", call(t, a, "personality", 0xffffffff), allow},
				{"personality 1", call(t, a, "personality", 1), eperm},
				{"unknown nr", Data{Nr: 4000, Arch: a.AuditArch}, eperm},
				{"high nr", Data{Nr: 0x3ffffffe, Arch: a.AuditArch}, eperm},
				{"foreign arch", Data{Nr: 0, Arch: 0x40000003}, Action(RetKillProcess)},
			}
			for _, c := range cases {
				if got := runVM(t, prog, c.d); got != c.want {
					t.Errorf("%s: VM = %v, want %v", c.name, got, c.want)
				}
				if got := Evaluate(p, a, c.d); got != c.want {
					t.Errorf("%s: Evaluate = %v, want %v", c.name, got, c.want)
				}
			}
			if len(prog.Instructions) > 200 {
				t.Errorf("default profile compiled to %d instructions; the range tree should keep it small", len(prog.Instructions))
			}
		})
	}
}

func TestX32AndSkipNumbers(t *testing.T) {
	p := mustProfile(t, DefaultProfile())
	prog := mustCompile(t, p, ArchX86_64)
	x32Read := Data{Nr: 0x40000000, Arch: ArchX86_64.AuditArch}
	if got := runVM(t, prog, x32Read); got != Action(RetKillProcess) {
		t.Errorf("x32 call = %v, want kill", got)
	}
	skip := Data{Nr: 0xffffffff, Arch: ArchX86_64.AuditArch}
	if got := runVM(t, prog, skip); got != p.DefaultAction {
		t.Errorf("nr -1 = %v, want default", got)
	}
	// arm64 has no x32 bit: high numbers just get the default action.
	progArm := mustCompile(t, p, ArchAArch64)
	if got := runVM(t, progArm, Data{Nr: 0x40000000, Arch: ArchAArch64.AuditArch}); got != p.DefaultAction {
		t.Errorf("arm64 high nr = %v", got)
	}
}

func TestSkippedNamesAreReported(t *testing.T) {
	p := mustProfile(t, &spec.Seccomp{DefaultAction: "SCMP_ACT_ALLOW", Syscalls: []spec.Syscall{
		{Names: []string{"open", "openat", "not_a_syscall"}, Action: "SCMP_ACT_ERRNO"},
	}})
	prog := mustCompile(t, p, ArchAArch64)
	if strings.Join(prog.Skipped, ",") != "not_a_syscall,open" {
		t.Errorf("Skipped = %v", prog.Skipped)
	}
	prog = mustCompile(t, p, ArchX86_64)
	if strings.Join(prog.Skipped, ",") != "not_a_syscall" {
		t.Errorf("Skipped = %v", prog.Skipped)
	}
}

func TestEmptyProfileIsDefaultOnly(t *testing.T) {
	p := mustProfile(t, &spec.Seccomp{DefaultAction: "SCMP_ACT_LOG"})
	prog := mustCompile(t, p, ArchAArch64)
	if prog.Ranges != 1 {
		t.Errorf("Ranges = %d", prog.Ranges)
	}
	if got := runVM(t, prog, Data{Nr: 7, Arch: ArchAArch64.AuditArch}); got != Action(RetLog) {
		t.Errorf("got %v", got)
	}
}

// randomProfile builds a profile over a small pool of real syscalls so rules
// collide often, with conditions whose constants are drawn from a small pool
// so random arguments hit equality and boundary cases.
func randomProfile(r *rand.Rand, a *Arch) (*spec.Seccomp, []uint64) {
	names := a.SyscallNames()
	pool := make([]string, 6+r.IntN(40))
	for i := range pool {
		pool[i] = names[r.IntN(len(names))]
	}
	consts := []uint64{0, 1, 2, 0xff, 0xffffffff, 0x100000000, 0x1_0000_0001, 1 << 63, ^uint64(0), r.Uint64()}
	actions := []string{"SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_TRAP", "SCMP_ACT_LOG", "SCMP_ACT_TRACE", "SCMP_ACT_KILL"}
	ops := []string{"SCMP_CMP_EQ", "SCMP_CMP_NE", "SCMP_CMP_LT", "SCMP_CMP_LE", "SCMP_CMP_GT", "SCMP_CMP_GE", "SCMP_CMP_MASKED_EQ"}
	s := &spec.Seccomp{DefaultAction: actions[r.IntN(len(actions))]}
	uncond := map[string]bool{}
	for range 1 + r.IntN(25) {
		rule := spec.Syscall{Action: actions[r.IntN(len(actions))]}
		if rule.Action == "SCMP_ACT_ERRNO" {
			e := uint(r.IntN(200))
			rule.ErrnoRet = &e
		}
		for range 1 + r.IntN(3) {
			rule.Names = append(rule.Names, pool[r.IntN(len(pool))])
		}
		if r.IntN(3) > 0 {
			for range 1 + r.IntN(3) {
				rule.Args = append(rule.Args, spec.Arg{
					Index:    uint(r.IntN(6)),
					Op:       ops[r.IntN(len(ops))],
					Value:    consts[r.IntN(len(consts))],
					ValueTwo: consts[r.IntN(len(consts))],
				})
			}
		} else {
			// Avoid conflicting unconditional rules, which FromSpec rejects.
			var keep []string
			for _, n := range rule.Names {
				if !uncond[n] {
					uncond[n] = true
					keep = append(keep, n)
				}
			}
			if len(keep) == 0 {
				continue
			}
			rule.Names = keep
		}
		s.Syscalls = append(s.Syscalls, rule)
	}
	return s, consts
}

func randomData(r *rand.Rand, a *Arch, s *spec.Seccomp, consts []uint64) Data {
	d := Data{Arch: a.AuditArch}
	switch r.IntN(10) {
	case 0:
		d.Nr = r.Uint32()
	case 1:
		d.Arch = r.Uint32()
	default:
		if len(s.Syscalls) > 0 {
			rule := s.Syscalls[r.IntN(len(s.Syscalls))]
			nr, ok := a.Syscall(rule.Names[r.IntN(len(rule.Names))])
			if ok {
				d.Nr = nr
			}
		}
	}
	for i := range d.Args {
		c := consts[r.IntN(len(consts))]
		switch r.IntN(4) {
		case 0:
			d.Args[i] = c
		case 1:
			d.Args[i] = c + 1
		case 2:
			d.Args[i] = c - 1
		default:
			d.Args[i] = r.Uint64()
		}
	}
	return d
}

// TestCompilerMatchesReferenceEvaluator is the main correctness property:
// for random profiles and random inputs, the compiled BPF program run in the
// interpreter returns exactly what the profile semantics prescribe.
func TestCompilerMatchesReferenceEvaluator(t *testing.T) {
	r := rand.New(rand.NewPCG(39, 2026))
	for iter := range 400 {
		for _, a := range []*Arch{ArchX86_64, ArchAArch64} {
			s, consts := randomProfile(r, a)
			p, err := FromSpec(s)
			if err != nil {
				t.Fatalf("iter %d: FromSpec: %v", iter, err)
			}
			prog := mustCompile(t, p, a)
			for range 60 {
				d := randomData(r, a, s, consts)
				want := Evaluate(p, a, d)
				if got := runVM(t, prog, d); got != want {
					t.Fatalf("iter %d %s: data %+v: VM %v, reference %v", iter, a.Name, d, got, want)
				}
			}
		}
	}
}

// TestLongJumpsUseTrampolines forces dispatch targets more than 255
// instructions away and checks the program is still correct.
func TestLongJumpsUseTrampolines(t *testing.T) {
	a := ArchAArch64
	s := &spec.Seccomp{DefaultAction: "SCMP_ACT_ERRNO"}
	names := a.SyscallNames()
	for i, n := range names[:150] {
		s.Syscalls = append(s.Syscalls, spec.Syscall{
			Names: []string{n}, Action: "SCMP_ACT_ALLOW",
			Args: []spec.Arg{{Index: uint(i % 6), Op: "SCMP_CMP_EQ", Value: uint64(i)}},
		})
	}
	p := mustProfile(t, s)
	prog := mustCompile(t, p, a)
	trampolines := 0
	for _, ins := range prog.Instructions {
		if ins.Op == bpfJMP|bpfJA {
			trampolines++
		}
	}
	if len(prog.Instructions) < 600 || trampolines == 0 {
		t.Fatalf("expected a long program with trampolines, got %d insns, %d ja", len(prog.Instructions), trampolines)
	}
	for i, n := range names[:150] {
		d := call(t, a, n)
		d.Args[i%6] = uint64(i)
		if got := runVM(t, prog, d); got != Action(RetAllow) {
			t.Fatalf("%s matching: %v", n, got)
		}
		d.Args[i%6]++
		if got := runVM(t, prog, d); got != Action(RetErrno|1) {
			t.Fatalf("%s not matching: %v", n, got)
		}
	}
}

func TestProgramTooLarge(t *testing.T) {
	a := ArchX86_64
	s := &spec.Seccomp{DefaultAction: "SCMP_ACT_ALLOW"}
	for _, n := range a.SyscallNames() {
		var args []spec.Arg
		for i := range 6 {
			args = append(args, spec.Arg{Index: uint(i), Op: "SCMP_CMP_GE", Value: uint64(i)})
		}
		s.Syscalls = append(s.Syscalls, spec.Syscall{Names: []string{n}, Action: "SCMP_ACT_KILL", Args: args})
	}
	_, err := Compile(mustProfile(t, s), a)
	if !errors.Is(err, ErrProgramTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestAliasedNumbersMerge(t *testing.T) {
	a := &Arch{Name: "TEST", AuditArch: 0x1234, table: map[string]uint32{"x": 5, "y": 5, "z": 6}}
	p := mustProfile(t, &spec.Seccomp{DefaultAction: "SCMP_ACT_ERRNO", Syscalls: []spec.Syscall{
		{Names: []string{"x"}, Action: "SCMP_ACT_ALLOW", Args: []spec.Arg{{Index: 0, Op: "SCMP_CMP_EQ", Value: 1}}},
		{Names: []string{"y"}, Action: "SCMP_ACT_LOG"},
	}})
	prog := mustCompile(t, p, a)
	if got := runVM(t, prog, Data{Nr: 5, Arch: 0x1234, Args: [6]uint64{1}}); got != Action(RetAllow) {
		t.Errorf("cond = %v", got)
	}
	if got := runVM(t, prog, Data{Nr: 5, Arch: 0x1234}); got != Action(RetLog) {
		t.Errorf("fallback = %v", got)
	}
	conflict := mustProfile(t, &spec.Seccomp{DefaultAction: "SCMP_ACT_ERRNO", Syscalls: []spec.Syscall{
		{Names: []string{"x"}, Action: "SCMP_ACT_ALLOW"},
		{Names: []string{"y"}, Action: "SCMP_ACT_LOG"},
	}})
	if _, err := Compile(conflict, a); err == nil || !strings.Contains(err.Error(), "different actions") {
		t.Errorf("err = %v", err)
	}
}

func TestDisassembleGolden(t *testing.T) {
	p := mustProfile(t, &spec.Seccomp{DefaultAction: "SCMP_ACT_ERRNO", Syscalls: []spec.Syscall{
		{Names: []string{"read", "write", "exit_group"}, Action: "SCMP_ACT_ALLOW"},
		{Names: []string{"socket"}, Action: "SCMP_ACT_ALLOW", Args: []spec.Arg{{Index: 0, Op: "SCMP_CMP_LE", Value: 10}}},
		{Names: []string{"ioctl"}, Action: "SCMP_ACT_ALLOW", Args: []spec.Arg{{Index: 1, Op: "SCMP_CMP_MASKED_EQ", Value: 0xff00, ValueTwo: 0x5400}}},
	}})
	prog := mustCompile(t, p, ArchX86_64)
	var buf bytes.Buffer
	if err := Disassemble(&buf, prog); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "small_x86_64.disasm")
	if update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != string(want) {
		t.Errorf("disassembly changed (UPDATE_GOLDEN=1 to accept):\n%s", buf.String())
	}
	if got := len(prog.Bytes()); got != 8*len(prog.Instructions) {
		t.Errorf("Bytes() length = %d", got)
	}
	if b := prog.Bytes(); b[0] != 0x20 || b[4] != offArch {
		t.Errorf("first instruction encoding = % x", b[:8])
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestDisassembleWriteError(t *testing.T) {
	prog := mustCompile(t, mustProfile(t, &spec.Seccomp{DefaultAction: "SCMP_ACT_ALLOW"}), ArchX86_64)
	if err := Disassemble(failWriter{}, prog); err == nil {
		t.Fatal("expected error")
	}
}

func FuzzCompileMatchesEvaluate(f *testing.F) {
	f.Add(uint64(1), uint64(2))
	f.Add(uint64(39), uint64(0))
	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		r := rand.New(rand.NewPCG(seed1, seed2))
		a := ArchX86_64
		if seed1%2 == 1 {
			a = ArchAArch64
		}
		s, consts := randomProfile(r, a)
		p, err := FromSpec(s)
		if err != nil {
			t.Fatalf("FromSpec: %v", err)
		}
		prog := mustCompile(t, p, a)
		for range 20 {
			d := randomData(r, a, s, consts)
			if got, want := runVM(t, prog, d), Evaluate(p, a, d); got != want {
				t.Fatalf("data %+v: VM %v, reference %v", d, got, want)
			}
		}
	})
}
