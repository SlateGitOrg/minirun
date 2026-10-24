package seccomp

import (
	"errors"
	"strings"
	"testing"

	"github.com/archit2501/minirun/internal/spec"
)

func ins(op uint16, jt, jf uint8, k uint32) Instruction {
	return Instruction{Op: op, Jt: jt, Jf: jf, K: k}
}

func TestVMArithmeticAndScratch(t *testing.T) {
	prog := []Instruction{
		ins(bpfLD|bpfIMM, 0, 0, 6),        // A = 6
		ins(bpfST, 0, 0, 3),               // M[3] = 6
		ins(bpfLDX|bpfIMM, 0, 0, 4),       // X = 4
		ins(bpfALU|bpfMUL|bpfX, 0, 0, 0),  // A = 24
		ins(bpfALU|bpfADD|bpfK, 0, 0, 1),  // 25
		ins(bpfALU|bpfSUB|bpfK, 0, 0, 5),  // 20
		ins(bpfALU|bpfDIV|bpfK, 0, 0, 3),  // 6
		ins(bpfALU|bpfMOD|bpfK, 0, 0, 4),  // 2
		ins(bpfALU|bpfLSH|bpfK, 0, 0, 4),  // 32
		ins(bpfALU|bpfRSH|bpfK, 0, 0, 1),  // 16
		ins(bpfALU|bpfOR|bpfK, 0, 0, 1),   // 17
		ins(bpfALU|bpfXOR|bpfK, 0, 0, 3),  // 18
		ins(bpfALU|bpfNEG, 0, 0, 0),       // -18
		ins(bpfALU|bpfNEG, 0, 0, 0),       // 18
		ins(bpfSTX, 0, 0, 4),              // M[4] = X = 4
		ins(bpfMISC|bpfTAX, 0, 0, 0),      // X = 18
		ins(bpfLD|bpfMEM, 0, 0, 3),        // A = 6
		ins(bpfALU|bpfADD|bpfX, 0, 0, 0),  // A = 24
		ins(bpfLDX|bpfMEM, 0, 0, 4),       // X = 4
		ins(bpfALU|bpfADD|bpfX, 0, 0, 0),  // A = 28
		ins(bpfJMP|bpfJSET|bpfK, 1, 0, 4), // 28&4 != 0 -> skip next
		ins(bpfRET|bpfK, 0, 0, 0xdead),    // not reached
		ins(bpfJMP|bpfJGT|bpfX, 0, 1, 0),  // 28 > 4 -> next
		ins(bpfLDX|bpfW|bpfLEN, 0, 0, 0),  // X = 64
		ins(bpfMISC|bpfTXA, 0, 0, 0),      // A = 64
		ins(bpfALU|bpfADD|bpfK, 0, 0, 0),  // still 64
		ins(bpfLD|bpfW|bpfLEN, 0, 0, 0),   // A = 64
		ins(bpfJMP|bpfJEQ|bpfK, 0, 1, 64), // equal -> next
		ins(bpfRET|bpfA, 0, 0, 0),         // return A
		ins(bpfRET|bpfK, 0, 0, 0xbad),
	}
	if err := Validate(prog); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got, err := Run(prog, Data{})
	if err != nil || got != 64 {
		t.Fatalf("Run = %d, %v", got, err)
	}
}

func TestVMDivisionByZeroKills(t *testing.T) {
	prog := []Instruction{
		ins(bpfLDX|bpfIMM, 0, 0, 0),
		ins(bpfALU|bpfDIV|bpfX, 0, 0, 0),
		ins(bpfRET|bpfK, 0, 0, RetAllow),
	}
	got, err := Run(prog, Data{})
	if err != nil || got != RetKillThread {
		t.Fatalf("Run = %#x, %v", got, err)
	}
	prog[1] = ins(bpfALU|bpfMOD|bpfX, 0, 0, 0)
	if got, _ := Run(prog, Data{}); got != RetKillThread {
		t.Fatalf("mod: %#x", got)
	}
}

func TestVMLoadsSeccompData(t *testing.T) {
	d := Data{Nr: 7, Arch: 9, InstructionPointer: 0x1122334455667788, Args: [6]uint64{0, 0, 0, 0, 0, 0xaabbccdd_00000001}}
	for _, c := range []struct {
		off  uint32
		want uint32
	}{{0, 7}, {4, 9}, {8, 0x55667788}, {12, 0x11223344}, {56, 1}, {60, 0xaabbccdd}} {
		prog := []Instruction{ins(bpfLD|bpfW|bpfABS, 0, 0, c.off), ins(bpfRET|bpfA, 0, 0, 0)}
		got, err := Run(prog, d)
		if err != nil || got != c.want {
			t.Errorf("ld [%d] = %#x, %v; want %#x", c.off, got, err, c.want)
		}
	}
}

func TestVMErrors(t *testing.T) {
	cases := map[string][]Instruction{
		"misaligned load":   {ins(bpfLD|bpfW|bpfABS, 0, 0, 2), ins(bpfRET|bpfK, 0, 0, 0)},
		"out of range load": {ins(bpfLD|bpfW|bpfABS, 0, 0, 64), ins(bpfRET|bpfK, 0, 0, 0)},
		"bad ld mode":       {ins(bpfLD|0x40, 0, 0, 0)},
		"bad ld mem":        {ins(bpfLD|bpfMEM, 0, 0, 16)},
		"bad ldx mode":      {ins(bpfLDX|0x40, 0, 0, 0)},
		"bad ldx mem":       {ins(bpfLDX|bpfMEM, 0, 0, 99)},
		"bad st":            {ins(bpfST, 0, 0, 16)},
		"bad alu":           {ins(bpfALU|0xf0, 0, 0, 0)},
		"bad jump":          {ins(bpfJMP|0x50, 0, 0, 0)},
		"bad ret":           {ins(bpfRET|0x18, 0, 0, 0)},
		"bad misc":          {ins(bpfMISC|0x40, 0, 0, 0)},
		"no return":         {ins(bpfLD|bpfIMM, 0, 0, 1)},
	}
	for name, prog := range cases {
		if _, err := Run(prog, Data{}); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := Run([]Instruction{ins(bpfLD|bpfIMM, 0, 0, 1)}, Data{}); !errors.Is(err, ErrNoReturn) {
		t.Errorf("err = %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	ret := ins(bpfRET|bpfK, 0, 0, 0)
	cases := map[string][]Instruction{
		"empty":            nil,
		"too long":         make([]Instruction, MaxInstructions+1),
		"no final return":  {ret, ins(bpfLD|bpfIMM, 0, 0, 0)},
		"load out of data": {ins(bpfLD|bpfW|bpfABS, 0, 0, 64), ret},
		"scratch index":    {ins(bpfST, 0, 0, 16), ret},
		"ja out of range":  {ins(bpfJMP|bpfJA, 0, 0, 1), ret},
		"jt out of range":  {ins(bpfJMP|bpfJEQ|bpfK, 1, 0, 0), ret},
		"div by const 0":   {ins(bpfALU|bpfDIV|bpfK, 0, 0, 0), ret},
		"bad opcode":       {ins(bpfLD|bpfW|0x40, 0, 0, 0), ret},
		"bad alu src":      {ins(bpfALU|bpfNEG|bpfX, 0, 0, 0), ret},
		"bad jump op":      {ins(bpfJMP|0x60, 0, 0, 0), ret},
	}
	for name, prog := range cases {
		if err := Validate(prog); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseAction(t *testing.T) {
	e := uint(13)
	big := uint(5000)
	cases := []struct {
		name  string
		errno *uint
		want  string
		err   bool
	}{
		{"SCMP_ACT_ALLOW", nil, "SCMP_ACT_ALLOW", false},
		{"SCMP_ACT_LOG", nil, "SCMP_ACT_LOG", false},
		{"SCMP_ACT_KILL", nil, "SCMP_ACT_KILL_THREAD", false},
		{"SCMP_ACT_KILL_THREAD", nil, "SCMP_ACT_KILL_THREAD", false},
		{"SCMP_ACT_KILL_PROCESS", nil, "SCMP_ACT_KILL_PROCESS", false},
		{"SCMP_ACT_TRAP", nil, "SCMP_ACT_TRAP", false},
		{"SCMP_ACT_ERRNO", nil, "SCMP_ACT_ERRNO(1)", false},
		{"SCMP_ACT_ERRNO", &e, "SCMP_ACT_ERRNO(13)", false},
		{"SCMP_ACT_TRACE", &e, "SCMP_ACT_TRACE(13)", false},
		{"SCMP_ACT_ERRNO", &big, "", true},
		{"SCMP_ACT_NOTIFY", nil, "", true},
		{"", nil, "", true},
		{"SCMP_ACT_NOPE", nil, "", true},
	}
	for _, c := range cases {
		a, err := ParseAction(c.name, c.errno)
		if (err != nil) != c.err {
			t.Errorf("%s: err = %v", c.name, err)
			continue
		}
		if !c.err && a.String() != c.want {
			t.Errorf("%s: %s, want %s", c.name, a, c.want)
		}
	}
	if got := Action(0x12345678).String(); !strings.HasPrefix(got, "SECCOMP_RET(") {
		t.Errorf("unknown action string = %s", got)
	}
}

func TestOpStringAndMatches(t *testing.T) {
	if OpMaskedEqual.String() != "SCMP_CMP_MASKED_EQ" || Op(99).String() != "Op(99)" {
		t.Error("Op.String")
	}
	if (Cond{Op: Op(99)}).Matches(0) {
		t.Error("unknown op should never match")
	}
}

func TestFromSpecErrors(t *testing.T) {
	if _, err := FromSpec(nil); err == nil {
		t.Error("nil profile")
	}
	s := &spec.Seccomp{
		DefaultAction: "SCMP_ACT_NOPE",
		Architectures: []string{"SCMP_ARCH_X86", "SCMP_ARCH_VAX"},
		Flags:         []string{"SECCOMP_FILTER_FLAG_LOG", "SECCOMP_FILTER_FLAG_BOGUS"},
		Syscalls: []spec.Syscall{
			{Names: []string{"read"}, Action: "SCMP_ACT_BOGUS"},
			{Names: nil, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW", Args: []spec.Arg{{Index: 6, Op: "SCMP_CMP_EQ"}}},
			{Names: []string{"read"}, Action: "SCMP_ACT_ALLOW", Args: []spec.Arg{{Index: 0, Op: "SCMP_CMP_ABOUT"}}},
			{Names: []string{"bad name"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"write"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"write"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"write"}, Action: "SCMP_ACT_LOG"},
		},
	}
	_, err := FromSpec(s)
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{
		"defaultAction", "SCMP_ARCH_VAX", "SECCOMP_FILTER_FLAG_BOGUS", "syscalls[0]", "syscalls[1]",
		"index 6", "SCMP_CMP_ABOUT", "bad name", "already has unconditional action",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "SCMP_ARCH_X86\"") {
		t.Errorf("known foreign arch should be accepted: %v", err)
	}
}

func TestFromSpecFlagsAndNames(t *testing.T) {
	p := mustProfile(t, &spec.Seccomp{
		DefaultAction: "SCMP_ACT_ALLOW",
		Flags:         []string{"SECCOMP_FILTER_FLAG_LOG", "SECCOMP_FILTER_FLAG_SPEC_ALLOW"},
		Syscalls: []spec.Syscall{
			{Names: []string{"write", "read"}, Action: "SCMP_ACT_LOG"},
			{Names: []string{"read"}, Action: "SCMP_ACT_LOG"},
		},
	})
	if p.Flags != 6 {
		t.Errorf("Flags = %d", p.Flags)
	}
	if got := strings.Join(p.SyscallNames(), ","); got != "read,write" {
		t.Errorf("SyscallNames = %s", got)
	}
	if len(p.Rules) != 2 {
		t.Errorf("duplicate identical rule should be dropped, got %d rules", len(p.Rules))
	}
}

func TestArchLookup(t *testing.T) {
	for _, n := range []string{"amd64", "x86_64", "SCMP_ARCH_X86_64"} {
		if a, err := LookupArch(n); err != nil || a != ArchX86_64 {
			t.Errorf("%s: %v %v", n, a, err)
		}
	}
	if _, err := LookupArch("SCMP_ARCH_PPC64"); err == nil {
		t.Error("ppc64 should be unsupported")
	}
	if name, ok := ArchAArch64.SyscallName(56); !ok || name != "openat" {
		t.Errorf("SyscallName(56) = %s %v", name, ok)
	}
	if _, ok := ArchAArch64.SyscallName(99999); ok {
		t.Error("unknown number resolved")
	}
	if ArchAArch64.String() != "SCMP_ARCH_AARCH64" {
		t.Error("String")
	}
	if a, err := NativeArch(); err == nil && a == nil {
		t.Error("NativeArch returned nil without error")
	}
}

func TestInstallOnUnsupportedPlatform(t *testing.T) {
	foreign := ArchAArch64
	if native, err := NativeArch(); err == nil && native == ArchAArch64 {
		foreign = ArchX86_64
	}
	prog := mustCompile(t, mustProfile(t, &spec.Seccomp{DefaultAction: "SCMP_ACT_ALLOW"}), foreign)
	// Either the platform cannot load filters at all, or the architecture
	// mismatch is rejected before anything reaches the kernel.
	if err := Install(prog); err == nil {
		t.Fatal("Install of a foreign-architecture program must fail")
	}
}
