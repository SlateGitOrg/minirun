// Package seccomp compiles OCI seccomp profiles into classic BPF programs for
// the kernel's seccomp filter mode, without libseccomp.
//
// The pipeline is: spec.Seccomp -> Profile (validated, normalised) ->
// Compile (per architecture) -> Program (classic BPF). The package also
// contains a classic-BPF interpreter and a direct reference evaluator of
// profile semantics; tests check the two agree on randomly generated
// profiles, which is how the compiler is verified on machines that cannot
// load filters (macOS, CI without privileges).
package seccomp

import (
	"fmt"
	"runtime"
	"sort"
)

// Arch is a CPU architecture the compiler has a syscall table for.
type Arch struct {
	// Name is the OCI/libseccomp name, e.g. "SCMP_ARCH_X86_64".
	Name string
	// AuditArch is the AUDIT_ARCH_* value the kernel reports in
	// seccomp_data.arch for this ABI.
	AuditArch uint32
	// X32Bit is the bit that marks x32-ABI syscall numbers on x86-64. Calls
	// with this bit set are treated as a foreign ABI. Zero elsewhere.
	X32Bit uint32
	table  map[string]uint32
}

// AUDIT_ARCH values from include/uapi/linux/audit.h.
const (
	auditArchX86_64  = 0xc000003e
	auditArchAArch64 = 0xc00000b7
)

// Supported architectures.
var (
	ArchX86_64  = &Arch{Name: "SCMP_ARCH_X86_64", AuditArch: auditArchX86_64, X32Bit: 0x40000000, table: syscallsX86_64}
	ArchAArch64 = &Arch{Name: "SCMP_ARCH_AARCH64", AuditArch: auditArchAArch64, table: syscallsAArch64}
)

var archByName = map[string]*Arch{
	ArchX86_64.Name:  ArchX86_64,
	ArchAArch64.Name: ArchAArch64,
	// Short aliases accepted on the command line.
	"x86_64":  ArchX86_64,
	"amd64":   ArchX86_64,
	"aarch64": ArchAArch64,
	"arm64":   ArchAArch64,
}

// knownForeignArches are libseccomp architecture names minirun recognises
// but has no table for. They may appear in a profile's architectures list
// (Docker's default lists SCMP_ARCH_X86 and SCMP_ARCH_X32); calls from those
// ABIs are rejected by the architecture check instead of being filtered.
var knownForeignArches = map[string]bool{
	"SCMP_ARCH_X86": true, "SCMP_ARCH_X32": true, "SCMP_ARCH_ARM": true,
	"SCMP_ARCH_MIPS": true, "SCMP_ARCH_MIPS64": true, "SCMP_ARCH_MIPS64N32": true,
	"SCMP_ARCH_MIPSEL": true, "SCMP_ARCH_MIPSEL64": true, "SCMP_ARCH_MIPSEL64N32": true,
	"SCMP_ARCH_PPC": true, "SCMP_ARCH_PPC64": true, "SCMP_ARCH_PPC64LE": true,
	"SCMP_ARCH_S390": true, "SCMP_ARCH_S390X": true, "SCMP_ARCH_RISCV64": true,
	"SCMP_ARCH_LOONGARCH64": true, "SCMP_ARCH_PARISC": true, "SCMP_ARCH_PARISC64": true,
}

// LookupArch returns the architecture with the given libseccomp name or
// short alias.
func LookupArch(name string) (*Arch, error) {
	if a, ok := archByName[name]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("unsupported architecture %q (supported: SCMP_ARCH_X86_64, SCMP_ARCH_AARCH64)", name)
}

// NativeArch returns the architecture of the running binary, or an error if
// minirun has no syscall table for it.
func NativeArch() (*Arch, error) {
	return LookupArch(runtime.GOARCH)
}

// Syscall returns the number of the named syscall on a.
func (a *Arch) Syscall(name string) (uint32, bool) {
	nr, ok := a.table[name]
	return nr, ok
}

// SyscallName returns the name of syscall number nr on a, if known. When
// several names share a number the alphabetically first is returned.
func (a *Arch) SyscallName(nr uint32) (string, bool) {
	for _, name := range a.SyscallNames() {
		if a.table[name] == nr {
			return name, true
		}
	}
	return "", false
}

// SyscallNames returns every syscall name a knows, sorted.
func (a *Arch) SyscallNames() []string {
	names := make([]string, 0, len(a.table))
	for n := range a.table {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (a *Arch) String() string { return a.Name }
