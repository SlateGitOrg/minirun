package seccomp

import "testing"

func BenchmarkCompileDefaultProfile(b *testing.B) {
	p, err := FromSpec(DefaultProfile())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Compile(p, ArchX86_64); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInterpretDefaultProfile(b *testing.B) {
	p, err := FromSpec(DefaultProfile())
	if err != nil {
		b.Fatal(err)
	}
	prog, err := Compile(p, ArchX86_64)
	if err != nil {
		b.Fatal(err)
	}
	nr, _ := ArchX86_64.Syscall("openat")
	d := Data{Nr: nr, Arch: ArchX86_64.AuditArch}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Run(prog.Instructions, d); err != nil {
			b.Fatal(err)
		}
	}
}
