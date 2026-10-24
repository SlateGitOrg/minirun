package seccomp

import (
	"fmt"
	"io"
)

// Disassemble writes a human-readable listing of p, one instruction per line,
// annotating loads with the seccomp_data field and returns/jumps with their
// meaning. The format is similar to libseccomp's scmp_bpf_disasm.
func Disassemble(w io.Writer, p *Program) error {
	// lastLoad tracks which seccomp_data field the accumulator was loaded
	// from most recently in program order, so comparisons against the
	// syscall number can be annotated with syscall names. The compiler only
	// emits forward jumps and reloads before every comparison sequence, so
	// program order is accurate for its output.
	lastLoad := uint32(seccompLen)
	for pc, ins := range p.Instructions {
		if ins.Op == bpfLD|bpfW|bpfABS {
			lastLoad = ins.K
		}
		text, note := describe(pc, ins, p.Arch, lastLoad == offNr)
		line := fmt.Sprintf("%04d: %-30s", pc, text)
		if note != "" {
			line += " ; " + note
		}
		if _, err := fmt.Fprintln(w, trimRight(line)); err != nil {
			return err
		}
	}
	return nil
}

func trimRight(s string) string {
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}

func describe(pc int, ins Instruction, arch *Arch, accIsNr bool) (string, string) {
	switch {
	case ins.Op == bpfLD|bpfW|bpfABS:
		return fmt.Sprintf("ld   [%d]", ins.K), fieldName(ins.K)
	case ins.Op == bpfALU|bpfAND|bpfK:
		return fmt.Sprintf("and  #%#x", ins.K), ""
	case ins.Op == bpfRET|bpfK:
		return fmt.Sprintf("ret  #%#08x", ins.K), Action(ins.K).String()
	case ins.Op == bpfJMP|bpfJA:
		return fmt.Sprintf("ja   %04d", pc+1+int(ins.K)), ""
	case ins.Op&0x07 == bpfJMP:
		mn := map[uint16]string{bpfJEQ: "jeq", bpfJGT: "jgt", bpfJGE: "jge", bpfJSET: "jset"}[ins.Op&0xf0]
		text := fmt.Sprintf("%-5s#%#x, %04d, %04d", mn, ins.K, pc+1+int(ins.Jt), pc+1+int(ins.Jf))
		note := ""
		switch {
		case arch == nil:
		case ins.K == arch.AuditArch:
			note = arch.Name
		case accIsNr:
			if name, ok := arch.SyscallName(ins.K); ok {
				note = "nr " + map[uint16]string{bpfJEQ: "==", bpfJGT: ">", bpfJGE: ">=", bpfJSET: "&"}[ins.Op&0xf0] + " " + name
			}
		}
		return text, note
	default:
		return fmt.Sprintf("op=%#04x jt=%d jf=%d k=%#x", ins.Op, ins.Jt, ins.Jf, ins.K), ""
	}
}

func fieldName(off uint32) string {
	switch {
	case off == offNr:
		return "nr"
	case off == offArch:
		return "arch"
	case off == offIP:
		return "instruction_pointer (lo)"
	case off == offIP+4:
		return "instruction_pointer (hi)"
	case off >= offArgs && off < seccompLen:
		i := (off - offArgs) / 8
		if (off-offArgs)%8 == 0 {
			return fmt.Sprintf("args[%d] (lo)", i)
		}
		return fmt.Sprintf("args[%d] (hi)", i)
	}
	return ""
}
