package seccomp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Classic BPF opcode fields (include/uapi/linux/bpf_common.h).
const (
	bpfLD   = 0x00
	bpfLDX  = 0x01
	bpfST   = 0x02
	bpfSTX  = 0x03
	bpfALU  = 0x04
	bpfJMP  = 0x05
	bpfRET  = 0x06
	bpfMISC = 0x07

	bpfW   = 0x00
	bpfIMM = 0x00
	bpfABS = 0x20
	bpfMEM = 0x60
	bpfLEN = 0x80

	bpfADD = 0x00
	bpfSUB = 0x10
	bpfMUL = 0x20
	bpfDIV = 0x30
	bpfOR  = 0x40
	bpfAND = 0x50
	bpfLSH = 0x60
	bpfRSH = 0x70
	bpfNEG = 0x80
	bpfMOD = 0x90
	bpfXOR = 0xa0

	bpfJA   = 0x00
	bpfJEQ  = 0x10
	bpfJGT  = 0x20
	bpfJGE  = 0x30
	bpfJSET = 0x40

	bpfK = 0x00
	bpfX = 0x08
	bpfA = 0x10

	bpfTAX = 0x00
	bpfTXA = 0x80

	bpfMemWords = 16
)

// MaxInstructions is BPF_MAXINSNS, the kernel's per-filter limit.
const MaxInstructions = 4096

// seccomp_data layout (include/uapi/linux/seccomp.h).
const (
	offNr      = 0
	offArch    = 4
	offIP      = 8
	offArgs    = 16
	seccompLen = 64
)

// Instruction is one classic BPF instruction (struct sock_filter).
type Instruction struct {
	Op uint16
	Jt uint8
	Jf uint8
	K  uint32
}

// Program is a compiled filter.
type Program struct {
	Arch         *Arch
	Instructions []Instruction
	Flags        uint
	// Skipped lists profile syscall names absent from Arch's table. They are
	// ignored, as libseccomp ignores names unknown to an architecture.
	Skipped []string
	// Ranges is the number of contiguous syscall-number ranges the dispatch
	// tree distinguishes (a measure of the tree's size).
	Ranges int
}

// Bytes encodes the program as the kernel's array of struct sock_filter
// (8 bytes each, host byte order; both supported architectures are
// little-endian).
func (p *Program) Bytes() []byte {
	out := make([]byte, 8*len(p.Instructions))
	for i, ins := range p.Instructions {
		b := out[8*i:]
		binary.LittleEndian.PutUint16(b[0:], ins.Op)
		b[2] = ins.Jt
		b[3] = ins.Jf
		binary.LittleEndian.PutUint32(b[4:], ins.K)
	}
	return out
}

// Data is the input a filter sees for one system call (struct seccomp_data).
type Data struct {
	Nr                 uint32
	Arch               uint32
	InstructionPointer uint64
	Args               [6]uint64
}

func (d *Data) encode() [seccompLen]byte {
	var b [seccompLen]byte
	binary.LittleEndian.PutUint32(b[offNr:], d.Nr)
	binary.LittleEndian.PutUint32(b[offArch:], d.Arch)
	binary.LittleEndian.PutUint64(b[offIP:], d.InstructionPointer)
	for i, a := range d.Args {
		binary.LittleEndian.PutUint64(b[offArgs+8*i:], a)
	}
	return b
}

// ErrNoReturn is returned when execution runs past the last instruction.
var ErrNoReturn = errors.New("bpf: fell off the end of the program")

// Run interprets a classic BPF program against d the way the kernel's
// seccomp filter does and returns the filter's 32-bit verdict. It implements
// every instruction the kernel's seccomp_check_filter admits; programs that
// would be rejected at load time should be checked with Validate first.
func Run(insns []Instruction, d Data) (uint32, error) {
	data := d.encode()
	var a, x uint32
	var mem [bpfMemWords]uint32
	for pc := 0; pc < len(insns); pc++ {
		ins := insns[pc]
		switch ins.Op & 0x07 {
		case bpfLD:
			switch ins.Op {
			case bpfLD | bpfW | bpfABS:
				if ins.K%4 != 0 || ins.K+4 > seccompLen {
					return 0, fmt.Errorf("bpf: pc %d: load at invalid offset %d", pc, ins.K)
				}
				a = binary.LittleEndian.Uint32(data[ins.K:])
			case bpfLD | bpfW | bpfLEN:
				a = seccompLen
			case bpfLD | bpfIMM:
				a = ins.K
			case bpfLD | bpfMEM:
				if ins.K >= bpfMemWords {
					return 0, fmt.Errorf("bpf: pc %d: scratch index %d", pc, ins.K)
				}
				a = mem[ins.K]
			default:
				return 0, fmt.Errorf("bpf: pc %d: unsupported load %#04x", pc, ins.Op)
			}
		case bpfLDX:
			switch ins.Op {
			case bpfLDX | bpfW | bpfLEN:
				x = seccompLen
			case bpfLDX | bpfIMM:
				x = ins.K
			case bpfLDX | bpfMEM:
				if ins.K >= bpfMemWords {
					return 0, fmt.Errorf("bpf: pc %d: scratch index %d", pc, ins.K)
				}
				x = mem[ins.K]
			default:
				return 0, fmt.Errorf("bpf: pc %d: unsupported ldx %#04x", pc, ins.Op)
			}
		case bpfST, bpfSTX:
			if ins.K >= bpfMemWords {
				return 0, fmt.Errorf("bpf: pc %d: scratch index %d", pc, ins.K)
			}
			if ins.Op&0x07 == bpfST {
				mem[ins.K] = a
			} else {
				mem[ins.K] = x
			}
		case bpfALU:
			if !validALU(ins.Op) {
				return 0, fmt.Errorf("bpf: pc %d: unsupported alu %#04x", pc, ins.Op)
			}
			operand := ins.K
			if ins.Op&bpfX != 0 {
				operand = x
			}
			var ok bool
			a, ok = alu(ins.Op&0xf0, a, operand)
			if !ok {
				// Division by zero terminates a classic BPF program with 0,
				// which for seccomp is SECCOMP_RET_KILL_THREAD.
				return 0, nil
			}
		case bpfJMP:
			if ins.Op == bpfJMP|bpfJA {
				pc += int(ins.K)
				continue
			}
			operand := ins.K
			if ins.Op&bpfX != 0 {
				operand = x
			}
			var cond bool
			switch ins.Op & 0xf0 {
			case bpfJEQ:
				cond = a == operand
			case bpfJGT:
				cond = a > operand
			case bpfJGE:
				cond = a >= operand
			case bpfJSET:
				cond = a&operand != 0
			default:
				return 0, fmt.Errorf("bpf: pc %d: unsupported jump %#04x", pc, ins.Op)
			}
			if cond {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}
		case bpfRET:
			switch ins.Op & 0x18 {
			case bpfK:
				return ins.K, nil
			case bpfA:
				return a, nil
			default:
				return 0, fmt.Errorf("bpf: pc %d: unsupported return %#04x", pc, ins.Op)
			}
		case bpfMISC:
			switch ins.Op & 0xf8 {
			case bpfTAX:
				x = a
			case bpfTXA:
				a = x
			default:
				return 0, fmt.Errorf("bpf: pc %d: unsupported misc %#04x", pc, ins.Op)
			}
		}
	}
	return 0, ErrNoReturn
}

func alu(op uint16, a, v uint32) (uint32, bool) {
	switch op {
	case bpfADD:
		return a + v, true
	case bpfSUB:
		return a - v, true
	case bpfMUL:
		return a * v, true
	case bpfDIV:
		if v == 0 {
			return 0, false
		}
		return a / v, true
	case bpfMOD:
		if v == 0 {
			return 0, false
		}
		return a % v, true
	case bpfOR:
		return a | v, true
	case bpfAND:
		return a & v, true
	case bpfXOR:
		return a ^ v, true
	case bpfLSH:
		return a << (v & 31), true
	case bpfRSH:
		return a >> (v & 31), true
	case bpfNEG:
		return -a, true
	default:
		return 0, false
	}
}

// Validate applies the kernel's load-time checks for seccomp filters
// (bpf_check_classic + seccomp_check_filter): length limits, permitted
// opcodes, aligned in-bounds data loads, in-range forward jumps and a
// terminating return.
func Validate(insns []Instruction) error {
	n := len(insns)
	if n == 0 || n > MaxInstructions {
		return fmt.Errorf("bpf: program length %d not in 1..%d", n, MaxInstructions)
	}
	for pc, ins := range insns {
		if err := checkInstruction(pc, n, ins); err != nil {
			return err
		}
	}
	if insns[n-1].Op&0x07 != bpfRET {
		return errors.New("bpf: last instruction must be a return")
	}
	return nil
}

func checkInstruction(pc, n int, ins Instruction) error {
	switch ins.Op {
	case bpfLD | bpfW | bpfABS:
		if ins.K%4 != 0 || ins.K+4 > seccompLen {
			return fmt.Errorf("bpf: pc %d: load offset %d outside seccomp_data", pc, ins.K)
		}
	case bpfLD | bpfW | bpfLEN, bpfLDX | bpfW | bpfLEN, bpfLD | bpfIMM, bpfLDX | bpfIMM,
		bpfRET | bpfK, bpfRET | bpfA, bpfMISC | bpfTAX, bpfMISC | bpfTXA:
	case bpfLD | bpfMEM, bpfLDX | bpfMEM, bpfST, bpfSTX:
		if ins.K >= bpfMemWords {
			return fmt.Errorf("bpf: pc %d: scratch index %d", pc, ins.K)
		}
	case bpfJMP | bpfJA:
		if uint64(pc)+1+uint64(ins.K) >= uint64(n) {
			return fmt.Errorf("bpf: pc %d: jump out of range", pc)
		}
	default:
		cls := ins.Op & 0x07
		switch {
		case cls == bpfALU && validALU(ins.Op):
			if (ins.Op&0xf0 == bpfDIV || ins.Op&0xf0 == bpfMOD) && ins.Op&bpfX == 0 && ins.K == 0 {
				return fmt.Errorf("bpf: pc %d: division by constant zero", pc)
			}
		case cls == bpfJMP && validJump(ins.Op):
			if pc+1+int(ins.Jt) >= n || pc+1+int(ins.Jf) >= n {
				return fmt.Errorf("bpf: pc %d: conditional jump out of range", pc)
			}
		default:
			return fmt.Errorf("bpf: pc %d: opcode %#04x not allowed in seccomp filters", pc, ins.Op)
		}
	}
	return nil
}

func validALU(op uint16) bool {
	switch op & 0xf0 {
	case bpfADD, bpfSUB, bpfMUL, bpfDIV, bpfOR, bpfAND, bpfLSH, bpfRSH, bpfMOD, bpfXOR:
		return op&^0xf8 == bpfALU
	case bpfNEG:
		return op == bpfALU|bpfNEG
	}
	return false
}

func validJump(op uint16) bool {
	switch op & 0xf0 {
	case bpfJEQ, bpfJGT, bpfJGE, bpfJSET:
		return op&^0xf8 == bpfJMP
	}
	return false
}
