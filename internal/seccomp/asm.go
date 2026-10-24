package seccomp

import (
	"errors"
	"fmt"
	"math"
)

// label names a position in an assembler program.
type label int

// item is one element of an assembler program: either a label definition or
// an instruction. Conditional jumps name both targets as labels (never an
// implicit fall-through), which lets the relaxation pass insert instructions
// after any jump without changing control flow.
type item struct {
	define  label // when isLabel
	isLabel bool

	ins    Instruction
	jt, jf label // conditional jump targets
	ja     label // unconditional jump target
	kind   itemKind
}

type itemKind int

const (
	kindPlain itemKind = iota // falls through to the next instruction
	kindCond                  // conditional jump with label targets
	kindJA                    // unconditional jump with a label target
)

// assembler builds a classic BPF program with symbolic forward jumps and
// resolves them, inserting trampolines where an 8-bit conditional offset is
// too short.
type assembler struct {
	items  []item
	labels int
}

func (as *assembler) newLabel() label {
	as.labels++
	return label(as.labels)
}

func (as *assembler) bind(l label) {
	as.items = append(as.items, item{isLabel: true, define: l})
}

func (as *assembler) plain(op uint16, k uint32) {
	as.items = append(as.items, item{kind: kindPlain, ins: Instruction{Op: op, K: k}})
}

func (as *assembler) loadAbs(off uint32) { as.plain(bpfLD|bpfW|bpfABS, off) }

func (as *assembler) and(k uint32) { as.plain(bpfALU|bpfAND|bpfK, k) }

func (as *assembler) ret(k uint32) { as.plain(bpfRET|bpfK, k) }

// jump emits "if A <op> k goto jt else goto jf".
func (as *assembler) jump(op uint16, k uint32, jt, jf label) {
	as.items = append(as.items, item{kind: kindCond, ins: Instruction{Op: bpfJMP | op | bpfK, K: k}, jt: jt, jf: jf})
}

func (as *assembler) jumpAlways(l label) {
	as.items = append(as.items, item{kind: kindJA, ins: Instruction{Op: bpfJMP | bpfJA}, ja: l})
}

// ErrProgramTooLarge is returned when a profile compiles to more than
// MaxInstructions instructions.
var ErrProgramTooLarge = errors.New("seccomp: compiled filter exceeds the kernel's 4096-instruction limit")

// assemble resolves labels and returns the final instructions.
//
// Classic BPF conditional jumps carry 8-bit forward offsets. When a target is
// more than 255 instructions away, the jump is redirected to a trampoline
// ("ja target", 32-bit offset) inserted directly after it. Inserting an
// instruction can push other jumps out of range, so the pass repeats until a
// fixed point; every iteration only adds instructions, so it terminates. The
// cost is O(passes * n) with n <= 4096.
func (as *assembler) assemble() ([]Instruction, error) {
	for {
		pos, insCount := as.layout()
		if insCount > MaxInstructions {
			return nil, ErrProgramTooLarge
		}
		var fixed []item
		changed := false
		idx := 0
		for _, it := range as.items {
			if it.isLabel {
				fixed = append(fixed, it)
				continue
			}
			if it.kind == kindCond {
				var trampolines []item
				for _, target := range []*label{&it.jt, &it.jf} {
					dist, err := distance(pos, *target, idx)
					if err != nil {
						return nil, err
					}
					if dist > math.MaxUint8 {
						tl := as.newLabel()
						trampolines = append(trampolines,
							item{isLabel: true, define: tl},
							item{kind: kindJA, ins: Instruction{Op: bpfJMP | bpfJA}, ja: *target})
						*target = tl
						changed = true
					}
				}
				fixed = append(fixed, it)
				fixed = append(fixed, trampolines...)
			} else {
				fixed = append(fixed, it)
			}
			idx++
		}
		as.items = fixed
		if !changed {
			break
		}
	}
	return as.encode()
}

// layout maps every label to the index of the instruction it precedes.
func (as *assembler) layout() (map[label]int, int) {
	pos := make(map[label]int, as.labels)
	n := 0
	for _, it := range as.items {
		if it.isLabel {
			pos[it.define] = n
			continue
		}
		n++
	}
	return pos, n
}

func distance(pos map[label]int, target label, from int) (int, error) {
	p, ok := pos[target]
	if !ok {
		return 0, fmt.Errorf("seccomp: internal error: label %d is never bound", target)
	}
	d := p - (from + 1)
	if d < 0 {
		return 0, fmt.Errorf("seccomp: internal error: backward jump to label %d", target)
	}
	return d, nil
}

func (as *assembler) encode() ([]Instruction, error) {
	pos, n := as.layout()
	out := make([]Instruction, 0, n)
	for _, it := range as.items {
		if it.isLabel {
			continue
		}
		ins := it.ins
		idx := len(out)
		switch it.kind {
		case kindCond:
			jt, err := distance(pos, it.jt, idx)
			if err != nil {
				return nil, err
			}
			jf, err := distance(pos, it.jf, idx)
			if err != nil {
				return nil, err
			}
			ins.Jt, ins.Jf = uint8(jt), uint8(jf)
		case kindJA:
			d, err := distance(pos, it.ja, idx)
			if err != nil {
				return nil, err
			}
			ins.K = uint32(d)
		case kindPlain:
		}
		out = append(out, ins)
	}
	return out, nil
}
