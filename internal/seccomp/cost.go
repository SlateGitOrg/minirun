package seccomp

import "sort"

// Cost summarises how many BPF instructions the kernel executes per system
// call for a compiled program.
type Cost struct {
	// Calls is the number of syscall numbers measured: every syscall in the
	// architecture's table, with all arguments zero.
	Calls int
	// Avg and Max are measured by running the program in the interpreter.
	Avg float64
	Max int
	// LinearAvg and LinearMax are the cost of the classic naive layout for
	// the same profile: one "jeq nr; ret" pair per syscall, tested in
	// profile order, so the i-th listed syscall costs 3+i+1 instructions
	// (load arch, check arch, load nr, i comparisons, return) and an
	// unlisted one 3+N+1. Argument checks are not included in the linear
	// figure, so it is a lower bound for that layout.
	LinearAvg float64
	LinearMax int
}

// MeasureCost computes Cost for prog, which must have been compiled from p.
func MeasureCost(p *Profile, prog *Program) (Cost, error) {
	arch := prog.Arch
	// Position of each syscall number in a naive chain: first appearance
	// in profile order.
	position := map[uint32]int{}
	for _, r := range p.Rules {
		nr, ok := arch.Syscall(r.Syscall)
		if !ok {
			continue
		}
		if _, seen := position[nr]; !seen {
			position[nr] = len(position) + 1
		}
	}
	n := len(position)
	names := arch.SyscallNames()
	sort.Strings(names)
	var c Cost
	total, linearTotal := 0, 0
	for _, name := range names {
		nr, _ := arch.Syscall(name)
		_, steps, err := RunCount(prog.Instructions, Data{Nr: nr, Arch: arch.AuditArch})
		if err != nil {
			return Cost{}, err
		}
		total += steps
		c.Max = max(c.Max, steps)
		linear := 3 + n + 1
		if pos, ok := position[nr]; ok {
			linear = 3 + pos + 1
		}
		linearTotal += linear
		c.LinearMax = max(c.LinearMax, linear)
		c.Calls++
	}
	if c.Calls > 0 {
		c.Avg = float64(total) / float64(c.Calls)
		c.LinearAvg = float64(linearTotal) / float64(c.Calls)
	}
	return c, nil
}
