package seccomp

import (
	"fmt"
	"sort"
)

// verdict is what the dispatch tree decides for one syscall number: either a
// final action, or "evaluate argument conditions in block n".
type verdict struct {
	conditional bool
	action      Action // when !conditional
	block       int    // when conditional
}

// segment is a maximal run of syscall numbers [lo, next segment's lo) that
// share a verdict.
type segment struct {
	lo uint32
	v  verdict
}

// condBlock holds the rules of one syscall that has argument conditions.
type condBlock struct {
	rules    []Rule
	fallback Action
}

// x32 syscall numbers carry this bit; 0xffffffff is the "skip this syscall"
// value tracers write and is not an x32 call.
const nrSkip = 0xffffffff

// Compile translates p into a classic BPF program for arch.
//
// Layout of the generated program:
//
//	ld  [arch]                      ; seccomp_data.arch
//	jeq AUDIT_ARCH, ok, kill_arch
//	ok:  ld [nr]
//	     (x86-64 only) x32 ABI numbers (bit 30) -> kill_arch
//	     balanced binary search over syscall-number ranges (jge),
//	     leaves jump straight to a shared "ret ACTION"
//	     or to the argument block of a conditional syscall
//	blocks: per conditional syscall, 64-bit argument tests as hi/lo
//	     32-bit word comparisons, falling back to its unconditional action
//	rets: one "ret K" per distinct action
//
// Dispatch costs O(log R) instructions per syscall for R ranges, instead of
// the O(N) jeq chain a naive allow-list needs.
func Compile(p *Profile, arch *Arch) (*Program, error) {
	c := &compiler{
		profile: p,
		arch:    arch,
		rets:    map[Action]label{},
	}
	return c.compile()
}

type compiler struct {
	profile *Profile
	arch    *Arch
	as      assembler
	rets    map[Action]label
	retList []Action
	blocks  []condBlock
	skipped []string
}

func (c *compiler) retLabel(a Action) label {
	if l, ok := c.rets[a]; ok {
		return l
	}
	l := c.as.newLabel()
	c.rets[a] = l
	c.retList = append(c.retList, a)
	return l
}

func (c *compiler) compile() (*Program, error) {
	perNr, err := c.resolveNumbers()
	if err != nil {
		return nil, err
	}
	segs := c.segments(perNr)
	blockLabels := make([]label, len(c.blocks))
	for i := range blockLabels {
		blockLabels[i] = c.as.newLabel()
	}
	target := func(v verdict) label {
		if v.conditional {
			return blockLabels[v.block]
		}
		return c.retLabel(v.action)
	}

	killArch := c.retLabel(Action(RetKillProcess))
	archOK := c.as.newLabel()
	c.as.loadAbs(offArch)
	c.as.jump(bpfJEQ, c.arch.AuditArch, archOK, killArch)
	c.as.bind(archOK)
	c.as.loadAbs(offNr)
	treeStart := c.as.newLabel()
	if c.arch.X32Bit != 0 {
		high := c.as.newLabel()
		c.as.jump(bpfJSET, c.arch.X32Bit, high, treeStart)
		c.as.bind(high)
		c.as.jump(bpfJEQ, nrSkip, treeStart, killArch)
	}
	c.as.bind(treeStart)
	c.emitTree(segs, target)

	for i, b := range c.blocks {
		c.as.bind(blockLabels[i])
		c.emitBlock(b)
	}
	for _, a := range c.retList {
		c.as.bind(c.rets[a])
		c.as.ret(uint32(a))
	}
	insns, err := c.as.assemble()
	if err != nil {
		return nil, err
	}
	if err := Validate(insns); err != nil {
		return nil, fmt.Errorf("seccomp: internal error: generated program is invalid: %w", err)
	}
	return &Program{
		Arch:         c.arch,
		Instructions: insns,
		Flags:        c.profile.Flags,
		Skipped:      c.skipped,
		Ranges:       len(segs),
	}, nil
}

// resolveNumbers maps the profile's syscall names to numbers on the target
// architecture, merging rules of names that share a number.
func (c *compiler) resolveNumbers() (map[uint32]*syscallRules, error) {
	byName := c.profile.bySyscall()
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	perNr := map[uint32]*syscallRules{}
	owner := map[uint32]string{}
	for _, name := range names {
		nr, ok := c.arch.Syscall(name)
		if !ok {
			c.skipped = append(c.skipped, name)
			continue
		}
		sr := byName[name]
		existing, dup := perNr[nr]
		if !dup {
			cp := *sr
			perNr[nr] = &cp
			owner[nr] = name
			continue
		}
		existing.conditional = append(existing.conditional, sr.conditional...)
		if sr.unconditional != nil {
			if existing.unconditional != nil && *existing.unconditional != *sr.unconditional {
				return nil, fmt.Errorf("seccomp: %s and %s are both syscall %d on %s but have different actions",
					owner[nr], name, nr, c.arch.Name)
			}
			existing.unconditional = sr.unconditional
		}
	}
	return perNr, nil
}

// segments partitions the 32-bit syscall-number space into maximal ranges
// with one verdict each, registering argument blocks as it goes.
func (c *compiler) segments(perNr map[uint32]*syscallRules) []segment {
	nrs := make([]uint32, 0, len(perNr))
	for nr := range perNr {
		nrs = append(nrs, nr)
	}
	sort.Slice(nrs, func(i, j int) bool { return nrs[i] < nrs[j] })

	def := verdict{action: c.profile.DefaultAction}
	var segs []segment
	push := func(lo uint32, v verdict) {
		if n := len(segs); n > 0 && !v.conditional && !segs[n-1].v.conditional && segs[n-1].v.action == v.action {
			return // extends the previous range
		}
		segs = append(segs, segment{lo: lo, v: v})
	}
	next := uint64(0)
	for _, nr := range nrs {
		if uint64(nr) > next {
			push(uint32(next), def)
		}
		sr := perNr[nr]
		fallback := c.profile.DefaultAction
		if sr.unconditional != nil {
			fallback = *sr.unconditional
		}
		if len(sr.conditional) == 0 {
			push(nr, verdict{action: fallback})
		} else {
			c.blocks = append(c.blocks, condBlock{rules: sr.conditional, fallback: fallback})
			push(nr, verdict{conditional: true, block: len(c.blocks) - 1})
		}
		next = uint64(nr) + 1
	}
	if next <= nrSkip {
		push(uint32(next), def)
	}
	return segs
}

// emitTree emits a balanced binary search over segs. The accumulator holds
// the syscall number throughout.
func (c *compiler) emitTree(segs []segment, target func(verdict) label) {
	if len(segs) == 1 {
		c.as.jumpAlways(target(segs[0].v))
		return
	}
	mid := len(segs) / 2
	left, right := segs[:mid], segs[mid:]
	sub := func(part []segment) (label, bool) {
		if len(part) == 1 {
			return target(part[0].v), false
		}
		return c.as.newLabel(), true
	}
	leftLabel, leftCode := sub(left)
	rightLabel, rightCode := sub(right)
	c.as.jump(bpfJGE, right[0].lo, rightLabel, leftLabel)
	if leftCode {
		c.as.bind(leftLabel)
		c.emitTree(left, target)
	}
	if rightCode {
		c.as.bind(rightLabel)
		c.emitTree(right, target)
	}
}

// emitBlock emits the argument checks of one conditional syscall.
func (c *compiler) emitBlock(b condBlock) {
	for _, r := range b.rules {
		nextRule := c.as.newLabel()
		for i, cond := range r.Conds {
			pass := c.retLabel(r.Action)
			if i < len(r.Conds)-1 {
				pass = c.as.newLabel()
			}
			c.emitCond(cond, pass, nextRule)
			if i < len(r.Conds)-1 {
				c.as.bind(pass)
			}
		}
		c.as.bind(nextRule)
	}
	c.as.jumpAlways(c.retLabel(b.fallback))
}

// emitCond emits a 64-bit unsigned comparison of one argument using 32-bit
// loads of its high and low words (seccomp_data is little-endian on the
// supported architectures, so the low word comes first).
func (c *compiler) emitCond(cond Cond, pass, fail label) {
	lo := uint32(offArgs + 8*cond.Index)
	hi := lo + 4
	vhi, vlo := uint32(cond.Value>>32), uint32(cond.Value)
	next := c.as.newLabel
	switch cond.Op {
	case OpEqual, OpNotEqual:
		t, f := pass, fail
		if cond.Op == OpNotEqual {
			t, f = fail, pass
		}
		l1 := next()
		c.as.loadAbs(hi)
		c.as.jump(bpfJEQ, vhi, l1, f)
		c.as.bind(l1)
		c.as.loadAbs(lo)
		c.as.jump(bpfJEQ, vlo, t, f)
	case OpGreaterThan, OpGreaterEqual, OpLessThan, OpLessEqual:
		// a > v  <=>  hi > vhi || (hi == vhi && lo > vlo); likewise for >=.
		// a < v is !(a >= v) and a <= v is !(a > v).
		lowOp := uint16(bpfJGT)
		if cond.Op == OpGreaterEqual || cond.Op == OpLessThan {
			lowOp = bpfJGE
		}
		t, f := pass, fail
		if cond.Op == OpLessThan || cond.Op == OpLessEqual {
			t, f = fail, pass
		}
		l1, l2 := next(), next()
		c.as.loadAbs(hi)
		c.as.jump(bpfJGT, vhi, t, l1)
		c.as.bind(l1)
		c.as.jump(bpfJEQ, vhi, l2, f)
		c.as.bind(l2)
		c.as.loadAbs(lo)
		c.as.jump(lowOp, vlo, t, f)
	case OpMaskedEqual:
		mhi, mlo := uint32(cond.Value>>32), uint32(cond.Value)
		whi, wlo := uint32(cond.ValueTwo>>32), uint32(cond.ValueTwo)
		l1 := next()
		c.as.loadAbs(hi)
		c.as.and(mhi)
		c.as.jump(bpfJEQ, whi, l1, fail)
		c.as.bind(l1)
		c.as.loadAbs(lo)
		c.as.and(mlo)
		c.as.jump(bpfJEQ, wlo, pass, fail)
	}
}
