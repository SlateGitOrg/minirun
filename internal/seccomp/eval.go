package seccomp

// Evaluate computes the verdict p prescribes for d on arch directly from the
// profile's semantics, without compiling. It is the specification the
// compiler is tested against, and it backs `minirun seccomp --test` output.
func Evaluate(p *Profile, arch *Arch, d Data) Action {
	if d.Arch != arch.AuditArch {
		return Action(RetKillProcess)
	}
	if arch.X32Bit != 0 && d.Nr&arch.X32Bit != 0 && d.Nr != nrSkip {
		return Action(RetKillProcess)
	}
	var unconditional *Action
	for _, r := range p.Rules {
		nr, ok := arch.Syscall(r.Syscall)
		if !ok || nr != d.Nr {
			continue
		}
		if len(r.Conds) == 0 {
			a := r.Action
			unconditional = &a
			continue
		}
		if condsHold(r.Conds, d.Args) {
			return r.Action
		}
	}
	if unconditional != nil {
		return *unconditional
	}
	return p.DefaultAction
}

func condsHold(conds []Cond, args [6]uint64) bool {
	for _, c := range conds {
		if !c.Matches(args[c.Index]) {
			return false
		}
	}
	return true
}
