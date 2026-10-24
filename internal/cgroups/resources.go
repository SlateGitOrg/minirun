package cgroups

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/archit2501/minirun/internal/spec"
)

// Setting is one write to a cgroup interface file.
type Setting struct {
	File  string `json:"file"`
	Value string `json:"value"`
}

// Controller returns the controller that owns the file ("memory" for
// "memory.max").
func (s Setting) Controller() string {
	c, _, _ := strings.Cut(s.File, ".")
	return c
}

// Default CFS period used when a quota is given without one, matching the
// kernel default.
const defaultCPUPeriod = 100000

var (
	unifiedKeyRE = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z0-9_.]+$`)
	cpuListRE    = regexp.MustCompile(`^\d+(-\d+)?(,\d+(-\d+)?)*$`)
)

// Settings translates OCI resources into cgroup v2 interface-file writes,
// sorted by file name. Conversions follow runc's cgroup v2 driver:
//
//   - memory.limit -> memory.max, memory.reservation -> memory.low
//   - memory.swap is memory+swap in OCI, so memory.swap.max = swap - limit
//   - cpu.shares (2..262144) -> cpu.weight (1..10000), linearly
//   - cpu.quota/period -> cpu.max "<quota|max> <period>"
//   - cpu.cpus/mems -> cpuset.cpus/mems; pids.limit -> pids.max
//   - linux.resources.unified entries are written verbatim and override the
//     converted values for the same file
func Settings(r *spec.Resources) ([]Setting, error) {
	if r == nil {
		return nil, nil
	}
	out := map[string]string{}
	var errs []error
	if err := memorySettings(r.Memory, out); err != nil {
		errs = append(errs, err)
	}
	if err := cpuSettings(r.CPU, out); err != nil {
		errs = append(errs, err)
	}
	if r.Pids != nil {
		out["pids.max"] = maxOrNumber(r.Pids.Limit)
	}
	for k, v := range r.Unified {
		if err := checkUnified(k, v); err != nil {
			errs = append(errs, err)
			continue
		}
		out[k] = v
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	settings := make([]Setting, 0, len(out))
	for f, v := range out {
		settings = append(settings, Setting{File: f, Value: v})
	}
	sort.Slice(settings, func(i, j int) bool { return settings[i].File < settings[j].File })
	return settings, nil
}

func maxOrNumber(v int64) string {
	if v <= 0 {
		return "max"
	}
	return strconv.FormatInt(v, 10)
}

func memorySettings(m *spec.Memory, out map[string]string) error {
	if m == nil {
		return nil
	}
	if m.Limit != nil {
		switch {
		case *m.Limit == -1:
			out["memory.max"] = "max"
		case *m.Limit <= 0:
			return fmt.Errorf("linux.resources.memory.limit %d: must be positive or -1", *m.Limit)
		default:
			out["memory.max"] = strconv.FormatInt(*m.Limit, 10)
		}
	}
	if m.Reservation != nil {
		switch r := *m.Reservation; {
		case r == -1:
			out["memory.low"] = "max"
		case r < 0:
			return fmt.Errorf("linux.resources.memory.reservation %d: must be >= 0 or -1", r)
		default:
			out["memory.low"] = strconv.FormatInt(r, 10)
		}
	}
	if m.Swap != nil {
		switch {
		case *m.Swap == -1:
			out["memory.swap.max"] = "max"
		case m.Limit == nil || *m.Limit == -1:
			return errors.New("linux.resources.memory.swap: a finite swap limit needs a finite memory.limit (OCI swap is memory+swap)")
		case *m.Swap < *m.Limit:
			return fmt.Errorf("linux.resources.memory.swap %d: must be >= memory.limit %d (OCI swap is memory+swap)", *m.Swap, *m.Limit)
		default:
			out["memory.swap.max"] = strconv.FormatInt(*m.Swap-*m.Limit, 10)
		}
	}
	return nil
}

// SharesToWeight converts cgroup v1 cpu.shares to cgroup v2 cpu.weight
// using the same linear map as runc and crun: 2 -> 1, 262144 -> 10000.
func SharesToWeight(shares uint64) uint64 {
	if shares == 0 {
		return 0
	}
	return 1 + ((shares-2)*9999)/262142
}

func cpuSettings(c *spec.CPU, out map[string]string) error {
	if c == nil {
		return nil
	}
	if c.Shares != nil {
		if *c.Shares < 2 || *c.Shares > 262144 {
			return fmt.Errorf("linux.resources.cpu.shares %d: must be in 2..262144", *c.Shares)
		}
		out["cpu.weight"] = strconv.FormatUint(SharesToWeight(*c.Shares), 10)
	}
	if c.Quota != nil || c.Period != nil {
		period := uint64(defaultCPUPeriod)
		if c.Period != nil {
			period = *c.Period
		}
		if period < 1000 || period > 1000000 {
			return fmt.Errorf("linux.resources.cpu.period %d: must be in 1000..1000000 microseconds", period)
		}
		quota := "max"
		if c.Quota != nil && *c.Quota > 0 {
			if *c.Quota < 1000 {
				return fmt.Errorf("linux.resources.cpu.quota %d: must be at least 1000 microseconds", *c.Quota)
			}
			quota = strconv.FormatInt(*c.Quota, 10)
		}
		out["cpu.max"] = quota + " " + strconv.FormatUint(period, 10)
	}
	if c.Cpus != "" {
		if !cpuListRE.MatchString(c.Cpus) {
			return fmt.Errorf("linux.resources.cpu.cpus %q: not a CPU list like 0-3,6", c.Cpus)
		}
		out["cpuset.cpus"] = c.Cpus
	}
	if c.Mems != "" {
		if !cpuListRE.MatchString(c.Mems) {
			return fmt.Errorf("linux.resources.cpu.mems %q: not a node list like 0-1", c.Mems)
		}
		out["cpuset.mems"] = c.Mems
	}
	return nil
}

func checkUnified(key, value string) error {
	if !unifiedKeyRE.MatchString(key) || strings.Contains(key, "..") {
		return fmt.Errorf("linux.resources.unified %q: not a cgroup interface file name", key)
	}
	if strings.HasPrefix(key, "cgroup.") {
		return fmt.Errorf("linux.resources.unified %q: cgroup core files are managed by minirun", key)
	}
	if strings.ContainsAny(value, "\n\x00") {
		return fmt.Errorf("linux.resources.unified %q: value must be a single line", key)
	}
	return nil
}

// Controllers returns the distinct controllers the settings need, sorted.
func Controllers(settings []Setting) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range settings {
		c := s.Controller()
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}
