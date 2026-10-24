package state

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcInfo is what minirun needs from /proc/<pid>/stat.
type ProcInfo struct {
	// State is the one-letter process state (R, S, D, Z, X, ...).
	State byte
	// StartTime is field 22, the start time in clock ticks since boot. A pid
	// together with its start time identifies a process across pid reuse.
	StartTime uint64
}

// ErrNoProcess is returned when the process does not exist.
var ErrNoProcess = errors.New("no such process")

// ParseStat parses the contents of /proc/<pid>/stat. The command name in
// field 2 is parenthesised and may itself contain spaces and ')' characters,
// so parsing resumes after the last ')'.
func ParseStat(data string) (ProcInfo, error) {
	end := strings.LastIndexByte(data, ')')
	if end < 0 {
		return ProcInfo{}, errors.New("stat: missing command name")
	}
	fields := strings.Fields(data[end+1:])
	// fields[0] is field 3 (state); start time is field 22 -> fields[19].
	if len(fields) < 20 || len(fields[0]) != 1 {
		return ProcInfo{}, fmt.Errorf("stat: expected at least 22 fields, got %d", len(fields)+2)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return ProcInfo{}, fmt.Errorf("stat: start time: %w", err)
	}
	return ProcInfo{State: fields[0][0], StartTime: start}, nil
}

// Inspector looks up processes.
type Inspector interface {
	Info(pid int) (ProcInfo, error)
}

// ProcFS reads process information from a procfs mount (normally /proc).
type ProcFS struct {
	Root string
}

// Info implements Inspector.
func (p ProcFS) Info(pid int) (ProcInfo, error) {
	if pid <= 0 {
		return ProcInfo{}, ErrNoProcess
	}
	data, err := os.ReadFile(filepath.Join(p.Root, strconv.Itoa(pid), "stat"))
	if errors.Is(err, fs.ErrNotExist) {
		return ProcInfo{}, ErrNoProcess
	}
	if err != nil {
		return ProcInfo{}, fmt.Errorf("read stat of %d: %w", pid, err)
	}
	return ParseStat(string(data))
}

// Refresh derives the live status of a container whose recorded status is
// created or running: if its init process is gone, a zombie, or the pid now
// belongs to a different process (start time mismatch), the container is
// stopped. Other statuses are returned unchanged. Errors other than "no such
// process" leave the recorded status in place.
func Refresh(st *State, insp Inspector) Status {
	if st.Status != Created && st.Status != Running {
		return st.Status
	}
	info, err := insp.Info(st.Pid)
	switch {
	case errors.Is(err, ErrNoProcess):
		return Stopped
	case err != nil:
		return st.Status
	case info.State == 'Z' || info.State == 'X':
		return Stopped
	case st.PidStartTime != 0 && info.StartTime != st.PidStartTime:
		return Stopped
	}
	return st.Status
}
