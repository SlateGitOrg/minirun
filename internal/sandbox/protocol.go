// Package sandbox is the code that runs inside the new container: the init
// process (`minirun __init`), which assembles the root filesystem, pivots
// into it and execs the container command, and the exec helper
// (`minirun __exec`), which enters a running container's mount namespace and
// execs a command there. Both receive their instructions from the parent as
// a launch plan and share the final privilege-dropping sequence.
//
// Parent/child protocol (file descriptors inherited by the child):
//
//	fd 3  plan pipe    parent -> child, one JSON document, then EOF
//	fd 4  start pipe   parent -> child, one byte once the parent is ready
//	                   (and one earlier byte answering "join-cgroup")
//	fd 5  status pipe  child -> parent, JSON lines; close-on-exec, so EOF
//	                   without an error message means exec succeeded
//	fd 6  (exec only)  the container's /proc/<pid>/ns/mnt
package sandbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/SlateGitOrg/minirun/internal/launch"
)

// File descriptor numbers of the protocol.
const (
	PlanFD   = 3
	StartFD  = 4
	StatusFD = 5
	MntNSFD  = 6
)

// Message types sent by the child.
const (
	MsgReady      = "ready"
	MsgError      = "error"
	MsgJoinCgroup = "join-cgroup"
)

// Message is one status line from the child.
type Message struct {
	Type    string `json:"type"` // MsgReady, MsgError or MsgJoinCgroup
	Message string `json:"message,omitempty"`
	Pid     int    `json:"pid,omitempty"`
}

// ExecPlan is what the exec helper receives.
type ExecPlan struct {
	Process launch.Process  `json:"process"`
	Seccomp *launch.Seccomp `json:"seccomp,omitempty"`
}

// WriteMessage writes one status line.
func WriteMessage(w io.Writer, m Message) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

// ErrExecSucceeded is returned by ReadStatus when the status pipe closes
// without an error: the child reached execve.
var ErrExecSucceeded = errors.New("child exec'd")

// StatusReader reads status lines from the child.
type StatusReader struct {
	r *bufio.Reader
}

// NewStatusReader wraps the read end of the status pipe.
func NewStatusReader(r io.Reader) *StatusReader {
	return &StatusReader{r: bufio.NewReader(r)}
}

// Next returns the next message. An "error" message is returned as an
// error; EOF is ErrExecSucceeded.
func (s *StatusReader) Next() (Message, error) {
	line, err := s.r.ReadBytes('\n')
	if errors.Is(err, io.EOF) && len(line) == 0 {
		return Message{}, ErrExecSucceeded
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return Message{}, fmt.Errorf("read child status: %w", err)
	}
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		return Message{}, fmt.Errorf("decode child status %q: %w", line, err)
	}
	if m.Type == MsgError {
		return m, fmt.Errorf("container setup failed: %s", m.Message)
	}
	return m, nil
}
