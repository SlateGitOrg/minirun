package state

import (
	"io/fs"
	"syscall"
)

// deviceOf returns the st_dev of a file, or 0 if the platform does not
// expose it.
func deviceOf(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev) //nolint:unconvert // int32 on darwin, uint64 on linux
	}
	return 0
}
