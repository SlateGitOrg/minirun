package state

import (
	"io/fs"
	"syscall"
)

// deviceOf returns the st_dev of a file.
func deviceOf(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Dev
	}
	return 0
}
