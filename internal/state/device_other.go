//go:build !linux

package state

import (
	"io/fs"
	"syscall"
)

// deviceOf returns the st_dev of a file (an int32 on the BSDs and macOS).
func deviceOf(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}
