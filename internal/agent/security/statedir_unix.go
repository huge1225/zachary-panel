//go:build unix

package security

import (
	"fmt"
	"os"
	"syscall"
)

func checkOwner(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("owned by uid %d, expected %d", st.Uid, os.Getuid())
	}
	return nil
}
