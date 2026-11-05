//go:build !unix

package security

import "os"

func checkOwner(fi os.FileInfo) error { return nil }
